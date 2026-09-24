"""Periodic "DHCP lease pull" task.

Fired every 10 seconds by Celery Beat. Gates on
``PlatformSettings.dhcp_pull_leases_enabled`` + its interval, so the
beat schedule stays static while the UI can change cadence live. The
interval is stored in *seconds* (minimum 10) so operators can tune
near-real-time IPAM population from Windows DHCP without restarting
beat.

Each run iterates every ``DHCPServer`` whose driver is registered as
agentless (``windows_dhcp``, ``fortigate``) and calls
``pull_leases_from_server`` to:

  1. Poll the server for active leases (driver-specific — WinRM +
     ``Get-DhcpServerv4Lease`` for windows_dhcp).
  2. Upsert ``DHCPLease`` rows keyed by ``(server_id, ip_address)``.
  3. Mirror each lease into IPAM (``IPAddress`` with ``status="dhcp"``
     and ``auto_from_lease=True``) when the lease IP falls within a
     known subnet.
  4. Absence-delete leases the server stopped reporting (#482, with the
     zero-wire floor guard) — sparing the shared IPAM mirror while a
     failover / HA peer still holds the lease (#1110).

For drivers with ``get_scopes`` it also reconciles scopes, pools and
reservations, and records each Windows server's failover relationships
and the scopes it holds (#1110). The ``dhcp_lease_cleanup`` sweep still
reclaims leases that pass their expiry between polls.

Idempotent: re-running is a no-op whenever DB and wire already agree.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_group_channel, publish_wake
from app.drivers.dhcp import is_agentless
from app.models.audit import AuditLog
from app.models.dhcp import DHCPServer
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1


async def _run_pull() -> dict[str, Any]:
    # Deferred import — keeps celery-worker startup light and avoids pulling
    # in the API router graph just to register the task.
    from app.services.dhcp.pull_leases import (  # noqa: PLC0415
        pull_leases_from_server,
    )

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dhcp"):
                return {"status": "disabled"}
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None or not ps.dhcp_pull_leases_enabled:
                return {"status": "disabled"}

            now = datetime.now(UTC)
            # Minimum 10 s — beat only ticks that often, and we don't want to
            # hammer the WinRM endpoint harder than that by accident.
            interval = timedelta(seconds=max(10, ps.dhcp_pull_leases_interval_seconds))
            if ps.dhcp_pull_leases_last_run_at is not None:
                elapsed = now - ps.dhcp_pull_leases_last_run_at
                if elapsed < interval:
                    return {
                        "status": "skipped",
                        "reason": "interval_not_elapsed",
                        "wait_seconds": int((interval - elapsed).total_seconds()),
                    }

            servers = list((await db.execute(select(DHCPServer))).scalars().all())

            servers_scanned = 0
            total_server_leases = 0
            total_imported = 0
            total_refreshed = 0
            total_removed = 0
            total_ipam_created = 0
            total_ipam_refreshed = 0
            total_ipam_revoked = 0
            total_out_of_scope = 0
            total_scopes_imported = 0
            total_scopes_refreshed = 0
            total_scopes_skipped = 0
            total_pools_synced = 0
            total_statics_synced = 0
            total_pools_removed = 0
            total_statics_removed = 0
            total_scopes_deferred = 0
            errors: list[str] = []
            # #1110 — persistent conditions (uncoordinated scopes, drifted
            # failover partners, denied failover reads). Carried in the audit
            # payload when a row is written, but never the reason one is: a
            # condition that holds for a week would otherwise write a row
            # every tick of that week.
            warnings: list[str] = []
            wake_group_ids: set[str] = set()  # #428 — DNS groups to wake post-commit

            for server in servers:
                if not is_agentless(server.driver):
                    continue

                servers_scanned += 1
                try:
                    result = await pull_leases_from_server(db, server, apply=True)
                except Exception as exc:  # noqa: BLE001 — don't let one server poison the run
                    errors.append(f"{server.name}: {exc}")
                    logger.warning(
                        "dhcp_pull_leases_server_failed",
                        server=str(server.id),
                        driver=server.driver,
                        error=str(exc),
                    )
                    continue

                total_server_leases += result.server_leases
                total_imported += result.imported
                total_refreshed += result.refreshed
                total_removed += result.removed
                total_ipam_created += result.ipam_created
                total_ipam_refreshed += result.ipam_refreshed
                total_ipam_revoked += result.ipam_revoked
                total_out_of_scope += result.out_of_scope
                total_scopes_imported += result.scopes_imported
                total_scopes_refreshed += result.scopes_refreshed
                total_scopes_skipped += result.scopes_skipped_no_subnet
                total_pools_synced += result.pools_synced
                total_statics_synced += result.statics_synced
                total_pools_removed += result.pools_removed
                total_statics_removed += result.statics_removed
                total_scopes_deferred += result.scopes_deferred
                wake_group_ids.update(result.dns_wake_group_ids)
                errors.extend(f"{server.name}: {e}" for e in result.errors)
                warnings.extend(f"{server.name}: {w}" for w in result.warnings)

            ps.dhcp_pull_leases_last_run_at = now

            if (
                total_imported
                or total_refreshed
                or total_removed
                or total_ipam_created
                or total_ipam_revoked
                # Destructive topology work counts too (#620). Without these, a
                # poll whose only effect was absence-deleting reservations — and
                # their IPAM mirrors, and their DNS records — wrote NO audit row
                # at all, because every counter above tracks leases, not statics.
                or total_statics_synced
                or total_statics_removed
                or total_pools_removed
                or errors
            ):
                db.add(
                    AuditLog(
                        user_display_name="<system>",
                        auth_source="system",
                        action="dhcp-lease-pull",
                        resource_type="platform",
                        resource_id=str(_SINGLETON_ID),
                        resource_display="auto-pull",
                        result="error" if errors else "success",
                        new_value={
                            "servers_scanned": servers_scanned,
                            "server_leases": total_server_leases,
                            "imported": total_imported,
                            "refreshed": total_refreshed,
                            "removed": total_removed,
                            "ipam_created": total_ipam_created,
                            "ipam_refreshed": total_ipam_refreshed,
                            "ipam_revoked": total_ipam_revoked,
                            "out_of_scope": total_out_of_scope,
                            "scopes_imported": total_scopes_imported,
                            "scopes_refreshed": total_scopes_refreshed,
                            "scopes_skipped_no_subnet": total_scopes_skipped,
                            "pools_synced": total_pools_synced,
                            "statics_synced": total_statics_synced,
                            "pools_removed": total_pools_removed,
                            "statics_removed": total_statics_removed,
                            "scopes_deferred": total_scopes_deferred,
                            "errors": errors[:20],
                            "warnings": warnings[:20],
                        },
                    )
                )
            await db.commit()

            # #428 — wake the agent long-polls for any DNS group whose zone
            # got a DDNS record this pull, AFTER commit (per the wake
            # contract), so Windows-pull DDNS converges instantly instead of
            # waiting on the agent's safety tick.
            for gid in wake_group_ids:
                await publish_wake(dns_group_channel(gid))

            logger.info(
                "dhcp_pull_leases_completed",
                servers_scanned=servers_scanned,
                server_leases=total_server_leases,
                imported=total_imported,
                refreshed=total_refreshed,
                removed=total_removed,
                ipam_created=total_ipam_created,
                ipam_refreshed=total_ipam_refreshed,
                ipam_revoked=total_ipam_revoked,
                out_of_scope=total_out_of_scope,
                scopes_imported=total_scopes_imported,
                scopes_refreshed=total_scopes_refreshed,
                scopes_skipped_no_subnet=total_scopes_skipped,
                pools_synced=total_pools_synced,
                statics_synced=total_statics_synced,
                scopes_deferred=total_scopes_deferred,
                error_count=len(errors),
                warning_count=len(warnings),
            )
            return {
                "status": "ran",
                "servers_scanned": servers_scanned,
                "server_leases": total_server_leases,
                "imported": total_imported,
                "refreshed": total_refreshed,
                "removed": total_removed,
                "ipam_created": total_ipam_created,
                "ipam_refreshed": total_ipam_refreshed,
                "ipam_revoked": total_ipam_revoked,
                "out_of_scope": total_out_of_scope,
                "scopes_imported": total_scopes_imported,
                "scopes_refreshed": total_scopes_refreshed,
                "scopes_skipped_no_subnet": total_scopes_skipped,
                "pools_synced": total_pools_synced,
                "statics_synced": total_statics_synced,
                "errors": len(errors),
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.dhcp_pull_leases.auto_pull_dhcp_leases", bind=True)
def auto_pull_dhcp_leases(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Celery beat entrypoint — fires every 10s; the task itself checks the
    platform-settings gate and the per-run interval (in seconds)."""
    try:
        return asyncio.run(_run_pull())
    except Exception as exc:  # noqa: BLE001
        logger.exception("dhcp_pull_leases_failed", error=str(exc))
        raise
