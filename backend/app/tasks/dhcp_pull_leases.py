"""Periodic "DHCP lease pull" task.

Fired every 10 seconds by Celery Beat. Gates on
``PlatformSettings.dhcp_pull_leases_enabled`` + its interval, so the
beat schedule stays static while the UI can change cadence live. The
interval is stored in *seconds* (minimum 10) so operators can tune
near-real-time IPAM population from Windows DHCP without restarting
beat.

Each run reads every ``DHCPServer`` whose driver is registered as
agentless (``windows_dhcp``, ``fortigate``) concurrently (bounded, with a
per-server deadline, #5008) so unreachable hosts cost one connect bound
between them, then calls ``pull_leases_from_server`` for each in turn to:

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
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_group_channel, publish_wake
from app.db import task_connect_args
from app.drivers.dhcp import is_agentless
from app.models.audit import AuditLog
from app.models.dhcp import DHCPServer
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled
from app.tasks._interval_gate import FAST_BEAT_JITTER_TOLERANCE, interval_skip
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1

# #5008 — the wire reads of every due server run together, at most this many
# at a time, so a few unreachable hosts cost one connect bound, not one each.
_READ_CONCURRENCY = 4
# Per-server ceiling on all of a server's reads (scopes, failover, leases): a
# host that stalls costs the pass this long and is recorded as failed.
_READ_TIMEOUT_S = 120.0


async def _run_pull() -> dict[str, Any]:
    # Deferred import — keeps celery-worker startup light and avoids pulling
    # in the API router graph just to register the task.
    from app.services.dhcp.pull_leases import (  # noqa: PLC0415
        _release_pass,
        claim_scan,
        pull_leases_from_server,
        read_wire_bounded,
        release_scan,
    )
    from app.services.ipam.utilization import (  # noqa: PLC0415
        recount_subnets_and_blocks,
    )

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    scan_token: str | None = None
    claim_tokens: dict[Any, str | None] = {}  # per-server pass claims (#5008)

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
            skip = interval_skip(
                now, ps.dhcp_pull_leases_last_run_at, interval, FAST_BEAT_JITTER_TOLERANCE
            )
            if skip is not None:
                return skip

            # #4776 — one scan at a time. The reads hold no transaction, so
            # nothing else stops a second scan reading other servers while
            # this one waits on an unreachable host, and the two together hold
            # every worker process. Taken BEFORE the interval stamp below, so
            # a scan turned away as busy leaves the stamp alone and the next
            # tick after this scan ends can run, instead of waiting a whole
            # interval more. Released in ``finally`` below.
            claimed_scan, scan_token = await claim_scan()
            if not claimed_scan:
                logger.info("dhcp_pull_leases_pass_busy")
                return {"status": "skipped", "reason": "pass_busy"}

            # #2262 — claim the interval BEFORE pulling, atomically. The stamp
            # used to be written only at the end of the pass, so a pull slower
            # than the 10 s beat tick was started again on every tick while it
            # was still running. The conditional UPDATE makes exactly one of
            # several concurrent ticks win; the per-server lock inside
            # ``pull_leases_from_server`` covers the rest (a pass slower than
            # the whole interval, and the manual Sync).
            claimed = await db.execute(
                update(PlatformSettings)
                .where(
                    PlatformSettings.id == _SINGLETON_ID,
                    or_(
                        PlatformSettings.dhcp_pull_leases_last_run_at.is_(None),
                        PlatformSettings.dhcp_pull_leases_last_run_at <= now - interval,
                    ),
                )
                .values(dhcp_pull_leases_last_run_at=now)
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount == 0:
                await db.rollback()
                return {"status": "skipped", "reason": "already_claimed"}
            await db.commit()

            servers = list((await db.execute(select(DHCPServer))).scalars().all())

            servers_busy = 0
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
            touched_subnet_ids: set[Any] = set()  # #3345 — recounted before commit

            agentless_servers = [srv for srv in servers if is_agentless(srv.driver)]
            servers_scanned = len(agentless_servers)

            # #5008 — read every due server's wire at once (bounded), then
            # write the results one server at a time below, so the
            # transactions, the recount and the DDNS wake stay serial. The
            # clock is the database's, taken before any read (#620).
            snapshot_at = (await db.execute(select(func.clock_timestamp()))).scalar_one()
            await db.commit()  # #4776 — no transaction open across the reads
            sem = asyncio.Semaphore(_READ_CONCURRENCY)
            reads = await asyncio.gather(
                *(
                    read_wire_bounded(srv, snapshot_at, sem, claim_tokens, _READ_TIMEOUT_S)
                    for srv in agentless_servers
                ),
                return_exceptions=True,
            )

            for server, wire_read in zip(agentless_servers, reads, strict=True):
                if wire_read is None:
                    # #2262 — a manual Sync (or a still-running pass) holds
                    # this server; it is doing the work, so skip it quietly.
                    servers_busy += 1
                    continue
                try:
                    if isinstance(wire_read, BaseException):
                        raise wire_read
                    # #3345 — recounted once, after the last server's pull.
                    # #4776 — the reads above ran with no transaction open.
                    result = await pull_leases_from_server(
                        db,
                        server,
                        apply=True,
                        recount=False,
                        release_txn_for_wire=True,
                        prefetched=wire_read,
                        claim_token=claim_tokens.get(server.id),
                    )
                except Exception as exc:  # noqa: BLE001 — don't let one server poison the run
                    errors.append(f"{server.name}: {exc}")
                    logger.warning(
                        "dhcp_pull_leases_server_failed",
                        server=str(server.id),
                        driver=server.driver,
                        error=str(exc),
                    )
                    # #2306 — persist on the row so the server list can show
                    # it; a later successful pull clears it.
                    server.last_sync_error = (str(exc) or type(exc).__name__)[:2000]
                    server.last_sync_error_at = now
                    await db.commit()
                    continue

                if result.busy:
                    # The server was deleted or re-pointed while its reads ran.
                    servers_busy += 1
                    await db.commit()
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
                touched_subnet_ids.update(result.touched_subnet_ids)
                errors.extend(f"{server.name}: {e}" for e in result.errors)
                warnings.extend(f"{server.name}: {w}" for w in result.warnings)
                # Each server's writes commit before the next one's, as the
                # reads-then-write pull always did (#4776).
                await db.commit()

            # (``dhcp_pull_leases_last_run_at`` was claimed at the start, #2262.)

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
            # #3345 — the mirrors every pull above created or removed. Last,
            # after the audit row is staged and every driver call is done, so
            # the audit-chain and subnet / block locks are held only to commit.
            await recount_subnets_and_blocks(db, touched_subnet_ids)
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
                servers_busy=servers_busy,
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
                "servers_busy": servers_busy,
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
        # Idempotent: a server's claim is normally released by its pull; this
        # covers one whose pull never started (or blew up before releasing).
        for sid, token in claim_tokens.items():
            await _release_pass(sid, token)
        await release_scan(scan_token)
        await engine.dispose()


@celery_app.task(name="app.tasks.dhcp_pull_leases.auto_pull_dhcp_leases", bind=True)
@module_gated("core.dhcp")
def auto_pull_dhcp_leases(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Celery beat entrypoint — fires every 10s; the task itself checks the
    platform-settings gate and the per-run interval (in seconds)."""
    try:
        return asyncio.run(_run_pull())
    except Exception as exc:  # noqa: BLE001
        logger.exception("dhcp_pull_leases_failed", error=str(exc))
        raise
