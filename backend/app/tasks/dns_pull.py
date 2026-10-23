"""Periodic "DNS server sync" task.

Fired every 60 seconds by Celery Beat. Gates on
``PlatformSettings.dns_pull_from_server_enabled`` (historical column name;
the feature is now two-way) + its interval, so the beat schedule stays
static while the UI can change cadence live.

Each run iterates every ``DNSZone`` whose primary server's driver supports
``pull_zone_records`` (today: ``windows_dns`` — BIND9 would need the same
driver method to participate and is left as a follow-up). For each such
zone we run the full bi-directional sync via
``sync_zone_with_server``:

  1. AXFR the server and additively import records missing from the DB.
  2. For every DB row not already on the wire, push it back via the
     driver's ``apply_record_change`` (RFC 2136 update).

Never deletes on either side. Idempotent: re-running is a no-op whenever
the two sides already agree.
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
from app.db import task_connect_args
from app.drivers.dns import get_driver
from app.models.audit import AuditLog
from app.models.dns import DNSServer, DNSZone
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled
from app.tasks._interval_gate import interval_skip

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1


async def _run_sync() -> dict[str, Any]:
    # Deferred imports — keep celery-worker startup light and avoid pulling
    # in the FastAPI router graph.
    from app.services.dns.pull_from_server import (  # noqa: PLC0415
        sync_zone_with_server,
    )

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return {"status": "disabled"}
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None or not ps.dns_pull_from_server_enabled:
                return {"status": "disabled"}

            now = datetime.now(UTC)
            interval = timedelta(minutes=max(1, ps.dns_pull_from_server_interval_minutes))
            skip = interval_skip(now, ps.dns_pull_from_server_last_run_at, interval)
            if skip is not None:
                return skip

            zones = list((await db.execute(select(DNSZone))).scalars().all())

            zones_scanned = 0
            zones_touched = 0
            total_imported = 0
            total_pushed = 0
            total_push_errors = 0
            total_server_records = 0
            errors: list[str] = []

            for zone in zones:
                # Resolve primary for this zone's group and check driver
                # supports the sync path. Skip silently otherwise —
                # agent-based drivers just aren't in scope for this
                # scheduler today.
                primary_res = await db.execute(
                    select(DNSServer).where(
                        DNSServer.group_id == zone.group_id,
                        DNSServer.is_primary.is_(True),
                    )
                )
                primary = primary_res.scalar_one_or_none()
                if primary is None:
                    continue
                # User flipped the server off in the UI — don't sync it.
                if not primary.is_enabled:
                    continue
                driver = get_driver(primary.driver)
                if not hasattr(driver, "pull_zone_records"):
                    continue

                zones_scanned += 1
                try:
                    result = await sync_zone_with_server(db, zone, apply=True)
                except Exception as exc:  # noqa: BLE001 — don't let one zone poison the run
                    errors.append(f"{zone.name}: {exc}")
                    logger.warning(
                        "dns_sync_zone_failed",
                        zone=zone.name,
                        server=str(primary.id),
                        driver=primary.driver,
                        error=str(exc),
                    )
                    continue

                total_server_records += result.pull.server_records
                total_imported += result.pull.imported
                total_pushed += result.push.pushed
                total_push_errors += len(result.push.push_errors)
                if result.pull.imported or result.push.pushed:
                    zones_touched += 1

            ps.dns_pull_from_server_last_run_at = now

            if total_imported or total_pushed or total_push_errors or errors:
                db.add(
                    AuditLog(
                        user_display_name="<system>",
                        auth_source="system",
                        action="dns-server-sync",
                        resource_type="platform",
                        resource_id=str(_SINGLETON_ID),
                        resource_display="auto-sync",
                        result=("error" if (errors or total_push_errors) else "success"),
                        new_value={
                            "imported": total_imported,
                            "pushed": total_pushed,
                            "push_errors": total_push_errors,
                            "zones_touched": zones_touched,
                            "zones_scanned": zones_scanned,
                            "server_records": total_server_records,
                            "errors": errors[:20],
                        },
                    )
                )
            await db.commit()

            logger.info(
                "dns_server_sync_completed",
                imported=total_imported,
                pushed=total_pushed,
                push_errors=total_push_errors,
                zones_touched=zones_touched,
                zones_scanned=zones_scanned,
                server_records=total_server_records,
                error_count=len(errors),
            )
            return {
                "status": "ran",
                "imported": total_imported,
                "pushed": total_pushed,
                "push_errors": total_push_errors,
                "zones_touched": zones_touched,
                "zones_scanned": zones_scanned,
                "server_records": total_server_records,
                "errors": len(errors),
            }
    finally:
        await engine.dispose()


# Celery task name kept stable for backward-compatibility with any deployed
# beat schedule / in-flight messages from the pull-only era.
@celery_app.task(name="app.tasks.dns_pull.auto_pull_dns_from_servers", bind=True)
def auto_pull_dns_from_servers(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Celery beat entrypoint — fires every 60 s; the task itself checks
    the platform-settings gate and the per-run interval. Runs the full
    bi-directional sync (pull + push) per zone."""
    try:
        return asyncio.run(_run_sync())
    except Exception as exc:  # noqa: BLE001
        logger.exception("dns_server_sync_failed", error=str(exc))
        raise
