"""Periodic "DHCP MAC block sync" task.

Fires every 60 s from Celery Beat and runs once
``PlatformSettings.dhcp_mac_blocks_sync_interval_seconds`` has elapsed
(60 by default, #4759). For every agentless DHCP server (Windows DHCP
today), reconciles the server's deny filter list against the active MAC
blocks on its group. Kea servers don't need this task —
they pick up blocklist changes through the ConfigBundle + DROP class
render, not per-object writes.

The task is idempotent: if the deny-list already matches the desired
set, the driver issues zero cmdlets and returns ``(0, 0)`` — but it
still reads the server's filter list, one WinRM round trip per server.
Each run picks up expiry transitions and toggle changes without any
explicit trigger from the API path, so the interval is also how long a
change can take to reach the server.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.drivers.dhcp import is_agentless
from app.drivers.dhcp.base import MACBlockDef
from app.drivers.dhcp.registry import get_driver
from app.models.dhcp import DHCPMACBlock, DHCPServer
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled
from app.tasks._interval_gate import interval_skip
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
# Beat fires the sync every 60 s; a shorter configured interval cannot be
# honoured, so it is floored here.
_MIN_INTERVAL = timedelta(seconds=60)


async def _run_sync() -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dhcp"):
                return {"status": "disabled"}

            now = datetime.now(UTC)
            # #4759 — the operator-configured cadence; the stamp is taken
            # before the servers are reached so a slow pass is not started
            # again by the next tick.
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is not None:
                interval = max(
                    _MIN_INTERVAL, timedelta(seconds=ps.dhcp_mac_blocks_sync_interval_seconds)
                )
                skip = interval_skip(now, ps.dhcp_mac_blocks_sync_last_run_at, interval)
                if skip is not None:
                    return skip
                ps.dhcp_mac_blocks_sync_last_run_at = now
                await db.commit()

            servers = list((await db.execute(select(DHCPServer))).scalars().all())
            by_group: dict[Any, list[MACBlockDef]] = {}

            servers_synced = 0
            total_added = 0
            total_removed = 0
            errors: list[str] = []

            for server in servers:
                if not is_agentless(server.driver) or server.server_group_id is None:
                    continue

                # Load the group's active (enabled + not expired) blocks
                # once per group; multiple Windows DHCPs in one group all
                # consume the same set.
                gid = server.server_group_id
                if gid not in by_group:
                    res = await db.execute(
                        select(DHCPMACBlock).where(
                            DHCPMACBlock.group_id == gid,
                            DHCPMACBlock.enabled.is_(True),
                            or_(
                                DHCPMACBlock.expires_at.is_(None),
                                DHCPMACBlock.expires_at > now,
                            ),
                        )
                    )
                    by_group[gid] = [
                        MACBlockDef(
                            mac_address=str(r.mac_address).lower(),
                            reason=r.reason or "other",
                            description=r.description or "",
                        )
                        for r in res.scalars().all()
                    ]

                desired = by_group[gid]
                try:
                    driver = get_driver(server.driver)
                except ValueError:
                    continue

                try:
                    added, removed = await driver.sync_mac_blocks(server, desired=desired)
                except Exception as exc:  # noqa: BLE001 — one server shouldn't poison the run
                    errors.append(f"{server.name}: {exc}")
                    logger.warning(
                        "dhcp_mac_blocks_sync_failed",
                        server=str(server.id),
                        driver=server.driver,
                        error=str(exc),
                    )
                    continue

                servers_synced += 1
                total_added += added
                total_removed += removed

            return {
                "status": "ok",
                "servers_synced": servers_synced,
                "added": total_added,
                "removed": total_removed,
                "errors": errors,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.dhcp_mac_blocks.sync_dhcp_mac_blocks",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    max_retries=2,
)
@module_gated("core.dhcp")
def sync_dhcp_mac_blocks(self: Any) -> dict[str, Any]:  # noqa: ARG001
    """Beat-fired entrypoint. Runs the async reconciler under asyncio."""
    return asyncio.run(_run_sync())


__all__ = ["sync_dhcp_mac_blocks"]
