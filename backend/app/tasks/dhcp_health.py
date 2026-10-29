"""DHCP server health check Celery tasks.

Two code paths:

* **Agent-based drivers** (``kea``): trust the agent heartbeat.
  ``agent_last_seen`` is stamped by ``POST /api/v1/dhcp/servers/{id}/heartbeat``;
  if it's fresh we flip status to ``active``, otherwise ``unreachable``.
* **Agentless drivers** (``windows_dhcp``, ``fortigate``): the control plane
  has to do the poking itself. We call ``driver.health_check(server)`` — a
  WinRM round-trip (``Get-DhcpServerVersion``) for Windows, a REST probe (list
  interfaces) for FortiGate — and flip status based on the boolean result.

Either way, ``last_health_check_at`` is always stamped so the dashboard shows
an up-to-date timestamp instead of the "never checked" placeholder.

Uses a per-task async engine + session factory (see
``app.tasks.dhcp_pull_leases`` for the same pattern). Re-using the shared
``AsyncSessionLocal`` from worker code ties its asyncpg connections to the
first event loop that touches it, which causes "Future attached to a
different loop" errors across concurrent Celery tasks.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.drivers.dhcp import get_driver, is_agentless
from app.models.dhcp import DHCPServer
from app.services.agents.daemon_state import forget_stale_ok
from app.services.feature_modules import is_module_enabled
from app.tasks.module_gate import module_gated

# If agent hasn't heartbeat'd in this long, mark unreachable.
AGENT_STALE_AFTER = timedelta(seconds=120)

logger = structlog.get_logger(__name__)


async def _check_health(server_id: uuid.UUID) -> None:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dhcp"):
                return
            server = await db.get(DHCPServer, server_id)
            if server is None:
                return

            now = datetime.now(UTC)

            # Issue #182: skip the health probe entirely for paused
            # servers. Status stays at whatever it was at pause time;
            # the UI's amber Maintenance chip is the operator-visible
            # signal while the server is intentionally offline.
            if server.maintenance_mode:
                server.last_health_check_at = now
                await db.commit()
                logger.info(
                    "dhcp_health_skipped_maintenance",
                    server_id=str(server_id),
                    host=server.host,
                )
                return

            if is_agentless(server.driver):
                # Agentless: ask the driver to round-trip against the server.
                # Any exception from get_driver / health_check is caught and
                # surfaced as status="unreachable" — we still stamp the check
                # timestamp so the dashboard reflects that we did try.
                try:
                    driver = get_driver(server.driver)
                    ok, _msg = await driver.health_check(server)
                    server.status = "active" if ok else "unreachable"
                except Exception as exc:  # noqa: BLE001 — surface any driver error
                    server.status = "unreachable"
                    logger.warning(
                        "dhcp_health_driver_probe_failed",
                        server_id=str(server_id),
                        driver=server.driver,
                        host=server.host,
                        error=str(exc),
                    )
            else:
                # Agent-based: trust the heartbeat.
                last_seen = server.agent_last_seen
                if last_seen is not None and (now - last_seen) <= AGENT_STALE_AFTER:
                    server.status = "active"
                else:
                    server.status = "unreachable"
                    # #2961 — no heartbeat, so no current daemon state: the
                    # last ``ok`` is not evidence of anything any more.
                    forget_stale_ok(server)

            server.last_health_check_at = now
            await db.commit()

            logger.info(
                "dhcp_health_checked",
                server_id=str(server_id),
                driver=server.driver,
                agentless=is_agentless(server.driver),
                status=server.status,
                host=server.host,
            )
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.dhcp_health.check_dhcp_server_health",
    bind=True,
    max_retries=3,
    acks_late=True,
)
def check_dhcp_server_health(self: object, server_id: str) -> None:  # type: ignore[type-arg]
    """Idempotent single-server health check."""
    try:
        asyncio.run(_check_health(uuid.UUID(server_id)))
    except Exception as exc:  # noqa: BLE001
        logger.warning("dhcp_health_check_error", server_id=server_id, error=str(exc))
        raise self.retry(exc=exc, countdown=30) from exc  # type: ignore[attr-defined]


async def _enqueue_all() -> None:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dhcp"):
                return
            result = await db.execute(select(DHCPServer.id))
            ids = [str(row[0]) for row in result.all()]
    finally:
        await engine.dispose()
    for sid in ids:
        check_dhcp_server_health.delay(sid)


@celery_app.task(name="app.tasks.dhcp_health.check_all_dhcp_servers_health", bind=True)
@module_gated("core.dhcp")
def check_all_dhcp_servers_health(self: object) -> None:  # type: ignore[type-arg]
    """Fan-out task — enqueues one health check per registered DHCP server.

    Scheduled every 60s by Celery beat (see app.celery_app).
    """
    asyncio.run(_enqueue_all())
