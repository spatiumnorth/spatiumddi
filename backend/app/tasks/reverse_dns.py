"""Reverse-DNS (PTR) auto-population task (issue #41).

Fired every 60 s by Celery Beat. A fast no-op when
``PlatformSettings.reverse_dns_enabled`` is False or the configured
interval hasn't elapsed — keeping the beat schedule static while letting
the operator change cadence from the UI. The on-demand "Run now" endpoint
calls the same task with ``force=True`` to bypass both gates.

The heavy lifting lives in ``services.ipam.reverse_dns.populate_reverse_dns``;
this module owns the platform-settings gate, the resolver list, the
``last_run_at`` stamp, and a single summary audit row per run.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings
from app.tasks._interval_gate import interval_skip

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1


async def _run_sweep(force: bool = False) -> dict[str, Any]:
    from app.services.ipam.reverse_dns import populate_reverse_dns  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _SINGLETON_ID)
            if ps is None or (not force and not ps.reverse_dns_enabled):
                return {"status": "disabled"}

            now = datetime.now(UTC)
            if not force:
                skip = interval_skip(
                    now,
                    ps.reverse_dns_last_run_at,
                    timedelta(minutes=max(1, ps.reverse_dns_interval_minutes)),
                )
                if skip is not None:
                    return skip

            counts = await populate_reverse_dns(db, resolvers=ps.reverse_dns_resolvers or None)
            ps.reverse_dns_last_run_at = now

            # One summary row per actual sweep — the enabled-gate + interval
            # early-returns above mean we only reach here on a real run (not
            # every 60s tick), so this matches the documented contract
            # without spamming the audit log.
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="reverse-dns",
                    resource_type="platform",
                    resource_id=str(_SINGLETON_ID),
                    resource_display="reverse-dns-sweep",
                    result="success",
                    new_value={"forced": force, **counts},
                )
            )
            await db.commit()

            logger.info("reverse_dns_sweep_completed", forced=force, **counts)
            return {"status": "ran", **counts}
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.reverse_dns.sweep_reverse_dns", bind=True)
def sweep_reverse_dns(self: object, force: bool = False) -> dict[str, Any]:  # type: ignore[type-arg]
    """Beat entrypoint (fires every 60 s) + on-demand entrypoint
    (``force=True`` bypasses the enabled-gate and the interval)."""
    try:
        return asyncio.run(_run_sweep(force=force))
    except Exception as exc:  # noqa: BLE001
        logger.exception("reverse_dns_sweep_failed", error=str(exc))
        raise
