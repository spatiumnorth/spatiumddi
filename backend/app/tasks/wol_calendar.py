"""Beat-driven refresh of Wake-on-LAN calendar subscriptions — Phase 2
(issue #586).

Mirrors the DNS blocklist feed refresh (:mod:`app.tasks.dns`) + the UniFi
per-target interval sweep (:mod:`app.tasks.unifi_sync`):

* :func:`sweep_wol_calendars` — 60 s beat tick. Gated on the
  ``tools.wake_scheduler`` feature module (non-negotiable #14). Walks every
  ENABLED calendar whose ``refresh_interval_minutes`` cadence has elapsed and
  reconciles it via :func:`app.services.wol_scheduler.calendar_sync.sync_calendar`.
  One bad calendar can't wedge the sweep (per-calendar try/except).
* :func:`sync_wol_calendar` — the programmatic single-calendar retry surface
  (``autoretry_for`` transient network errors + backoff, like
  ``refresh_blocklist_feed``). The REST "sync now" button runs ``sync_calendar``
  INLINE in the request for immediate feedback; this task exists for
  retry-on-transient dispatch.

Idempotent + safe to retry (non-negotiable #9) — ``sync_calendar`` is a pure
set-reconcile of the current horizon's events.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.models.wol_schedule import WolCalendar
from app.services.feature_modules import get_enabled_modules
from app.services.wol_scheduler.calendar_sync import sync_calendar
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

MODULE_ID = "tools.wake_scheduler"


def _due(calendar: WolCalendar, now: datetime) -> bool:
    """Whether ``calendar``'s per-target refresh interval has elapsed."""
    if calendar.last_synced_at is None:
        return True
    interval = max(1, calendar.refresh_interval_minutes)
    return (now - calendar.last_synced_at) >= timedelta(minutes=interval)


async def _sweep() -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if MODULE_ID not in await get_enabled_modules(db):
                return {"status": "module_disabled", "synced": 0}

            rows = (
                (await db.execute(select(WolCalendar).where(WolCalendar.enabled.is_(True))))
                .scalars()
                .all()
            )
            now = datetime.now(UTC)
            synced = 0
            skipped_interval = 0
            errors = 0
            for calendar in rows:
                if not _due(calendar, now):
                    skipped_interval += 1
                    continue
                try:
                    await sync_calendar(db, calendar)
                    synced += 1
                except Exception as exc:  # noqa: BLE001 — one bad feed can't wedge the sweep
                    errors += 1
                    logger.warning(
                        "wol_calendar_sweep_error",
                        calendar_id=str(calendar.id),
                        error=str(exc),
                    )
            return {
                "status": "ok",
                "synced": synced,
                "skipped_interval": skipped_interval,
                "errors": errors,
            }
    finally:
        await engine.dispose()


async def _sync_one(calendar_id: str) -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            calendar = await db.get(WolCalendar, uuid.UUID(calendar_id))
            if calendar is None:
                return {"status": "not_found"}
            return await sync_calendar(db, calendar)
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.wol_calendar.sweep_wol_calendars", bind=True)
@module_gated("tools.wake_scheduler")
def sweep_wol_calendars(self: object) -> dict[str, Any]:  # noqa: ARG001
    result = asyncio.run(_sweep())
    if result.get("synced") or result.get("errors"):
        logger.info("wol_calendar_sweep_tick", **result)
    return result


@celery_app.task(
    name="app.tasks.wol_calendar.sync_wol_calendar",
    bind=True,
    autoretry_for=(httpx.HTTPError, socket.gaierror),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
)
def sync_wol_calendar(self: object, calendar_id: str) -> dict[str, Any]:  # noqa: ARG001
    """Refresh one calendar with transient-error retry (backoff).

    ``sync_calendar`` re-raises ``httpx.HTTPError`` / ``socket.gaierror`` after
    persisting the per-row error state, so ``autoretry_for`` backs off; a parse
    failure is swallowed (no retry).
    """
    return asyncio.run(_sync_one(calendar_id))


__all__ = ["sweep_wol_calendars", "sync_wol_calendar"]
