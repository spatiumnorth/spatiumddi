"""Retention sweep for the E911 lookup trail (#3514).

``POST /held`` is read-scoped but writes one ``e911_resolution_log`` row per
lookup, so the table needs a retention cap alongside the per-caller logging
budget. The window is ``PlatformSettings.e911_resolution_log_retention_days``
(default 90), read on every run. Idempotent: a re-run only deletes rows
still past the cutoff.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete

from app.celery_app import celery_app
from app.db import task_session
from app.models.e911 import E911ResolutionLog
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

#: Used when the settings row is missing (a fresh DB before first boot).
DEFAULT_RETENTION_DAYS = 90


async def _sweep() -> int:
    async with task_session() as db:
        ps = await db.get(PlatformSettings, 1)
        days = DEFAULT_RETENTION_DAYS
        if ps is not None and ps.e911_resolution_log_retention_days > 0:
            days = ps.e911_resolution_log_retention_days
        cutoff = datetime.now(UTC) - timedelta(days=days)
        res = await db.execute(
            delete(E911ResolutionLog).where(E911ResolutionLog.queried_at < cutoff)
        )
        await db.commit()
        return res.rowcount or 0


@celery_app.task(name="app.tasks.prune_e911_resolution_log.prune_e911_resolution_log")
def prune_e911_resolution_log() -> dict[str, int]:
    removed = asyncio.run(_sweep())
    logger.info("e911_resolution_log_pruned", removed=removed)
    return {"removed": removed}
