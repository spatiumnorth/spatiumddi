"""Retention sweep for the E911 lookup trail (#3514).

``POST /held`` is read-scoped but writes one ``e911_resolution_log`` row per
lookup, so the table needs a retention cap alongside the per-caller logging
budget. Idempotent: a re-run only deletes rows still past the cutoff.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete

from app.celery_app import celery_app
from app.db import task_session
from app.models.e911 import E911ResolutionLog

logger = structlog.get_logger(__name__)

RETENTION_DAYS = 90


async def _sweep() -> int:
    cutoff = datetime.now(UTC) - timedelta(days=RETENTION_DAYS)
    async with task_session() as db:
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
