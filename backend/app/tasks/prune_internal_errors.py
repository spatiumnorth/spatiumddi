"""Nightly retention sweep for the diagnostics ``internal_error``
table (issue #123).

Two retention windows:

* **Acknowledged** rows prune after 30 days. Once an operator has
  marked a crash reviewed, there's no value keeping it around once
  it's a month old.
* **Unacknowledged** rows prune after 90 days. Slightly more
  generous because they represent crashes nobody's looked at yet —
  three months gives the next operator a fair chance to triage
  before the row disappears.

Runs once a day; the table is small enough that a daily DELETE is
cheap. No platform-settings knob today; if operators care about
volume we can add one later.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.models.diagnostics import InternalError

logger = structlog.get_logger(__name__)

ACKED_RETENTION_DAYS = 30
UNACKED_RETENTION_DAYS = 90


async def _sweep() -> dict[str, int]:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        now = datetime.now(UTC)
        acked_cutoff = now - timedelta(days=ACKED_RETENTION_DAYS)
        unacked_cutoff = now - timedelta(days=UNACKED_RETENTION_DAYS)

        acked_del = await db.execute(
            delete(InternalError).where(
                InternalError.acknowledged_by.isnot(None),
                InternalError.last_seen_at < acked_cutoff,
            )
        )
        unacked_del = await db.execute(
            delete(InternalError).where(
                InternalError.acknowledged_by.is_(None),
                InternalError.last_seen_at < unacked_cutoff,
            )
        )
        await db.commit()
        return {
            "acked_removed": acked_del.rowcount or 0,
            "unacked_removed": unacked_del.rowcount or 0,
        }


@celery_app.task(name="app.tasks.prune_internal_errors.prune_internal_errors")
def prune_internal_errors() -> dict[str, int]:
    result = asyncio.run(_sweep())
    logger.info("internal_errors_pruned", **result)
    return result
