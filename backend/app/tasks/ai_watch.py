"""Copilot Watch beat task (issue #4405).

Fires every 60 s. The task itself decides whether a run is due (an
operator asked, an alert opened or got worse and the debounce passed, or
the sweep interval elapsed), so changing the schedule in the UI needs no
beat restart. See ``app.services.ai.watch.runner`` for the logic.

One run at a time: a session-level advisory lock is taken first and held
on the task's single connection until the task ends. A second worker that
picks up an overlapping tick finds the lock taken and returns. That also
makes the task safe to retry (non-negotiable #9): a retried tick either
waits its turn or finds the trigger already spent.

Gated on the ``ai.watch`` module, which requires ``ai.copilot``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog
from sqlalchemy import text

from app.celery_app import celery_app
from app.db import task_session
from app.services.ai.watch import runner
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

# Session-stable advisory-lock key: one Watch tick at a time across
# workers. Released when the connection closes.
_WATCH_LOCK_KEY = 0x53504D415757  # "SPMAWW"


async def _tick() -> dict[str, Any]:
    async with task_session() as db:
        got = (
            await db.execute(text("select pg_try_advisory_lock(:k)"), {"k": _WATCH_LOCK_KEY})
        ).scalar()
        if not got:
            return {"status": "locked"}
        try:
            return await runner.tick(db)
        finally:
            await db.rollback()
            await db.execute(text("select pg_advisory_unlock(:k)"), {"k": _WATCH_LOCK_KEY})
            await db.commit()


@celery_app.task(name="app.tasks.ai_watch.tick")
@module_gated("ai.watch")
def tick() -> dict[str, Any]:
    result = asyncio.run(_tick())
    if result.get("status") not in ("disabled", "idle", "paused", "locked"):
        logger.info("ai_watch_tick", **result)
    return result


__all__ = ["tick"]
