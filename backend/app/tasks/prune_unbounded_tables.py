"""Daily retention sweep for the tables that used to grow forever (#2274).

The windows are ``PlatformSettings`` columns (0 = keep forever); the table
list, terminal-row predicates and batching live in
:mod:`app.services.retention`. Idempotent (non-negotiable #9): a re-run only
finds rows still past their cutoff.
"""

from __future__ import annotations

import asyncio

import structlog

from app.celery_app import celery_app
from app.services.retention import prune_unbounded_tables

logger = structlog.get_logger(__name__)


@celery_app.task(name="app.tasks.prune_unbounded_tables.prune_unbounded_tables")
def prune_unbounded_tables_task() -> dict[str, int]:
    removed = asyncio.run(prune_unbounded_tables())
    logger.info("unbounded_tables_pruned", removed=removed)
    return removed
