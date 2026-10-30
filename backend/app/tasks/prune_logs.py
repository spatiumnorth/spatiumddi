"""Nightly retention sweep for the agent ingest receipts.

The agent-shipped log tables, ``dns_query_log_entry``, ``dhcp_log_entry``
and ``dns_rpz_hit``, are time-partitioned (#2185) and their retention is a
partition drop, run by ``maintain_log_partitions`` (see
``app.services.logs.partitions``). What is left here is the receipts (#1077)
older than ``RECEIPT_RETENTION_DAYS``: replay-dedupe state for the same agent
pushes those logs arrive by, so their retention lives next to the logs'. The
delete is a plain age cutoff, so the task is safe to retry (non-negotiable
#9).

``log_retention_hours`` lives with the partition maintenance
(``app.services.logs.partitions``), which applies the window.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.services.agents.ingest_receipt import RECEIPT_RETENTION_DAYS, prune_receipts
from app.services.logs.partitions import RPZ_HIT_RETENTION_DAYS, log_retention_hours

logger = structlog.get_logger(__name__)

#: Reported in place of a count when a table's delete failed, so a caller can
#: tell "could not prune" apart from "nothing to prune" (0).
FAILED = -1


async def _sweep_with_session(db: AsyncSession) -> dict[str, Any]:
    """Run the prune against an explicit session.

    Split out so tests can hand in their pytest-managed session
    against the test database — the celery wrapper opens its own
    against the prod ``DATABASE_URL``.
    """
    try:
        receipts_removed = await prune_receipts(db)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error("log_prune_table_failed", table="agent_ingest_receipt", error=repr(exc))
        receipts_removed = FAILED
    return {
        "agent_ingest_receipt_removed": receipts_removed,
        "failed_tables": ["agent_ingest_receipt"] if receipts_removed == FAILED else [],
        "retention_hours": await log_retention_hours(db),
        "rpz_retention_days": RPZ_HIT_RETENTION_DAYS,
        "receipt_retention_days": RECEIPT_RETENTION_DAYS,
    }


async def _sweep() -> dict[str, Any]:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        return await _sweep_with_session(db)


@celery_app.task(name="app.tasks.prune_logs.prune_log_entries")
def prune_log_entries() -> dict[str, Any]:
    result = asyncio.run(_sweep())
    logger.info("log_entries_pruned", **result)
    return result
