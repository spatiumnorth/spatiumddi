"""Nightly retention sweep for agent-shipped log entries.

Deletes ``dns_query_log_entry`` and ``dhcp_log_entry`` rows older
than ``PlatformSettings.log_retention_hours`` (default 24 h, capped at
168 h by the settings API, #2273). Query logs are operator-triage
tooling, not analytics — keeping a short rolling window caps the table
size on busy resolvers (10k+ qps means ~36M rows in an hour, so even at
24 h we're already managing a substantial table — we deliberately avoid
a longer default).

Symmetric to ``prune_metrics``: tick once a day, delete everything
past the cutoff. Runs under the default queue.

Also retires agent ingest receipts (#1077) older than
``RECEIPT_RETENTION_DAYS``. They are replay-dedupe state for the same
agent pushes these logs arrive by, so their retention lives with the rest
of agent-shipped data. Every delete here is a plain age cutoff, so the
task is safe to retry (non-negotiable #9).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.models.settings import PlatformSettings
from app.services.agents.ingest_receipt import RECEIPT_RETENTION_DAYS, prune_receipts

logger = structlog.get_logger(__name__)

# Operator-triage window when no settings row exists (the column's own
# default is the same). Anyone wanting longer history should
# stand up Loki / a SIEM and ship there in addition to (or instead
# of) the agent push.
DEFAULT_RETENTION_HOURS = 24

# RPZ policy hits (issue #699) are kept far longer than raw queries and
# swept here rather than in their own task, so all agent-shipped log
# retention stays in one place.
#
# They earn the longer window: a hit is a *summary-shaped* event, not a
# firehose. A busy resolver emits tens of thousands of queries a second
# and a handful of blocklist hits a minute, so 30 days of hits is a
# fraction of a day of queries. And the question they answer — "has this
# host been reaching for blocked domains all week?" — is unanswerable
# inside a 24 h window, which is the whole reason the table exists.
# Matches the threat rollup's WINDOW_RETENTION_DAYS deliberately: both
# are behavioural evidence about clients and should age out together.
RPZ_HIT_RETENTION_DAYS = 30


async def log_retention_hours(db: AsyncSession) -> int:
    """The configured query / activity log window, in hours (#2273).

    Shared by the prune and by the two agent ingest endpoints, which skip
    lines already older than the window instead of inserting rows the next
    prune deletes. Falls back to :data:`DEFAULT_RETENTION_HOURS` when no
    settings row exists yet.
    """
    ps = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    if ps is not None and isinstance(ps.log_retention_hours, int) and ps.log_retention_hours > 0:
        return ps.log_retention_hours
    return DEFAULT_RETENTION_HOURS


async def _sweep_with_session(db: AsyncSession) -> dict[str, int]:
    """Run the prune against an explicit session.

    Split out so tests can hand in their pytest-managed session
    against the test database — the celery wrapper opens its own
    against the prod ``DATABASE_URL``.
    """
    retention_hours = await log_retention_hours(db)
    cutoff = datetime.now(UTC) - timedelta(hours=retention_hours)
    dns_del = await db.execute(delete(DNSQueryLogEntry).where(DNSQueryLogEntry.ts < cutoff))
    dhcp_del = await db.execute(delete(DHCPLogEntry).where(DHCPLogEntry.ts < cutoff))
    rpz_cutoff = datetime.now(UTC) - timedelta(days=RPZ_HIT_RETENTION_DAYS)
    rpz_del = await db.execute(delete(DNSRPZHit).where(DNSRPZHit.ts < rpz_cutoff))
    receipts_removed = await prune_receipts(db)
    await db.commit()
    return {
        "dns_query_log_removed": dns_del.rowcount or 0,
        "dhcp_log_removed": dhcp_del.rowcount or 0,
        "dns_rpz_hit_removed": rpz_del.rowcount or 0,
        "agent_ingest_receipt_removed": receipts_removed,
        "retention_hours": retention_hours,
        "rpz_retention_days": RPZ_HIT_RETENTION_DAYS,
        "receipt_retention_days": RECEIPT_RETENTION_DAYS,
    }


async def _sweep() -> dict[str, int]:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        return await _sweep_with_session(db)


@celery_app.task(name="app.tasks.prune_logs.prune_log_entries")
def prune_log_entries() -> dict[str, int]:
    result = asyncio.run(_sweep())
    logger.info("log_entries_pruned", **result)
    return result
