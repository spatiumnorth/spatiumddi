"""Nightly retention sweep for per-server metric samples.

Deletes rows older than ``PlatformSettings.metric_retention_days``
(default 7 d, 1-365 via the settings API, #2273). The tables are
per-server + per-bucket, so a nightly sweep is plenty — a 7-day window at 60 s bucketing is ~10k rows per
server, which stays comfortably small without aggressive pruning.

Symmetric to ``dhcp_lease_cleanup`` / ``oui_update`` — tick once a
day, delete everything older than the retention window. Runs under
the default queue.
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
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

DEFAULT_RETENTION_DAYS = 7


async def _sweep_with_session(db: AsyncSession) -> dict[str, int]:
    """Run the prune against an explicit session (tests hand in theirs)."""
    res = await db.execute(select(PlatformSettings).limit(1))
    ps = res.scalar_one_or_none()
    retention_days = DEFAULT_RETENTION_DAYS
    if ps is not None:
        configured = ps.metric_retention_days
        if isinstance(configured, int) and configured > 0:
            retention_days = configured

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)

    dns_del = await db.execute(delete(DNSMetricSample).where(DNSMetricSample.bucket_at < cutoff))
    dhcp_del = await db.execute(delete(DHCPMetricSample).where(DHCPMetricSample.bucket_at < cutoff))
    await db.commit()

    return {
        "dns_removed": dns_del.rowcount or 0,
        "dhcp_removed": dhcp_del.rowcount or 0,
        "retention_days": retention_days,
    }


async def _sweep() -> dict[str, int]:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        return await _sweep_with_session(db)


@celery_app.task(name="app.tasks.prune_metrics.prune_metric_samples")
def prune_metric_samples() -> dict[str, int]:
    result = asyncio.run(_sweep())
    logger.info("metric_samples_pruned", **result)
    return result
