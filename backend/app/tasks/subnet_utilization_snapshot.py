"""Daily per-subnet utilization snapshot + 90-day retention prune (#44).

Records each (non-deleted) subnet's already-maintained
``allocated_ips`` / ``total_ips`` into ``subnet_utilization_history`` once a
day, then deletes rows older than the retention window. Powers the
30 / 90-day "% used over time" chart on the subnet detail. Idempotent at
the day granularity isn't enforced (a manual re-run just adds another
sample); the chart tolerates multiple same-day points.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.ipam import Subnet, SubnetUtilizationHistory
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)

RETENTION_DAYS = 90


async def _snapshot() -> dict[str, int]:
    async with task_session() as db:
        now = datetime.now(UTC)
        subnets = list(
            (await db.execute(select(Subnet).where(Subnet.deleted_at.is_(None)))).scalars().all()
        )
        for s in subnets:
            db.add(
                SubnetUtilizationHistory(
                    subnet_id=s.id,
                    sampled_at=now,
                    allocated_ips=int(s.allocated_ips or 0),
                    total_ips=int(s.total_ips or 0),
                )
            )
        cutoff = now - timedelta(days=RETENTION_DAYS)
        pruned = await db.execute(
            delete(SubnetUtilizationHistory).where(SubnetUtilizationHistory.sampled_at < cutoff)
        )
        await db.commit()
        return {"sampled": len(subnets), "pruned": pruned.rowcount or 0}


@celery_app.task(name="app.tasks.subnet_utilization_snapshot.snapshot_subnet_utilization")
def snapshot_subnet_utilization() -> dict[str, int]:
    result = run_task(_snapshot())
    logger.info("subnet_utilization_snapshot", **result)
    return result
