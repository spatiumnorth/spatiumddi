"""InfluxDB push-export beat task (issue #889).

Ticks every 30 s; each enabled target is gated on its own
``push_interval_seconds`` inside the task, so cadence changes in the UI
take effect without restarting beat (the ``ipam_dns_sync`` pattern).

Idempotent per non-negotiable #9. Two things make a retry safe: line
protocol overwrites a point with the same measurement + tag set +
timestamp, so re-sending a batch is a no-op at the server; and a
session-scoped advisory lock keeps two workers from pushing the same
targets concurrently.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select, text

from app.celery_app import celery_app
from app.db import task_session
from app.models.influxdb import InfluxDBTarget
from app.services.influxdb.push import is_due, push_target
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)

# Session-stable advisory-lock key — one pusher at a time across api /
# worker replicas. Released when the connection closes.
_PUSH_LOCK_KEY = 0x53504D494E46  # "SPMINF"


async def _push_all() -> dict[str, int]:
    async with task_session() as db:
        got = (
            await db.execute(text("select pg_try_advisory_lock(:k)"), {"k": _PUSH_LOCK_KEY})
        ).scalar()
        if not got:
            return {"targets": 0, "pushed": 0, "failed": 0, "points": 0, "skipped_locked": 1}

        rows = list(
            (await db.execute(select(InfluxDBTarget).where(InfluxDBTarget.enabled.is_(True))))
            .scalars()
            .all()
        )
        now = datetime.now(UTC)
        due = [r for r in rows if is_due(r, now)]
        pushed = failed = points = 0
        for row in due:
            result = await push_target(db, row, now=now)
            if result.ok:
                pushed += 1
                points += result.points
            else:
                failed += 1
        await db.commit()
        return {
            "targets": len(rows),
            "pushed": pushed,
            "failed": failed,
            "points": points,
            "skipped_locked": 0,
        }


@celery_app.task(name="app.tasks.influxdb_push.push_influxdb_metrics")
def push_influxdb_metrics() -> dict[str, int]:
    result = run_task(_push_all())
    if result.get("targets"):
        logger.info("influxdb_push_sweep", **result)
    return result
