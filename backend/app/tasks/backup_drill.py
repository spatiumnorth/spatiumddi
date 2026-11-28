"""Beat-driven sweep that fires due restore-verification drills
(issue #702).

Tick cadence: every 60 s, matching the backup-target sweep. Each
tick walks every enabled target with drills turned on and a
``drill_next_run_at`` now in the past, and runs one drill for it.
:func:`run_drill_for_target` re-stamps ``drill_next_run_at`` from
the cron after the run lands, so a row won't fire twice in the
same tick.

Per-target dispatch is mutexed by ``drill_last_status =
"in_progress"``, which the runner stamps on entry — a drill that
spans several ticks (a large archive can) won't double up.

A drill replays a full dump into a scratch database, so it is
substantially more expensive than a backup. That cost is the
reason drills carry their own cron rather than riding
``schedule_cron``: weekly drills against nightly backups is the
expected shape.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.models.backup import BackupTarget
from app.services.backup.drill import (
    DrillError,
    drill_mutex_is_stale,
    reap_orphaned_scratch_dbs,
    run_drill_for_target,
)
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)


async def _sweep() -> dict[str, int]:
    fired = 0
    skipped_in_progress = 0
    reaped = 0
    async with task_session() as db:
        now = datetime.now(UTC)
        # Drop scratch databases left behind by drills that were killed
        # before their cleanup ran. Cheap when there is nothing to do
        # (one indexed catalogue query), and the only thing standing
        # between a SIGKILLed drill and a permanent full-size copy of
        # the production database sitting on the same volume.
        try:
            reaped = len(await reap_orphaned_scratch_dbs(live_db_url=str(settings.database_url)))
        except DrillError as exc:
            logger.warning("restore_drill_reap_failed", error=str(exc))
        rows = (
            (
                await db.execute(
                    select(BackupTarget).where(
                        BackupTarget.enabled.is_(True),
                        BackupTarget.drill_enabled.is_(True),
                        BackupTarget.drill_cron.is_not(None),
                        BackupTarget.drill_next_run_at.is_not(None),
                        BackupTarget.drill_next_run_at <= now,
                    )
                )
            )
            .scalars()
            .all()
        )
        for target in rows:
            if target.drill_last_status == "in_progress" and not drill_mutex_is_stale(target, now):
                skipped_in_progress += 1
                continue
            try:
                await run_drill_for_target(db, target=target, triggered_by="schedule")
                await db.commit()
                fired += 1
            except Exception as exc:  # noqa: BLE001
                # ``run_drill_for_target`` turns every expected
                # failure into a persisted verdict, so a bubble-up
                # here is something deeper (DB lost mid-run). Roll
                # back and move on so one sick target can't wedge
                # the sweep for the others.
                await db.rollback()
                logger.exception(
                    "restore_drill_sweep_unexpected",
                    target_id=str(target.id),
                    error=str(exc),
                )
    return {
        "fired": fired,
        "skipped_in_progress": skipped_in_progress,
        "reaped_scratch_dbs": reaped,
    }


@celery_app.task(name="app.tasks.backup_drill.sweep_restore_drills")
def sweep_restore_drills() -> dict[str, int]:
    result = run_task(_sweep())
    if any(result.values()):
        logger.info("restore_drill_sweep_tick", **result)
    return result
