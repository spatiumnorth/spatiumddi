"""Beat-driven sweep that fires due backup targets (issue #117
Phase 1b).

Tick cadence: every 60 s. Each tick walks every enabled target
with a non-NULL ``next_run_at`` that's now in the past, fires
:func:`run_backup_for_target` for it, and moves on. The runner
itself recomputes ``next_run_at`` after the run lands so the row
won't fire twice in the same tick.

Per-target dispatch is mutexed by ``last_run_status =
"in_progress"`` — the runner claims that state with one atomic
conditional UPDATE on entry (#1571), so a slow target whose backup
spans more than one tick won't double up, and neither can a Run Now
racing this sweep. The sweep skips rows already in_progress.

The sweep is its own task module so it can opt out via a
platform-settings toggle later (Phase 1c) — for now it fires
unconditionally. Targets whose ``schedule_cron`` is NULL are
ignored entirely (manual-only).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.celery_app import celery_app
from app.db import task_session
from app.models.backup import BackupTarget
from app.services.backup.runner import (
    BackupRunBusyError,
    reap_stale_backup_run,
    run_backup_for_target,
)

logger = structlog.get_logger(__name__)


async def _sweep() -> dict[str, int]:
    fired = 0
    skipped_in_progress = 0
    reaped_stale = 0
    async with task_session() as db:
        now = datetime.now(UTC)
        rows = (
            (
                await db.execute(
                    select(BackupTarget).where(
                        BackupTarget.enabled.is_(True),
                        BackupTarget.schedule_cron.is_not(None),
                        BackupTarget.next_run_at.is_not(None),
                        BackupTarget.next_run_at <= now,
                    )
                )
            )
            .scalars()
            .all()
        )
        for target in rows:
            if target.last_run_status == "in_progress":
                # A live run: skip. A STRANDED one — the process died
                # mid-run and never stamped a terminal state — is
                # reaped to ``failed`` (audit row + next_run_at) and
                # the due run proceeds in this same tick (#1515).
                # Without the reap the row was skipped forever and
                # the target's schedule silently stopped.
                if await reap_stale_backup_run(db, target=target):
                    reaped_stale += 1
                else:
                    skipped_in_progress += 1
                    continue
            try:
                await run_backup_for_target(
                    db,
                    target=target,
                    triggered_by="schedule",
                    actor_id=None,
                    actor_display="system (schedule)",
                )
                fired += 1
            except BackupRunBusyError:
                # Lost the claim race to a concurrent Run Now / sweep
                # (#1571). The pre-check above is only a filter; the
                # runner's atomic claim is the authority, and losing
                # it is a skip, not an error.
                skipped_in_progress += 1
                continue
            except Exception as exc:  # noqa: BLE001
                # ``run_backup_for_target`` already swallows its
                # own driver / archive errors and persists a
                # failed row + audit entry. A bubble-up here is
                # something deeper (DB lost, etc.); log + move on
                # so one sick target can't wedge the whole sweep.
                logger.exception(
                    "backup_sweep_unexpected",
                    target_id=str(target.id),
                    error=str(exc),
                )
    return {
        "fired": fired,
        "skipped_in_progress": skipped_in_progress,
        "reaped_stale": reaped_stale,
    }


@celery_app.task(name="app.tasks.backup_sweep.sweep_backup_targets")
def sweep_backup_targets() -> dict[str, int]:
    result = asyncio.run(_sweep())
    if result["fired"] or result["skipped_in_progress"] or result["reaped_stale"]:
        logger.info("backup_sweep_tick", **result)
    return result
