"""Scheduled-backup health (issue #1262).

Answers "is each scheduled backup target actually producing backups?"
for the ``backup_failed`` / ``backup_stale`` alert rules and the
``get_backup_health`` copilot tool. One function decides it for all
three, so the alert and the tool cannot disagree.

A target is only *watched* when it is enabled and has a schedule. A
manual-only target has no expected cadence, so it can't be late.

* **failed** — the last finished run failed.
* **stale** — no successful run within ``stale_after_runs`` scheduled
  runs plus :data:`STALE_GRACE`. Counted from the last success, but
  never from before the schedule was set: a schedule added to an old
  manual-only target gets its first expected run before it can go
  stale. A run left ``in_progress`` (the process died mid-run) is not
  a success, so it goes stale like any other missing run. That matters
  because the beat sweep skips an ``in_progress`` target, so a dead run
  silently stops every later run of that target too.

There is no ``last_success_at`` column. When the latest run succeeded
it is ``last_run_at``; otherwise it is the newest
``backup_target_run_success`` audit row, which the runner writes on
every success and which is never pruned.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup.schedule import (
    InvalidCronExpression,
    compute_next_run,
    compute_prev_run,
)

logger = structlog.get_logger(__name__)

# How many scheduled runs may pass without a success before a target is
# stale. Two means "one missed run is a warning (backup_failed), the
# second is a problem". The rule's ``threshold_percent`` overrides it.
STALE_AFTER_RUNS_DEFAULT = 2
# Slack after the last allowed slot: the sweep fires up to a minute late
# and the run itself takes time.
STALE_GRACE = timedelta(hours=1)
# An ``in_progress`` run younger than this is treated as genuinely
# running: it neither opens nor resolves anything. Older, it is presumed
# dead. Runs have no hard timeout, so this is a judgement call, kept well
# above a normal run.
RUN_PRESUMED_DEAD_AFTER = timedelta(hours=2)


@dataclass(frozen=True)
class BackupHealth:
    target_id: uuid.UUID
    name: str
    kind: str
    enabled: bool
    schedule_cron: str | None
    last_run_status: str
    last_run_at: datetime | None
    last_success_at: datetime | None
    next_run_at: datetime | None
    stale_after: datetime | None
    failed: bool
    stale: bool
    run_in_progress: bool
    run_presumed_dead: bool

    @property
    def watched(self) -> bool:
        return self.enabled and bool(self.schedule_cron)

    @property
    def state(self) -> str:
        if not self.enabled:
            return "disabled"
        if not self.schedule_cron:
            return "manual_only"
        if self.stale:
            return "stale"
        if self.failed:
            return "failed"
        if self.run_presumed_dead:
            return "stuck"
        if self.run_in_progress:
            return "running"
        if self.last_success_at is None:
            return "awaiting_first_run"
        return "ok"

    def as_dict(self) -> dict[str, Any]:
        def _iso(dt: datetime | None) -> str | None:
            return dt.isoformat() if dt is not None else None

        return {
            "id": str(self.target_id),
            "name": self.name,
            "kind": self.kind,
            "enabled": self.enabled,
            "schedule_cron": self.schedule_cron,
            "state": self.state,
            "failed": self.failed,
            "stale": self.stale,
            "last_run_status": self.last_run_status,
            "last_run_at": _iso(self.last_run_at),
            "last_success_at": _iso(self.last_success_at),
            "next_run_at": _iso(self.next_run_at),
            "stale_after": _iso(self.stale_after),
            "run_presumed_dead": self.run_presumed_dead,
        }


def stale_deadline(
    *,
    schedule_cron: str,
    last_success_at: datetime | None,
    created_at: datetime,
    last_run_at: datetime | None,
    next_run_at: datetime | None,
    runs: int,
) -> datetime:
    """When a target with no further success becomes stale.

    The ``runs``-th scheduled slot after the anchor, plus the grace. The
    anchor is the last success (or the target's creation), moved forward
    to the slot before ``next_run_at`` when the schedule was set after the
    last run. Both the runner and the PATCH handler recompute
    ``next_run_at``, but only a run stamps ``last_run_at``. So a
    ``last_run_at`` older than the slot before ``next_run_at`` means the
    last thing that touched ``next_run_at`` was a schedule change, and
    the count starts there.
    """
    anchor = last_success_at or created_at
    if next_run_at is not None:
        prev_slot = compute_prev_run(schedule_cron, before=next_run_at)
        if last_run_at is None or last_run_at < prev_slot:
            anchor = max(anchor, prev_slot)
    slot = anchor
    for _ in range(max(1, runs)):
        slot = compute_next_run(schedule_cron, after=slot)
    return slot + STALE_GRACE


async def _last_success_from_audit(db: AsyncSession, target_ids: list[str]) -> dict[str, datetime]:
    if not target_ids:
        return {}
    rows = (
        await db.execute(
            select(AuditLog.resource_id, func.max(AuditLog.timestamp))
            .where(
                AuditLog.resource_type == "backup_target",
                AuditLog.resource_id.in_(target_ids),
                AuditLog.action == "backup_target_run_success",
            )
            .group_by(AuditLog.resource_id)
        )
    ).all()
    return {rid: ts for rid, ts in rows if ts is not None}


async def evaluate_backup_health(
    db: AsyncSession,
    *,
    now: datetime,
    stale_after_runs: int = STALE_AFTER_RUNS_DEFAULT,
) -> list[BackupHealth]:
    """Health of every backup target, ordered by name."""
    targets = list(
        (await db.execute(select(BackupTarget).order_by(BackupTarget.name.asc()))).scalars().all()
    )
    need_audit = [str(t.id) for t in targets if t.last_run_status != "success"]
    audit_success = await _last_success_from_audit(db, need_audit)

    out: list[BackupHealth] = []
    for t in targets:
        if t.last_run_status == "success":
            last_success = t.last_run_at
        else:
            last_success = audit_success.get(str(t.id))
        in_progress = t.last_run_status == "in_progress"
        presumed_dead = in_progress and (
            t.last_run_at is None or now - t.last_run_at >= RUN_PRESUMED_DEAD_AFTER
        )
        running = in_progress and not presumed_dead
        watched = t.enabled and bool(t.schedule_cron)

        deadline: datetime | None = None
        if watched and t.schedule_cron:
            try:
                deadline = stale_deadline(
                    schedule_cron=t.schedule_cron,
                    last_success_at=last_success,
                    created_at=t.created_at,
                    last_run_at=t.last_run_at,
                    next_run_at=t.next_run_at,
                    runs=stale_after_runs,
                )
            except InvalidCronExpression:
                # Validated on write; only reachable if a croniter upgrade
                # stops accepting a stored string. Not evaluable, not stale.
                logger.warning("backup_health_bad_cron", target_id=str(t.id))

        out.append(
            BackupHealth(
                target_id=t.id,
                name=t.name,
                kind=t.kind,
                enabled=t.enabled,
                schedule_cron=t.schedule_cron,
                last_run_status=t.last_run_status,
                last_run_at=t.last_run_at,
                last_success_at=last_success,
                next_run_at=t.next_run_at,
                stale_after=deadline,
                failed=watched and t.last_run_status == "failed",
                stale=deadline is not None and not running and now >= deadline,
                run_in_progress=running,
                run_presumed_dead=presumed_dead,
            )
        )
    return out
