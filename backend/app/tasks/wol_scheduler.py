"""Beat-driven sweep + shared runner for Scheduled Wake-on-LAN — Phase 1
(issue #586).

Tick cadence: every 60 s. Each tick walks every **enabled** schedule with a
non-NULL ``schedule_cron`` whose denormalised ``next_run_at`` (UTC) is now in
the past, and fires it. The runner recomputes ``next_run_at`` after the run
lands — in *every* branch (fired, gated-skip, failed) — so the row can't
re-fire in the same tick and a sick schedule retries next cadence instead of
hot-looping.

Per-schedule dispatch is mutexed by an ATOMIC claim: the runner stamps
``last_run_status = "in_progress"`` + ``in_progress_since = now`` via a single
``UPDATE … RETURNING`` that only wins when the row isn't already claimed (or its
lease has expired). This is the single source of truth for the mutex — race-free
across overlapping sweeps and concurrent run-nows (no in-memory pre-check to go
stale). A worker that crashes mid-run leaves the claim stamped; the next runner
reclaims any row whose ``in_progress_since`` lease exceeds ``CLAIM_LEASE_SECONDS``
(default 15 min), fails the orphaned ``wol_run``, and re-fires — so a crash can
never wedge a schedule forever. Combined with the always-advancing
``next_run_at`` this makes a double-tick a no-op (non-negotiable #9 — idempotent
+ safe to retry).

The task also re-checks the ``tools.wake_scheduler`` feature module inside its
body (non-negotiable #14) — a disabled module fires nothing even while beat
keeps ticking.

Two entry points share one runner (:func:`run_wol_schedule`):

* :func:`sweep_wol_schedules` — the beat task (scheduled fires, gate applied).
* :func:`run_schedule_now` — the callable the ``run-now`` REST endpoint reuses
  (manual fire; the built-in holiday gate is *bypassed* because a manual
  "wake now" is an explicit operator action).

A gated-off scheduled occurrence still writes a ``wol_run`` (with the
run-level ``skip_reason``) AND advances ``next_run_at`` — "skipped because
holiday" is visible history, never a silent no-op.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import structlog
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import selectinload

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.models.auth import Group, User
from app.models.wol_schedule import (
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    STATUS_OK,
    STATUS_PARTIAL,
    STATUS_SKIPPED,
    VERIFY_STATE_DONE,
    VERIFY_STATE_NONE,
    VERIFY_STATE_PENDING,
    VERIFY_STATE_VERIFYING,
    WolRun,
    WolRunTarget,
    WolSchedule,
)
from app.services.feature_modules import get_enabled_modules
from app.services.wol_scheduler.dispatch import dispatch_wol_targets
from app.services.wol_scheduler.gating import gate_verdict, load_gate_calendar_events
from app.services.wol_scheduler.resolver import WakeTarget, resolve_wol_targets
from app.services.wol_scheduler.schedule import (
    InvalidCronExpression,
    InvalidTimezone,
    compute_next_run,
)
from app.services.wol_scheduler.verify import (
    VERIFY_METHOD_PING,
    auto_stagger_ms,
    verify_run_targets,
)
from app.tasks.module_gate import module_gated

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# Feature-module id gating the whole surface (non-negotiable #14).
MODULE_ID = "tools.wake_scheduler"

# Run + schedule status enum (STATUS_* imported from the model above, so the
# ad-hoc IPAM wake can stamp a run status without the Celery bootstrap).

# Run-level (gate) skip reasons stored on ``wol_run.skip_reason``.
SKIP_EMPTY_TARGET_SET = "empty_target_set"

# Post-wake verify state machine (``wol_run.verify_state``). Terminal is
# ``done``. ``none`` == verify off / never scheduled; ``pending`` == a verify
# pass is enqueued + awaiting its atomic claim; ``verifying`` == a pass holds
# the run's verify mutex. The strings live on the model so readers outside this
# Celery module (the alert evaluator, MCP tools) can key on them without
# importing the Celery bootstrap; these aliases keep the task-local names.
VERIFY_NONE = VERIFY_STATE_NONE
VERIFY_PENDING = VERIFY_STATE_PENDING
VERIFY_VERIFYING = VERIFY_STATE_VERIFYING
VERIFY_DONE = VERIFY_STATE_DONE

# Verify mutex lease — the ``verifying`` case. A run stuck in ``verifying`` past
# this is a crash-wedged probe pass (worker SIGKILL mid-probe) and is reclaimed
# by the sweep's verify reaper. 30 min sits comfortably above a worst-case probe
# window (a 512-host fleet fanned out at ``_PROBE_CONCURRENCY``), so a genuinely
# in-flight pass is never reaped out from under itself.
VERIFY_CLAIM_LEASE_SECONDS = 30 * 60

# Verify lease — the ``pending`` case, deliberately LONGER. A ``pending`` run is
# not wedged: it is waiting ``verify_wait_seconds`` (capped at 3600 in the API
# schema) for its already-enqueued task to fire. Reaping it on the shorter
# ``verifying`` lease would re-fire the probe up to ~30 min early — before a
# slow-booting host has finished POSTing — yielding a false ``down`` verdict and,
# once #596's ``wol_wake_failed`` alert is enabled, a spurious page. So the
# ``pending`` reaper only fires past the MAX possible countdown plus a margin for
# broker/scheduling delay; beyond that a ``pending`` run really is a failed-enqueue
# hole worth reclaiming. Keep ``> 3600`` in lockstep with the schema's
# ``verify_wait_seconds`` ``le=3600`` bound.
VERIFY_PENDING_LEASE_SECONDS = 3600 + 10 * 60

# System audit actor for beat-fired runs (mirrors the backup runner).
SYSTEM_ACTOR_DISPLAY = "system (schedule)"

# In_progress mutex lease. A row whose claim is older than this is treated as
# an orphaned crash (worker SIGKILL / OOM / pod-eviction mid-run) and is
# reclaimed by the next runner instead of being skipped forever.
CLAIM_LEASE_SECONDS = 15 * 60


class ScheduleBusyError(RuntimeError):
    """Raised when a schedule can't be claimed because another runner already
    holds its ``in_progress`` mutex and the lease has not yet expired.

    The atomic claim (:func:`run_wol_schedule`) is the single source of truth
    for the mutex — it can't be bypassed. The beat sweep catches this and
    counts a ``skipped_in_progress``; the ``run-now`` endpoint maps it to a
    409 (already running).
    """


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def _enqueue_verify(run_id: str, attempt: int, countdown: int, *, log_event: str) -> None:
    """Best-effort push of one ``verify_wol_run`` pass to the broker.

    Centralises the "a broker hiccup must never fail an already-landed wake"
    contract shared by the arm, the re-wake re-enqueue, and the reaper: the
    ``apply_async`` push is wrapped so any exception is logged (under
    ``log_event``) and swallowed, never propagated back into the wake path.
    """
    try:
        verify_wol_run.apply_async(args=[run_id, attempt], countdown=countdown)
    except Exception as exc:  # noqa: BLE001 — verify is best-effort.
        logger.warning(log_event, run_id=run_id, attempt=attempt, error=str(exc))


def _restamp_next_run(schedule: WolSchedule, after: datetime) -> None:
    """Advance ``next_run_at`` past ``after`` for a cron schedule.

    Called in EVERY runner branch so a fired/gated/failed occurrence never
    re-fires the same tick. A manual-only schedule (``schedule_cron`` NULL)
    keeps ``next_run_at`` NULL. A schedule whose cron/tz has since become
    unparseable is parked (``next_run_at`` NULL) rather than left to hot-loop
    on a stale past timestamp — the operator has to fix + re-save it.
    """
    if not schedule.schedule_cron:
        schedule.next_run_at = None
        return
    try:
        schedule.next_run_at = compute_next_run(
            schedule.schedule_cron, schedule.timezone, after=after
        )
    except (InvalidCronExpression, InvalidTimezone) as exc:
        logger.warning(
            "wol_schedule_bad_cron_parked",
            schedule_id=str(schedule.id),
            cron=schedule.schedule_cron,
            timezone=schedule.timezone,
            error=str(exc),
        )
        schedule.next_run_at = None


def _write_audit(
    db: AsyncSession,
    schedule: WolSchedule,
    *,
    action: str,
    result_state: str,
    new_value: dict[str, Any],
    actor_id: uuid.UUID | None,
    actor_display: str,
    error_detail: str | None = None,
) -> None:
    """Append one append-only audit row for a fire (non-negotiable #4).

    Built directly (not via the API ``_audit`` helper) to keep the task layer
    free of an API-router import.
    """
    db.add(
        AuditLog(
            action=action,
            resource_type="wol_schedule",
            resource_id=str(schedule.id),
            resource_display=schedule.name,
            user_id=actor_id,
            user_display_name=actor_display,
            result=result_state,
            new_value=new_value,
            error_detail=error_detail,
        )
    )


async def _load_owner(db: AsyncSession, schedule: WolSchedule) -> User | None:
    """Load the schedule owner with groups → roles eager-loaded.

    The resolver enforces the owner's readable-subnet scope (non-negotiable
    #3) via the synchronous ``user_has_permission`` RBAC walk, which touches
    ``user.groups`` / ``group.roles`` — those must be eager-loaded or the walk
    raises on an async lazy load.
    """
    if schedule.created_by_user_id is None:
        return None
    return (
        await db.execute(
            select(User)
            .options(selectinload(User.groups).selectinload(Group.roles))
            .where(User.id == schedule.created_by_user_id)
        )
    ).scalar_one_or_none()


async def run_wol_schedule(
    db: AsyncSession,
    schedule: WolSchedule,
    *,
    trigger: str,
    actor_id: uuid.UUID | None,
    actor_display: str,
    apply_gate: bool,
    resolve_user: User | None = None,
) -> dict[str, Any]:
    """Fire (or gate-skip) one schedule and persist the full history.

    Steps: stamp ``in_progress`` (+ commit → mutex) → optional built-in gate →
    resolve targets against the owner's permission scope → dispatch via the
    shipped #533 send path → persist the ``wol_run`` + per-host
    ``wol_run_target`` rows → mirror ``schedule.last_run_*`` → re-stamp
    ``next_run_at`` → audit → commit.

    Shared by the beat sweep (``trigger="schedule"``, ``apply_gate=True``) and
    the run-now endpoint (``trigger="manual"``, ``apply_gate=False``,
    ``resolve_user=<caller>``). Never re-raises on a dispatch/resolve error —
    it records a ``failed`` run and still advances ``next_run_at`` so the
    schedule self-heals next cadence (non-negotiable #9). Returns a summary
    dict (``run_id`` / ``status`` / counts) for the caller.
    """
    now = datetime.now(UTC)
    lease_cutoff = now - timedelta(seconds=CLAIM_LEASE_SECONDS)

    # ── 1. Mutex — ATOMICALLY claim the row (single source of truth) before
    #        the slow dispatch so overlapping sweeps / double run-nows can't
    #        double-fire (cross-session TOCTOU). A UPDATE … RETURNING that
    #        succeeds only when the row is not currently ``in_progress`` OR its
    #        lease has expired (crashed worker) is race-free: concurrent
    #        claimers block on the row lock, then re-evaluate the WHERE against
    #        the committed row and come back empty → ``ScheduleBusyError``. ──
    claimed_id = (
        await db.execute(
            update(WolSchedule)
            .where(
                WolSchedule.id == schedule.id,
                or_(
                    WolSchedule.last_run_status.is_distinct_from(STATUS_IN_PROGRESS),
                    WolSchedule.in_progress_since.is_(None),
                    WolSchedule.in_progress_since < lease_cutoff,
                ),
            )
            .values(last_run_status=STATUS_IN_PROGRESS, in_progress_since=now)
            .returning(WolSchedule.id)
        )
    ).scalar_one_or_none()
    if claimed_id is None:
        # Capture the id BEFORE the rollback — rollback expires every instance
        # in the session, so reading ``schedule.id`` afterwards would trip a
        # greenlet-less lazy refresh (MissingGreenlet) instead of raising the
        # ScheduleBusyError the caller expects.
        busy_id = schedule.id
        await db.rollback()
        raise ScheduleBusyError(f"wol_schedule {busy_id} already in_progress")

    # The claim proved no live runner holds the mutex, so any lingering
    # ``in_progress`` run for this schedule is a crashed orphan (lease reaper) —
    # fail it so history isn't wedged, then open the fresh run.
    await db.execute(
        update(WolRun)
        .where(
            WolRun.schedule_id == schedule.id,
            WolRun.status == STATUS_IN_PROGRESS,
        )
        .values(
            status=STATUS_FAILED,
            finished_at=now,
            error="reclaimed: in_progress lease expired (worker crash)",
        )
    )

    run = WolRun(
        schedule_id=schedule.id,
        trigger=trigger,
        started_at=now,
        status=STATUS_IN_PROGRESS,
        target_count=0,
        triggered_by_user_id=actor_id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    await db.refresh(schedule)

    try:
        # ── 2. Built-in holiday / term gate (scheduled fires only) ─────────
        if apply_gate:
            # Evaluate the gate at the candidate FIRE instant (the still-unadvanced
            # ``next_run_at``), not wall-clock ``now`` — a tick that slipped past
            # midnight must still see the scheduled day's blackout/term status.
            # Load the attached calendar's cached spans (None when no calendar
            # gate is active) so the Phase-2 calendar step is evaluated too.
            calendar_events = await load_gate_calendar_events(db, schedule)
            verdict = gate_verdict(
                schedule.next_run_at or now, schedule, calendar_events=calendar_events
            )
            if verdict is not None:
                return await _finalise_skip(
                    db,
                    schedule,
                    run,
                    skip_reason=verdict,
                    trigger=trigger,
                    actor_id=actor_id,
                    actor_display=actor_display,
                )

        # ── 3. Resolve the target fleet against the owner's read scope ─────
        owner = resolve_user if resolve_user is not None else await _load_owner(db, schedule)
        if owner is None:
            # No user to scope against (never-owned or owner deleted) — cannot
            # safely resolve, so nothing wakes. Recorded, not silently dropped.
            return await _finalise_skip(
                db,
                schedule,
                run,
                skip_reason=SKIP_EMPTY_TARGET_SET,
                trigger=trigger,
                actor_id=actor_id,
                actor_display=actor_display,
                error="schedule owner unavailable for permission scoping",
            )

        resolved = await resolve_wol_targets(db, owner, schedule.target_selector or {})

        # Persist every per-host skip the resolver flagged (no_mac, etc.).
        for skip in resolved.skipped:
            db.add(
                WolRunTarget(
                    run_id=run.id,
                    ip_address_id=skip.ip_address_id,
                    address=skip.address,
                    mac=None,
                    subnet_id=skip.subnet_id,
                    broadcast=None,
                    vantage=None,
                    mac_source=None,
                    sent=False,
                    skip_reason=skip.reason,
                )
            )

        if not resolved.wakes:
            return await _finalise_skip(
                db,
                schedule,
                run,
                skip_reason=SKIP_EMPTY_TARGET_SET,
                trigger=trigger,
                actor_id=actor_id,
                actor_display=actor_display,
                skipped_count=len(resolved.skipped),
            )

        # ── 4. Dispatch — reuse the #533 send path via the dispatch loop ───
        # ``stagger_ms == 0`` means "auto": ramp a large fleet so a same-second
        # all-at-once fire can't power-inrush / PXE-thundering-herd. Any positive
        # operator value always wins (auto_stagger_ms returns it verbatim).
        effective_stagger = auto_stagger_ms(len(resolved.wakes), schedule.stagger_ms)
        outcomes = await dispatch_wol_targets(
            db,
            resolved.wakes,
            vantage=schedule.vantage,
            repeat_count=schedule.repeat_count,
            repeat_interval_ms=schedule.repeat_interval_ms,
            stagger_ms=effective_stagger,
            port=schedule.port,
        )

        sent_count = 0
        failed_count = 0
        for outcome in outcomes:
            if outcome.sent:
                sent_count += 1
            else:
                failed_count += 1
            db.add(
                WolRunTarget(
                    run_id=run.id,
                    ip_address_id=outcome.target.ip_address_id,
                    address=outcome.target.address,
                    mac=outcome.target.mac,
                    subnet_id=outcome.target.subnet_id,
                    broadcast=outcome.target.broadcast,
                    vantage=outcome.vantage,
                    mac_source=outcome.target.mac_source,
                    sent=outcome.sent,
                    skip_reason=None,
                    error=outcome.error,
                )
            )

        # ── 5. Record + mirror + re-stamp ──────────────────────────────────
        finished = datetime.now(UTC)
        if sent_count == 0:
            status = STATUS_FAILED
        elif failed_count:
            status = STATUS_PARTIAL
        else:
            status = STATUS_OK

        run.status = status
        run.skip_reason = None
        run.finished_at = finished
        run.target_count = len(resolved.wakes)
        run.sent_count = sent_count
        run.skipped_count = len(resolved.skipped)
        run.failed_count = failed_count

        # Arm post-wake verify when configured and at least one packet went out
        # (nothing to probe otherwise). ``pending`` is the state the chained
        # ``verify_wol_run`` task atomically claims below; leave ``none`` when
        # verify is off so the run reads as "never scheduled a verify".
        will_verify = bool(schedule.verify_enabled) and sent_count > 0
        if will_verify:
            run.verify_state = VERIFY_PENDING
            # Anchor the attempt at 1 (the initial ``apply_async(..., 1)`` below)
            # and stamp the lease so a failed enqueue leaves a reaper-reclaimable
            # ``pending`` row rather than a stuck one with no task.
            run.verify_attempt = 1
            run.verify_claimed_at = finished

        schedule.last_run_at = finished
        schedule.last_run_status = status
        schedule.last_run_skip_reason = None
        schedule.last_target_count = len(resolved.wakes)
        schedule.in_progress_since = None
        _restamp_next_run(schedule, finished)

        _write_audit(
            db,
            schedule,
            action="wol_schedule_fired",
            result_state="success" if sent_count else "failure",
            new_value={
                "trigger": trigger,
                "target_count": len(resolved.wakes),
                "sent": sent_count,
                "skipped": len(resolved.skipped),
                "failed": failed_count,
            },
            actor_id=actor_id,
            actor_display=actor_display,
        )
        # Snapshot the enqueue inputs BEFORE commit — ``expire_on_commit`` blanks
        # the ORM instances, and a post-commit attribute read would trip an async
        # lazy refresh (MissingGreenlet).
        verify_run_id = str(run.id) if will_verify else None
        verify_wait = schedule.verify_wait_seconds if will_verify else 0
        await db.commit()

        # Chain the non-blocking verify pass (best-effort: a broker hiccup must
        # never fail an already-landed wake). ``apply_async`` just pushes to the
        # broker, so this works from both the beat sweep (worker) and the
        # run-now endpoint (api).
        if verify_run_id is not None:
            _enqueue_verify(
                verify_run_id, 1, max(0, verify_wait), log_event="wol_verify_enqueue_failed"
            )

        return {
            "run_id": str(run.id),
            "status": status,
            "skip_reason": None,
            "trigger": trigger,
            "target_count": len(resolved.wakes),
            "sent": sent_count,
            "skipped": len(resolved.skipped),
            "failed": failed_count,
        }

    except Exception as exc:  # noqa: BLE001
        # Any resolve/dispatch failure is recorded as a ``failed`` run and the
        # schedule is re-stamped so it self-heals next cadence — the sweep is
        # never wedged and the row never hot-loops (non-negotiable #9).
        await db.rollback()
        await db.refresh(run)
        await db.refresh(schedule)
        finished = datetime.now(UTC)
        run.status = STATUS_FAILED
        run.finished_at = finished
        run.error = str(exc)[:5000]
        schedule.last_run_at = finished
        schedule.last_run_status = STATUS_FAILED
        schedule.last_run_skip_reason = None
        schedule.in_progress_since = None
        _restamp_next_run(schedule, finished)
        _write_audit(
            db,
            schedule,
            action="wol_schedule_fired",
            result_state="failure",
            new_value={"trigger": trigger, "target_count": 0},
            actor_id=actor_id,
            actor_display=actor_display,
            error_detail=str(exc),
        )
        await db.commit()
        logger.warning(
            "wol_schedule_run_failed",
            schedule_id=str(schedule.id),
            error=str(exc),
        )
        return {
            "run_id": str(run.id),
            "status": STATUS_FAILED,
            "skip_reason": None,
            "trigger": trigger,
            "target_count": 0,
            "sent": 0,
            "skipped": 0,
            "failed": 0,
            "error": str(exc),
        }


async def _finalise_skip(
    db: AsyncSession,
    schedule: WolSchedule,
    run: WolRun,
    *,
    skip_reason: str,
    trigger: str,
    actor_id: uuid.UUID | None,
    actor_display: str,
    skipped_count: int = 0,
    error: str | None = None,
) -> dict[str, Any]:
    """Persist a run-level skip (gate / empty-target-set): stamp the run +
    schedule mirror, re-stamp ``next_run_at``, audit, commit.

    A gated occurrence is visible history — "skipped because holiday" is a real
    ``wol_run`` row, not a no-op — and ``next_run_at`` still advances.
    """
    finished = datetime.now(UTC)
    run.status = STATUS_SKIPPED
    run.skip_reason = skip_reason
    run.finished_at = finished
    run.target_count = 0
    run.skipped_count = skipped_count
    if error:
        run.error = error[:5000]

    schedule.last_run_at = finished
    schedule.last_run_status = STATUS_SKIPPED
    schedule.last_run_skip_reason = skip_reason
    schedule.last_target_count = 0
    schedule.in_progress_since = None
    _restamp_next_run(schedule, finished)

    _write_audit(
        db,
        schedule,
        action="wol_schedule_skipped",
        result_state="success",
        new_value={
            "trigger": trigger,
            "skip_reason": skip_reason,
            "target_count": 0,
            "skipped": skipped_count,
        },
        actor_id=actor_id,
        actor_display=actor_display,
        error_detail=error,
    )
    await db.commit()
    return {
        "run_id": str(run.id),
        "status": STATUS_SKIPPED,
        "skip_reason": skip_reason,
        "trigger": trigger,
        "target_count": 0,
        "sent": 0,
        "skipped": skipped_count,
        "failed": 0,
    }


async def run_schedule_now(
    schedule_id: uuid.UUID | str,
    *,
    trigger: str = "manual",
    actor_id: uuid.UUID | None = None,
    actor_display: str = "system",
    apply_gate: bool = False,
    resolve_user: User | None = None,
    db: AsyncSession | None = None,
) -> dict[str, Any]:
    """Fire ``schedule_id`` immediately, reusing :func:`run_wol_schedule`.

    Backs the ``POST /wake-scheduler/schedules/{id}/run-now`` endpoint (which
    passes its own ``db`` + the calling user as ``resolve_user`` + actor). The
    built-in holiday gate is *bypassed* by default — a manual "wake now" is an
    explicit operator action; the gate only governs scheduled fires. When no
    ``db`` is supplied a task-scoped session is opened (standalone use).

    Raises ``KeyError`` if the schedule doesn't exist.
    """
    sid = _coerce_uuid(schedule_id)
    if sid is None:
        raise KeyError(f"invalid schedule id: {schedule_id!r}")

    async def _run(session: AsyncSession) -> dict[str, Any]:
        schedule = await session.get(WolSchedule, sid)
        if schedule is None:
            raise KeyError(f"wol_schedule {sid} not found")
        return await run_wol_schedule(
            session,
            schedule,
            trigger=trigger,
            actor_id=actor_id,
            actor_display=actor_display,
            apply_gate=apply_gate,
            resolve_user=resolve_user,
        )

    if db is not None:
        return await _run(db)
    async with task_session() as own_db:
        return await _run(own_db)


async def _finalise_verify(
    db: AsyncSession,
    run: WolRun,
    schedule: WolSchedule | None,
) -> dict[str, Any]:
    """Terminal verify state: roll up the SENT-target liveness counts, stamp
    ``verify_state='done'``, write one audit row, commit.

    ``verified_count`` = SENT targets that probed UP; ``unverified_count`` =
    every other SENT target (probed DOWN, or address-less/never-probed — an
    honest "did not confirm live" bucket). Recomputed from the child rows so a
    partial mid-flight crash can't leave a stale rollup.
    """
    # One round-trip: a filtered aggregate over the SENT rows yields both the
    # UP count and the SENT total, differing only by the extra ``verified``
    # predicate on the FILTER.
    verified_count, sent_total = (
        await db.execute(
            select(
                func.count().filter(WolRunTarget.verified.is_(True)),
                func.count(),
            )
            .select_from(WolRunTarget)
            .where(
                WolRunTarget.run_id == run.id,
                WolRunTarget.sent.is_(True),
            )
        )
    ).one()
    unverified_count = sent_total - verified_count

    run.verify_state = VERIFY_DONE
    run.verified_count = verified_count
    run.unverified_count = unverified_count

    # One append-only audit row for the verify outcome (non-negotiable #4).
    # Anchor on the schedule when it still exists, else on the run itself (the
    # schedule may have been deleted mid-flight — history still survives).
    db.add(
        AuditLog(
            action="wol_run_verified",
            resource_type="wol_schedule" if schedule is not None else "wol_run",
            resource_id=str(schedule.id) if schedule is not None else str(run.id),
            resource_display=schedule.name if schedule is not None else f"run {run.id}",
            user_id=run.triggered_by_user_id,
            user_display_name=SYSTEM_ACTOR_DISPLAY,
            result="success" if unverified_count == 0 else "failure",
            new_value={
                "verify_state": VERIFY_DONE,
                "verified": verified_count,
                "unverified": unverified_count,
                "sent_targets": sent_total,
            },
        )
    )
    await db.commit()
    logger.info(
        "wol_verify_done",
        run_id=str(run.id),
        verified=verified_count,
        unverified=unverified_count,
    )
    return {
        "run_id": str(run.id),
        "verify_state": VERIFY_DONE,
        "verified": verified_count,
        "unverified": unverified_count,
    }


async def _verify_run(run_id: uuid.UUID | str, attempt: int) -> dict[str, Any]:
    """One post-wake verify pass — chained, non-blocking, bounded, idempotent.

    Enqueued by :func:`run_wol_schedule` (attempt 1) and by this task itself
    (re-wake passes). Each invocation:

    1. **Atomic, attempt-anchored claim** — ``UPDATE wol_run SET
       verify_state='verifying', verify_claimed_at=now WHERE id=run AND
       verify_state='pending' AND verify_attempt=:attempt``. Only one worker
       wins the row lock + ``pending`` guard, so a concurrent double-delivery of
       the same attempt is a no-op and a re-fire after ``done`` is a no-op. The
       ``verify_attempt`` guard additionally makes a SEQUENTIAL redelivery of
       attempt N (arriving after a re-wake already advanced the row to N+1 +
       reset it to ``pending``) a no-op, so the down set is never re-woken twice
       (non-negotiable #9).
    2. Probe the still-unverified SENT targets under the schedule's
       ``verify_method`` (ping / tcp / seen / auto) + stamp the Seen infra on
       active responders (``verify_run_targets``).
    3. **Bounded retry** — if non-responders remain AND ``attempt <=
       verify_retries``, re-wake ONLY those (reuse the dispatch path), bump
       their ``wake_attempts``, release the mutex back to ``pending`` while
       advancing ``verify_attempt`` to ``attempt+1``, and re-enqueue
       ``attempt+1`` with a ``verify_wait_seconds`` countdown.
    4. Otherwise **finalise** (``done`` + count rollup + audit).

    Crash recovery: the post-claim body is wrapped so a plain exception resets
    the mutex back to ``pending`` (self-heal via the reaper); a worker SIGKILL
    leaves the row wedged at ``verifying`` but ``verify_claimed_at`` lets the
    sweep's verify reaper (:func:`_sweep`) reclaim it after
    ``VERIFY_CLAIM_LEASE_SECONDS`` and re-enqueue at ``verify_attempt``.

    Bound proof: ``attempt`` is strictly incremented and the re-enqueue guard is
    ``attempt <= verify_retries``, so at most ``verify_retries`` re-waves fire;
    the terminal ``done`` state + the attempt-anchored ``pending`` claim
    guarantee no unbounded loop and no double-wake even under a redelivery.
    """
    rid = _coerce_uuid(run_id)
    if rid is None:
        return {"skipped": "invalid_run_id", "run_id": str(run_id), "attempt": attempt}

    now = datetime.now(UTC)
    async with task_session() as db:
        # ── 1. Idempotent, attempt-anchored claim (pending → verifying) ────
        # The claim keys on BOTH verify_state AND verify_attempt: a stale
        # ``acks_late`` redelivery of attempt N finds ``verify_attempt`` already
        # advanced to N+1 (a re-wake bumped it) and no-ops, so a redelivery
        # arriving after the deliberate reset-to-``pending`` can't re-run the
        # attempt (re-waking the down set + branching a second attempt chain).
        # ``verify_claimed_at`` is (re-)stamped so the sweep's verify reaper can
        # tell an in-flight pass from a crash-wedged one.
        claimed = (
            await db.execute(
                update(WolRun)
                .where(
                    WolRun.id == rid,
                    WolRun.verify_state == VERIFY_PENDING,
                    WolRun.verify_attempt == attempt,
                )
                .values(verify_state=VERIFY_VERIFYING, verify_claimed_at=now)
                .returning(WolRun.id)
            )
        ).scalar_one_or_none()
        if claimed is None:
            await db.rollback()
            logger.info(
                "wol_verify_claim_skipped",
                run_id=str(rid),
                attempt=attempt,
            )
            return {"skipped": "not_pending", "run_id": str(rid), "attempt": attempt}
        await db.commit()

        # The claim is committed (mutex held). Wrap the slow probe / dispatch /
        # finalise so a plain exception self-heals: reset ``verify_state`` back
        # to ``pending`` (keeping ``verify_claimed_at`` + ``verify_attempt``) and
        # commit, so the next verify-reaper tick re-enqueues this SAME attempt.
        # A worker SIGKILL in this window never runs this handler at all — the
        # reaper's lease on ``verify_claimed_at`` is the backstop for that case.
        try:
            run = await db.get(WolRun, rid)
            if run is None:  # deleted between claim + load — nothing to verify.
                return {"skipped": "run_gone", "run_id": str(rid), "attempt": attempt}
            schedule = (
                await db.get(WolSchedule, run.schedule_id) if run.schedule_id is not None else None
            )

            # ── 2. Verify turned off mid-flight — finalise immediately ─────
            if schedule is not None and not schedule.verify_enabled:
                return await _finalise_verify(db, run, schedule)

            # Config resolution, in precedence order:
            #   1. the live ``wol_schedule`` row (scheduled + run-now runs) — read
            #      fresh each pass, so an operator edit mid-flight takes effect;
            #   2. ``run.verify_params`` (ad-hoc runs, #596 Phase 1b) — an
            #      ephemeral run has no parent schedule to read;
            #   3. the model defaults (a schedule deleted mid-flight).
            # ``verify_params`` keys are the ``WolSchedule`` attribute names
            # verbatim, so the same ``attr`` reads either source — a snapshot key
            # can't silently drift from the column it mirrors.
            # ``verify_method`` falls back to ``ping`` rather than the ``auto``
            # default new schedules get: an orphaned run should finish the way it
            # started, not change probe semantics because its parent vanished.
            params = run.verify_params or {}

            def _cfg(attr: str, default: Any) -> Any:
                if schedule is not None:
                    return getattr(schedule, attr)
                return params.get(attr, default)

            retries = _cfg("verify_retries", 1)
            wait_seconds = _cfg("verify_wait_seconds", 60)
            vantage = _cfg("vantage", None)
            repeat_count = _cfg("repeat_count", 2)
            repeat_interval_ms = _cfg("repeat_interval_ms", 100)
            stagger_override = _cfg("stagger_ms", 0)
            port = _cfg("port", 9)
            method = _cfg("verify_method", VERIFY_METHOD_PING)

            # ── 3. Probe the still-unverified SENT targets ─────────────────
            non_responders = await verify_run_targets(db, run, attempt, method=method)

            # A row can only be re-woken if it still carries a mac + broadcast
            # (the WakeTarget requires both). An address-less / mac-less edge row
            # is counted as unverified but never re-woken.
            rewakeable = [t for t in non_responders if t.mac and t.broadcast]

            # ── 4. Bounded retry — re-wake ONLY the non-responders ─────────
            if rewakeable and attempt <= retries:
                targets = [
                    WakeTarget(
                        ip_address_id=t.ip_address_id,
                        address=t.address,
                        mac=t.mac,  # type: ignore[arg-type]  # filtered non-null above
                        subnet_id=t.subnet_id,
                        broadcast=t.broadcast,  # type: ignore[arg-type]
                        mac_source=t.mac_source or "ip",
                    )
                    for t in rewakeable
                ]
                await dispatch_wol_targets(
                    db,
                    targets,
                    vantage=vantage,
                    repeat_count=repeat_count,
                    repeat_interval_ms=repeat_interval_ms,
                    stagger_ms=auto_stagger_ms(len(targets), stagger_override),
                    port=port,
                )
                for t in rewakeable:
                    t.wake_attempts = (t.wake_attempts or 1) + 1

                # Release the mutex back to ``pending`` AND advance the attempt
                # anchor in the SAME update: a redelivered stale attempt N then
                # fails the ``verify_attempt == N`` claim while the legit attempt
                # N+1 wins. ``verify_claimed_at`` is re-stamped so the reaper's
                # lease clock restarts on this reset. (verify_run_targets'
                # verdicts + the bumped wake_attempts commit atomically here.)
                run.verify_state = VERIFY_PENDING
                run.verify_attempt = attempt + 1
                run.verify_claimed_at = now
                await db.commit()

                # The re-enqueue is best-effort: if it fails the row is back in
                # ``pending`` at anchor ``attempt + 1``, so a future run-now or
                # the verify reaper picks it up. Never fails the landed re-wake.
                _enqueue_verify(
                    str(rid),
                    attempt + 1,
                    max(0, wait_seconds),
                    log_event="wol_verify_reenqueue_failed",
                )
                logger.info(
                    "wol_verify_rewake",
                    run_id=str(rid),
                    attempt=attempt,
                    rewoke=len(targets),
                )
                return {
                    "run_id": str(rid),
                    "attempt": attempt,
                    "verify_state": VERIFY_PENDING,
                    "rewoke": len(targets),
                    "reenqueued": True,
                }

            # ── 5. Finalise — no re-wake candidates left, or retries done ──
            return await _finalise_verify(db, run, schedule)

        except Exception as exc:  # noqa: BLE001
            # Plain-exception self-heal: roll back the failed pass, reset the
            # mutex ``verifying → pending`` (SAME attempt — verify_claimed_at +
            # verify_attempt preserved) so the verify reaper re-enqueues this
            # attempt once the lease expires. Best-effort by design: never
            # re-raise (``acks_late`` + default ``acks_on_failure`` would ack a
            # raised failure anyway → no redelivery; the reaper is the recovery).
            await db.rollback()
            try:
                await db.execute(
                    update(WolRun)
                    .where(WolRun.id == rid, WolRun.verify_state == VERIFY_VERIFYING)
                    .values(verify_state=VERIFY_PENDING)
                )
                await db.commit()
            except Exception as reset_exc:  # noqa: BLE001
                await db.rollback()
                logger.warning(
                    "wol_verify_reset_failed",
                    run_id=str(rid),
                    attempt=attempt,
                    error=str(reset_exc),
                )
            logger.warning(
                "wol_verify_pass_failed",
                run_id=str(rid),
                attempt=attempt,
                error=str(exc),
            )
            return {"error": str(exc), "run_id": str(rid), "attempt": attempt}


@celery_app.task(name="app.tasks.wol_scheduler.verify_wol_run")
def verify_wol_run(run_id: str, attempt: int = 1) -> dict[str, Any]:
    """Celery entrypoint for one post-wake verify pass (see :func:`_verify_run`).

    Enqueued on demand (no beat entry) with a ``countdown`` grace so the probe
    waits for hosts to boot. Lives in this module — already in the celery
    ``include=[...]`` list — so no include change is needed (#218 gotcha
    satisfied).
    """
    return asyncio.run(_verify_run(run_id, attempt))


async def _sweep() -> dict[str, int]:
    fired = 0
    gated = 0
    skipped_in_progress = 0
    errors = 0
    verify_reclaimed = 0
    stale_verifies: list[Any] = []
    async with task_session() as db:
        # Module gate — a disabled feature module fires nothing (non-neg #14).
        if MODULE_ID not in await get_enabled_modules(db):
            return {
                "fired": 0,
                "gated": 0,
                "skipped_in_progress": 0,
                "errors": 0,
                "verify_reclaimed": 0,
                "module_disabled": 1,
            }

        now = datetime.now(UTC)
        rows = (
            (
                await db.execute(
                    select(WolSchedule).where(
                        WolSchedule.enabled.is_(True),
                        WolSchedule.schedule_cron.is_not(None),
                        WolSchedule.next_run_at.is_not(None),
                        WolSchedule.next_run_at <= now,
                    )
                )
            )
            .scalars()
            .all()
        )
        for schedule in rows:
            # Per-schedule mutex is enforced by the atomic claim inside
            # ``run_wol_schedule`` (single source of truth — no racy in-memory
            # pre-check). A row another worker already holds raises
            # ``ScheduleBusyError``; a stale-lease orphan is reclaimed + re-fired.
            try:
                summary = await run_wol_schedule(
                    db,
                    schedule,
                    trigger="schedule",
                    actor_id=None,
                    actor_display=SYSTEM_ACTOR_DISPLAY,
                    apply_gate=True,
                )
                if summary.get("status") == STATUS_SKIPPED:
                    gated += 1
                else:
                    fired += 1
            except ScheduleBusyError:
                skipped_in_progress += 1
                continue
            except Exception as exc:  # noqa: BLE001
                # ``run_wol_schedule`` records its own failed run + re-stamps
                # next_run_at, so a bubble-up here is something deeper (DB
                # lost mid-commit). Log + move on so one sick schedule can't
                # wedge the whole sweep.
                errors += 1
                logger.exception(
                    "wol_sweep_unexpected",
                    schedule_id=str(schedule.id),
                    error=str(exc),
                )

        # ── Verify-state reaper (folded into this tick — NO new beat entry) ──
        # A worker crash mid-verify leaves a run wedged at ``verifying`` (or a
        # ``pending`` hole if ``apply_async`` raised at the arm / re-wake
        # enqueue). Unlike the schedule mutex above, the verify machine has no
        # ``status==in_progress`` row for the lease reaper to catch, so reclaim
        # any WolRun whose ``verify_claimed_at`` lease is older than
        # ``VERIFY_CLAIM_LEASE_SECONDS``: reset it to ``pending`` + re-stamp the
        # lease (so a second tick within the window doesn't double-fire) and
        # re-enqueue ``verify_wol_run`` at the row's current ``verify_attempt``
        # anchor. Idempotent + bounded (the attempt-guarded claim no-ops any
        # already-progressing pass).
        # Two leases, one per state: a wedged ``verifying`` pass is reclaimed on
        # the short lease; a ``pending`` run (legitimately counting down up to the
        # 3600 s max wait) only on the long one, so a genuine countdown is never
        # cut short (see the lease constants above).
        verifying_cutoff = now - timedelta(seconds=VERIFY_CLAIM_LEASE_SECONDS)
        pending_cutoff = now - timedelta(seconds=VERIFY_PENDING_LEASE_SECONDS)
        stale_verifies = (
            await db.execute(
                select(WolRun.id, WolRun.verify_attempt).where(
                    WolRun.verify_claimed_at.is_not(None),
                    or_(
                        and_(
                            WolRun.verify_state == VERIFY_VERIFYING,
                            WolRun.verify_claimed_at < verifying_cutoff,
                        ),
                        and_(
                            WolRun.verify_state == VERIFY_PENDING,
                            WolRun.verify_claimed_at < pending_cutoff,
                        ),
                    ),
                )
            )
        ).all()
        # The guard doesn't depend on the per-row attempt, so every stale row
        # takes the identical reset — collapse the N per-row UPDATEs into one
        # set-based statement (the per-row attempts are still read below for the
        # out-of-session re-enqueue). Same DB effect + reclaimed count as the
        # loop, one round-trip instead of N.
        if stale_verifies:
            await db.execute(
                update(WolRun)
                .where(
                    WolRun.id.in_([s[0] for s in stale_verifies]),
                    WolRun.verify_state.in_([VERIFY_PENDING, VERIFY_VERIFYING]),
                )
                .values(verify_state=VERIFY_PENDING, verify_claimed_at=now)
            )
            verify_reclaimed = len(stale_verifies)
            await db.commit()

    # Re-enqueue reclaimed verify passes outside the session (best-effort broker
    # push at the row's attempt anchor — a hiccup just defers to the next tick).
    for stale_id, stale_attempt in stale_verifies:
        _enqueue_verify(
            str(stale_id), stale_attempt or 1, 0, log_event="wol_verify_reaper_reenqueue_failed"
        )

    return {
        "fired": fired,
        "gated": gated,
        "skipped_in_progress": skipped_in_progress,
        "errors": errors,
        "verify_reclaimed": verify_reclaimed,
    }


@celery_app.task(name="app.tasks.wol_scheduler.sweep_wol_schedules")
@module_gated("tools.wake_scheduler")
def sweep_wol_schedules() -> dict[str, int]:
    result = asyncio.run(_sweep())
    if (
        result.get("fired")
        or result.get("gated")
        or result.get("errors")
        or result.get("verify_reclaimed")
    ):
        logger.info("wol_sweep_tick", **result)
    return result
