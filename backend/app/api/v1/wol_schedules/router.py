"""Scheduled Wake-on-LAN REST API (issue #586).

Mounted at ``/api/v1/wake-scheduler`` (see the include in
``app.api.v1.router``) behind the ``tools.wake_scheduler`` feature module.
The Python package is ``wol_schedules`` but the HTTP prefix is
``wake-scheduler`` — that prefix is the cross-surface contract shared with
the frontend api client, the MCP tools, and the runner docstrings.

Surface:

* CRUD on ``wol_schedule`` rows (list / create / get / patch / delete).
* ``POST /schedules/{id}/run-now`` — fire immediately via the shared runner
  (``app.tasks.wol_scheduler.run_schedule_now``); the built-in holiday gate
  is *bypassed* because a manual wake is an explicit operator action.
* ``POST /schedules/{id}/preview-targets`` — resolve a saved schedule's
  selector (against the schedule owner's read scope) + its next fire + the
  built-in gate verdict at that fire.
* ``POST /preview-targets`` — resolve an *unsaved* selector against the
  caller's read scope (the create modal's live match count).
* ``GET /runs`` / ``GET /runs/{id}`` — execution history + per-host detail.
* ``/calendars`` CRUD + ``POST /calendars/{id}/sync-now`` +
  ``GET /calendars/{id}/upcoming-events`` — Phase 2 iCal / CalDAV subscriptions
  whose all-day event spans gate scheduled wakes. The CalDAV password is
  Fernet-encrypted at rest and never returned (only ``password_set``).

Every mutation gates on ``use_network_tools`` (symmetry with the manual
``POST /ipam/addresses/{id}/wake`` — no new role seed) and writes an
append-only ``audit_log`` row BEFORE the response returns, in the same
transaction as the mutation (non-negotiable #4). Async throughout.

Target resolution reuses the one shared resolver
(``app.services.wol_scheduler.resolve_wol_targets``) — one resolver, three
surfaces (REST preview + beat runner + MCP), non-negotiables #1 / #13. It
enforces the schedule owner's readable-subnet scope at resolve time
(non-negotiable #3), so a schedule can never wake hosts in subnets its owner
has lost read access to.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.core.crypto import encrypt_str
from app.core.permissions import require_permission
from app.models.auth import Group, User
from app.models.ipam import Subnet
from app.models.wol_schedule import (
    WolCalendar,
    WolCalendarEvent,
    WolRun,
    WolRunTarget,
    WolSchedule,
)
from app.services import wol
from app.services.api_token_scopes import read_only_post
from app.services.wol_scheduler.gating import gate_verdict, load_gate_calendar_events
from app.services.wol_scheduler.resolver import (
    SKIP_NO_MAC,
    InvalidSelector,
    ResolvedTargets,
    _readable_subnet_ids,
    resolve_wol_targets,
)
from app.services.wol_scheduler.schedule import (
    InvalidCronExpression,
    InvalidTimezone,
    compute_next_run,
)
from app.services.wol_scheduler.verify import auto_stagger_ms

from .schemas import (
    CalendarEventRead,
    CalendarSyncResult,
    SkippedTargetRead,
    TargetPreviewRead,
    TargetPreviewRequest,
    WakeCalendarCreate,
    WakeCalendarRead,
    WakeCalendarUpdate,
    WakeRunDetailRead,
    WakeRunRead,
    WakeRunTargetRead,
    WakeScheduleCreate,
    WakeScheduleRead,
    WakeScheduleUpdate,
    WakeTargetRead,
)

# WoL is a network tool — reuse the tools permission already seeded into the
# Network Editor built-in role (symmetry with POST /ipam/addresses/{id}/wake).
PERMISSION = "use_network_tools"
RESOURCE_TYPE = "wol_schedule"

# Cap on the number of sample rows a preview returns per bucket (the UI wants
# a taste, not the whole fleet).
_SAMPLE_CAP = 50

# PATCH: non-nullable columns where an explicit ``null`` means "unchanged"
# (the operator can't null them out); nullable columns accept an explicit
# ``null`` to clear them.
_NON_NULLABLE_FIELDS = frozenset(
    {
        "name",
        "enabled",
        "timezone",
        "target_selector",
        "calendar_mode",
        "vantage",
        "repeat_count",
        "repeat_interval_ms",
        "stagger_ms",
        "port",
        "verify_enabled",
        "verify_wait_seconds",
        "verify_retries",
        "verify_alert_enabled",
        "verify_method",
    }
)

router = APIRouter(tags=["wake-scheduler"])


# ── Serialisers ──────────────────────────────────────────────────────


def _to_schedule_read(row: WolSchedule) -> WakeScheduleRead:
    return WakeScheduleRead(
        id=row.id,
        name=row.name,
        description=row.description,
        enabled=row.enabled,
        target_selector=row.target_selector or {},
        schedule_cron=row.schedule_cron,
        timezone=row.timezone,
        blackout_dates=row.blackout_dates,
        active_from=row.active_from,
        active_until=row.active_until,
        calendar_id=row.calendar_id,
        calendar_mode=row.calendar_mode,
        calendar_match=row.calendar_match,
        vantage=row.vantage or {"kind": "server", "id": None},
        repeat_count=row.repeat_count,
        repeat_interval_ms=row.repeat_interval_ms,
        stagger_ms=row.stagger_ms,
        port=row.port,
        verify_enabled=row.verify_enabled,
        verify_wait_seconds=row.verify_wait_seconds,
        verify_retries=row.verify_retries,
        verify_alert_enabled=row.verify_alert_enabled,
        verify_method=row.verify_method,
        last_run_at=row.last_run_at,
        last_run_status=row.last_run_status,
        last_run_skip_reason=row.last_run_skip_reason,
        last_target_count=row.last_target_count,
        next_run_at=row.next_run_at,
        created_by_user_id=row.created_by_user_id,
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


def _to_calendar_read(row: WolCalendar) -> WakeCalendarRead:
    return WakeCalendarRead(
        id=row.id,
        name=row.name,
        kind=row.kind,
        url=row.url,
        username=row.username,
        password_set=bool(row.password_encrypted),
        enabled=row.enabled,
        refresh_interval_minutes=row.refresh_interval_minutes,
        last_synced_at=row.last_synced_at,
        last_sync_status=row.last_sync_status,
        last_sync_error=row.last_sync_error,
        event_count=row.event_count,
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


def _to_event_read(row: WolCalendarEvent) -> CalendarEventRead:
    return CalendarEventRead(
        id=row.id,
        starts_on=row.starts_on,
        ends_on=row.ends_on,
        summary=row.summary,
        categories=list(row.categories or []),
        uid=row.uid,
    )


def _to_run_read(row: WolRun) -> WakeRunRead:
    return WakeRunRead(
        id=row.id,
        schedule_id=row.schedule_id,
        trigger=row.trigger,
        started_at=row.started_at,
        finished_at=row.finished_at,
        status=row.status,
        skip_reason=row.skip_reason,
        target_count=row.target_count,
        sent_count=row.sent_count,
        skipped_count=row.skipped_count,
        failed_count=row.failed_count,
        verify_state=row.verify_state,
        verified_count=row.verified_count,
        unverified_count=row.unverified_count,
        triggered_by_user_id=row.triggered_by_user_id,
        error=row.error,
        created_at=row.created_at,
    )


def _to_run_target_read(row: WolRunTarget) -> WakeRunTargetRead:
    return WakeRunTargetRead(
        id=row.id,
        run_id=row.run_id,
        ip_address_id=row.ip_address_id,
        address=row.address,
        mac=row.mac,
        subnet_id=row.subnet_id,
        broadcast=row.broadcast,
        vantage=row.vantage,
        mac_source=row.mac_source,
        sent=row.sent,
        skip_reason=row.skip_reason,
        error=row.error,
        verified=row.verified,
        verified_at=row.verified_at,
        verify_method=row.verify_method,
        verify_evidence=row.verify_evidence,
        wake_attempts=row.wake_attempts,
        created_at=row.created_at,
    )


def _resolved_to_preview(
    resolved: ResolvedTargets,
    *,
    next_run_at: datetime | None,
    verdict: str | None,
    visible_subnet_ids: set[uuid.UUID] | None = None,
) -> TargetPreviewRead:
    """Serialise a resolver result into the preview shape.

    Counts stay **owner-scoped** (the full ``resolved`` set) so the preview
    matches what will actually fire. Per-host *detail* in the sample, however,
    is filtered through ``visible_subnet_ids`` — the CALLER's readable-subnet
    scope — so a narrower-scoped caller previewing an admin-owned schedule sees
    the real fire count but never host address/mac/hostname/subnet for subnets
    it can't read (non-negotiable #3). ``None`` == caller is unrestricted
    (effective superadmin, or resolution was already caller-scoped) → show all.
    """

    def _visible(subnet_id: uuid.UUID | None) -> bool:
        if visible_subnet_ids is None:
            return True
        return subnet_id is not None and subnet_id in visible_subnet_ids

    wake_sample = [w for w in resolved.wakes if _visible(w.subnet_id)][:_SAMPLE_CAP]
    skipped_sample = [s for s in resolved.skipped if _visible(s.subnet_id)][:_SAMPLE_CAP]

    mac_less = sum(1 for s in resolved.skipped if s.reason == SKIP_NO_MAC)
    return TargetPreviewRead(
        matched_count=len(resolved.wakes) + len(resolved.skipped),
        wake_count=len(resolved.wakes),
        skipped_count=len(resolved.skipped),
        mac_less_count=mac_less,
        # Auto-tune suggestion for the resolved wake count (override=0 → raw
        # suggestion). 0 for a small set == "no artificial delay needed".
        suggested_stagger_ms=auto_stagger_ms(len(resolved.wakes), 0),
        sample=[
            WakeTargetRead(
                ip_address_id=w.ip_address_id,
                address=w.address,
                mac=w.mac,
                subnet_id=w.subnet_id,
                broadcast=w.broadcast,
                mac_source=w.mac_source,
                hostname=w.hostname,
            )
            for w in wake_sample
        ],
        skipped_sample=[
            SkippedTargetRead(
                reason=s.reason,
                ip_address_id=s.ip_address_id,
                address=s.address,
                subnet_id=s.subnet_id,
            )
            for s in skipped_sample
        ],
        next_run_at=next_run_at,
        gate_verdict=verdict,
    )


# ── Internal helpers ─────────────────────────────────────────────────


async def _load_scoped_user(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Load a user with groups → roles eager-loaded.

    The resolver's resolve-time permission gate (non-negotiable #3) runs the
    synchronous ``user_has_permission`` RBAC walk, which touches
    ``user.groups`` / ``group.roles`` — those must be eager-loaded or the walk
    trips an async lazy-load. Used to scope both the run-now fire and the
    preview against the correct principal.
    """
    return (
        await db.execute(
            select(User)
            .options(selectinload(User.groups).selectinload(Group.roles))
            .where(User.id == user_id)
        )
    ).scalar_one_or_none()


async def _caller_visible_subnet_ids(db: AsyncSession, user: User) -> set[uuid.UUID] | None:
    """The subnet ids ``user`` may READ, for filtering owner-scoped host detail
    down to the CALLER's scope on the read surfaces (preview + run detail).

    Returns ``None`` for an effective superadmin ("no restriction" — show every
    host); otherwise the concrete readable set. Mirrors the resolver's own
    resolve-time gate (unicast + not-deleted candidate set) so the two agree.
    """
    ids = await _readable_subnet_ids(
        db, user, [Subnet.kind == "unicast", Subnet.deleted_at.is_(None)]
    )
    return None if ids is None else set(ids)


def _compute_next(schedule: WolSchedule) -> None:
    """(Re)compute ``next_run_at`` for a schedule from its cron + tz.

    NULL / empty cron == manual-only → ``next_run_at`` stays NULL (never
    swept). Called on create + on every update so a cron/tz edit takes effect
    immediately without waiting for a beat restart.
    """
    if not schedule.schedule_cron:
        schedule.next_run_at = None
        return
    try:
        schedule.next_run_at = compute_next_run(
            schedule.schedule_cron, schedule.timezone, after=datetime.now(UTC)
        )
    except (InvalidCronExpression, InvalidTimezone) as exc:
        # Validated at the schema layer already; this is belt-and-braces.
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# Vantage serialization is shared with the ad-hoc IPAM wake via
# wol.vantage_to_jsonb so the {kind, id} wire shape has one source of truth.
_vantage_to_jsonb = wol.vantage_to_jsonb


async def _assert_calendar_exists(db: AsyncSession, calendar_id: uuid.UUID | None) -> None:
    """422 if a schedule references a non-existent calendar (FK would 500)."""
    if calendar_id is None:
        return
    if await db.get(WolCalendar, calendar_id) is None:
        raise HTTPException(status_code=422, detail=f"calendar {calendar_id} not found")


async def _resolve_for_preview(
    db: AsyncSession,
    principal: User,
    selector: dict[str, Any],
) -> ResolvedTargets:
    try:
        return await resolve_wol_targets(db, principal, selector)
    except InvalidSelector as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ── Schedules CRUD ───────────────────────────────────────────────────


@router.get(
    "/schedules",
    response_model=list[WakeScheduleRead],
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def list_schedules(
    db: DB,
    current_user: CurrentUser,  # noqa: ARG001 — gate handled by dep
    enabled: bool | None = Query(None),
) -> list[WakeScheduleRead]:
    stmt = select(WolSchedule)
    if enabled is not None:
        stmt = stmt.where(WolSchedule.enabled.is_(enabled))
    stmt = stmt.order_by(WolSchedule.name.asc())
    rows = list((await db.execute(stmt)).scalars().all())
    return [_to_schedule_read(r) for r in rows]


@router.post(
    "/schedules",
    response_model=WakeScheduleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def create_schedule(
    body: WakeScheduleCreate, db: DB, current_user: CurrentUser
) -> WakeScheduleRead:
    await _assert_calendar_exists(db, body.calendar_id)
    row = WolSchedule(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        target_selector=body.target_selector.to_jsonb(),
        schedule_cron=body.schedule_cron,
        timezone=body.timezone,
        blackout_dates=body.blackout_dates,
        active_from=body.active_from,
        active_until=body.active_until,
        calendar_id=body.calendar_id,
        calendar_mode=body.calendar_mode,
        calendar_match=body.calendar_match,
        vantage=_vantage_to_jsonb(body.vantage),
        repeat_count=body.repeat_count,
        repeat_interval_ms=body.repeat_interval_ms,
        stagger_ms=body.stagger_ms,
        port=body.port,
        verify_enabled=body.verify_enabled,
        verify_wait_seconds=body.verify_wait_seconds,
        verify_retries=body.verify_retries,
        verify_alert_enabled=body.verify_alert_enabled,
        verify_method=body.verify_method,
        created_by_user_id=current_user.id,
    )
    _compute_next(row)
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=current_user,
        action="create",
        resource_type=RESOURCE_TYPE,
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={
            "name": row.name,
            "enabled": row.enabled,
            "target_selector": row.target_selector,
            "schedule_cron": row.schedule_cron,
            "timezone": row.timezone,
            "vantage": row.vantage,
        },
    )
    await db.commit()
    await db.refresh(row)
    return _to_schedule_read(row)


@router.get(
    "/schedules/{schedule_id}",
    response_model=WakeScheduleRead,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def get_schedule(
    schedule_id: uuid.UUID, db: DB, current_user: CurrentUser  # noqa: ARG001
) -> WakeScheduleRead:
    row = await db.get(WolSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _to_schedule_read(row)


@router.patch(
    "/schedules/{schedule_id}",
    response_model=WakeScheduleRead,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def update_schedule(
    schedule_id: uuid.UUID,
    body: WakeScheduleUpdate,
    db: DB,
    current_user: CurrentUser,
) -> WakeScheduleRead:
    row = await db.get(WolSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    fields = body.model_dump(exclude_unset=True)
    changed: list[str] = []

    # A newly-referenced calendar must exist (FK would 500 on commit otherwise).
    if "calendar_id" in fields and fields["calendar_id"] is not None:
        await _assert_calendar_exists(db, body.calendar_id)

    for field, value in fields.items():
        if field in _NON_NULLABLE_FIELDS and value is None:
            continue
        if field == "target_selector":
            row.target_selector = body.target_selector.to_jsonb()  # type: ignore[union-attr]
        elif field == "vantage":
            row.vantage = _vantage_to_jsonb(body.vantage)
        else:
            setattr(row, field, value)
        changed.append(field)

    # Post-apply consistency — a non-'none' calendar_mode needs an attached
    # calendar (mirror the create-time model validator, but against the merged
    # row so "set mode now, calendar already attached" is accepted).
    if (row.calendar_mode or "none") != "none" and row.calendar_id is None:
        raise HTTPException(
            status_code=422,
            detail=f"calendar_id is required when calendar_mode is {row.calendar_mode!r}",
        )

    # Any cron/tz change (or clear) must re-derive the next fire immediately.
    # Re-enabling must ALSO recompute: a schedule that sat disabled across a
    # cron slot has a stale, now-past ``next_run_at`` (the sweep froze it while
    # ``enabled=False``); without a fresh compute the very next sweep fires an
    # immediate unintended fleet wake at re-enable instead of the next slot.
    if (
        "schedule_cron" in changed
        or "timezone" in changed
        or ("enabled" in changed and row.enabled)
    ):
        _compute_next(row)

    write_audit(
        db,
        user=current_user,
        action="update",
        resource_type=RESOURCE_TYPE,
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=changed,
        new_value={k: fields[k] for k in changed if k in fields},
    )
    await db.commit()
    await db.refresh(row)
    return _to_schedule_read(row)


@router.delete(
    "/schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("delete", PERMISSION))],
)
async def delete_schedule(schedule_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    row = await db.get(WolSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    name = row.name
    write_audit(
        db,
        user=current_user,
        action="delete",
        resource_type=RESOURCE_TYPE,
        resource_id=str(row.id),
        resource_display=name,
    )
    # ``wol_run.schedule_id`` is ON DELETE SET NULL — history survives so a
    # deleted schedule's "skipped because holiday" runs stay visible.
    await db.delete(row)
    await db.commit()


# ── Run now ──────────────────────────────────────────────────────────


@router.post(
    "/schedules/{schedule_id}/run-now",
    response_model=WakeRunRead,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def run_now(schedule_id: uuid.UUID, db: DB, current_user: CurrentUser) -> WakeRunRead:
    """Fire ``schedule_id`` immediately.

    Reuses the shared runner (``run_schedule_now``); the built-in holiday gate
    is bypassed — a manual "wake now" is an explicit operator action, the gate
    only governs scheduled fires. Targets are resolved against the *caller's*
    read scope so a manual run can't wake hosts the operator can't see.

    Concurrency is guarded by the runner's ATOMIC ``in_progress`` claim (the
    single source of truth shared with the beat sweep): a run-now that races an
    in-progress sweep fire (or a double-click) raises ``ScheduleBusyError``,
    which we surface as a 409 instead of double-dispatching magic packets.
    """
    row = await db.get(WolSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Eager-load the caller's groups/roles for the resolver's sync RBAC walk.
    principal = await _load_scoped_user(db, current_user.id)

    # Lazy import — keep the task module (celery bootstrap) off the router's
    # import-time graph (pcap uses the same lazy-import pattern).
    from app.tasks.wol_scheduler import (  # noqa: PLC0415
        ScheduleBusyError,
        run_schedule_now,
    )

    try:
        summary = await run_schedule_now(
            schedule_id,
            trigger="manual",
            actor_id=current_user.id,
            actor_display=current_user.display_name,
            apply_gate=False,
            resolve_user=principal,
            db=db,
        )
    except ScheduleBusyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Schedule is already running",
        ) from exc

    run_id = summary.get("run_id")
    run = await db.get(WolRun, uuid.UUID(run_id)) if run_id else None

    # Symmetry with the manual POST /ipam/addresses/{id}/wake — a second audit
    # row under the shared ``wake_on_lan`` action so scheduled + ad-hoc manual
    # wakes land under one audit filter. (The runner already audited the fire
    # itself under ``wol_schedule_fired``.)
    write_audit(
        db,
        user=current_user,
        action="wake_on_lan",
        resource_type=RESOURCE_TYPE,
        resource_id=str(schedule_id),
        resource_display=row.name,
        new_value=summary,
        result="success" if summary.get("sent") else "failure",
    )
    await db.commit()

    if run is None:
        # Defensive — the runner always persists a run row, but never 500 if a
        # concurrent delete raced the SET-NULL. Return the summary shape.
        raise HTTPException(status_code=500, detail="run row not found after dispatch")
    return _to_run_read(run)


# ── Target preview ───────────────────────────────────────────────────


@router.post(
    "/schedules/{schedule_id}/preview-targets",
    response_model=TargetPreviewRead,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
@read_only_post
async def preview_schedule_targets(
    schedule_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> TargetPreviewRead:
    """Resolve a saved schedule's selector against the *schedule owner's* read
    scope (mirrors what will actually fire) + report the next fire and the
    built-in gate verdict at that fire ("who wakes next, and is that day a
    blackout?").

    Counts are owner-scoped for fire-time parity, but the returned per-host
    detail sample is filtered down to the CALLER's readable-subnet scope so a
    narrower-scoped caller can't read host address/mac/hostname/subnet outside
    its own RBAC scope by previewing a broader-owned schedule (non-neg #3)."""
    row = await db.get(WolSchedule, schedule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    # Resolve against the owner (fall back to the caller if the schedule is
    # unowned / the owner was deleted) so the count matches fire-time scoping.
    principal: User | None = None
    if row.created_by_user_id is not None:
        principal = await _load_scoped_user(db, row.created_by_user_id)
    caller = await _load_scoped_user(db, current_user.id)
    if principal is None:
        principal = caller
    if principal is None or caller is None:  # pragma: no cover — caller always exists
        raise HTTPException(status_code=422, detail="no principal to scope target resolution")

    resolved = await _resolve_for_preview(db, principal, row.target_selector or {})

    # Host detail is clamped to what the CALLER may read; owner-scoped counts
    # stay intact for fire-time parity.
    visible = await _caller_visible_subnet_ids(db, caller)

    # Gate verdict at the NEXT fire (or now for a manual-only schedule),
    # including the Phase-2 calendar gate (events loaded when one is attached).
    candidate = row.next_run_at or datetime.now(UTC)
    calendar_events = await load_gate_calendar_events(db, row)
    verdict = gate_verdict(candidate, row, calendar_events=calendar_events)
    return _resolved_to_preview(
        resolved,
        next_run_at=row.next_run_at,
        verdict=verdict,
        visible_subnet_ids=visible,
    )


@router.post(
    "/preview-targets",
    response_model=TargetPreviewRead,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
@read_only_post
async def preview_selector(
    body: TargetPreviewRequest, db: DB, current_user: CurrentUser
) -> TargetPreviewRead:
    """Resolve an *unsaved* selector against the caller's read scope — the
    create/edit modal's live "N hosts · M no-MAC" match count. No gate /
    next-fire (the schedule isn't persisted yet)."""
    principal = await _load_scoped_user(db, current_user.id)
    if principal is None:  # pragma: no cover — caller always exists
        raise HTTPException(status_code=422, detail="no principal to scope target resolution")
    resolved = await _resolve_for_preview(db, principal, body.target_selector.to_jsonb())
    return _resolved_to_preview(resolved, next_run_at=None, verdict=None)


# ── Run history ──────────────────────────────────────────────────────


@router.get(
    "/runs",
    response_model=list[WakeRunRead],
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def list_runs(
    db: DB,
    current_user: CurrentUser,  # noqa: ARG001
    schedule_id: uuid.UUID | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
) -> list[WakeRunRead]:
    stmt = select(WolRun)
    if schedule_id is not None:
        stmt = stmt.where(WolRun.schedule_id == schedule_id)
    if status_filter:
        stmt = stmt.where(WolRun.status == status_filter)
    stmt = stmt.order_by(WolRun.started_at.desc()).limit(limit)
    rows = list((await db.execute(stmt)).scalars().all())
    return [_to_run_read(r) for r in rows]


@router.get(
    "/runs/{run_id}",
    response_model=WakeRunDetailRead,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def get_run(run_id: uuid.UUID, db: DB, current_user: CurrentUser) -> WakeRunDetailRead:
    """Return one run + its per-host target rows.

    The run-level counts are owner-scoped (they record what the fire actually
    did); the per-host ``WolRunTarget`` rows carry address/mac/subnet, so they
    are filtered down to the CALLER's readable-subnet scope — a narrower-scoped
    caller can't read host inventory outside its RBAC scope via a broader-owned
    schedule's run detail (non-neg #3)."""
    run = await db.get(WolRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    targets = list(
        (
            await db.execute(
                select(WolRunTarget)
                .where(WolRunTarget.run_id == run_id)
                .order_by(WolRunTarget.created_at.asc())
            )
        )
        .scalars()
        .all()
    )

    # Clamp per-host detail to the caller's readable subnets (None == effective
    # superadmin → no restriction). Rows with a NULL subnet_id (owner-less /
    # legacy) are only shown to an unrestricted caller.
    caller = await _load_scoped_user(db, current_user.id)
    visible = await _caller_visible_subnet_ids(db, caller) if caller is not None else set()
    if visible is not None:
        targets = [t for t in targets if t.subnet_id is not None and t.subnet_id in visible]

    base = _to_run_read(run)
    return WakeRunDetailRead(
        **base.model_dump(),
        targets=[_to_run_target_read(t) for t in targets],
    )


# ── Calendars CRUD (Phase 2) ─────────────────────────────────────────


@router.get(
    "/calendars",
    response_model=list[WakeCalendarRead],
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def list_calendars(
    db: DB,
    current_user: CurrentUser,  # noqa: ARG001
    enabled: bool | None = Query(None),
) -> list[WakeCalendarRead]:
    stmt = select(WolCalendar)
    if enabled is not None:
        stmt = stmt.where(WolCalendar.enabled.is_(enabled))
    stmt = stmt.order_by(WolCalendar.name.asc())
    rows = list((await db.execute(stmt)).scalars().all())
    return [_to_calendar_read(r) for r in rows]


@router.post(
    "/calendars",
    response_model=WakeCalendarRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def create_calendar(
    body: WakeCalendarCreate, db: DB, current_user: CurrentUser
) -> WakeCalendarRead:
    row = WolCalendar(
        name=body.name,
        kind=body.kind,
        url=body.url,
        username=body.username,
        password_encrypted=(encrypt_str(body.password) if body.password else None),
        enabled=body.enabled,
        refresh_interval_minutes=body.refresh_interval_minutes,
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=current_user,
        action="create",
        resource_type="wol_calendar",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={
            "name": row.name,
            "kind": row.kind,
            "url": row.url,
            "enabled": row.enabled,
            "refresh_interval_minutes": row.refresh_interval_minutes,
        },
    )
    await db.commit()
    await db.refresh(row)
    return _to_calendar_read(row)


@router.get(
    "/calendars/{calendar_id}",
    response_model=WakeCalendarRead,
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def get_calendar(
    calendar_id: uuid.UUID, db: DB, current_user: CurrentUser  # noqa: ARG001
) -> WakeCalendarRead:
    row = await db.get(WolCalendar, calendar_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Calendar not found")
    return _to_calendar_read(row)


@router.patch(
    "/calendars/{calendar_id}",
    response_model=WakeCalendarRead,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def update_calendar(
    calendar_id: uuid.UUID,
    body: WakeCalendarUpdate,
    db: DB,
    current_user: CurrentUser,
) -> WakeCalendarRead:
    row = await db.get(WolCalendar, calendar_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Calendar not found")

    fields = body.model_dump(exclude_unset=True)
    changed: list[str] = []
    # Non-nullable columns where an explicit null means "unchanged".
    non_nullable = {"name", "kind", "url", "enabled", "refresh_interval_minutes"}

    for field, value in fields.items():
        if field == "password":
            # Explicit "" clears the stored secret; a non-empty string
            # re-encrypts; omitting the field (not in ``fields``) leaves it.
            row.password_encrypted = encrypt_str(value) if value else None
            changed.append("password")
            continue
        if field in non_nullable and value is None:
            continue
        setattr(row, field, value)
        changed.append(field)

    write_audit(
        db,
        user=current_user,
        action="update",
        resource_type="wol_calendar",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=changed,
        # Never echo the password back into the audit trail.
        new_value={k: fields[k] for k in changed if k in fields and k != "password"},
    )
    await db.commit()
    await db.refresh(row)
    return _to_calendar_read(row)


@router.delete(
    "/calendars/{calendar_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("delete", PERMISSION))],
)
async def delete_calendar(calendar_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    row = await db.get(WolCalendar, calendar_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Calendar not found")
    name = row.name
    write_audit(
        db,
        user=current_user,
        action="delete",
        resource_type="wol_calendar",
        resource_id=str(row.id),
        resource_display=name,
    )
    # ``wol_schedule.calendar_id`` is ON DELETE SET NULL — schedules survive,
    # their calendar gate reverts to none-effect (mode stays but no events).
    await db.delete(row)
    await db.commit()


@router.post(
    "/calendars/{calendar_id}/sync-now",
    response_model=CalendarSyncResult,
    dependencies=[Depends(require_permission("write", PERMISSION))],
)
async def sync_calendar_now(
    calendar_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> CalendarSyncResult:
    """Refresh a calendar's cached event spans right now (inline, for immediate
    operator feedback) reusing the shared reconciler. A transient fetch failure
    surfaces as a generic 502 (the specific error is persisted on the row's
    ``last_sync_error`` and the audit log, never echoed to the caller); a parse
    failure returns a ``status='error'`` result (the row's error state is
    persisted either way)."""
    row = await db.get(WolCalendar, calendar_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Calendar not found")

    # Lazy import — keep the sync service (httpx/caldav/icalendar) off the
    # router's import-time graph (matches the run-now lazy-import pattern).
    from app.services.wol_scheduler.calendar_sync import sync_calendar  # noqa: PLC0415

    try:
        # force=True: an explicit operator click may legitimately empty a
        # cleared calendar (the beat sweep keeps the zero-result guard).
        summary = await sync_calendar(db, row, force=True)
    except Exception as exc:  # noqa: BLE001 — transient re-raise from the reconciler
        await db.refresh(row)
        write_audit(
            db,
            user=current_user,
            action="sync",
            resource_type="wol_calendar",
            resource_id=str(row.id),
            resource_display=row.name,
            result="failure",
            new_value={"error": str(exc)[:2000]},
        )
        await db.commit()
        raise HTTPException(
            status_code=502,
            detail="calendar sync failed — see the calendar's last sync status",
        ) from exc

    await db.refresh(row)
    write_audit(
        db,
        user=current_user,
        action="sync",
        resource_type="wol_calendar",
        resource_id=str(row.id),
        resource_display=row.name,
        result="success" if summary.get("status") == "success" else "failure",
        new_value=summary,
    )
    await db.commit()
    return CalendarSyncResult(
        status=summary.get("status", "error"),
        added=summary.get("added", 0),
        removed=summary.get("removed", 0),
        total=summary.get("total", 0),
        error=summary.get("error"),
        last_synced_at=row.last_synced_at,
        last_sync_status=row.last_sync_status,
        last_sync_error=row.last_sync_error,
    )


@router.get(
    "/calendars/{calendar_id}/upcoming-events",
    response_model=list[CalendarEventRead],
    dependencies=[Depends(require_permission("read", PERMISSION))],
)
async def upcoming_calendar_events(
    calendar_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,  # noqa: ARG001
    days: int = Query(60, ge=1, le=400),
    limit: int = Query(100, ge=1, le=500),
) -> list[CalendarEventRead]:
    """Preview the calendar's cached events whose span reaches into the next
    ``days`` window (an event still running today counts) — the operator's
    "does this feed actually mark our holidays?" confirmation."""
    row = await db.get(WolCalendar, calendar_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Calendar not found")
    today = datetime.now(UTC).date()
    horizon = today + timedelta(days=days)
    stmt = (
        select(WolCalendarEvent)
        .where(
            WolCalendarEvent.calendar_id == calendar_id,
            WolCalendarEvent.ends_on >= today,
            WolCalendarEvent.starts_on <= horizon,
        )
        .order_by(WolCalendarEvent.starts_on.asc())
        .limit(limit)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return [_to_event_read(r) for r in rows]


__all__ = ["router"]
