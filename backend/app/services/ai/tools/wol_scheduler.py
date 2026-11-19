"""Operator Copilot tools for Scheduled Wake-on-LAN (issue #586, Phase 1).

Surfaces the ``wol_schedule`` registry + ``wol_run`` execution history so
the Copilot can answer "which hosts wake tomorrow morning, and is that a
school day?", "did last night's lab wake actually fire?", "how many wake
schedules are disabled?".

Read tools (``find_*`` / ``get_*`` / ``count_*`` / ``preview_*``) ship
default-enabled per CLAUDE.md non-negotiable #13 — no secrets, no off-prem
call, no mutation. Write intent rides the ``propose_*`` tools below, which
mirror the shipped ``propose_wake_host`` convention: the propose tool itself
is read-only (``writes=False``) and only persists an ``AIOperationProposal``;
the actual send / mutation runs through the operator's explicit Apply against
``POST /api/v1/ai/proposals/{id}/apply`` (backed by the three matching
``Operation``s registered in ``services/ai/operations.py``). Following
``propose_wake_host`` they ship default-enabled too (a schedule fires nothing
until it is created + enabled, and every apply is separately RBAC-gated on
``use_network_tools``).

Every tool is tagged ``module="tools.wake_scheduler"`` — the #14 kill-switch:
disable the feature module and the whole cluster is stripped from the
registry's effective set regardless of per-platform / per-provider allowlists.

All target resolution reuses the ONE shared resolver
(``app.services.wol_scheduler.resolve_wol_targets``) — one resolver, four
surfaces (REST preview + beat runner + these MCP reads + the propose preview),
non-negotiables #1 / #13. It enforces the schedule owner's readable-subnet
scope at resolve time (non-negotiable #3) for the AGGREGATE counts.  The
per-host sample that ``preview_wol_schedule_targets`` hands back to the LLM is
additionally filtered through the CALLING user's readable-subnet scope, so a
Copilot caller can never see host detail (address/mac/hostname/subnet) for a
subnet they themselves can't read — even when the schedule owner can.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.auth import Group, User
from app.models.wol_schedule import (
    VERIFY_STATE_DONE,
    WolCalendar,
    WolCalendarEvent,
    WolRun,
    WolSchedule,
)
from app.services.ai.operations import (
    CreateWolScheduleArgs,
    RunWolScheduleNowArgs,
    SetWolScheduleEnabledArgs,
)
from app.services.ai.tools.base import register_tool
from app.services.ai.tools.proposals import _propose_via

_MODULE = "tools.wake_scheduler"

# Cap on preview sample rows returned to the LLM (a taste, not the fleet).
_SAMPLE_CAP = 25


# ── Serialisers ──────────────────────────────────────────────────────


def _schedule_summary(row: WolSchedule) -> dict[str, Any]:
    """Compact schedule row for list views."""
    selector = row.target_selector or {}
    return {
        "id": str(row.id),
        "name": row.name,
        "enabled": row.enabled,
        "target_mode": selector.get("mode"),
        "schedule_cron": row.schedule_cron,
        "timezone": row.timezone,
        "manual_only": not row.schedule_cron,
        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
        "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
        "last_run_status": row.last_run_status,
        "last_run_skip_reason": row.last_run_skip_reason,
        "last_target_count": row.last_target_count,
        "vantage": row.vantage or {"kind": "server", "id": None},
        # Surfaced on the LIST view (not just the detail) so the copilot can
        # answer "which schedules still verify with ping only?" in one call.
        "verify_method": row.verify_method,
    }


def _schedule_detail(row: WolSchedule) -> dict[str, Any]:
    """Full schedule row (adds the gate + send knobs)."""
    detail = _schedule_summary(row)
    detail.update(
        {
            "description": row.description,
            "target_selector": row.target_selector or {},
            "blackout_dates": row.blackout_dates,
            "active_from": row.active_from.isoformat() if row.active_from else None,
            "active_until": row.active_until.isoformat() if row.active_until else None,
            "repeat_count": row.repeat_count,
            "repeat_interval_ms": row.repeat_interval_ms,
            # stagger_ms == 0 means "auto" (the runner ramps large fleets); any
            # positive value is an explicit operator override.
            "stagger_ms": row.stagger_ms,
            "port": row.port,
            # Post-wake verify config (Phase 3): whether a run probes SENT hosts
            # for liveness after firing, how long it waits, and the re-wake bound.
            # ``verify_method`` already rides along from _schedule_summary.
            "verify_enabled": row.verify_enabled,
            "verify_wait_seconds": row.verify_wait_seconds,
            "verify_retries": row.verify_retries,
            "verify_alert_enabled": row.verify_alert_enabled,
            "created_by_user_id": (str(row.created_by_user_id) if row.created_by_user_id else None),
            "created_at": row.created_at.isoformat(),
            "modified_at": row.modified_at.isoformat(),
        }
    )
    return detail


def _run_summary(row: WolRun) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "schedule_id": str(row.schedule_id) if row.schedule_id else None,
        "trigger": row.trigger,
        "started_at": row.started_at.isoformat(),
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "status": row.status,
        "skip_reason": row.skip_reason,
        "target_count": row.target_count,
        "sent_count": row.sent_count,
        "skipped_count": row.skipped_count,
        "failed_count": row.failed_count,
        # Post-wake liveness verify rollup (Phase 3) — distinct from send
        # success. verify_state: none|pending|verifying|done. verified_count /
        # unverified_count are the SENT-target liveness split (did the fleet
        # actually come UP?), populated once verify finalises.
        "verify_state": row.verify_state,
        "verified_count": row.verified_count,
        "unverified_count": row.unverified_count,
        "error": row.error,
    }


async def _load_scoped_user(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Eager-load groups → roles for the resolver's synchronous RBAC walk
    (mirrors the REST router's ``_load_scoped_user``)."""
    return (
        await db.execute(
            select(User)
            .options(selectinload(User.groups).selectinload(Group.roles))
            .where(User.id == user_id)
        )
    ).scalar_one_or_none()


# ── Read tools ───────────────────────────────────────────────────────


class FindWolSchedulesArgs(BaseModel):
    enabled: bool | None = Field(
        default=None,
        description="True = only enabled, False = only disabled, omitted = both.",
    )
    name_contains: str | None = Field(
        default=None, description="Case-insensitive substring match on the schedule name."
    )
    manual_only: bool | None = Field(
        default=None,
        description="True = only manual-only schedules (no cron), False = only cron-driven.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_wol_schedules",
    permission=("read", "use_network_tools"),
    description=(
        "List scheduled Wake-on-LAN jobs. Each row carries the target mode, "
        "cron + timezone (or manual-only), next/last fire and last run status. "
        "Answers 'which wake schedules do we have?', 'list disabled wake "
        "schedules', 'what wakes on a cron?'. Read-only."
    ),
    args_model=FindWolSchedulesArgs,
    category="network",
    module=_MODULE,
)
async def find_wol_schedules(
    db: AsyncSession, user: User, args: FindWolSchedulesArgs
) -> list[dict[str, Any]]:
    stmt = select(WolSchedule)
    if args.enabled is not None:
        stmt = stmt.where(WolSchedule.enabled.is_(args.enabled))
    if args.name_contains:
        stmt = stmt.where(WolSchedule.name.ilike(f"%{args.name_contains}%"))
    if args.manual_only is True:
        stmt = stmt.where(WolSchedule.schedule_cron.is_(None))
    elif args.manual_only is False:
        stmt = stmt.where(WolSchedule.schedule_cron.is_not(None))
    stmt = stmt.order_by(WolSchedule.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_schedule_summary(r) for r in rows]


class GetWolScheduleArgs(BaseModel):
    schedule_id: uuid.UUID = Field(description="UUID of the wol_schedule row.")


@register_tool(
    name="get_wol_schedule",
    permission=("read", "use_network_tools"),
    description=(
        "Get one Wake-on-LAN schedule in full — target selector, cron + "
        "timezone, the built-in holiday gate (blackout dates + active term "
        "range), the send knobs (vantage, repeat count, stagger, port), and "
        "last-run mirror. Read-only."
    ),
    args_model=GetWolScheduleArgs,
    category="network",
    module=_MODULE,
)
async def get_wol_schedule(
    db: AsyncSession, user: User, args: GetWolScheduleArgs
) -> dict[str, Any]:
    row = await db.get(WolSchedule, args.schedule_id)
    if row is None:
        return {"error": f"schedule {args.schedule_id} not found"}
    return _schedule_detail(row)


class CountWolSchedulesArgs(BaseModel):
    enabled: bool | None = Field(
        default=None,
        description="True = count enabled, False = count disabled, omitted = all.",
    )


@register_tool(
    name="count_wol_schedules",
    permission=("read", "use_network_tools"),
    description=(
        "Count Wake-on-LAN schedules, optionally filtered by enabled state. "
        "Returns {total, enabled, disabled, manual_only}. Read-only."
    ),
    args_model=CountWolSchedulesArgs,
    category="network",
    module=_MODULE,
)
async def count_wol_schedules(
    db: AsyncSession, user: User, args: CountWolSchedulesArgs
) -> dict[str, int]:
    base = select(func.count(WolSchedule.id))
    total = (await db.execute(base)).scalar_one()
    enabled = (await db.execute(base.where(WolSchedule.enabled.is_(True)))).scalar_one()
    manual = (await db.execute(base.where(WolSchedule.schedule_cron.is_(None)))).scalar_one()
    result = {
        "total": int(total),
        "enabled": int(enabled),
        "disabled": int(total) - int(enabled),
        "manual_only": int(manual),
    }
    if args.enabled is True:
        result["matched"] = int(enabled)
    elif args.enabled is False:
        result["matched"] = int(total) - int(enabled)
    return result


class FindWolRunsArgs(BaseModel):
    schedule_id: uuid.UUID | None = Field(
        default=None, description="Restrict to runs of one schedule."
    )
    status: str | None = Field(
        default=None,
        description="Filter by status: ok / partial / skipped / failed / in_progress.",
    )
    trigger: str | None = Field(
        default=None,
        description=(
            "Filter by trigger: 'schedule' (a cron/calendar fire), 'manual' "
            "(run-now), or 'adhoc' (a single-host wake from the IPAM address "
            "action that opted into verify)."
        ),
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_wol_runs",
    permission=("read", "use_network_tools"),
    description=(
        "List Wake-on-LAN execution history — one row per fire (scheduled OR "
        "manual), INCLUDING gated-skip runs so 'skipped because holiday' is "
        "visible. Carries per-run sent/skipped/failed counts + skip_reason AND "
        "the post-wake liveness rollup (verify_state + verified_count / "
        "unverified_count) — so 'did last night's wake actually bring the fleet "
        "UP?' is answerable, not just 'did it send?'. Most recent first. "
        "Read-only."
    ),
    args_model=FindWolRunsArgs,
    category="network",
    module=_MODULE,
)
async def find_wol_runs(
    db: AsyncSession, user: User, args: FindWolRunsArgs
) -> list[dict[str, Any]]:
    stmt = select(WolRun)
    if args.schedule_id is not None:
        stmt = stmt.where(WolRun.schedule_id == args.schedule_id)
    if args.status:
        stmt = stmt.where(WolRun.status == args.status)
    if args.trigger:
        stmt = stmt.where(WolRun.trigger == args.trigger)
    stmt = stmt.order_by(WolRun.started_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_run_summary(r) for r in rows]


class PreviewWolScheduleTargetsArgs(BaseModel):
    schedule_id: uuid.UUID = Field(
        description="UUID of the wol_schedule to resolve targets + next-fire gate for."
    )


@register_tool(
    name="preview_wol_schedule_targets",
    permission=("read", "use_network_tools"),
    description=(
        "Resolve a saved Wake-on-LAN schedule's target fleet against its "
        "owner's read scope (what will actually fire), plus report the next "
        "fire time and the built-in gate verdict at that fire — 'who wakes "
        "next, and is that day a blackout / outside the active term?'. Returns "
        "owner-scoped wake/skipped counts (fire-time parity), a mac-less count "
        "(hosts with no known MAC), a capped host sample LIMITED to the "
        "CALLER's own readable subnets (a host in a subnet you can't read is "
        "counted but never sampled), next_run_at and gate_verdict (null = "
        "would fire, 'holiday'/'off_term' = suppressed), plus a "
        "suggested_stagger_ms (the ms inter-host gap to avoid a large-fleet "
        "power-inrush / PXE thundering-herd). Read-only."
    ),
    args_model=PreviewWolScheduleTargetsArgs,
    category="network",
    module=_MODULE,
)
async def preview_wol_schedule_targets(
    db: AsyncSession, user: User, args: PreviewWolScheduleTargetsArgs
) -> dict[str, Any]:
    # Lazy import — keep the resolver/gating service off this module's
    # import-time graph (matches the REST router's lazy service use).
    from app.models.ipam import Subnet  # noqa: PLC0415
    from app.services.wol_scheduler import (  # noqa: PLC0415
        SKIP_NO_MAC,
        InvalidSelector,
        auto_stagger_ms,
        gate_verdict,
        load_gate_calendar_events,
        resolve_wol_targets,
    )
    from app.services.wol_scheduler.resolver import _readable_subnet_ids  # noqa: PLC0415

    row = await db.get(WolSchedule, args.schedule_id)
    if row is None:
        return {"error": f"schedule {args.schedule_id} not found"}

    # Resolve against the schedule OWNER (fall back to the caller) so the
    # AGGREGATE counts match fire-time scoping — non-negotiable #3.  Per-host
    # sample detail is a separate concern (see caller-scope filter below).
    principal: User | None = None
    if row.created_by_user_id is not None:
        principal = await _load_scoped_user(db, row.created_by_user_id)
    if principal is None:
        principal = await _load_scoped_user(db, user.id)
    if principal is None:  # pragma: no cover — caller always exists
        return {"error": "no principal to scope target resolution"}

    try:
        resolved = await resolve_wol_targets(db, principal, row.target_selector or {})
    except InvalidSelector as exc:
        return {"error": str(exc)}

    # ── Caller-scope the per-host sample ─────────────────────────────────
    # The counts above reflect the owner's fire-time scope, but returning
    # real address/mac/hostname/subnet for a host in a subnet the CALLER can't
    # read is a cross-tenant inventory leak (non-negotiable #3 applies to the
    # CALLER too, not just the owner).  Filter every sample row through the
    # caller's readable-subnet set; a superadmin caller (None) sees all.
    present_subnet_ids = {w.subnet_id for w in resolved.wakes if w.subnet_id is not None} | {
        s.subnet_id for s in resolved.skipped if s.subnet_id is not None
    }
    caller_readable = await _readable_subnet_ids(
        db,
        user,
        [Subnet.id.in_(present_subnet_ids)] if present_subnet_ids else [Subnet.id.is_(None)],
    )

    def _caller_can_read(subnet_id: uuid.UUID | None) -> bool:
        if caller_readable is None:  # caller is an effective superadmin
            return True
        return subnet_id is not None and subnet_id in caller_readable

    visible_wakes = [w for w in resolved.wakes if _caller_can_read(w.subnet_id)]
    visible_skipped = [s for s in resolved.skipped if _caller_can_read(s.subnet_id)]

    mac_less = sum(1 for s in resolved.skipped if s.reason == SKIP_NO_MAC)
    candidate = row.next_run_at or datetime.now(UTC)
    # Include the Phase-2 calendar gate (events loaded when one is attached),
    # mirroring the REST preview + fire path exactly.
    calendar_events = await load_gate_calendar_events(db, row)
    verdict = gate_verdict(candidate, row, calendar_events=calendar_events)
    return {
        "schedule_id": str(row.id),
        "name": row.name,
        "matched_count": len(resolved.wakes) + len(resolved.skipped),
        "wake_count": len(resolved.wakes),
        "skipped_count": len(resolved.skipped),
        "mac_less_count": mac_less,
        # Stagger auto-tune suggestion for this wake count (Phase 3): the ms gap
        # to space a large fleet's wakes so it can't power-inrush / PXE-herd. 0
        # == small enough to fire all-at-once. Advisory — the schedule's own
        # stagger_ms (if > 0) overrides.
        "suggested_stagger_ms": auto_stagger_ms(len(resolved.wakes), 0),
        "sample_scoped_to_caller": True,
        "next_run_at": row.next_run_at.isoformat() if row.next_run_at else None,
        "gate_verdict": verdict,
        "would_fire": verdict is None,
        "sample": [
            {
                "address": w.address,
                "mac": w.mac,
                "broadcast": w.broadcast,
                "mac_source": w.mac_source,
                "hostname": w.hostname,
            }
            for w in visible_wakes[:_SAMPLE_CAP]
        ],
        "skipped_sample": [
            {"reason": s.reason, "address": s.address} for s in visible_skipped[:_SAMPLE_CAP]
        ],
    }


# ── Calendar reads (Phase 2) ─────────────────────────────────────────


def _calendar_summary(row: WolCalendar) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "name": row.name,
        "kind": row.kind,
        "url": row.url,
        "enabled": row.enabled,
        "refresh_interval_minutes": row.refresh_interval_minutes,
        "event_count": row.event_count,
        "last_synced_at": row.last_synced_at.isoformat() if row.last_synced_at else None,
        "last_sync_status": row.last_sync_status,
        "last_sync_error": row.last_sync_error,
        # Never leak the CalDAV password — only whether one is stored.
        "password_set": bool(row.password_encrypted),
        "username": row.username,
    }


class FindWolCalendarsArgs(BaseModel):
    enabled: bool | None = Field(
        default=None, description="True = only enabled, False = only disabled, omitted = both."
    )
    name_contains: str | None = Field(
        default=None, description="Case-insensitive substring match on the calendar name."
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_wol_calendars",
    permission=("read", "use_network_tools"),
    description=(
        "List Wake-on-LAN calendar subscriptions (iCal .ics URL or CalDAV) whose "
        "all-day events gate scheduled wakes. Each row carries kind, refresh "
        "cadence, cached event_count, and last sync status/error. The CalDAV "
        "password is never returned (only a password_set boolean). Answers 'which "
        "holiday calendars are wired up?', 'did the school calendar sync?'. "
        "Read-only."
    ),
    args_model=FindWolCalendarsArgs,
    category="network",
    module=_MODULE,
)
async def find_wol_calendars(
    db: AsyncSession, user: User, args: FindWolCalendarsArgs
) -> list[dict[str, Any]]:
    stmt = select(WolCalendar)
    if args.enabled is not None:
        stmt = stmt.where(WolCalendar.enabled.is_(args.enabled))
    if args.name_contains:
        stmt = stmt.where(WolCalendar.name.ilike(f"%{args.name_contains}%"))
    stmt = stmt.order_by(WolCalendar.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_calendar_summary(r) for r in rows]


class GetWolCalendarArgs(BaseModel):
    calendar_id: uuid.UUID = Field(description="UUID of the wol_calendar row.")


@register_tool(
    name="get_wol_calendar",
    permission=("read", "use_network_tools"),
    description=(
        "Get one Wake-on-LAN calendar subscription in full — kind, URL, refresh "
        "cadence, cached event_count, last sync status/error, and whether a "
        "CalDAV password is stored (password_set; the secret itself is never "
        "returned). Read-only."
    ),
    args_model=GetWolCalendarArgs,
    category="network",
    module=_MODULE,
)
async def get_wol_calendar(
    db: AsyncSession, user: User, args: GetWolCalendarArgs
) -> dict[str, Any]:
    row = await db.get(WolCalendar, args.calendar_id)
    if row is None:
        return {"error": f"calendar {args.calendar_id} not found"}
    return _calendar_summary(row)


class FindWolCalendarEventsArgs(BaseModel):
    calendar_id: uuid.UUID = Field(description="UUID of the wol_calendar to preview.")
    days: int = Field(default=60, ge=1, le=400, description="Forward window in days from today.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_wol_calendar_events",
    permission=("read", "use_network_tools"),
    description=(
        "Preview a Wake-on-LAN calendar's upcoming cached all-day event spans "
        "(recurrence already expanded) within the next N days — the "
        "'is tomorrow marked as a holiday / school day on this feed?' check. "
        "Returns start/end date, summary, categories. Read-only."
    ),
    args_model=FindWolCalendarEventsArgs,
    category="network",
    module=_MODULE,
)
async def find_wol_calendar_events(
    db: AsyncSession, user: User, args: FindWolCalendarEventsArgs
) -> list[dict[str, Any]]:
    from datetime import timedelta  # noqa: PLC0415

    cal = await db.get(WolCalendar, args.calendar_id)
    if cal is None:
        return [{"error": f"calendar {args.calendar_id} not found"}]
    today = datetime.now(UTC).date()
    horizon = today + timedelta(days=args.days)
    rows = (
        (
            await db.execute(
                select(WolCalendarEvent)
                .where(
                    WolCalendarEvent.calendar_id == args.calendar_id,
                    WolCalendarEvent.ends_on >= today,
                    WolCalendarEvent.starts_on <= horizon,
                )
                .order_by(WolCalendarEvent.starts_on.asc())
                .limit(args.limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "starts_on": r.starts_on.isoformat(),
            "ends_on": r.ends_on.isoformat(),
            "summary": r.summary,
            "categories": list(r.categories or []),
        }
        for r in rows
    ]


# ── Wake-failure reads (#596 Phase 3) ────────────────────────────────


class FindWolWakeFailuresArgs(BaseModel):
    days: int = Field(
        default=7,
        ge=1,
        le=90,
        description="Look back this many days over finalised runs.",
    )
    schedule_id: str | None = Field(
        default=None, description="Restrict to one schedule (UUID). Omitted = all."
    )
    limit: int = Field(default=50, ge=1, le=200)


def _wake_failure_row(run: WolRun, schedule_name: str | None) -> dict[str, Any]:
    return {
        "run_id": str(run.id),
        "schedule_id": str(run.schedule_id) if run.schedule_id else None,
        "schedule_name": schedule_name,
        # ``adhoc`` runs have no schedule; they come from the single-host wake
        # action on an IP. They never raise an alert, so surfacing them here is
        # the only way the copilot can answer for them.
        "trigger": run.trigger,
        "started_at": run.started_at.isoformat(),
        "sent_count": run.sent_count,
        "verified_count": run.verified_count,
        "unverified_count": run.unverified_count,
    }


@register_tool(
    name="find_wol_wake_failures",
    permission=("read", "use_network_tools"),
    description=(
        "List Wake-on-LAN runs whose post-wake verify finished with hosts that "
        "never came up (unverified_count > 0), newest first. Covers both "
        "scheduled and ad-hoc single-host wakes. Answers 'which wakes failed "
        "this week?', 'did the lab come up on Monday?'. Read-only."
    ),
    args_model=FindWolWakeFailuresArgs,
    category="network",
    module=_MODULE,
    # Read-only, no secrets, no off-prem call — default on so operators discover
    # it exists (non-negotiable #13).
    default_enabled=True,
)
async def find_wol_wake_failures(
    db: AsyncSession, user: User, args: FindWolWakeFailuresArgs
) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC) - timedelta(days=args.days)
    stmt = (
        select(WolRun, WolSchedule.name)
        .outerjoin(WolSchedule, WolRun.schedule_id == WolSchedule.id)
        .where(
            WolRun.verify_state == VERIFY_STATE_DONE,
            WolRun.unverified_count > 0,
            WolRun.started_at >= cutoff,
        )
        .order_by(WolRun.started_at.desc())
        .limit(args.limit)
    )
    if args.schedule_id:
        try:
            stmt = stmt.where(WolRun.schedule_id == uuid.UUID(args.schedule_id))
        except ValueError:
            return []
    rows = (await db.execute(stmt)).all()
    return [_wake_failure_row(run, name) for run, name in rows]


class CountWolWakeFailuresArgs(BaseModel):
    days: int = Field(default=7, ge=1, le=90)


@register_tool(
    name="count_wol_wake_failures",
    permission=("read", "use_network_tools"),
    description=(
        "Count Wake-on-LAN runs whose verify finished with unconfirmed hosts, "
        "over the last N days. Returns {runs_with_failures, hosts_unverified, "
        "runs_verified_clean}. Read-only."
    ),
    args_model=CountWolWakeFailuresArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_wol_wake_failures(
    db: AsyncSession, user: User, args: CountWolWakeFailuresArgs
) -> dict[str, int]:
    cutoff = datetime.now(UTC) - timedelta(days=args.days)
    # One scan of the finalised-runs window with filtered aggregates, rather than
    # two passes sharing the same WHERE (mirrors _finalise_verify's rollup).
    row = (
        await db.execute(
            select(
                func.count(WolRun.id).filter(WolRun.unverified_count > 0),
                func.coalesce(
                    func.sum(WolRun.unverified_count).filter(WolRun.unverified_count > 0), 0
                ),
                func.count(WolRun.id).filter(WolRun.unverified_count == 0),
            ).where(
                WolRun.verify_state == VERIFY_STATE_DONE,
                WolRun.started_at >= cutoff,
            )
        )
    ).one()
    return {
        "runs_with_failures": int(row[0]),
        "hosts_unverified": int(row[1]),
        "runs_verified_clean": int(row[2]),
    }


# ── Write proposals (propose → operator Apply) ───────────────────────


@register_tool(
    name="propose_create_wol_schedule",
    permission=("write", "use_network_tools"),
    description=(
        "Prepare a proposal to CREATE a scheduled Wake-on-LAN job. The operator "
        "must click Apply for it to land — nothing is created by this call. "
        "Pass name, a selector ({mode, tags/subnet_ids/address_ids}), an "
        "optional 5-field cron + IANA timezone (omit cron for manual-only), the "
        "built-in holiday gate (blackout_dates + active_from/active_until), and "
        "the vantage (server or appliance). Returns a kind='proposal' card — "
        "surface the preview (including how many hosts would wake) and wait for "
        "the operator's decision. Never call twice for the same change."
    ),
    args_model=CreateWolScheduleArgs,
    writes=False,  # The propose tool is read-only; Apply is the write.
    category="network",
    module=_MODULE,
)
async def propose_create_wol_schedule(
    db: AsyncSession, user: User, args: CreateWolScheduleArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="create_wol_schedule", args=args)


@register_tool(
    name="propose_run_wol_schedule_now",
    permission=("write", "use_network_tools"),
    description=(
        "Prepare a proposal to FIRE a Wake-on-LAN schedule immediately — the "
        "built-in holiday gate is bypassed (a manual run is an explicit "
        "action). The operator must click Apply to actually send the magic "
        "packets. Pass schedule_id. Returns a kind='proposal' card showing how "
        "many hosts would wake; wait for the operator's decision."
    ),
    args_model=RunWolScheduleNowArgs,
    writes=False,
    category="network",
    module=_MODULE,
)
async def propose_run_wol_schedule_now(
    db: AsyncSession, user: User, args: RunWolScheduleNowArgs
) -> dict[str, Any]:
    return await _propose_via(db=db, user=user, operation_name="run_wol_schedule_now", args=args)


@register_tool(
    name="propose_set_wol_schedule_enabled",
    permission=("write", "use_network_tools"),
    description=(
        "Prepare a proposal to ENABLE or DISABLE a Wake-on-LAN schedule. The "
        "operator must click Apply for the toggle to land. Pass schedule_id + "
        "enabled (true/false). Disabling pauses the sweep; enabling recomputes "
        "the next fire from the cron. Returns a kind='proposal' card."
    ),
    args_model=SetWolScheduleEnabledArgs,
    writes=False,
    category="network",
    module=_MODULE,
)
async def propose_set_wol_schedule_enabled(
    db: AsyncSession, user: User, args: SetWolScheduleEnabledArgs
) -> dict[str, Any]:
    return await _propose_via(
        db=db, user=user, operation_name="set_wol_schedule_enabled", args=args
    )
