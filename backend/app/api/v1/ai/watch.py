"""Copilot Watch REST surface (issue #4405), mounted at ``/api/v1/ai/watch``.

Two audiences:

* **Configuration** (``/config``, ``/pause``, ``/run-now``): superadmin
  only. It decides which provider receives install data unattended and
  how much may be spent.
* **Findings** (``/findings``, ``/runs``, ``/mutes``, ``/summary``):
  ``read`` on ``ai_finding`` to see them, ``write`` on ``ai_finding`` to
  acknowledge, dismiss, reopen or leave feedback. A holder sees every
  finding; findings are not filtered by what the reader could otherwise
  read, which is why the grant is its own resource type.

Nothing here changes the DDI configuration. Watch observes and advises.

The router is gated on the ``ai.watch`` feature module where it is
included (``app/api/v1/router.py``), which resolves on only while
``ai.copilot`` is also on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select

from app.api.deps import DB, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.core.permissions import require_permission
from app.models.ai import AIProvider
from app.models.ai_watch import (
    FEEDBACK_VERDICTS,
    FINDING_ACKNOWLEDGED,
    FINDING_ACTIVE_STATES,
    FINDING_DISMISSED,
    FINDING_KINDS,
    FINDING_OPEN,
    FINDING_SEVERITIES,
    FINDING_STATES,
    PAUSE_MANUAL,
    AIFinding,
    AIFindingFeedback,
    AIFindingMute,
    AIWatchConfig,
    AIWatchRun,
)
from app.models.auth import User
from app.services.ai.watch import budget as budget_svc
from app.services.ai.watch import runner
from app.services.ai.watch.principal import (
    WatchPrincipalError,
    ensure_watch_principal,
    principal_summary,
)
from app.services.ai.watch.providers import provider_eligible, resolve_provider_chain
from app.services.ai.watch.tools import DEFAULT_WATCH_TOOLS, allowable_tools, validate_allowlist

logger = structlog.get_logger(__name__)
router = APIRouter()

RESOURCE_FINDING = "ai_finding"
RESOURCE_WATCH = "ai_watch"

_FindingReader = Depends(require_permission("read", RESOURCE_FINDING))
_FindingWriter = Depends(require_permission("write", RESOURCE_FINDING))


# ── Schemas ──────────────────────────────────────────────────────────────


class WatchProviderOption(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    default_model: str
    is_enabled: bool
    is_on_prem: bool
    # Whether Watch may use it with the settings as they are now.
    eligible: bool


class WatchToolOption(BaseModel):
    name: str
    category: str
    description: str
    default: bool


class WatchPrincipalInfo(BaseModel):
    id: str
    username: str
    is_active: bool
    group: str
    roles: list[str]
    problem: str | None


class WatchUsageInfo(BaseModel):
    runs: int
    tokens: int
    cost_usd: Decimal
    token_budget: int
    cost_budget_usd: Decimal


class WatchConfigResponse(BaseModel):
    enabled: bool
    paused: bool
    paused_reason: str | None
    paused_detail: str
    paused_at: datetime | None
    paused_until: datetime | None
    provider_id: uuid.UUID | None
    allow_hosted_provider: bool
    sweep_interval_hours: int
    event_trigger_enabled: bool
    event_debounce_seconds: int
    enabled_tools: list[str] | None
    daily_token_budget: int
    daily_cost_budget_usd: Decimal
    max_runs_per_hour: int
    max_rounds: int
    max_tokens_per_run: int
    last_sweep_at: datetime | None
    run_requested_at: datetime | None
    consecutive_failures: int
    # Why a run could not start right now, or None: ``no_provider`` /
    # ``hosted_not_allowed`` / ``principal_*``.
    blocked_reason: str | None
    usage_today: WatchUsageInfo
    principal: WatchPrincipalInfo
    providers: list[WatchProviderOption]
    tools: list[WatchToolOption]


class WatchConfigUpdate(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool | None = None
    provider_id: uuid.UUID | None = None
    allow_hosted_provider: bool | None = None
    sweep_interval_hours: int | None = Field(default=None, ge=0, le=24 * 30)
    event_trigger_enabled: bool | None = None
    event_debounce_seconds: int | None = Field(default=None, ge=60, le=3600)
    enabled_tools: list[str] | None = None
    daily_token_budget: int | None = Field(default=None, ge=1, le=100_000_000)
    daily_cost_budget_usd: Decimal | None = Field(default=None, gt=0, le=10_000)
    max_runs_per_hour: int | None = Field(default=None, ge=1, le=60)
    max_rounds: int | None = Field(default=None, ge=1, le=10)
    max_tokens_per_run: int | None = Field(default=None, ge=1000, le=2_000_000)


class PauseRequest(BaseModel):
    paused: bool
    reason: str = Field(default="", max_length=500)


class RunNowResponse(BaseModel):
    requested_at: datetime


class RunSummary(BaseModel):
    id: uuid.UUID
    trigger: str
    state: str
    skip_reason: str | None
    error: str | None
    provider_name: str
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal | None
    rounds: int
    tool_calls: int
    evidence_count: int
    findings_opened: int
    findings_updated: int
    findings_resolved: int
    findings_dropped: int
    findings_muted: int
    started_at: datetime
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class RunDetail(RunSummary):
    transcript: list[Any] | None


class RunList(BaseModel):
    items: list[RunSummary]
    total: int


class FeedbackEntry(BaseModel):
    user_id: uuid.UUID
    username: str
    verdict: str
    note: str
    modified_at: datetime


class FindingResponse(BaseModel):
    id: uuid.UUID
    fingerprint: str
    kind: str
    severity: str
    title: str
    explanation: str
    evidence: list[dict[str, Any]]
    recommendations: list[str]
    confidence: str
    state: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    run_id: uuid.UUID | None
    model: str
    state_changed_at: datetime | None
    state_changed_by: str | None
    state_note: str
    my_verdict: str | None = None
    feedback: list[FeedbackEntry] = Field(default_factory=list)


class FindingList(BaseModel):
    items: list[FindingResponse]
    total: int


class WatchSummary(BaseModel):
    enabled: bool
    paused: bool
    paused_reason: str | None
    paused_detail: str
    paused_until: datetime | None
    open_total: int
    open_by_severity: dict[str, int]
    acknowledged_total: int
    last_run: RunSummary | None


class FeedbackStat(BaseModel):
    # ``kind`` or ``model``.
    dimension: str
    value: str
    useful: int
    not_useful: int
    wrong: int


class AcknowledgeRequest(BaseModel):
    note: str = Field(default="", max_length=2000)


class DismissRequest(BaseModel):
    note: str = Field(default="", max_length=2000)
    # How long the same finding stays unfiled. 0 = do not mute; NULL =
    # until an operator removes the mute.
    mute_days: int | None = Field(default=7, ge=0, le=3650)


class FeedbackRequest(BaseModel):
    verdict: str
    note: str = Field(default="", max_length=2000)

    @field_validator("verdict")
    @classmethod
    def _verdict(cls, v: str) -> str:
        if v not in FEEDBACK_VERDICTS:
            raise ValueError(f"verdict must be one of {list(FEEDBACK_VERDICTS)}")
        return v


class MuteResponse(BaseModel):
    id: uuid.UUID
    fingerprint: str
    title: str
    reason: str
    until: datetime | None
    finding_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Config (superadmin) ──────────────────────────────────────────────────


async def _config_response(db: DB, config: AIWatchConfig) -> WatchConfigResponse:
    try:
        principal = await ensure_watch_principal(db)
    except WatchPrincipalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    summary = principal_summary(principal)
    providers = (
        (await db.execute(select(AIProvider).order_by(AIProvider.priority, AIProvider.name)))
        .scalars()
        .all()
    )
    _chain, blocked = await resolve_provider_chain(db, config)
    blocked = blocked or summary["problem"]  # type: ignore[assignment]
    usage = await budget_svc.usage_today(db, config, datetime.now(UTC))
    defaults = set(DEFAULT_WATCH_TOOLS)
    return WatchConfigResponse(
        enabled=config.enabled,
        paused=config.paused,
        paused_reason=config.paused_reason,
        paused_detail=config.paused_detail,
        paused_at=config.paused_at,
        paused_until=config.paused_until,
        provider_id=config.provider_id,
        allow_hosted_provider=config.allow_hosted_provider,
        sweep_interval_hours=config.sweep_interval_hours,
        event_trigger_enabled=config.event_trigger_enabled,
        event_debounce_seconds=config.event_debounce_seconds,
        enabled_tools=config.enabled_tools,
        daily_token_budget=config.daily_token_budget,
        daily_cost_budget_usd=config.daily_cost_budget_usd,
        max_runs_per_hour=config.max_runs_per_hour,
        max_rounds=config.max_rounds,
        max_tokens_per_run=config.max_tokens_per_run,
        last_sweep_at=config.last_sweep_at,
        run_requested_at=config.run_requested_at,
        consecutive_failures=config.consecutive_failures,
        blocked_reason=blocked,
        usage_today=WatchUsageInfo(
            runs=usage.runs,
            tokens=usage.tokens,
            cost_usd=usage.cost_usd,
            token_budget=usage.token_budget,
            cost_budget_usd=usage.cost_budget_usd,
        ),
        principal=WatchPrincipalInfo(**summary),  # type: ignore[arg-type]
        providers=[
            WatchProviderOption(
                id=p.id,
                name=p.name,
                kind=p.kind,
                default_model=p.default_model,
                is_enabled=p.is_enabled,
                is_on_prem=p.is_on_prem,
                eligible=provider_eligible(p, config),
            )
            for p in providers
        ],
        tools=[
            WatchToolOption(
                name=t.name,
                category=t.category,
                description=t.description.splitlines()[0] if t.description else "",
                default=t.name in defaults,
            )
            for t in allowable_tools()
        ],
    )


@router.get("/config", response_model=WatchConfigResponse)
async def get_watch_config(current_user: SuperAdmin, db: DB) -> WatchConfigResponse:
    config = await runner.get_config(db)
    response = await _config_response(db, config)
    # First read creates the settings row and the service identity.
    await db.commit()
    return response


@router.put("/config", response_model=WatchConfigResponse)
async def update_watch_config(
    body: WatchConfigUpdate, current_user: SuperAdmin, db: DB
) -> WatchConfigResponse:
    config = await runner.get_config(db)
    changes = body.model_dump(exclude_unset=True)

    if changes.get("enabled_tools") is not None:
        problems = validate_allowlist(changes["enabled_tools"])
        if problems:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="These tools cannot be offered to Copilot Watch: " + "; ".join(problems),
            )
    if changes.get("provider_id") is not None:
        if await db.get(AIProvider, changes["provider_id"]) is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="AI provider not found"
            )
    for required in ("daily_token_budget", "daily_cost_budget_usd"):
        if required in changes and changes[required] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"{required} is required; Copilot Watch has no unlimited mode.",
            )
    # A field sent as null that has no "unset" meaning keeps its value.
    nullable = {"provider_id", "enabled_tools"}
    changes = {k: v for k, v in changes.items() if v is not None or k in nullable}

    old: dict[str, Any] = {}
    new: dict[str, Any] = {}
    for key, value in changes.items():
        before = getattr(config, key)
        if before != value:
            old[key] = str(before) if isinstance(before, uuid.UUID | Decimal) else before
            new[key] = str(value) if isinstance(value, uuid.UUID | Decimal) else value
            setattr(config, key, value)

    if config.enabled and ("enabled" in new or "provider_id" in new or "allow_hosted_provider" in new):
        # Arming Watch, or changing where it sends data while armed: it
        # must have somewhere it is allowed to send it.
        _chain, reason = await resolve_provider_chain(db, config)
        if reason is not None:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Copilot Watch needs an enabled AI provider marked on-prem. "
                    "Mark one on-prem under AI Providers, or turn on "
                    "'Allow a hosted provider' to send data to one that is not."
                    if reason == "hosted_not_allowed"
                    else "Copilot Watch needs an enabled AI provider. "
                    "The pinned provider is missing or disabled, or none is enabled."
                ),
            )
    if new.get("enabled") is True:
        # Start clean: the first tick reviews what is open now.
        config.alert_cursor = None
        config.event_pending_since = None
        config.last_sweep_at = None
        config.consecutive_failures = 0

    if new:
        write_audit(
            db,
            user=current_user,
            action="update",
            resource_type=RESOURCE_WATCH,
            resource_id="1",
            resource_display="Copilot Watch settings",
            changed_fields=sorted(new),
            old_value=old,
            new_value=new,
        )
    response = await _config_response(db, config)
    await db.commit()
    return response


@router.post("/pause", response_model=WatchConfigResponse)
async def pause_watch(body: PauseRequest, current_user: SuperAdmin, db: DB) -> WatchConfigResponse:
    """Pause or resume. Resuming also clears an automatic pause (budget
    reached, repeated failures)."""
    config = await runner.get_config(db)
    if body.paused != config.paused:
        before = {"paused": config.paused, "paused_reason": config.paused_reason}
        if body.paused:
            runner.pause(
                config,
                reason=PAUSE_MANUAL,
                detail=body.reason or f"Paused by {current_user.username}.",
                now=datetime.now(UTC),
            )
        else:
            runner.resume(config)
        write_audit(
            db,
            user=current_user,
            action="pause" if body.paused else "resume",
            resource_type=RESOURCE_WATCH,
            resource_id="1",
            resource_display="Copilot Watch",
            old_value=before,
            new_value={"paused": config.paused, "paused_reason": config.paused_reason},
        )
    response = await _config_response(db, config)
    await db.commit()
    return response


@router.post("/run-now", response_model=RunNowResponse, status_code=status.HTTP_202_ACCEPTED)
async def run_watch_now(current_user: SuperAdmin, db: DB) -> RunNowResponse:
    """Ask for a run. It starts on the worker within a minute; the guards
    (budget, provider, maintenance mode) still apply, and a refused run
    shows on the Runs tab as skipped with the reason."""
    config = await runner.get_config(db)
    if not config.enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Copilot Watch is not enabled."
        )
    if config.paused:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Copilot Watch is paused: {config.paused_detail or config.paused_reason}",
        )
    now = datetime.now(UTC)
    config.run_requested_at = now
    config.run_requested_by_user_id = current_user.id
    write_audit(
        db,
        user=current_user,
        action="run",
        resource_type=RESOURCE_WATCH,
        resource_id="1",
        resource_display="Copilot Watch run requested",
        new_value={"trigger": "manual"},
    )
    await db.commit()
    try:
        from app.tasks.ai_watch import tick  # noqa: PLC0415

        tick.delay()
    except Exception as exc:  # noqa: BLE001
        # The request is stored; the 60 s beat tick picks it up.
        logger.warning("ai_watch_run_now_enqueue_failed", error=str(exc))
    return RunNowResponse(requested_at=now)


# ── Runs ─────────────────────────────────────────────────────────────────


@router.get("/runs", response_model=RunList, dependencies=[_FindingReader])
async def list_watch_runs(
    db: DB,
    state: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> RunList:
    stmt = select(AIWatchRun)
    count = select(func.count(AIWatchRun.id))
    if state:
        stmt = stmt.where(AIWatchRun.state == state)
        count = count.where(AIWatchRun.state == state)
    rows = (
        (await db.execute(stmt.order_by(AIWatchRun.started_at.desc()).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return RunList(
        items=[RunSummary.model_validate(r) for r in rows],
        total=int(await db.scalar(count) or 0),
    )


@router.get("/runs/{run_id}", response_model=RunDetail, dependencies=[_FindingReader])
async def get_watch_run(run_id: uuid.UUID, db: DB) -> RunDetail:
    run = await db.get(AIWatchRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return RunDetail.model_validate(run)


# ── Findings ─────────────────────────────────────────────────────────────


async def _usernames(db: DB, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    rows = await db.execute(select(User.id, User.username).where(User.id.in_(ids)))
    return {uid: name for uid, name in rows.all()}


async def _finding_responses(
    db: DB, findings: list[AIFinding], me: User, *, with_feedback: bool
) -> list[FindingResponse]:
    ids = [f.id for f in findings]
    feedback_rows: list[AIFindingFeedback] = []
    if ids:
        feedback_rows = list(
            (
                await db.execute(
                    select(AIFindingFeedback)
                    .where(AIFindingFeedback.finding_id.in_(ids))
                    .order_by(AIFindingFeedback.modified_at.desc())
                )
            )
            .scalars()
            .all()
        )
    user_ids = {f.state_changed_by_user_id for f in findings if f.state_changed_by_user_id}
    user_ids |= {fb.user_id for fb in feedback_rows}
    names = await _usernames(db, user_ids)
    out: list[FindingResponse] = []
    for f in findings:
        mine = [fb for fb in feedback_rows if fb.finding_id == f.id]
        out.append(
            FindingResponse(
                id=f.id,
                fingerprint=f.fingerprint,
                kind=f.kind,
                severity=f.severity,
                title=f.title,
                explanation=f.explanation,
                evidence=list(f.evidence or []),
                recommendations=list(f.recommendations or []),
                confidence=f.confidence,
                state=f.state,
                first_seen_at=f.first_seen_at,
                last_seen_at=f.last_seen_at,
                resolved_at=f.resolved_at,
                run_id=f.run_id,
                model=f.model,
                state_changed_at=f.state_changed_at,
                state_changed_by=(
                    names.get(f.state_changed_by_user_id) if f.state_changed_by_user_id else None
                ),
                state_note=f.state_note,
                my_verdict=next((fb.verdict for fb in mine if fb.user_id == me.id), None),
                feedback=(
                    [
                        FeedbackEntry(
                            user_id=fb.user_id,
                            username=names.get(fb.user_id, ""),
                            verdict=fb.verdict,
                            note=fb.note,
                            modified_at=fb.modified_at,
                        )
                        for fb in mine
                    ]
                    if with_feedback
                    else []
                ),
            )
        )
    return out


_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


@router.get("/findings", response_model=FindingList)
async def list_findings(
    db: DB,
    current_user: User = _FindingReader,
    state: str | None = Query(
        default="active",
        description="open / acknowledged / dismissed / resolved, 'active' (open + "
        "acknowledged) or 'all'.",
    ),
    severity: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FindingList:
    stmt = select(AIFinding)
    if state == "active":
        stmt = stmt.where(AIFinding.state.in_(FINDING_ACTIVE_STATES))
    elif state and state != "all":
        if state not in FINDING_STATES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"state must be one of {[*FINDING_STATES, 'active', 'all']}",
            )
        stmt = stmt.where(AIFinding.state == state)
    if severity:
        if severity not in FINDING_SEVERITIES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"severity must be one of {list(FINDING_SEVERITIES)}",
            )
        stmt = stmt.where(AIFinding.severity == severity)
    if kind:
        if kind not in FINDING_KINDS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"kind must be one of {list(FINDING_KINDS)}",
            )
        stmt = stmt.where(AIFinding.kind == kind)
    total = int(await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    rows = list(
        (
            await db.execute(
                stmt.order_by(AIFinding.last_seen_at.desc(), AIFinding.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    rows.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 3))
    return FindingList(
        items=await _finding_responses(db, rows, current_user, with_feedback=False),
        total=total,
    )


@router.get("/summary", response_model=WatchSummary, dependencies=[_FindingReader])
async def watch_summary(db: DB) -> WatchSummary:
    """What the dashboard card shows: open counts and whether Watch is running."""
    config = await db.get(AIWatchConfig, 1)
    counts = (
        await db.execute(
            select(AIFinding.state, AIFinding.severity, func.count(AIFinding.id))
            .where(AIFinding.state.in_(FINDING_ACTIVE_STATES))
            .group_by(AIFinding.state, AIFinding.severity)
        )
    ).all()
    by_severity: dict[str, int] = {}
    acknowledged = 0
    for f_state, f_severity, n in counts:
        if f_state == FINDING_OPEN:
            by_severity[f_severity] = by_severity.get(f_severity, 0) + int(n)
        else:
            acknowledged += int(n)
    last_run = await db.scalar(select(AIWatchRun).order_by(AIWatchRun.started_at.desc()).limit(1))
    return WatchSummary(
        enabled=bool(config and config.enabled),
        paused=bool(config and config.paused),
        paused_reason=config.paused_reason if config else None,
        paused_detail=config.paused_detail if config else "",
        paused_until=config.paused_until if config else None,
        open_total=sum(by_severity.values()),
        open_by_severity=by_severity,
        acknowledged_total=acknowledged,
        last_run=RunSummary.model_validate(last_run) if last_run is not None else None,
    )


@router.get(
    "/feedback-stats", response_model=list[FeedbackStat], dependencies=[_FindingReader]
)
async def feedback_stats(db: DB) -> list[FeedbackStat]:
    """Useful / not useful / wrong counts per finding kind and per model.
    A kind or a model that keeps being marked wrong is one to mute, narrow
    or replace."""
    out: list[FeedbackStat] = []
    for dimension, column in (("kind", AIFinding.kind), ("model", AIFinding.model)):
        rows = (
            await db.execute(
                select(column, AIFindingFeedback.verdict, func.count(AIFindingFeedback.id))
                .join(AIFinding, AIFinding.id == AIFindingFeedback.finding_id)
                .group_by(column, AIFindingFeedback.verdict)
                .order_by(column)
            )
        ).all()
        merged: dict[str, dict[str, int]] = {}
        for value, verdict, n in rows:
            merged.setdefault(value or "", {})[verdict] = int(n)
        out.extend(
            FeedbackStat(
                dimension=dimension,
                value=value,
                useful=v.get("useful", 0),
                not_useful=v.get("not_useful", 0),
                wrong=v.get("wrong", 0),
            )
            for value, v in merged.items()
        )
    return out


async def _get_finding(db: DB, finding_id: uuid.UUID) -> AIFinding:
    finding = await db.get(AIFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


async def _one(db: DB, finding: AIFinding, me: User) -> FindingResponse:
    return (await _finding_responses(db, [finding], me, with_feedback=True))[0]


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID, db: DB, current_user: User = _FindingReader
) -> FindingResponse:
    return await _one(db, await _get_finding(db, finding_id), current_user)


def _set_state(finding: AIFinding, state: str, user: User, note: str) -> dict[str, Any]:
    before = {"state": finding.state}
    finding.state = state
    finding.state_changed_at = datetime.now(UTC)
    finding.state_changed_by_user_id = user.id
    finding.state_note = note
    return before


@router.post("/findings/{finding_id}/acknowledge", response_model=FindingResponse)
async def acknowledge_finding(
    finding_id: uuid.UUID,
    body: AcknowledgeRequest,
    db: DB,
    current_user: User = _FindingWriter,
) -> FindingResponse:
    """Mark a finding as seen. It stays in the inbox and still closes by
    itself when its evidence clears."""
    finding = await _get_finding(db, finding_id)
    if finding.state != FINDING_OPEN:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Only an open finding can be acknowledged; this one is {finding.state}.",
        )
    before = _set_state(finding, FINDING_ACKNOWLEDGED, current_user, body.note)
    write_audit(
        db,
        user=current_user,
        action="acknowledge",
        resource_type=RESOURCE_FINDING,
        resource_id=str(finding.id),
        resource_display=finding.title,
        old_value=before,
        new_value={"state": finding.state, "note": body.note},
    )
    response = await _one(db, finding, current_user)
    await db.commit()
    return response


@router.post("/findings/{finding_id}/dismiss", response_model=FindingResponse)
async def dismiss_finding(
    finding_id: uuid.UUID,
    body: DismissRequest,
    db: DB,
    current_user: User = _FindingWriter,
) -> FindingResponse:
    """Dismiss a finding and, unless ``mute_days`` is 0, keep Watch from
    filing the same one again for that long (NULL = until unmuted)."""
    finding = await _get_finding(db, finding_id)
    if finding.state not in FINDING_ACTIVE_STATES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"This finding is already {finding.state}.",
        )
    before = _set_state(finding, FINDING_DISMISSED, current_user, body.note)
    muted_until: datetime | None = None
    if body.mute_days != 0:
        muted_until = (
            datetime.now(UTC) + timedelta(days=body.mute_days) if body.mute_days else None
        )
        mute = await db.scalar(
            select(AIFindingMute).where(AIFindingMute.fingerprint == finding.fingerprint)
        )
        if mute is None:
            mute = AIFindingMute(fingerprint=finding.fingerprint)
            db.add(mute)
        mute.until = muted_until
        mute.reason = body.note
        mute.title = finding.title
        mute.finding_id = finding.id
        mute.created_by_user_id = current_user.id
    write_audit(
        db,
        user=current_user,
        action="dismiss",
        resource_type=RESOURCE_FINDING,
        resource_id=str(finding.id),
        resource_display=finding.title,
        old_value=before,
        new_value={
            "state": finding.state,
            "note": body.note,
            "muted": body.mute_days != 0,
            "muted_until": muted_until.isoformat() if muted_until else None,
        },
    )
    response = await _one(db, finding, current_user)
    await db.commit()
    return response


@router.post("/findings/{finding_id}/reopen", response_model=FindingResponse)
async def reopen_finding(
    finding_id: uuid.UUID, db: DB, current_user: User = _FindingWriter
) -> FindingResponse:
    """Put an acknowledged or dismissed finding back to open. A dismissed
    one also loses its mute. A resolved finding cannot be reopened: its
    evidence cleared, and Watch files it again if the problem returns."""
    finding = await _get_finding(db, finding_id)
    if finding.state not in (FINDING_ACKNOWLEDGED, FINDING_DISMISSED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A finding that is {finding.state} cannot be reopened.",
        )
    if finding.state == FINDING_DISMISSED:
        clash = await db.scalar(
            select(AIFinding.id)
            .where(AIFinding.fingerprint == finding.fingerprint)
            .where(AIFinding.state.in_(FINDING_ACTIVE_STATES))
        )
        if clash is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Copilot Watch has already filed this finding again.",
            )
        await db.execute(
            delete(AIFindingMute).where(AIFindingMute.fingerprint == finding.fingerprint)
        )
    before = _set_state(finding, FINDING_OPEN, current_user, "")
    write_audit(
        db,
        user=current_user,
        action="reopen",
        resource_type=RESOURCE_FINDING,
        resource_id=str(finding.id),
        resource_display=finding.title,
        old_value=before,
        new_value={"state": finding.state},
    )
    response = await _one(db, finding, current_user)
    await db.commit()
    return response


@router.post("/findings/{finding_id}/feedback", response_model=FindingResponse)
async def leave_feedback(
    finding_id: uuid.UUID,
    body: FeedbackRequest,
    db: DB,
    current_user: User = _FindingWriter,
) -> FindingResponse:
    """Say whether a finding was useful. One verdict per user per finding;
    sending another replaces it."""
    finding = await _get_finding(db, finding_id)
    row = await db.scalar(
        select(AIFindingFeedback)
        .where(AIFindingFeedback.finding_id == finding.id)
        .where(AIFindingFeedback.user_id == current_user.id)
    )
    before = {"verdict": row.verdict} if row is not None else None
    if row is None:
        row = AIFindingFeedback(finding_id=finding.id, user_id=current_user.id)
        db.add(row)
    row.verdict = body.verdict
    row.note = body.note
    write_audit(
        db,
        user=current_user,
        action="feedback",
        resource_type=RESOURCE_FINDING,
        resource_id=str(finding.id),
        resource_display=finding.title,
        old_value=before,
        new_value={"verdict": body.verdict, "note": body.note},
    )
    await db.flush()
    await db.refresh(row)
    response = await _one(db, finding, current_user)
    await db.commit()
    return response


# ── Mutes ────────────────────────────────────────────────────────────────


@router.get("/mutes", response_model=list[MuteResponse], dependencies=[_FindingReader])
async def list_mutes(db: DB) -> list[MuteResponse]:
    rows = (
        (await db.execute(select(AIFindingMute).order_by(AIFindingMute.created_at.desc())))
        .scalars()
        .all()
    )
    return [MuteResponse.model_validate(r) for r in rows]


@router.delete("/mutes/{mute_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mute(mute_id: uuid.UUID, db: DB, current_user: User = _FindingWriter) -> None:
    mute = await db.get(AIFindingMute, mute_id)
    if mute is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mute not found")
    write_audit(
        db,
        user=current_user,
        action="delete",
        resource_type="ai_finding_mute",
        resource_id=str(mute.id),
        resource_display=mute.title or mute.fingerprint[:12],
        old_value={"fingerprint": mute.fingerprint, "until": str(mute.until)},
    )
    await db.delete(mute)
    await db.commit()


__all__ = ["router"]
