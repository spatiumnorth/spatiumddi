"""The Copilot Watch tick: triggers, guards and one run (issue #4405).

``tick`` is called once a minute by ``app.tasks.ai_watch`` under an
advisory lock, so at most one run is in flight across all workers. Each
tick:

1. closes findings whose evidence has cleared (no model involved);
2. decides whether a run is due: an operator asked (**manual**), an alert
   opened or got worse and the debounce has passed (**event**), or the
   sweep interval elapsed (**sweep**);
3. checks the guards. A run that a guard refuses is still recorded, as a
   ``skipped`` row with the reason: a skipped run is never silent;
4. runs: evidence pack -> bounded tool loop -> validated findings.

It reads the database. It does not hook the alert evaluator, so a slow
model can never delay alerting.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import structlog
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.denial_audit import note_denial_audited
from app.drivers.llm.base import ChatMessage, ToolDefinition
from app.models.ai_watch import (
    FINDING_ACTIVE_STATES,
    PAUSE_BUDGET,
    PAUSE_FAILURES,
    RUN_FAILED,
    RUN_OK,
    RUN_RUNNING,
    RUN_SKIPPED,
    TRIGGER_EVENT,
    TRIGGER_MANUAL,
    TRIGGER_SWEEP,
    WATCH_CONFIG_ID,
    AIFinding,
    AIWatchConfig,
    AIWatchRun,
)
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.pricing import compute_cost
from app.services.ai.tool_loop import HeadlessResult, run_headless
from app.services.ai.watch import budget as budget_svc
from app.services.ai.watch import evidence as ev
from app.services.ai.watch import findings as findings_svc
from app.services.ai.watch import prompt
from app.services.ai.watch.principal import (
    AUDIT_VIA,
    ensure_watch_principal,
    principal_problem,
)
from app.services.ai.watch.providers import resolve_provider_chain
from app.services.ai.watch.tools import tools_for_run
from app.tasks._interval_gate import interval_skip

logger = structlog.get_logger(__name__)

# Consecutive failed runs after which Watch pauses itself and waits for
# an operator. A provider that is down or a model that cannot produce the
# reply format would otherwise burn the budget one failed run at a time.
MAX_CONSECUTIVE_FAILURES = 3
# Runs are kept this long, transcripts included.
RUN_RETENTION = timedelta(days=30)
# Stored tool results are cut to this many characters each.
_TRANSCRIPT_TEXT_CAP = 8000


async def get_config(db: AsyncSession) -> AIWatchConfig:
    """The singleton settings row, created with its defaults on first use."""
    config = await db.get(AIWatchConfig, WATCH_CONFIG_ID)
    if config is None:
        config = AIWatchConfig(id=WATCH_CONFIG_ID)
        db.add(config)
        await db.flush()
        await db.refresh(config)
    return config


def _system_audit(action: str, display: str, new_value: dict[str, Any]) -> AuditLog:
    return AuditLog(
        user_id=None,
        user_display_name="<system>",
        auth_source="system",
        action=action,
        resource_type="ai_watch",
        resource_id=str(WATCH_CONFIG_ID),
        resource_display=display,
        new_value={**new_value, "via": AUDIT_VIA},
    )


def pause(config: AIWatchConfig, *, reason: str, detail: str, now: datetime) -> None:
    config.paused = True
    config.paused_reason = reason
    config.paused_detail = detail
    config.paused_at = now
    config.paused_until = budget_svc.next_utc_midnight(now) if reason == PAUSE_BUDGET else None


def resume(config: AIWatchConfig) -> None:
    config.paused = False
    config.paused_reason = None
    config.paused_detail = ""
    config.paused_at = None
    config.paused_until = None
    config.consecutive_failures = 0


def _alerts_changed(cursor: dict[str, str], current: dict[str, str]) -> bool:
    """A new open alert, or a known one whose severity got worse."""
    for event_id, severity in current.items():
        seen = cursor.get(event_id)
        if seen is None or ev.severity_rank(severity) < ev.severity_rank(seen):
            return True
    return False


async def _runs_last_hour(db: AsyncSession, now: datetime) -> int:
    return int(
        await db.scalar(
            select(func.count(AIWatchRun.id))
            .where(AIWatchRun.started_at >= now - timedelta(hours=1))
            .where(AIWatchRun.state.in_((RUN_OK, RUN_FAILED, RUN_RUNNING)))
        )
        or 0
    )


async def _record_skip(
    db: AsyncSession,
    *,
    trigger: str,
    reason: str,
    detail: str,
    now: datetime,
    requested_by: uuid.UUID | None,
) -> AIWatchRun:
    run = AIWatchRun(
        trigger=trigger,
        state=RUN_SKIPPED,
        skip_reason=reason,
        error=detail or None,
        started_at=now,
        finished_at=now,
        requested_by_user_id=requested_by,
    )
    db.add(run)
    await db.flush()
    # A skipped run is a refusal, not an HTTP 403; mark it audited so a
    # run-now request that also 403s never gets a second row (#3644).
    note_denial_audited()
    db.add(
        AuditLog(
            user_id=None,
            user_display_name="<system>",
            auth_source="system",
            action="run",
            resource_type="ai_watch_run",
            resource_id=str(run.id),
            resource_display=f"Copilot Watch run skipped: {reason}",
            result="denied",
            new_value={"trigger": trigger, "skip_reason": reason, "via": AUDIT_VIA},
        )
    )
    logger.info("ai_watch_run_skipped", trigger=trigger, reason=reason)
    return run


_SKIP_DETAIL = {
    "maintenance": "Maintenance mode is on.",
    "principal_disabled": "The copilot-watch service identity is disabled.",
    "principal_not_read_only": (
        "The Copilot Watch group holds a role that grants more than read. "
        "Watch runs only as a read-only identity."
    ),
    "no_provider": "No enabled AI provider is available to Copilot Watch.",
    "hosted_not_allowed": (
        "No enabled AI provider is marked on-prem, and hosted providers are not allowed."
    ),
    "rate_limited": "The runs-per-hour limit was reached.",
}


async def tick(db: AsyncSession, *, now: datetime | None = None) -> dict[str, Any]:
    """One pass of the trigger logic. Commits its own work."""
    now = now or datetime.now(UTC)
    config = await get_config(db)
    if not config.enabled:
        await db.commit()
        return {"status": "disabled"}

    # A budget pause lifts by itself when the day rolls over.
    if (
        config.paused
        and config.paused_reason == PAUSE_BUDGET
        and config.paused_until is not None
        and config.paused_until <= now
    ):
        resume(config)
        db.add(_system_audit("resume", "Copilot Watch resumed", {"reason": "budget reset"}))

    principal = await ensure_watch_principal(db)

    # This tick holds the lock, so a run still marked running belongs to
    # a worker that died.
    stale = (
        (await db.execute(select(AIWatchRun).where(AIWatchRun.state == RUN_RUNNING)))
        .scalars()
        .all()
    )
    for row in stale:
        row.state = RUN_FAILED
        row.error = "The worker stopped before the run finished."
        row.finished_at = now

    closed = await findings_svc.close_cleared(db, principal=principal, now=now)
    await db.execute(delete(AIWatchRun).where(AIWatchRun.started_at < now - RUN_RETENTION))
    await db.commit()

    if config.paused:
        return {"status": "paused", "reason": config.paused_reason, "findings_resolved": closed}

    # ── Is a run due? ────────────────────────────────────────────────
    current_alerts = await ev.open_alert_severities(db)
    if config.alert_cursor is None:
        # First look: record what is already open. The first sweep, due
        # at once, reviews it; from here on only changes count.
        config.alert_cursor = current_alerts
    elif config.event_trigger_enabled and _alerts_changed(config.alert_cursor, current_alerts):
        if config.event_pending_since is None:
            config.event_pending_since = now
    elif config.event_pending_since is None and config.alert_cursor != current_alerts:
        config.alert_cursor = current_alerts  # only resolutions: nothing to review

    sweep_due = (
        config.sweep_interval_hours > 0
        and interval_skip(now, config.last_sweep_at, timedelta(hours=config.sweep_interval_hours))
        is None
    )
    event_due = (
        config.event_trigger_enabled
        and config.event_pending_since is not None
        and now - config.event_pending_since >= timedelta(seconds=config.event_debounce_seconds)
    )
    if config.run_requested_at is not None:
        trigger = TRIGGER_MANUAL
    elif event_due:
        trigger = TRIGGER_EVENT
    elif sweep_due:
        trigger = TRIGGER_SWEEP
    else:
        await db.commit()
        return {"status": "idle", "findings_resolved": closed}

    # Whatever happens next, this trigger is spent: a run reviews
    # everything that is open, and a skip must not repeat every minute.
    requested_by = config.run_requested_by_user_id
    config.run_requested_at = None
    config.run_requested_by_user_id = None
    config.alert_cursor = current_alerts
    config.event_pending_since = None
    if sweep_due:
        config.last_sweep_at = now

    # ── Guards ───────────────────────────────────────────────────────
    skip: str | None = None
    detail = ""
    settings_row = await db.get(PlatformSettings, 1)
    chain: list[Any] = []
    if settings_row is not None and settings_row.maintenance_mode_enabled:
        skip = "maintenance"
    if skip is None:
        skip = principal_problem(principal)
    if skip is None:
        chain, skip = await resolve_provider_chain(db, config)
    usage = await budget_svc.usage_today(db, config, now)
    if skip is None and usage.exhausted is not None:
        skip = "budget_exhausted"
        detail = (
            f"The daily {usage.exhausted} budget is used up "
            f"({usage.tokens} of {usage.token_budget} tokens, "
            f"${usage.cost_usd} of ${usage.cost_budget_usd}). "
            "Copilot Watch is paused until 00:00 UTC."
        )
        pause(config, reason=PAUSE_BUDGET, detail=detail, now=now)
        db.add(_system_audit("pause", "Copilot Watch paused", {"reason": PAUSE_BUDGET}))
    if skip is None and await _runs_last_hour(db, now) >= config.max_runs_per_hour:
        skip = "rate_limited"

    if skip is not None:
        run = await _record_skip(
            db,
            trigger=trigger,
            reason=skip,
            detail=detail or _SKIP_DETAIL.get(skip, ""),
            now=now,
            requested_by=requested_by,
        )
        await db.commit()
        return {"status": "skipped", "reason": skip, "run_id": str(run.id)}

    run = await execute_run(
        db,
        config=config,
        principal=principal,
        chain=chain,
        trigger=trigger,
        now=now,
        requested_by=requested_by,
        tokens_remaining=usage.tokens_remaining,
    )
    return {"status": run.state, "run_id": str(run.id), "trigger": trigger}


def _clip_transcript(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for entry in entries:
        content = entry.get("content")
        if isinstance(content, str) and len(content) > _TRANSCRIPT_TEXT_CAP:
            entry = {**entry, "content": content[:_TRANSCRIPT_TEXT_CAP] + "…[cut]"}
        out.append(entry)
    return out


def _add_usage(run: AIWatchRun, result: HeadlessResult) -> None:
    run.tokens_in += result.tokens_in
    run.tokens_out += result.tokens_out
    run.rounds += result.rounds
    run.tool_calls += len(result.tool_calls)


async def execute_run(
    db: AsyncSession,
    *,
    config: AIWatchConfig,
    principal: User,
    chain: list[Any],
    trigger: str,
    now: datetime,
    requested_by: uuid.UUID | None,
    tokens_remaining: int,
) -> AIWatchRun:
    """One run, start to finish. Commits."""
    provider = chain[0]
    model = provider.default_model or ""
    run = AIWatchRun(
        trigger=trigger,
        state=RUN_RUNNING,
        provider_id=provider.id,
        provider_name=provider.name,
        model=model,
        started_at=now,
        requested_by_user_id=requested_by,
    )
    db.add(run)
    # Committed before the model is called, so the run shows as running
    # and no transaction is held open across the call.
    await db.commit()

    pack = await ev.build_evidence_pack(db, principal)
    run.evidence_count = len(pack.detector_items)
    transcript: list[dict[str, Any]] = [{"role": "evidence", "content": pack.for_model()}]
    usage_by_model: dict[str, tuple[int, int]] = {}
    drafts: list[findings_svc.FindingDraft] = []
    invalid = 0
    failure: str | None = None

    if not pack.detector_items:
        # Nothing any detector reports: no model call, no findings.
        transcript.append({"role": "info", "content": "No detector reports a problem."})
    else:
        tools = await tools_for_run(db, config=config, principal=principal, provider=provider)
        tool_defs = [
            ToolDefinition(name=t.name, description=t.description, parameters=t.parameters_schema())
            for t in tools
        ]
        open_findings = list(
            (
                await db.execute(
                    select(AIFinding)
                    .where(AIFinding.state.in_(FINDING_ACTIVE_STATES))
                    .order_by(AIFinding.first_seen_at)
                )
            )
            .scalars()
            .all()
        )
        messages = [
            ChatMessage(role="system", content=prompt.SYSTEM_PROMPT),
            ChatMessage(role="user", content=prompt.build_user_message(pack, open_findings)),
        ]
        token_cap = max(0, min(config.max_tokens_per_run, tokens_remaining))
        log_context = {"run_id": str(run.id)}
        result = await run_headless(
            db=db,
            user=principal,
            messages=messages,
            tools=tool_defs,
            chain=chain,
            model=model,
            max_rounds=config.max_rounds,
            max_tokens=token_cap,
            final_round_nudge=prompt.FINAL_ROUND_NUDGE,
            log_event_prefix="ai_watch",
            log_context=log_context,
        )
        results = [result]
        if result.status == "ok":
            try:
                drafts, invalid = findings_svc.parse_output(result.content)
            except findings_svc.OutputError as exc:
                failure = f"The model's reply could not be used: {exc}."
                spent = result.tokens_total
                if spent < token_cap:
                    # One more chance to produce the format, then give up.
                    messages.append(ChatMessage(role="user", content=prompt.REPAIR_MESSAGE))
                    retry = await run_headless(
                        db=db,
                        user=principal,
                        messages=messages,
                        tools=tool_defs,
                        chain=chain,
                        model=model,
                        max_rounds=1,
                        max_tokens=token_cap - spent,
                        log_event_prefix="ai_watch",
                        log_context=log_context,
                    )
                    results.append(retry)
                    if retry.status == "ok":
                        try:
                            drafts, invalid = findings_svc.parse_output(retry.content)
                            failure = None
                        except findings_svc.OutputError:
                            pass
        elif result.status == "error":
            failure = f"The AI provider failed: {result.error}"
        elif result.status == "token_cap":
            failure = "The run reached its token limit before the model answered."
        else:
            failure = (
                f"The model was still asking for tools after {config.max_rounds} rounds "
                "and gave no answer."
            )

        for res in results:
            _add_usage(run, res)
            transcript.extend(res.transcript)
            for name, (tin, tout) in res.usage_by_model.items():
                prev = usage_by_model.get(name, (0, 0))
                usage_by_model[name] = (prev[0] + tin, prev[1] + tout)
            if res.provider is not None:
                run.provider_id = res.provider.id
                run.provider_name = res.provider.name
                run.model = res.model
            # Every tool call is audited under the Watch identity.
            for tc in res.tool_calls:
                db.add(
                    AuditLog(
                        user_id=principal.id,
                        user_display_name=principal.display_name,
                        auth_source=principal.auth_source,
                        action="tool_call",
                        resource_type="ai_watch_run",
                        resource_id=str(run.id),
                        resource_display=tc["name"],
                        result="error" if tc["is_error"] else "success",
                        new_value={
                            "tool": tc["name"],
                            "arguments": tc["arguments"],
                            "via": AUDIT_VIA,
                        },
                    )
                )

    settings_row = await db.scalar(select(PlatformSettings))
    overrides = (settings_row.ai_pricing_overrides if settings_row else None) or None
    costs = [compute_cost(m, tin, tout, overrides) for m, (tin, tout) in usage_by_model.items()]
    known = [c for c in costs if c is not None]
    run.cost_usd = sum(known, Decimal("0")) if known else None

    if failure is None:
        applied = await findings_svc.apply_drafts(
            db, principal=principal, run=run, drafts=drafts, model=run.model, now=now
        )
        run.findings_opened = applied.opened
        run.findings_updated = applied.updated
        run.findings_dropped = applied.dropped + invalid
        run.findings_muted = applied.muted
        if applied.notes or invalid:
            transcript.append(
                {
                    "role": "validation",
                    "content": {"not_filed": applied.notes, "did_not_match_schema": invalid},
                }
            )
        run.findings_resolved = await findings_svc.close_cleared(db, principal=principal, now=now)
        run.state = RUN_OK
        config.consecutive_failures = 0
    else:
        run.state = RUN_FAILED
        run.error = failure
        config.consecutive_failures += 1
    run.transcript = _clip_transcript(transcript)
    run.finished_at = max(datetime.now(UTC), now)

    db.add(
        AuditLog(
            user_id=principal.id,
            user_display_name=principal.display_name,
            auth_source=principal.auth_source,
            action="run",
            resource_type="ai_watch_run",
            resource_id=str(run.id),
            resource_display=f"Copilot Watch {trigger} run",
            result="success" if failure is None else "error",
            error_detail=failure,
            new_value={
                "trigger": trigger,
                "state": run.state,
                "provider": run.provider_name,
                "model": run.model,
                "tokens_in": run.tokens_in,
                "tokens_out": run.tokens_out,
                "tool_calls": run.tool_calls,
                "findings_opened": run.findings_opened,
                "findings_updated": run.findings_updated,
                "findings_dropped": run.findings_dropped,
                "via": AUDIT_VIA,
            },
        )
    )

    if failure is not None and config.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
        pause(
            config,
            reason=PAUSE_FAILURES,
            detail=(
                f"{config.consecutive_failures} runs in a row failed. Last error: {failure} "
                "Resume Copilot Watch once the cause is fixed."
            ),
            now=now,
        )
        db.add(_system_audit("pause", "Copilot Watch paused", {"reason": PAUSE_FAILURES}))
    else:
        await db.flush()
        usage = await budget_svc.usage_today(db, config, now)
        if usage.exhausted is not None:
            pause(
                config,
                reason=PAUSE_BUDGET,
                detail=(
                    f"The daily {usage.exhausted} budget is used up "
                    f"({usage.tokens} of {usage.token_budget} tokens, "
                    f"${usage.cost_usd} of ${usage.cost_budget_usd}). "
                    "Copilot Watch is paused until 00:00 UTC."
                ),
                now=now,
            )
            db.add(_system_audit("pause", "Copilot Watch paused", {"reason": PAUSE_BUDGET}))

    await db.commit()
    logger.info(
        "ai_watch_run_finished",
        run_id=str(run.id),
        trigger=trigger,
        state=run.state,
        tokens_in=run.tokens_in,
        tokens_out=run.tokens_out,
        findings_opened=run.findings_opened,
        findings_updated=run.findings_updated,
        findings_dropped=run.findings_dropped,
    )
    return run


__all__ = [
    "MAX_CONSECUTIVE_FAILURES",
    "execute_run",
    "get_config",
    "pause",
    "resume",
    "tick",
]
