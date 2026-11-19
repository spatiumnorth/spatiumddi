"""Operator Copilot read tools for Copilot Watch (issue #4405).

Four read tools over what Watch has filed: ``find_ai_findings``,
``count_ai_findings``, ``get_ai_finding`` and ``find_ai_watch_runs``.
They need ``read`` on ``ai_finding``, the same grant the Findings inbox
needs, and a holder sees every finding. Enabled by default (#13): they
read rows Watch already wrote and send nothing anywhere.

No ``propose_*`` tool, by decision: Watch observes and advises, and
triaging a finding (acknowledge, dismiss, feedback) is a person's
judgement recorded under their own name on the Findings page.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_watch import (
    FINDING_ACTIVE_STATES,
    FINDING_KINDS,
    FINDING_SEVERITIES,
    FINDING_STATES,
    WATCH_RUN_STATES,
    AIFinding,
    AIWatchRun,
)
from app.models.auth import User
from app.services.ai.tools.base import register_tool

_PERMISSION = ("read", "ai_finding")
_MODULE = "ai.watch"


def _finding_row(f: AIFinding, *, full: bool) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": str(f.id),
        "kind": f.kind,
        "severity": f.severity,
        "state": f.state,
        "title": f.title,
        "confidence": f.confidence,
        "first_seen_at": f.first_seen_at.isoformat(),
        "last_seen_at": f.last_seen_at.isoformat(),
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "evidence_count": len(f.evidence or []),
    }
    if full:
        row["explanation"] = f.explanation
        row["recommendations"] = list(f.recommendations or [])
        row["evidence"] = [
            {
                "ref": e.get("ref"),
                "subject": e.get("subject"),
                "what": e.get("display"),
                "severity": e.get("severity"),
                "cleared": bool(e.get("cleared")),
            }
            for e in (f.evidence or [])
        ]
        row["model"] = f.model
        row["state_note"] = f.state_note
        row["run_id"] = str(f.run_id) if f.run_id else None
    return row


class FindAIFindingsArgs(BaseModel):
    state: str = Field(
        default="active",
        description=(
            "``active`` (open + acknowledged, the default), ``all``, or one of "
            + " / ".join(FINDING_STATES)
            + "."
        ),
    )
    severity: str | None = Field(
        default=None, description="One of " + " / ".join(FINDING_SEVERITIES) + "."
    )
    kind: str | None = Field(default=None, description="One of " + " / ".join(FINDING_KINDS) + ".")
    search: str | None = Field(
        default=None, description="Substring to match in the title or the explanation."
    )
    limit: int = Field(default=25, ge=1, le=200)


def _filter(stmt: Any, args: FindAIFindingsArgs) -> Any:
    if args.state == "active":
        stmt = stmt.where(AIFinding.state.in_(FINDING_ACTIVE_STATES))
    elif args.state != "all":
        stmt = stmt.where(AIFinding.state == args.state)
    if args.severity:
        stmt = stmt.where(AIFinding.severity == args.severity)
    if args.kind:
        stmt = stmt.where(AIFinding.kind == args.kind)
    if args.search:
        like = f"%{args.search}%"
        stmt = stmt.where(or_(AIFinding.title.ilike(like), AIFinding.explanation.ilike(like)))
    return stmt


@register_tool(
    name="find_ai_findings",
    permission=_PERMISSION,
    description=(
        "List the findings Copilot Watch has filed: problems it grouped and "
        "explained from open alerts, failing conformity checks, unhealthy "
        "servers and agents that rejected their configuration. Each has a "
        "severity, a kind, a state (open / acknowledged / dismissed / "
        "resolved) and a one-line title. Use for 'what has Watch found?', "
        "'any critical findings?', 'what did Watch say about the DHCP "
        "outage?'. Newest activity first. Call get_ai_finding with an id for "
        "the explanation, the evidence and the recommended next steps."
    ),
    args_model=FindAIFindingsArgs,
    category="ops",
    module=_MODULE,
)
async def find_ai_findings(
    db: AsyncSession, user: User, args: FindAIFindingsArgs
) -> list[dict[str, Any]]:
    stmt = _filter(select(AIFinding), args).order_by(AIFinding.last_seen_at.desc())
    rows = (await db.execute(stmt.limit(args.limit))).scalars().all()
    return [_finding_row(f, full=False) for f in rows]


class CountAIFindingsArgs(BaseModel):
    """No arguments."""


@register_tool(
    name="count_ai_findings",
    permission=_PERMISSION,
    description=(
        "Count Copilot Watch findings by state and, for the open ones, by "
        "severity. Use for 'how many findings are open?' before listing them."
    ),
    args_model=CountAIFindingsArgs,
    category="ops",
    module=_MODULE,
)
async def count_ai_findings(
    db: AsyncSession, user: User, args: CountAIFindingsArgs
) -> dict[str, Any]:
    rows = (
        await db.execute(
            select(AIFinding.state, AIFinding.severity, func.count(AIFinding.id)).group_by(
                AIFinding.state, AIFinding.severity
            )
        )
    ).all()
    by_state: dict[str, int] = {}
    open_by_severity: dict[str, int] = {}
    for state, severity, n in rows:
        by_state[state] = by_state.get(state, 0) + int(n)
        if state == "open":
            open_by_severity[severity] = int(n)
    return {
        "total": sum(by_state.values()),
        "by_state": by_state,
        "open_by_severity": open_by_severity,
    }


class GetAIFindingArgs(BaseModel):
    id: str = Field(description="UUID of the finding, from find_ai_findings.")


@register_tool(
    name="get_ai_finding",
    permission=_PERMISSION,
    description=(
        "Return one Copilot Watch finding in full: the explanation, the "
        "evidence it rests on (alert, conformity, server and agent "
        "references, each marked cleared or not), the recommended next "
        "steps, the model that wrote it and its triage state. The text was "
        "written by a model from the evidence; treat it as advice, and the "
        "evidence as the facts."
    ),
    args_model=GetAIFindingArgs,
    category="ops",
    module=_MODULE,
)
async def get_ai_finding(db: AsyncSession, user: User, args: GetAIFindingArgs) -> dict[str, Any]:
    try:
        finding_id = uuid.UUID(args.id)
    except ValueError:
        return {"error": f"{args.id!r} is not a finding id"}
    finding = await db.get(AIFinding, finding_id)
    if finding is None:
        return {"error": "finding not found"}
    return _finding_row(finding, full=True)


class FindAIWatchRunsArgs(BaseModel):
    state: str | None = Field(
        default=None, description="One of " + " / ".join(WATCH_RUN_STATES) + "."
    )
    limit: int = Field(default=20, ge=1, le=100)


@register_tool(
    name="find_ai_watch_runs",
    permission=_PERMISSION,
    description=(
        "List recent Copilot Watch runs, newest first: what triggered each "
        "(manual / event / sweep), whether it ran, failed or was skipped and "
        "why (budget_exhausted, no_provider, hosted_not_allowed, "
        "rate_limited, maintenance ...), the provider and model, tokens and "
        "cost, and how many findings it opened, updated, resolved or dropped "
        "for citing no real evidence. Use for 'is Watch running?', 'why did "
        "Watch stop?', 'how much has Watch spent?'."
    ),
    args_model=FindAIWatchRunsArgs,
    category="ops",
    module=_MODULE,
)
async def find_ai_watch_runs(
    db: AsyncSession, user: User, args: FindAIWatchRunsArgs
) -> list[dict[str, Any]]:
    stmt = select(AIWatchRun)
    if args.state:
        stmt = stmt.where(AIWatchRun.state == args.state)
    rows = (
        (await db.execute(stmt.order_by(AIWatchRun.started_at.desc()).limit(args.limit)))
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "trigger": r.trigger,
            "state": r.state,
            "skip_reason": r.skip_reason,
            "error": r.error,
            "provider": r.provider_name,
            "model": r.model,
            "tokens_in": r.tokens_in,
            "tokens_out": r.tokens_out,
            "cost_usd": str(r.cost_usd) if r.cost_usd is not None else None,
            "tool_calls": r.tool_calls,
            "evidence_count": r.evidence_count,
            "findings_opened": r.findings_opened,
            "findings_updated": r.findings_updated,
            "findings_resolved": r.findings_resolved,
            "findings_dropped": r.findings_dropped,
            "findings_muted": r.findings_muted,
            "started_at": r.started_at.isoformat(),
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        }
        for r in rows
    ]
