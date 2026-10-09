"""Operator Copilot read tools for the conformity surface (#105/#106).

Surfaces the declarative ``ConformityPolicy`` registry + the
append-only ``ConformityResult`` history so the Copilot can answer
"are we PCI-clean?", "which subnets fail the HIPAA policies?",
"when was this policy last evaluated?". No write tools here — the
``propose_*_conformity_policy`` shells live in ``proposals.py``
next to the other ``propose_*`` write proposals, default-disabled
per CLAUDE.md non-negotiable #13 (writes against compliance config
have broad blast radius — flipping a single policy from
warning → critical changes alert wiring across the fleet).

Issue #280 — catch-up to MCP coverage parity with the REST surface.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import Integer, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.conformity import ConformityPolicy, ConformityResult
from app.services.ai.tools.base import register_tool


class ListConformityPoliciesArgs(BaseModel):
    framework: str | None = Field(
        default=None,
        description="Filter to one framework (``PCI-DSS 4.0``, ``HIPAA``, ``SOC2``, ``custom``, …).",
    )
    enabled: bool | None = Field(
        default=None,
        description="True = only enabled, False = only disabled, omitted = both.",
    )
    target_kind: str | None = Field(
        default=None,
        description="Filter to one target kind (``subnet`` / ``ip_address`` / ``dns_zone`` / ``dhcp_scope`` / ``multicast_group`` / ``platform``).",
    )
    limit: int = Field(default=200, ge=1, le=500)


@register_tool(
    name="list_conformity_policies",
    permission=("read", "conformity"),
    description=(
        "List declarative conformity policies. Each policy carries a "
        "framework label (PCI-DSS / HIPAA / NIST / SOC2 / custom), "
        "reference (control id within the framework), severity, "
        "target_kind (what the predicate runs against), check_kind "
        "(the named evaluator), eval_interval_hours, and the "
        "last_evaluated_at timestamp. Operator uses this to answer "
        "'which PCI policies do we have?' or 'list all disabled "
        "compliance policies'. Read-only."
    ),
    args_model=ListConformityPoliciesArgs,
    category="compliance",
    module="compliance.conformity",
)
async def list_conformity_policies(
    db: AsyncSession, user: User, args: ListConformityPoliciesArgs
) -> list[dict[str, Any]]:
    stmt = select(ConformityPolicy)
    if args.framework:
        stmt = stmt.where(ConformityPolicy.framework == args.framework)
    if args.enabled is not None:
        stmt = stmt.where(ConformityPolicy.enabled.is_(args.enabled))
    if args.target_kind:
        stmt = stmt.where(ConformityPolicy.target_kind == args.target_kind)
    stmt = stmt.order_by(ConformityPolicy.framework.asc(), ConformityPolicy.name.asc()).limit(
        args.limit
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "description": p.description,
            "framework": p.framework,
            "reference": p.reference,
            "severity": p.severity,
            "target_kind": p.target_kind,
            "check_kind": p.check_kind,
            "is_builtin": p.is_builtin,
            "enabled": p.enabled,
            "eval_interval_hours": p.eval_interval_hours,
            "last_evaluated_at": (p.last_evaluated_at.isoformat() if p.last_evaluated_at else None),
        }
        for p in rows
    ]


class FindConformityResultsArgs(BaseModel):
    policy_id: uuid.UUID | None = Field(
        default=None,
        description="Restrict to results for one policy. UUID of the conformity_policy row.",
    )
    status: str | None = Field(
        default=None,
        description="Filter by status: ``pass`` / ``fail`` / ``warn`` / ``not_applicable``.",
    )
    resource_kind: str | None = Field(
        default=None,
        description="Filter by resource kind (``subnet`` / ``ip_address`` / ``platform`` / …).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_conformity_results",
    permission=("read", "conformity"),
    description=(
        "List recent conformity evaluation results — append-only "
        "history of every (policy × resource × pass). Operator uses "
        "this to answer 'which PCI subnets are failing right now?' "
        "or 'show every failure in the last 24h'. Most recent first. "
        "Read-only."
    ),
    args_model=FindConformityResultsArgs,
    category="compliance",
    module="compliance.conformity",
)
async def find_conformity_results(
    db: AsyncSession, user: User, args: FindConformityResultsArgs
) -> list[dict[str, Any]]:
    stmt = select(ConformityResult)
    if args.policy_id:
        stmt = stmt.where(ConformityResult.policy_id == args.policy_id)
    if args.status:
        stmt = stmt.where(ConformityResult.status == args.status)
    if args.resource_kind:
        stmt = stmt.where(ConformityResult.resource_kind == args.resource_kind)
    stmt = stmt.order_by(ConformityResult.evaluated_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "policy_id": str(r.policy_id),
            "resource_kind": r.resource_kind,
            "resource_id": r.resource_id,
            "resource_display": r.resource_display,
            "evaluated_at": r.evaluated_at.isoformat(),
            "status": r.status,
            "detail": r.detail,
            "diagnostic": r.diagnostic,
        }
        for r in rows
    ]


class GetConformitySummaryArgs(BaseModel):
    framework: str | None = Field(
        default=None,
        description="Optional — narrow the summary to one framework (PCI-DSS, HIPAA, …).",
    )


@register_tool(
    name="get_conformity_summary",
    permission=("read", "conformity"),
    description=(
        "Per-framework rollup of policy + result counts. Returns a "
        "list of ``{framework, policy_count, enabled_count, "
        "pass_count, fail_count, warn_count, not_applicable_count}``. "
        "Counts EVERY ``conformity_result`` row by status — the "
        "evaluator overwrites results per pass via UPSERT keyed on "
        "(policy × resource), so the trailing-edge of a given "
        "eval-interval window is what these counts reflect. Useful "
        "for 'roughly how do we look against PCI?' rollups. For "
        "point-in-time precise per-resource status, query "
        "``find_conformity_results`` directly. Read-only."
    ),
    args_model=GetConformitySummaryArgs,
    category="compliance",
    module="compliance.conformity",
)
async def get_conformity_summary(
    db: AsyncSession, user: User, args: GetConformitySummaryArgs
) -> list[dict[str, Any]]:
    pol_stmt = select(
        ConformityPolicy.framework.label("framework"),
        func.count(ConformityPolicy.id).label("policy_count"),
        # Conditional sum — count rows with enabled=True. ``func.sum(bool)``
        # works on Postgres but mypy + Sqlalchemy prefer an explicit CASE
        # mapping to a known integer type.
        func.sum(case((ConformityPolicy.enabled.is_(True), 1), else_=0))
        .cast(Integer)
        .label("enabled_count"),
    ).group_by(ConformityPolicy.framework)
    if args.framework:
        pol_stmt = pol_stmt.where(ConformityPolicy.framework == args.framework)
    pol_rows = (await db.execute(pol_stmt)).all()

    # Latest result per (policy, resource) pair via a windowed
    # max(evaluated_at) join would be ideal; for the rollup shape we
    # just count every result-by-status grouped by framework. The
    # append-only nature of ``conformity_result`` means stale rows
    # exist, but the periodic eval task overwrites with each new
    # pass so the per-resource trailing edge dominates within an
    # eval-interval window.
    res_stmt = (
        select(
            ConformityPolicy.framework.label("framework"),
            ConformityResult.status.label("status"),
            # ``.count`` would shadow the Row.count() method; ``n``
            # keeps mypy + SQLAlchemy Row attribute access clean.
            func.count(ConformityResult.id).label("n"),
        )
        .join(ConformityPolicy, ConformityPolicy.id == ConformityResult.policy_id)
        .group_by(ConformityPolicy.framework, ConformityResult.status)
    )
    if args.framework:
        res_stmt = res_stmt.where(ConformityPolicy.framework == args.framework)
    res_rows = (await db.execute(res_stmt)).all()

    by_fw: dict[str, dict[str, Any]] = {}
    for row in pol_rows:
        by_fw[row.framework] = {
            "framework": row.framework,
            "policy_count": int(row.policy_count or 0),
            "enabled_count": int(row.enabled_count or 0),
            "pass_count": 0,
            "fail_count": 0,
            "warn_count": 0,
            "not_applicable_count": 0,
        }
    for row in res_rows:
        bucket = by_fw.setdefault(
            row.framework,
            {
                "framework": row.framework,
                "policy_count": 0,
                "enabled_count": 0,
                "pass_count": 0,
                "fail_count": 0,
                "warn_count": 0,
                "not_applicable_count": 0,
            },
        )
        key = f"{row.status}_count"
        if key in bucket:
            bucket[key] = int(row.n or 0)
    return sorted(by_fw.values(), key=lambda b: b["framework"])
