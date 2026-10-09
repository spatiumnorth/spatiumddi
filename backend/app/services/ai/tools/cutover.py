"""Operator Copilot tools for Windows → SpatiumDDI cutover plans (issue #756).

The importers (#128 / #129) get a Windows estate into native rows; the cutover
workflow is the rest of the journey (parity → parallel run → switch →
decommission). These four tools let the copilot answer the questions an
operator actually asks mid-migration — "what's left in the plan?", "why won't
corp.example cut over?", "is anything blocked?" — without them having to read
the Fleet-style UI.

Every tool carries ``module="migration.cutover"`` so turning the (default-on)
feature module off strips them from the AI surface as well as the REST surface
(non-negotiable #14).

**Superadmin on all four.** The REST surface is superadmin-only on every
endpoint — a cutover is strictly more dangerous than an import — and an MCP
tool has no router dependency to inherit that from, so each executor re-checks
in-tool. That is the same shape ``pairing`` / ``appliance`` use for their
superadmin-only REST surfaces, and the reason ``changes`` re-implements its
router's read rule in-tool.

**Why one of them is default-off.** ``find_cutover_plans`` /
``find_cutover_plan_status`` / ``count_cutover_blockers`` read persisted rows
and nothing else, so they ship enabled — an operator should discover them
without opting in. ``find_cutover_parity_check`` runs a **live pull from the
Windows source over WinRM using stored credentials**, exactly like
``find_dns_import_preview``, so it ships disabled per non-negotiable #13's
"off-prem calls default to disabled" rule and the operator opts in via
Settings → AI → Tool Catalog.

All four are reads. The parity tool deliberately does *not* persist its report
onto the item — that is a mutation, and it belongs to
``POST /api/v1/migration/cutover/plans/{pid}/items/{iid}/parity``.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.models.cutover import (
    ITEM_STAGES,
    PLAN_STATUSES,
    CutoverChecklistItem,
    CutoverItem,
    CutoverPlan,
)
from app.models.dhcp import DHCPScope, DHCPServer
from app.models.dns import DNSServer, DNSZone
from app.services.ai.tools.base import register_tool
from app.services.cutover.canonical import ParityReport
from app.services.cutover.parity import compute_dhcp_parity, compute_dns_parity

MODULE = "migration.cutover"

# Payload caps. A plan can legitimately carry hundreds of zones and a parity
# report thousands of differences; neither belongs in an LLM context window in
# full. Every truncation is flagged in the payload so the model can say so
# rather than silently under-reporting.
_MAX_ITEMS = 100
_MAX_DIFFERENCES = 25
_MAX_WARNINGS = 10
_MAX_BLOCKERS = 20
_MAX_BLOCKED_ITEMS = 100
#: Ceiling on the item rows ``count_cutover_blockers`` scans when it runs
#: across every plan.
_MAX_SCAN = 1000


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {"error": "Cutover tools are restricted to superadmin users."}
    return None


class _PlanLookupError(ValueError):
    """A plan could not be resolved from the supplied args.

    Carries an operator-readable message that each tool returns as
    ``{"error": …}`` rather than raising out to the MCP layer — "no plan called
    that" is an answer, not a failure.
    """


async def _resolve_plan(db: AsyncSession, *, plan_id: str | None, name: str | None) -> CutoverPlan:
    """Find a plan by id or by exact (case-insensitive) name."""
    if plan_id:
        try:
            pid = uuid.UUID(plan_id)
        except ValueError as exc:
            raise _PlanLookupError(f"plan_id must be a UUID, got {plan_id!r}.") from exc
        plan = await db.get(CutoverPlan, pid)
        if plan is None:
            raise _PlanLookupError(f"No cutover plan with id {plan_id}.")
        return plan
    if name:
        wanted = name.strip().lower()
        plan = (
            await db.execute(select(CutoverPlan).where(func.lower(CutoverPlan.name) == wanted))
        ).scalar_one_or_none()
        if plan is None:
            raise _PlanLookupError(
                f"No cutover plan named {name!r}. Use find_cutover_plans to list them."
            )
        return plan
    raise _PlanLookupError("Pass either plan_id or name to identify the cutover plan.")


def _blockers_of(item: CutoverItem) -> list[dict[str, Any]]:
    """``item.blockers`` as a list of well-formed dicts.

    The column is JSONB written by ``readiness.refresh_blockers``, so the shape
    is ours — but it is still free-form JSON at the DB level, and a malformed
    entry must not take out a whole rollup, so anything that is not a dict is
    dropped.
    """
    raw = item.blockers if isinstance(item.blockers, list) else []
    return [
        {
            "code": str(b.get("code") or ""),
            "severity": str(b.get("severity") or ""),
            "message": str(b.get("message") or ""),
        }
        for b in raw
        if isinstance(b, dict)
    ]


def _blocker_counts(blockers: list[dict[str, Any]]) -> tuple[int, int]:
    """``(blocking, warning)`` counts for one item's blocker list."""
    blocking = sum(1 for b in blockers if b["severity"] == "block")
    return blocking, len(blockers) - blocking


def _parity_summary(item: CutoverItem) -> dict[str, Any] | None:
    """The persisted parity report with its ``differences`` list stripped.

    The stored blob is a full ``ParityReport.as_dict()``; the per-difference
    detail is what ``find_cutover_parity_check`` is for. Here only the verdict
    and the counts travel, which keeps a 40-zone plan inside a context window.
    """
    stored = item.last_parity
    if not isinstance(stored, dict):
        return None
    return {
        "status": stored.get("status"),
        "error": stored.get("error"),
        "is_parity": stored.get("is_parity"),
        "in_sync": stored.get("in_sync"),
        "not_compared": stored.get("not_compared"),
        "difference_count": stored.get("difference_count"),
        "counts_by_class": stored.get("counts_by_class"),
        "at": item.last_parity_at.isoformat() if item.last_parity_at else None,
    }


def _shadow_summary(item: CutoverItem) -> dict[str, Any] | None:
    """Counts from the persisted shadow-comparison report, without the samples."""
    stored = item.last_shadow
    if not isinstance(stored, dict):
        return None
    return {
        "sample_source": stored.get("sample_source"),
        "sampled": stored.get("sampled"),
        "matched": stored.get("matched"),
        "mismatched": stored.get("mismatched"),
        "errors": stored.get("errors"),
        "at": item.last_shadow_at.isoformat() if item.last_shadow_at else None,
    }


def _ttl_summary(item: CutoverItem) -> dict[str, Any] | None:
    """Pre-flight TTL snapshot metadata — never the snapshot itself.

    The snapshot holds one entry per record in the zone, so returning it would
    blow the payload for exactly the large zones an operator is most likely to
    be asking about.
    """
    snapshot = item.ttl_snapshot
    if not isinstance(snapshot, dict):
        return None
    records = snapshot.get("records")
    return {
        "target_ttl": snapshot.get("target_ttl"),
        "taken_at": snapshot.get("taken_at"),
        "records_snapshotted": len(records) if isinstance(records, list) else None,
        "lowered_at": item.ttl_lowered_at.isoformat() if item.ttl_lowered_at else None,
    }


def _item_row(item: CutoverItem) -> dict[str, Any]:
    blockers = _blockers_of(item)
    blocking, warning = _blocker_counts(blockers)
    return {
        "item_id": str(item.id),
        "kind": item.kind,
        "source_ref": item.source_ref,
        "stage": item.stage,
        "zone_id": str(item.zone_id) if item.zone_id else None,
        "scope_id": str(item.scope_id) if item.scope_id else None,
        "blocking_count": blocking,
        "warning_count": warning,
        "blockers": blockers[:_MAX_BLOCKERS],
        "blockers_truncated": len(blockers) > _MAX_BLOCKERS,
        "parity": _parity_summary(item),
        "shadow": _shadow_summary(item),
        "ttl_preflight": _ttl_summary(item),
        "lease_handover": item.lease_handover if isinstance(item.lease_handover, dict) else None,
        "cut_over_at": item.cut_over_at.isoformat() if item.cut_over_at else None,
        "rolled_back_at": item.rolled_back_at.isoformat() if item.rolled_back_at else None,
        "notes": item.notes,
    }


def _plan_row(plan: CutoverPlan) -> dict[str, Any]:
    return {
        "id": str(plan.id),
        "name": plan.name,
        "description": plan.description,
        "status": plan.status,
        "source_dns_server_id": (
            str(plan.source_dns_server_id) if plan.source_dns_server_id else None
        ),
        "source_dhcp_server_id": (
            str(plan.source_dhcp_server_id) if plan.source_dhcp_server_id else None
        ),
        "target_dns_group_id": (
            str(plan.target_dns_group_id) if plan.target_dns_group_id else None
        ),
        "target_dhcp_group_id": (
            str(plan.target_dhcp_group_id) if plan.target_dhcp_group_id else None
        ),
        "notes": plan.notes,
        "created_at": plan.created_at.isoformat(),
        "completed_at": plan.completed_at.isoformat() if plan.completed_at else None,
        "rolled_back_at": plan.rolled_back_at.isoformat() if plan.rolled_back_at else None,
    }


def _empty_stage_rollup() -> dict[str, int]:
    return {stage: 0 for stage in sorted(ITEM_STAGES)}


# ── find_cutover_plans ───────────────────────────────────────────────


class FindCutoverPlansArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Case-insensitive substring match on the plan name or description.",
    )
    status: str | None = Field(
        default=None,
        description=(
            "Filter to one lifecycle status: draft / verifying / parallel / "
            "cutting_over / completed / rolled_back / abandoned. Omit for all."
        ),
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_cutover_plans",
    permission="superadmin",
    description=(
        "List Windows → SpatiumDDI cutover plans (superadmin only). Each row "
        "carries the plan's lifecycle status, its source Windows DNS / DHCP "
        "server ids, its target SpatiumDDI group ids, and a rollup of its "
        "items by stage (pending / parity_checked / preflight_done / "
        "cut_over / rolled_back) plus how many items currently have a "
        "blocking readiness problem. Use to answer 'what migrations are in "
        "flight?', 'is the corp.example cutover finished?', or to find a "
        "plan id for the other cutover tools. Read-only, DB-only."
    ),
    args_model=FindCutoverPlansArgs,
    category="ops",
    default_enabled=True,
    module=MODULE,
)
async def find_cutover_plans(
    db: AsyncSession, user: User, args: FindCutoverPlansArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    if args.status is not None and args.status not in PLAN_STATUSES:
        return {
            "error": (
                f"Unknown status {args.status!r}. Valid values: "
                f"{', '.join(sorted(PLAN_STATUSES))}."
            )
        }

    stmt = select(CutoverPlan).order_by(CutoverPlan.created_at.desc()).limit(args.limit)
    if args.status is not None:
        stmt = stmt.where(CutoverPlan.status == args.status)
    if args.search:
        needle = f"%{args.search.strip()}%"
        stmt = stmt.where(
            or_(CutoverPlan.name.ilike(needle), CutoverPlan.description.ilike(needle))
        )
    plans = list((await db.execute(stmt)).scalars().all())

    rollups: dict[uuid.UUID, dict[str, Any]] = {
        p.id: {"total": 0, "blocked": 0, "by_stage": _empty_stage_rollup()} for p in plans
    }
    if plans:
        item_rows = (
            await db.execute(
                select(CutoverItem.plan_id, CutoverItem.stage, CutoverItem.blockers).where(
                    CutoverItem.plan_id.in_([p.id for p in plans])
                )
            )
        ).all()
        for plan_id, stage, blockers in item_rows:
            rollup = rollups[plan_id]
            rollup["total"] += 1
            rollup["by_stage"][stage] = rollup["by_stage"].get(stage, 0) + 1
            if isinstance(blockers, list) and any(
                isinstance(b, dict) and b.get("severity") == "block" for b in blockers
            ):
                rollup["blocked"] += 1

    return {
        "plans": [{**_plan_row(p), "items": rollups[p.id]} for p in plans],
        "count": len(plans),
    }


# ── find_cutover_plan_status ─────────────────────────────────────────


class FindCutoverPlanStatusArgs(BaseModel):
    plan_id: str | None = Field(default=None, description="The plan's UUID.")
    name: str | None = Field(
        default=None,
        description="The plan's exact name (case-insensitive). Use instead of plan_id.",
    )
    kind: str | None = Field(
        default=None,
        description="Filter items to 'dns_zone' or 'dhcp_scope'. Omit for both.",
    )
    stage: str | None = Field(
        default=None,
        description=(
            "Filter items to one stage: pending / parity_checked / "
            "preflight_done / cut_over / rolled_back. Omit for all."
        ),
    )
    item_limit: int = Field(default=_MAX_ITEMS, ge=1, le=_MAX_ITEMS)


@register_tool(
    name="find_cutover_plan_status",
    permission="superadmin",
    description=(
        "Full status of one cutover plan (superadmin only) — the per-item "
        "detail behind find_cutover_plans. Identify the plan by plan_id or "
        "name. Returns each zone / scope item with its stage, its current "
        "readiness blockers (code + severity + the operator-facing fix), a "
        "summary of the last parity check and last shadow-query comparison, "
        "TTL pre-flight snapshot metadata, lease-handover counts, and "
        "cut-over / rollback timestamps, plus the decommission-checklist "
        "progress. Use to answer 'why can't this zone cut over?' or 'what "
        "stage is each scope at?'. Per-difference parity detail is NOT "
        "included here — that is find_cutover_parity_check. Read-only, "
        "DB-only (no Windows pull)."
    ),
    args_model=FindCutoverPlanStatusArgs,
    category="ops",
    default_enabled=True,
    module=MODULE,
)
async def find_cutover_plan_status(
    db: AsyncSession, user: User, args: FindCutoverPlanStatusArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    try:
        plan = await _resolve_plan(db, plan_id=args.plan_id, name=args.name)
    except _PlanLookupError as exc:
        return {"error": str(exc)}
    if args.stage is not None and args.stage not in ITEM_STAGES:
        return {
            "error": (
                f"Unknown stage {args.stage!r}. Valid values: {', '.join(sorted(ITEM_STAGES))}."
            )
        }

    stmt = (
        select(CutoverItem)
        .where(CutoverItem.plan_id == plan.id)
        .order_by(CutoverItem.kind, CutoverItem.source_ref)
    )
    if args.kind is not None:
        stmt = stmt.where(CutoverItem.kind == args.kind)
    if args.stage is not None:
        stmt = stmt.where(CutoverItem.stage == args.stage)
    items = list((await db.execute(stmt)).scalars().all())

    by_stage = _empty_stage_rollup()
    blocked = 0
    warned = 0
    for item in items:
        by_stage[item.stage] = by_stage.get(item.stage, 0) + 1
        blocking, warning = _blocker_counts(_blockers_of(item))
        if blocking:
            blocked += 1
        if warning:
            warned += 1

    checklist_rows = (
        await db.execute(
            select(CutoverChecklistItem.is_done, func.count())
            .where(CutoverChecklistItem.plan_id == plan.id)
            .group_by(CutoverChecklistItem.is_done)
        )
    ).all()
    checklist_done = 0
    checklist_total = 0
    for is_done, count in checklist_rows:
        checklist_total += count
        if is_done:
            checklist_done += count

    return {
        "plan": _plan_row(plan),
        "summary": {
            "items_total": len(items),
            "items_blocked": blocked,
            "items_with_warnings": warned,
            "by_stage": by_stage,
        },
        "checklist": {
            "done": checklist_done,
            "total": checklist_total,
            # 0 items means the checklist has never been read (it seeds
            # lazily on the first GET of the plan's checklist), not that
            # there is nothing to do.
            "seeded": checklist_total > 0,
        },
        "items": [_item_row(i) for i in items[: args.item_limit]],
        "items_truncated": len(items) > args.item_limit,
    }


# ── count_cutover_blockers ───────────────────────────────────────────


class CountCutoverBlockersArgs(BaseModel):
    plan_id: str | None = Field(
        default=None,
        description="Restrict to one plan by UUID. Omit (and omit name) to count across all plans.",
    )
    name: str | None = Field(
        default=None,
        description="Restrict to one plan by exact name (case-insensitive).",
    )
    severity: str | None = Field(
        default=None,
        description=(
            "Filter the code rollup to 'block' (refuses the cutover outright) "
            "or 'warn' (acknowledgeable). Omit for both."
        ),
    )


@register_tool(
    name="count_cutover_blockers",
    permission="superadmin",
    description=(
        "Roll up cutover readiness blockers (superadmin only) — across every "
        "plan, or one plan identified by plan_id / name. Returns how many "
        "items are blocked outright versus merely warned, a per-code "
        "breakdown (ad_secure_dynamic_update, no_target_zone, "
        "managed_scope_active, parity_not_verified, …), and the blocked "
        "items themselves. The blocker set is whatever the last readiness "
        "evaluation persisted, so re-run a parity check if it looks stale. "
        "Use to answer 'is anything blocking the migration?' or 'how many "
        "zones are stuck on secure dynamic updates?'. Read-only, DB-only."
    ),
    args_model=CountCutoverBlockersArgs,
    category="ops",
    default_enabled=True,
    module=MODULE,
)
async def count_cutover_blockers(
    db: AsyncSession, user: User, args: CountCutoverBlockersArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    if args.severity is not None and args.severity not in {"block", "warn"}:
        return {"error": f"severity must be 'block' or 'warn', got {args.severity!r}."}

    plan: CutoverPlan | None = None
    if args.plan_id or args.name:
        try:
            plan = await _resolve_plan(db, plan_id=args.plan_id, name=args.name)
        except _PlanLookupError as exc:
            return {"error": str(exc)}

    stmt = select(CutoverItem).order_by(CutoverItem.plan_id, CutoverItem.source_ref)
    if plan is not None:
        stmt = stmt.where(CutoverItem.plan_id == plan.id)
    # +1 so the payload can honestly say the scan hit its ceiling.
    items = list((await db.execute(stmt.limit(_MAX_SCAN + 1))).scalars().all())
    truncated = len(items) > _MAX_SCAN
    items = items[:_MAX_SCAN]

    plan_names: dict[uuid.UUID, str] = {}
    if plan is not None:
        plan_names[plan.id] = plan.name
    elif items:
        plan_names = {
            pid: pname
            for pid, pname in (
                await db.execute(
                    select(CutoverPlan.id, CutoverPlan.name).where(
                        CutoverPlan.id.in_({i.plan_id for i in items})
                    )
                )
            ).all()
        }

    by_code: dict[str, dict[str, Any]] = {}
    blocked_items: list[dict[str, Any]] = []
    items_blocked = 0
    items_warned = 0

    for item in items:
        blockers = _blockers_of(item)
        blocking, warning = _blocker_counts(blockers)
        if blocking:
            items_blocked += 1
        if warning:
            items_warned += 1
        for blocker in blockers:
            if args.severity is not None and blocker["severity"] != args.severity:
                continue
            entry = by_code.setdefault(
                blocker["code"],
                {"code": blocker["code"], "severity": blocker["severity"], "items": 0},
            )
            entry["items"] += 1
        if blocking and len(blocked_items) < _MAX_BLOCKED_ITEMS:
            blocked_items.append(
                {
                    "plan_id": str(item.plan_id),
                    "plan_name": plan_names.get(item.plan_id, ""),
                    **_item_row(item),
                }
            )

    return {
        "scope": {
            "plan_id": str(plan.id) if plan is not None else None,
            "plan_name": plan.name if plan is not None else None,
        },
        "items_scanned": len(items),
        "items_blocked": items_blocked,
        "items_with_warnings": items_warned,
        "by_code": sorted(by_code.values(), key=lambda e: (-e["items"], e["code"])),
        "blocked_items": blocked_items,
        "blocked_items_truncated": items_blocked > len(blocked_items),
        "scan_truncated": truncated,
    }


# ── find_cutover_parity_check ────────────────────────────────────────


class FindCutoverParityCheckArgs(BaseModel):
    plan_id: str | None = Field(default=None, description="The plan's UUID.")
    name: str | None = Field(
        default=None,
        description="The plan's exact name (case-insensitive). Use instead of plan_id.",
    )
    item_id: str | None = Field(
        default=None,
        description="Check exactly one item by its UUID (from find_cutover_plan_status).",
    )
    source_ref: str | None = Field(
        default=None,
        description=(
            "Check the item whose Windows-side reference matches — a zone name "
            "without its trailing dot, or a DHCP scope id (its network address)."
        ),
    )
    max_items: int = Field(
        default=5,
        ge=1,
        le=25,
        description=(
            "Ceiling on how many items to check when neither item_id nor "
            "source_ref is given. Each item is one live pull from the Windows "
            "server, so keep this small."
        ),
    )


def _trim_report(report: ParityReport) -> dict[str, Any]:
    """``ParityReport.as_dict()`` with its unbounded lists capped."""
    data = report.as_dict()
    differences = data["differences"]
    warnings = data["warnings"]
    data["differences"] = differences[:_MAX_DIFFERENCES]
    data["differences_truncated"] = len(differences) > _MAX_DIFFERENCES
    data["warnings"] = warnings[:_MAX_WARNINGS]
    return data


async def _parity_for_item(
    db: AsyncSession,
    *,
    item: CutoverItem,
    dns_source: DNSServer | None,
    dhcp_source: DHCPServer | None,
) -> dict[str, Any]:
    """Run one item's parity check, or explain why it could not run.

    Both ``compute_*_parity`` helpers already turn a driver / WinRM failure
    into ``status="error"`` on the report, so nothing here needs a catch-all —
    what this function handles is the item being unrunnable in the first place
    (no source server configured on the plan, or the SpatiumDDI-side row gone).
    """
    head: dict[str, Any] = {
        "item_id": str(item.id),
        "kind": item.kind,
        "source_ref": item.source_ref,
        "stage": item.stage,
    }

    if item.kind == "dns_zone":
        if dns_source is None:
            return {
                **head,
                "status": "error",
                "error": (
                    "The plan has no source Windows DNS server set (or it has been "
                    "deleted), so there is nothing to compare against."
                ),
            }
        zone: DNSZone | None = None
        if item.zone_id is not None:
            zone = (
                await db.execute(select(DNSZone).where(DNSZone.id == item.zone_id))
            ).scalar_one_or_none()
        if zone is None:
            return {
                **head,
                "status": "error",
                "error": (
                    "This item is not linked to a live SpatiumDDI zone (never matched, "
                    "or the zone was deleted). Re-run Discover on the plan."
                ),
            }
        report = await compute_dns_parity(
            db, source_server=dns_source, zone=zone, source_zone_name=item.source_ref
        )
        return {**head, "zone_id": str(zone.id), "zone_name": zone.name, **_trim_report(report)}

    if item.kind == "dhcp_scope":
        if dhcp_source is None:
            return {
                **head,
                "status": "error",
                "error": (
                    "The plan has no source Windows DHCP server set (or it has been "
                    "deleted), so there is nothing to compare against."
                ),
            }
        scope: DHCPScope | None = None
        if item.scope_id is not None:
            scope = (
                await db.execute(select(DHCPScope).where(DHCPScope.id == item.scope_id))
            ).scalar_one_or_none()
        if scope is None:
            return {
                **head,
                "status": "error",
                "error": (
                    "This item is not linked to a live SpatiumDDI scope (never matched, "
                    "or the scope was deleted). Re-run Discover on the plan."
                ),
            }
        report = await compute_dhcp_parity(
            db, source_server=dhcp_source, scope=scope, source_scope_id=item.source_ref
        )
        return {**head, "scope_id": str(scope.id), "scope_name": scope.name, **_trim_report(report)}

    return {**head, "status": "error", "error": f"Unsupported cutover item kind {item.kind!r}."}


@register_tool(
    name="find_cutover_parity_check",
    permission="superadmin",
    description=(
        "Run a LIVE parity check for cutover plan items (superadmin only; "
        "makes an off-prem WinRM pull from the source Windows server). "
        "Identify the plan by plan_id or name, then optionally one item by "
        "item_id or source_ref — otherwise up to max_items are checked. For "
        "a DNS zone it diffs the records Windows is serving right now "
        "against the SpatiumDDI zone; for a DHCP scope it diffs lease time, "
        "activation, pools, reservations, and options. Each difference is "
        "classified: value_mismatch / drifted_since_import / never_imported "
        "/ intentionally_diverged. Use before a cutover to answer 'is this "
        "zone actually in sync?'. Nothing is persisted — the plan item's "
        "stored report is only updated by the REST parity endpoint."
    ),
    args_model=FindCutoverParityCheckArgs,
    category="ops",
    default_enabled=False,
    module=MODULE,
)
async def find_cutover_parity_check(
    db: AsyncSession, user: User, args: FindCutoverParityCheckArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    try:
        plan = await _resolve_plan(db, plan_id=args.plan_id, name=args.name)
    except _PlanLookupError as exc:
        return {"error": str(exc)}

    stmt = (
        select(CutoverItem)
        .where(CutoverItem.plan_id == plan.id)
        .order_by(CutoverItem.kind, CutoverItem.source_ref)
    )
    if args.item_id:
        try:
            iid = uuid.UUID(args.item_id)
        except ValueError:
            return {"error": f"item_id must be a UUID, got {args.item_id!r}."}
        stmt = stmt.where(CutoverItem.id == iid)
    elif args.source_ref:
        stmt = stmt.where(func.lower(CutoverItem.source_ref) == args.source_ref.strip().lower())
    else:
        # Each item is a separate WinRM round trip, so a whole-plan run is
        # capped rather than fanned out over everything.
        stmt = stmt.limit(args.max_items)
    items = list((await db.execute(stmt)).scalars().all())
    if not items:
        return {
            "error": (
                f"No matching items in plan {plan.name!r}. Use find_cutover_plan_status "
                "to list them."
            )
        }

    dns_source: DNSServer | None = None
    if plan.source_dns_server_id is not None and any(i.kind == "dns_zone" for i in items):
        dns_source = (
            await db.execute(select(DNSServer).where(DNSServer.id == plan.source_dns_server_id))
        ).scalar_one_or_none()
    dhcp_source: DHCPServer | None = None
    if plan.source_dhcp_server_id is not None and any(i.kind == "dhcp_scope" for i in items):
        dhcp_source = (
            await db.execute(select(DHCPServer).where(DHCPServer.id == plan.source_dhcp_server_id))
        ).scalar_one_or_none()

    # Sequential on purpose, and there is no concurrent path anywhere: one
    # AsyncSession cannot serve concurrent operations, so the REST fan-out in
    # ``api/v1/cutover/router.py`` is a plain loop for the same reason (see the
    # session note at the top of ``services/cutover/parity.py``). This is also a
    # pull against one operator's production Windows box, which is not somewhere
    # an LLM-triggered fan-out belongs.
    reports = [
        await _parity_for_item(db, item=item, dns_source=dns_source, dhcp_source=dhcp_source)
        for item in items
    ]

    return {
        "plan_id": str(plan.id),
        "plan_name": plan.name,
        "checked": len(reports),
        "in_parity": sum(1 for r in reports if r.get("is_parity") is True),
        "reports": reports,
    }
