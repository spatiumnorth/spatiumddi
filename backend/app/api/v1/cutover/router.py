"""Windows → SpatiumDDI cutover REST surface (issue #756).

Every handler here is transport, authorization, audit, and the timeline row —
the workflow itself lives in :mod:`app.services.cutover`. Three conventions run
through the whole file:

**Superadmin on every route.** The same posture as the three importers this
extends (``docs/features/MIGRATION.md``, RBAC row). A cutover is strictly more
dangerous than an import: it deactivates a live DHCP scope, rewrites TTLs on a
production zone, and mints reservations. Delegating that with a grantable
permission is a decision worth making deliberately later, not a side effect of
shipping the surface.

**Every mutation writes an ``AuditLog`` row before the response** (non-negotiable
#4), plus a :class:`~app.models.cutover.CutoverEvent` so the plan keeps an
ordered, human-readable timeline of what was done to it and by whom. The audit
row is the compliance record; the event is the operator's narrative. They are
deliberately both written rather than one derived from the other — ``audit_log``
is append-only and global, the timeline is per-plan and rendered in the UI.

**Session discipline on the fan-out endpoints.** ``POST …/parity`` walks every
item in a plan, and each parity computation makes a network call. The obvious
``asyncio.gather`` over the whole thing is wrong: one ``AsyncSession`` cannot
serve concurrent operations, and every parity function reads from the DB before
it touches the wire (see the module note in ``services/cutover/parity.py``). So
the fan-out here is **sequential**. A slow Windows box makes the request slow;
it does not corrupt the session.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.api.deps import DB, SuperAdmin
from app.core.dns_names import sanitize_hostname
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.cutover import (
    PLAN_STATUSES,
    CutoverEvent,
    CutoverItem,
    CutoverPlan,
)
from app.models.dhcp import DHCPScope, DHCPServer
from app.models.dns import DNSServer, DNSZone
from app.services.api_token_scopes import token_write
from app.services.cutover import checklist as checklist_svc
from app.services.cutover import leases as leases_svc
from app.services.cutover import parity as parity_svc
from app.services.cutover import plans as plans_svc
from app.services.cutover import preflight as preflight_svc
from app.services.cutover import readiness as readiness_svc
from app.services.cutover import runbook as runbook_svc
from app.services.cutover import shadow as shadow_svc
from app.services.cutover import switch as switch_svc
from app.services.cutover.canonical import LeaseHandoverEntry, LeaseHandoverPlan, ParityReport
from app.services.dhcp_import.options import normalise_mac

logger = structlog.get_logger(__name__)

router = APIRouter()

_RESOURCE_TYPE = "cutover_plan"


# ── Schemas ────────────────────────────────────────────────────────────


class PlanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    source_dns_server_id: uuid.UUID | None = None
    source_dhcp_server_id: uuid.UUID | None = None
    target_dns_group_id: uuid.UUID | None = None
    target_dhcp_group_id: uuid.UUID | None = None
    notes: str = ""


class PlanUpdate(BaseModel):
    """Every field optional; ``exclude_unset`` decides what actually changes."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    status: str | None = None
    source_dns_server_id: uuid.UUID | None = None
    source_dhcp_server_id: uuid.UUID | None = None
    target_dns_group_id: uuid.UUID | None = None
    target_dhcp_group_id: uuid.UUID | None = None
    notes: str | None = None


class ItemIn(BaseModel):
    kind: Literal["dns_zone", "dhcp_scope"]
    source_ref: str = Field(min_length=1, max_length=255)
    zone_id: uuid.UUID | None = None
    scope_id: uuid.UUID | None = None
    notes: str = ""


class ItemsIn(BaseModel):
    items: list[ItemIn] = Field(min_length=1)


class ItemOut(BaseModel):
    id: uuid.UUID
    plan_id: uuid.UUID
    kind: str
    source_ref: str
    zone_id: uuid.UUID | None
    scope_id: uuid.UUID | None
    stage: str
    blockers: list[dict[str, Any]]
    last_parity: dict[str, Any] | None
    last_parity_at: datetime | None
    last_shadow: dict[str, Any] | None
    last_shadow_at: datetime | None
    ttl_snapshot: dict[str, Any] | None
    ttl_lowered_at: datetime | None
    lease_handover: dict[str, Any] | None
    cut_over_at: datetime | None
    rolled_back_at: datetime | None
    notes: str


class PlanOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    status: str
    source_dns_server_id: uuid.UUID | None
    source_dhcp_server_id: uuid.UUID | None
    target_dns_group_id: uuid.UUID | None
    target_dhcp_group_id: uuid.UUID | None
    notes: str
    created_at: datetime
    modified_at: datetime
    completed_at: datetime | None
    rolled_back_at: datetime | None
    item_count: int
    stage_counts: dict[str, int]
    blocked_count: int


class PlanDetailOut(PlanOut):
    items: list[ItemOut]


class ChecklistItemOut(BaseModel):
    key: str
    category: str
    label: str
    description: str
    applies_to: str
    is_done: bool
    done_at: datetime | None
    notes: str
    sort_order: int
    auto_state: str
    auto_detail: str


class ChecklistPatch(BaseModel):
    is_done: bool | None = None
    notes: str | None = None


class EventOut(BaseModel):
    id: uuid.UUID
    item_id: uuid.UUID | None
    at: datetime
    kind: str
    summary: str
    detail: dict[str, Any] | None
    user_display_name: str


class TTLPreflightIn(BaseModel):
    target_ttl: int = Field(
        default=300,
        description="Seconds. Bounded by the service (30..86400); see preflight.validate_target_ttl.",
    )


class ShadowIn(BaseModel):
    sample_size: int = Field(default=25, ge=1, le=shadow_svc.MAX_SAMPLE_SIZE)


class LeaseHandoverCommitIn(BaseModel):
    """The previewed plan, handed straight back.

    Same statelessness contract as the importers: the server keeps nothing
    between preview and commit, and the commit re-validates every entry against
    live DB state rather than trusting what it is given.
    """

    # Bounded like every other list input on this router. Each ``create`` entry
    # costs a savepoint, a flush and an IPAM upsert inside one transaction, so
    # an unbounded body would hold that transaction open against every other
    # writer. 8192 is far above any real scope (a /19 of live leases) and far
    # below a body that could wedge the database.
    entries: list[dict[str, Any]] = Field(default_factory=list, max_length=8192)


class CutoverIn(BaseModel):
    force: bool = Field(
        default=False,
        description=(
            "Acknowledge the warn-severity blockers. Never bypasses a "
            "block-severity one — notably not the AD 'Secure only' refusal."
        ),
    )


# ── Helpers ────────────────────────────────────────────────────────────


def _stage_counts(items: list[CutoverItem]) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        out[it.stage] = out.get(it.stage, 0) + 1
    return out


def _blocked_count(items: list[CutoverItem]) -> int:
    return sum(
        1 for it in items if any((b or {}).get("severity") == "block" for b in (it.blockers or []))
    )


def _item_out(item: CutoverItem) -> ItemOut:
    return ItemOut(
        id=item.id,
        plan_id=item.plan_id,
        kind=item.kind,
        source_ref=item.source_ref,
        zone_id=item.zone_id,
        scope_id=item.scope_id,
        stage=item.stage,
        blockers=list(item.blockers or []),
        last_parity=item.last_parity,
        last_parity_at=item.last_parity_at,
        last_shadow=item.last_shadow,
        last_shadow_at=item.last_shadow_at,
        ttl_snapshot=item.ttl_snapshot,
        ttl_lowered_at=item.ttl_lowered_at,
        lease_handover=item.lease_handover,
        cut_over_at=item.cut_over_at,
        rolled_back_at=item.rolled_back_at,
        notes=item.notes,
    )


def _plan_out(plan: CutoverPlan, items: list[CutoverItem]) -> PlanOut:
    return PlanOut(
        id=plan.id,
        name=plan.name,
        description=plan.description,
        status=plan.status,
        source_dns_server_id=plan.source_dns_server_id,
        source_dhcp_server_id=plan.source_dhcp_server_id,
        target_dns_group_id=plan.target_dns_group_id,
        target_dhcp_group_id=plan.target_dhcp_group_id,
        notes=plan.notes,
        created_at=plan.created_at,
        modified_at=plan.modified_at,
        completed_at=plan.completed_at,
        rolled_back_at=plan.rolled_back_at,
        item_count=len(items),
        stage_counts=_stage_counts(items),
        blocked_count=_blocked_count(items),
    )


async def _require_plan(db: DB, plan_id: uuid.UUID) -> CutoverPlan:
    plan = (
        await db.execute(
            select(CutoverPlan)
            .where(CutoverPlan.id == plan_id)
            .options(selectinload(CutoverPlan.items))
        )
    ).scalar_one_or_none()
    if plan is None:
        raise HTTPException(status_code=404, detail="Cutover plan not found")
    return plan


async def _require_item(db: DB, plan: CutoverPlan, item_id: uuid.UUID) -> CutoverItem:
    """Fetch an item, enforcing that it belongs to ``plan``.

    Scoping on both ids rather than looking the item up alone: the URL makes
    the plan explicit at every level, and an item id from another plan must
    404, not silently operate on someone else's migration.
    """
    item = (
        await db.execute(
            select(CutoverItem).where(CutoverItem.id == item_id, CutoverItem.plan_id == plan.id)
        )
    ).scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Cutover item not found on this plan")
    return item


def _require_kind(item: CutoverItem, kind: str, what: str) -> None:
    if item.kind != kind:
        raise HTTPException(
            status_code=422,
            detail=f"{what} applies to {kind} items; {item.source_ref!r} is a {item.kind}.",
        )


async def _require_zone(db: DB, item: CutoverItem) -> DNSZone:
    if item.zone_id is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Item {item.source_ref!r} is not linked to a SpatiumDDI zone. Run Discover "
                "and re-add it, or set zone_id."
            ),
        )
    zone = await db.get(DNSZone, item.zone_id)
    if zone is None:
        raise HTTPException(
            status_code=422,
            detail=f"The zone item {item.source_ref!r} points at no longer exists.",
        )
    return zone


async def _require_scope(db: DB, item: CutoverItem) -> DHCPScope:
    if item.scope_id is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Item {item.source_ref!r} is not linked to a SpatiumDDI scope. Run Discover "
                "and re-add it, or set scope_id."
            ),
        )
    scope = await db.get(DHCPScope, item.scope_id)
    if scope is None:
        raise HTTPException(
            status_code=422,
            detail=f"The scope item {item.source_ref!r} points at no longer exists.",
        )
    return scope


async def _require_source_dns(db: DB, plan: CutoverPlan) -> DNSServer:
    if plan.source_dns_server_id is None:
        raise HTTPException(status_code=422, detail="This plan has no source Windows DNS server.")
    server = await db.get(DNSServer, plan.source_dns_server_id)
    if server is None:
        raise HTTPException(
            status_code=422, detail="The plan's source DNS server no longer exists."
        )
    return server


async def _require_source_dhcp(db: DB, plan: CutoverPlan) -> DHCPServer:
    if plan.source_dhcp_server_id is None:
        raise HTTPException(status_code=422, detail="This plan has no source Windows DHCP server.")
    server = await db.get(DHCPServer, plan.source_dhcp_server_id)
    if server is None:
        raise HTTPException(
            status_code=422, detail="The plan's source DHCP server no longer exists."
        )
    return server


def _audit(
    db: DB,
    user: User,
    *,
    action: str,
    plan: CutoverPlan,
    detail: dict[str, Any] | None = None,
) -> None:
    """One ``audit_log`` row per mutation, keyed to the plan (non-negotiable #4)."""
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type=_RESOURCE_TYPE,
            resource_id=str(plan.id),
            resource_display=plan.name,
            result="success",
            new_value=detail or {},
        )
    )


def _event(
    db: DB,
    user: User,
    *,
    plan: CutoverPlan,
    item: CutoverItem | None,
    kind: str,
    summary: str,
    detail: dict[str, Any] | None = None,
) -> None:
    db.add(
        CutoverEvent(
            plan_id=plan.id,
            item_id=item.id if item is not None else None,
            kind=kind,
            summary=summary[:512],
            detail=detail,
            user_id=user.id,
            user_display_name=user.display_name,
        )
    )


async def _run_parity(db: DB, plan: CutoverPlan, item: CutoverItem) -> ParityReport:
    """Compute + persist one item's parity report, refreshing its blockers.

    Does not commit. Raises ``HTTPException`` only for a wiring problem the
    operator has to fix (an unlinked item, a missing source server); a failed
    *pull* comes back inside the report, which is what lets the whole-plan run
    report per-item failures instead of dying on the first unreachable host.
    """
    if item.kind == "dns_zone":
        zone = await _require_zone(db, item)
        dns_source = await _require_source_dns(db, plan)
        report = await parity_svc.compute_dns_parity(
            db, source_server=dns_source, zone=zone, source_zone_name=item.source_ref
        )
    else:
        scope = await _require_scope(db, item)
        dhcp_source = await _require_source_dhcp(db, plan)
        report = await parity_svc.compute_dhcp_parity(
            db, source_server=dhcp_source, scope=scope, source_scope_id=item.source_ref
        )

    item.last_parity = report.as_dict()
    item.last_parity_at = datetime.now(UTC)
    if item.stage == "pending":
        item.stage = "parity_checked"
    await readiness_svc.refresh_blockers(db, plan=plan, item=item)
    return report


# ── Plans ──────────────────────────────────────────────────────────────


@router.get("/plans", response_model=list[PlanOut])
async def list_plans(db: DB, _user: SuperAdmin) -> list[PlanOut]:
    """Every plan, newest first, with a per-plan item-stage rollup."""
    plans = list(
        (
            await db.execute(
                select(CutoverPlan)
                .options(selectinload(CutoverPlan.items))
                .order_by(CutoverPlan.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [_plan_out(p, list(p.items)) for p in plans]


@router.post("/plans", response_model=PlanDetailOut, status_code=status.HTTP_201_CREATED)
async def create_plan(body: PlanCreate, db: DB, user: SuperAdmin) -> PlanDetailOut:
    plan = CutoverPlan(
        name=body.name.strip(),
        description=body.description,
        status="draft",
        source_dns_server_id=body.source_dns_server_id,
        source_dhcp_server_id=body.source_dhcp_server_id,
        target_dns_group_id=body.target_dns_group_id,
        target_dhcp_group_id=body.target_dhcp_group_id,
        notes=body.notes,
        created_by_user_id=user.id,
    )
    db.add(plan)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=409, detail=f"A cutover plan named {body.name!r} already exists."
        ) from exc

    _audit(db, user, action="create_cutover_plan", plan=plan, detail={"name": plan.name})
    _event(db, user, plan=plan, item=None, kind="plan", summary=f"Created plan {plan.name!r}")
    await db.commit()
    await db.refresh(plan)
    return PlanDetailOut(**_plan_out(plan, []).model_dump(), items=[])


@router.get("/plans/{plan_id}", response_model=PlanDetailOut)
async def get_plan(plan_id: uuid.UUID, db: DB, _user: SuperAdmin) -> PlanDetailOut:
    plan = await _require_plan(db, plan_id)
    items = list(plan.items)
    return PlanDetailOut(**_plan_out(plan, items).model_dump(), items=[_item_out(i) for i in items])


@router.patch("/plans/{plan_id}", response_model=PlanDetailOut)
async def update_plan(
    plan_id: uuid.UUID, body: PlanUpdate, db: DB, user: SuperAdmin
) -> PlanDetailOut:
    plan = await _require_plan(db, plan_id)
    changes = body.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in PLAN_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of {sorted(PLAN_STATUSES)}.",
        )

    # ``create_plan`` strips; PATCH must too, or " Retire DC01" and
    # "Retire DC01" become two rows the unique index treats as distinct and
    # the name-addressable MCP tools cannot find.
    if isinstance(changes.get("name"), str):
        changes["name"] = changes["name"].strip()
        if not changes["name"]:
            raise HTTPException(status_code=422, detail="name cannot be blank.")
    for field_name, value in changes.items():
        setattr(plan, field_name, value)
    if changes.get("status") == "completed" and plan.completed_at is None:
        plan.completed_at = datetime.now(UTC)
    if changes.get("status") == "rolled_back" and plan.rolled_back_at is None:
        plan.rolled_back_at = datetime.now(UTC)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=409, detail="Another cutover plan already uses that name."
        ) from exc

    _audit(db, user, action="update_cutover_plan", plan=plan, detail=changes)
    _event(
        db,
        user,
        plan=plan,
        item=None,
        kind="plan",
        summary=f"Updated plan ({', '.join(sorted(changes)) or 'no fields'})",
        detail=changes,
    )
    await db.commit()

    plan = await _require_plan(db, plan_id)
    items = list(plan.items)
    return PlanDetailOut(**_plan_out(plan, items).model_dump(), items=[_item_out(i) for i in items])


@router.delete("/plans/{plan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_plan(plan_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    """Hard delete. Cascades to items, checklist, and timeline.

    Nothing the plan points at is touched — the zones, scopes, reservations and
    TTLs it references are owned by their own tables. Deleting an in-flight plan
    does throw away its pre-flight TTL snapshot, which is the only record of the
    pre-migration values, so the UI confirms first.
    """
    plan = await _require_plan(db, plan_id)
    name = plan.name
    _audit(
        db,
        user,
        action="delete_cutover_plan",
        plan=plan,
        detail={"name": name, "items": len(plan.items)},
    )
    await db.delete(plan)
    await db.commit()
    logger.info("cutover.plan.deleted", plan=str(plan_id), name=name, user=user.username)


# ── Discovery + items ──────────────────────────────────────────────────


@router.post("/plans/{plan_id}/discover")
async def discover(plan_id: uuid.UUID, db: DB, _user: SuperAdmin) -> dict[str, Any]:
    """Live-pull the Windows source estate and return addable candidates.

    Read-only, so no audit row: it writes nothing and reads the same data the
    parity check does. The DNS and DHCP halves are independent — a WinRM failure
    on one comes back as an ``error`` string on that side only.
    """
    plan = await _require_plan(db, plan_id)
    return await plans_svc.discover_candidates(db, plan=plan)


@router.post("/plans/{plan_id}/items", response_model=list[ItemOut], status_code=201)
async def add_items(plan_id: uuid.UUID, body: ItemsIn, db: DB, user: SuperAdmin) -> list[ItemOut]:
    plan = await _require_plan(db, plan_id)
    existing = {(i.kind, i.source_ref) for i in plan.items}

    created: list[CutoverItem] = []
    # ``ItemIn.kind`` is a Literal, so pydantic has already rejected anything
    # outside ITEM_KINDS with a 422 before this body runs.
    for spec in body.items:
        ref = spec.source_ref.strip()
        if (spec.kind, ref) in existing:
            # Idempotent add: re-selecting a candidate that is already on the
            # plan is a no-op rather than a 409, because the discover UI
            # legitimately re-offers rows the operator already picked.
            continue
        item = CutoverItem(
            plan_id=plan.id,
            kind=spec.kind,
            source_ref=ref,
            zone_id=spec.zone_id,
            scope_id=spec.scope_id,
            stage="pending",
            blockers=[],
            notes=spec.notes,
        )
        db.add(item)
        created.append(item)
        existing.add((spec.kind, ref))

    if not created:
        return []

    await db.flush()
    _audit(
        db,
        user,
        action="add_cutover_items",
        plan=plan,
        detail={"added": [{"kind": i.kind, "source_ref": i.source_ref} for i in created]},
    )
    _event(
        db,
        user,
        plan=plan,
        item=None,
        kind="plan",
        summary=f"Added {len(created)} item(s) to the plan",
        detail={"source_refs": [i.source_ref for i in created]},
    )
    await db.commit()
    for item in created:
        await db.refresh(item)
    return [_item_out(i) for i in created]


@router.delete("/plans/{plan_id}/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(plan_id: uuid.UUID, item_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    if item.stage == "cut_over":
        raise HTTPException(
            status_code=409,
            detail=(
                f"{item.source_ref!r} has been cut over. Roll it back before removing it, or "
                "the plan loses the only record of how to reverse the switch."
            ),
        )
    ref, kind = item.source_ref, item.kind
    _audit(
        db,
        user,
        action="remove_cutover_item",
        plan=plan,
        detail={"kind": kind, "source_ref": ref},
    )
    _event(
        db,
        user,
        plan=plan,
        item=None,
        kind="plan",
        summary=f"Removed {kind} item {ref!r} from the plan",
    )
    await db.delete(item)
    await db.commit()


# ── Phase 1 — parity ───────────────────────────────────────────────────


@router.post("/plans/{plan_id}/items/{item_id}/parity")
async def run_item_parity(
    plan_id: uuid.UUID, item_id: uuid.UUID, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    report = await _run_parity(db, plan, item)

    _audit(
        db,
        user,
        action="run_cutover_parity",
        plan=plan,
        detail={"source_ref": item.source_ref, "status": report.status},
    )
    _event(
        db,
        user,
        plan=plan,
        item=item,
        kind="parity",
        summary=(
            f"Parity check on {item.source_ref}: {report.status}, "
            f"{report.difference_count} difference(s)"
        ),
        detail=report.as_dict(),
    )
    await db.commit()
    return {"report": report.as_dict(), "blockers": list(item.blockers or [])}


@router.post("/plans/{plan_id}/parity")
async def run_plan_parity(plan_id: uuid.UUID, db: DB, user: SuperAdmin) -> dict[str, Any]:
    """Run parity for every item on the plan.

    Sequential on purpose — see the module docstring. Per-item wiring problems
    (an unlinked item, a deleted zone) are caught and reported in-band so one
    bad item does not deny the operator the whole report; pull failures are
    already in-band by construction.
    """
    plan = await _require_plan(db, plan_id)
    results: list[dict[str, Any]] = []

    for item in list(plan.items):
        try:
            report = await _run_parity(db, plan, item)
        except HTTPException as exc:
            results.append(
                {
                    "item_id": str(item.id),
                    "source_ref": item.source_ref,
                    "kind": item.kind,
                    "status": "error",
                    "error": str(exc.detail),
                }
            )
            continue
        results.append(
            {
                "item_id": str(item.id),
                "source_ref": item.source_ref,
                "kind": item.kind,
                **report.as_dict(),
            }
        )

    in_parity = sum(1 for r in results if r.get("is_parity"))
    _audit(
        db,
        user,
        action="run_cutover_parity_all",
        plan=plan,
        detail={"items": len(results), "in_parity": in_parity},
    )
    _event(
        db,
        user,
        plan=plan,
        item=None,
        kind="parity",
        summary=f"Parity check across {len(results)} item(s): {in_parity} in parity",
        detail={"results": results},
    )
    await db.commit()
    return {"items": results, "in_parity": in_parity, "total": len(results)}


# ── Phase 2 — parallel run ─────────────────────────────────────────────


@router.post("/plans/{plan_id}/items/{item_id}/shadow")
async def run_shadow(
    plan_id: uuid.UUID, item_id: uuid.UUID, body: ShadowIn, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    """Replay recently-observed queries at both sides and compare the answers."""
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    _require_kind(item, "dns_zone", "The shadow query comparison")

    zone = await _require_zone(db, item)
    source = await _require_source_dns(db, plan)
    report = await shadow_svc.run_shadow_comparison(
        db, source_server=source, zone=zone, sample_size=body.sample_size
    )

    item.last_shadow = report.as_dict()
    item.last_shadow_at = datetime.now(UTC)
    _audit(
        db,
        user,
        action="run_cutover_shadow",
        plan=plan,
        detail={
            "source_ref": item.source_ref,
            "sampled": report.sampled,
            "mismatched": report.mismatched,
        },
    )
    _event(
        db,
        user,
        plan=plan,
        item=item,
        kind="shadow",
        summary=(
            f"Shadow comparison on {item.source_ref}: {report.matched}/{report.sampled} matched "
            f"({report.sample_source})"
        ),
        detail=report.as_dict(),
    )
    await db.commit()
    return report.as_dict()


# ── Phase 3a — TTL pre-flight ──────────────────────────────────────────


@router.post("/plans/{plan_id}/items/{item_id}/ttl-preflight/preview")
@token_write(
    "Reads the zone from the DB, no write and no outbound call; kept write-scoped as the preview half of the SuperAdmin-only cutover TTL step"
)
async def preview_ttl(
    plan_id: uuid.UUID, item_id: uuid.UUID, body: TTLPreflightIn, db: DB, _user: SuperAdmin
) -> dict[str, Any]:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    _require_kind(item, "dns_zone", "The TTL pre-flight")
    zone = await _require_zone(db, item)
    try:
        result = await preflight_svc.preview_ttl_preflight(
            db, zone=zone, target_ttl=body.target_ttl
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result.as_dict()


@router.post("/plans/{plan_id}/items/{item_id}/ttl-preflight/commit")
async def commit_ttl(
    plan_id: uuid.UUID, item_id: uuid.UUID, body: TTLPreflightIn, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    _require_kind(item, "dns_zone", "The TTL pre-flight")
    zone = await _require_zone(db, item)
    try:
        result = await preflight_svc.apply_ttl_preflight(
            db, zone=zone, item=item, target_ttl=body.target_ttl, current_user=user
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _audit(
        db,
        user,
        action="apply_cutover_ttl_preflight",
        plan=plan,
        detail={
            "source_ref": item.source_ref,
            "zone": zone.name,
            "target_ttl": result.target_ttl,
            "records_changed": len(result.records),
        },
    )
    _event(
        db,
        user,
        plan=plan,
        item=item,
        kind="preflight",
        summary=(
            f"Lowered TTLs on {zone.name} to {result.target_ttl}s "
            f"({len(result.records)} record(s))"
        ),
        detail=result.as_dict(),
    )
    await db.commit()
    return result.as_dict()


@router.post("/plans/{plan_id}/items/{item_id}/ttl-preflight/restore")
async def restore_ttl(
    plan_id: uuid.UUID, item_id: uuid.UUID, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    _require_kind(item, "dns_zone", "The TTL pre-flight")
    zone = await _require_zone(db, item)

    restored = await preflight_svc.restore_ttl_preflight(
        db, zone=zone, item=item, current_user=user
    )
    _audit(
        db,
        user,
        action="restore_cutover_ttl_preflight",
        plan=plan,
        detail={"source_ref": item.source_ref, "zone": zone.name, "records_restored": restored},
    )
    _event(
        db,
        user,
        plan=plan,
        item=item,
        kind="preflight",
        summary=f"Restored the pre-flight TTL snapshot on {zone.name} ({restored} record(s))",
    )
    await db.commit()
    return {"records_restored": restored, "zone": zone.name}


# ── Phase 3b — DHCP lease handover ─────────────────────────────────────


@router.post("/plans/{plan_id}/items/{item_id}/lease-handover/preview")
@token_write(
    "Pulls the live lease table from the source Windows DHCP server over WinRM (outbound); a SuperAdmin cutover step"
)
async def preview_leases(
    plan_id: uuid.UUID, item_id: uuid.UUID, db: DB, _user: SuperAdmin
) -> dict[str, Any]:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    _require_kind(item, "dhcp_scope", "The lease handover")
    scope = await _require_scope(db, item)
    source = await _require_source_dhcp(db, plan)
    try:
        result = await leases_svc.preview_lease_handover(
            db, source_server=source, scope=scope, source_scope_id=item.source_ref
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result.as_dict()


@router.post("/plans/{plan_id}/items/{item_id}/lease-handover/commit")
async def commit_leases(
    plan_id: uuid.UUID,
    item_id: uuid.UUID,
    body: LeaseHandoverCommitIn,
    db: DB,
    user: SuperAdmin,
) -> dict[str, Any]:
    """Write the previewed ``create`` entries as reservations.

    The plan comes back from the client (the server keeps no state between the
    two calls, same as the importers), but every entry is re-classified against
    live DB state inside the service — an operator who added a reservation
    between preview and commit gets that entry skipped, not an IntegrityError.
    """
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)
    _require_kind(item, "dhcp_scope", "The lease handover")
    scope = await _require_scope(db, item)
    source = await _require_source_dhcp(db, plan)

    # The body is client-supplied, so it gets the same normalisation the preview
    # applied — it is not a trusted echo. An un-normalised MAC would miss the
    # dedup maps in ``_classify`` (which key on the canonical form) and only
    # fail at the MACADDR unique index, and an unsanitised hostname would reach
    # the Kea reservation and the DDNS name path verbatim.
    entries: list[LeaseHandoverEntry] = []
    for raw in body.entries:
        ip = str(raw.get("ip_address") or "").strip()
        mac = normalise_mac(raw.get("mac_address"))
        if not ip or mac is None:
            continue
        entries.append(
            LeaseHandoverEntry(
                ip_address=ip,
                mac_address=mac,
                hostname=sanitize_hostname(raw.get("hostname")),
                action=raw.get("action") or "create",
                reason=str(raw.get("reason") or ""),
            )
        )
    if not entries:
        raise HTTPException(
            status_code=422,
            detail="No usable lease entries in the request body. Re-run the preview.",
        )

    handover = LeaseHandoverPlan(scope_cidr="", source_scope_id=item.source_ref, entries=entries)
    try:
        result = await leases_svc.commit_lease_handover(
            db,
            source_server=source,
            scope=scope,
            item=item,
            plan=handover,
            current_user=user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _audit(
        db,
        user,
        action="commit_cutover_lease_handover",
        plan=plan,
        detail={
            "source_ref": item.source_ref,
            "created": result.created,
            "skipped": result.skipped,
            "failed": result.failed,
        },
    )
    _event(
        db,
        user,
        plan=plan,
        item=item,
        kind="lease_handover",
        summary=(
            f"Lease handover on {item.source_ref}: {result.created} reservation(s) created, "
            f"{result.skipped} skipped, {result.failed} failed"
        ),
        detail=result.as_dict(),
    )
    await db.commit()
    return result.as_dict()


# ── Phase 3c — the switch ──────────────────────────────────────────────


@router.post("/plans/{plan_id}/items/{item_id}/cutover")
async def cut_item_over(
    plan_id: uuid.UUID, item_id: uuid.UUID, body: CutoverIn, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    """Cut one item over. 409 with the blocker list when it is refused.

    409 rather than 422 because the request is well-formed — the *state* is what
    refuses it, and the UI renders ``detail.blockers`` verbatim so the operator
    reads the fix rather than a status code.
    """
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)

    # The switch pairs an irreversible WinRM call with a database write, so
    # WHERE the commit lands relative to that call decides what a crash leaves
    # behind. That sequencing knowledge belongs with the ordering rules in
    # ``switch.py``, so the transaction boundary is handed in rather than
    # applied here — see that module's docstring.
    async def _finalize() -> None:
        if plan.status in ("draft", "verifying", "parallel"):
            plan.status = "cutting_over"
        _audit(
            db,
            user,
            action="cutover_item",
            plan=plan,
            detail={"source_ref": item.source_ref, "kind": item.kind, "force": body.force},
        )
        await db.commit()

    try:
        result = await switch_svc.execute_cutover(
            db, plan=plan, item=item, current_user=user, force=body.force, finalize=_finalize
        )
    except switch_svc.CutoverBlocked as exc:
        # Persist the refusal rather than rolling it away. ``execute_cutover``
        # re-derives the blockers against live Windows state and writes them onto
        # the item; that is precisely the verdict the plan list, the MCP tools and
        # the runbook read. Discarding it would leave every one of those surfaces
        # reporting the stale set at the exact moment it matters most — a zone
        # that was just flipped to AD 'Secure only'. Nothing was mutated on either
        # server: the switch raised before it acted.
        item.blockers = [b.as_dict() for b in exc.blockers]
        _event(
            db,
            user,
            plan=plan,
            item=item,
            kind="cutover",
            summary=f"Cutover of {item.source_ref} refused: {len(exc.blockers)} blocker(s)",
            detail=exc.as_dict(),
        )
        _audit(
            db,
            user,
            action="cutover_item_refused",
            plan=plan,
            detail={"source_ref": item.source_ref, "blockers": [b.as_dict() for b in exc.blockers]},
        )
        await db.commit()
        raise HTTPException(status_code=409, detail=exc.as_dict()) from exc
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return result


@router.post("/plans/{plan_id}/items/{item_id}/rollback")
async def roll_item_back(
    plan_id: uuid.UUID, item_id: uuid.UUID, db: DB, user: SuperAdmin
) -> dict[str, Any]:
    plan = await _require_plan(db, plan_id)
    item = await _require_item(db, plan, item_id)

    # Same reasoning as the cutover above: the rollback commits the managed-side
    # deactivation BEFORE re-activating Windows, so a failed commit can never
    # leave both servers answering. ``switch.py`` owns that ordering.
    async def _finalize() -> None:
        _audit(
            db,
            user,
            action="rollback_cutover_item",
            plan=plan,
            detail={"source_ref": item.source_ref, "kind": item.kind},
        )
        await db.commit()

    try:
        result = await switch_svc.execute_rollback(
            db, plan=plan, item=item, current_user=user, finalize=_finalize
        )
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return result


# ── Phase 4 — decommission checklist ───────────────────────────────────


@router.get("/plans/{plan_id}/checklist", response_model=list[ChecklistItemOut])
async def get_checklist(plan_id: uuid.UUID, db: DB, _user: SuperAdmin) -> list[ChecklistItemOut]:
    """The plan's checklist: the static catalog merged with the plan's state.

    Read-only. Rows are created lazily by the PATCH below when the operator
    first ticks or annotates a line, so a plan created before a catalog entry
    existed still shows it with no write. A GET that seeded rows would owe an
    ``audit_log`` entry per non-negotiable #4 and would slip a database write
    past the maintenance-mode middleware, which gates on the HTTP method.
    """
    plan = await _require_plan(db, plan_id)
    rows = await checklist_svc.read_checklist(db, plan=plan)
    auto = await checklist_svc.evaluate_auto_checks(db, plan=plan)
    return [
        ChecklistItemOut(
            key=r.key,
            category=r.category,
            label=r.label,
            description=r.description,
            applies_to=r.applies_to,
            is_done=r.is_done,
            done_at=r.done_at,
            notes=r.notes,
            sort_order=r.sort_order,
            auto_state=(auto.get(r.key) or {}).get("state", "manual"),
            auto_detail=(auto.get(r.key) or {}).get("detail", ""),
        )
        for r in rows
    ]


@router.patch("/plans/{plan_id}/checklist/{key}", response_model=ChecklistItemOut)
async def patch_checklist_item(
    plan_id: uuid.UUID, key: str, body: ChecklistPatch, db: DB, user: SuperAdmin
) -> ChecklistItemOut:
    plan = await _require_plan(db, plan_id)
    # Creates the row from the catalog on first touch; returns None only for a
    # key that is neither in the catalog nor already stored, so a typo 404s
    # rather than minting a phantom checklist line.
    row = await checklist_svc.upsert_checklist_row(db, plan=plan, key=key)
    if row is None:
        raise HTTPException(status_code=404, detail=f"No checklist item {key!r} on this plan.")

    changes = body.model_dump(exclude_unset=True)
    if "is_done" in changes:
        row.is_done = bool(changes["is_done"])
        # ``done_at`` / ``done_by`` follow the tick in both directions, so an
        # un-tick does not leave a stale "completed by" on an open item.
        row.done_at = datetime.now(UTC) if row.is_done else None
        row.done_by_user_id = user.id if row.is_done else None
    if "notes" in changes:
        row.notes = changes["notes"] or ""

    _audit(
        db,
        user,
        action="update_cutover_checklist_item",
        plan=plan,
        detail={"key": key, **changes},
    )
    _event(
        db,
        user,
        plan=plan,
        item=None,
        kind="checklist",
        summary=(
            f"Marked decommission step {key!r} " f"{'done' if row.is_done else 'not done'}"
            if "is_done" in changes
            else f"Annotated decommission step {key!r}"
        ),
        detail=changes,
    )
    await db.commit()
    await db.refresh(row)

    auto = await checklist_svc.evaluate_auto_checks(db, plan=plan)
    return ChecklistItemOut(
        key=row.key,
        category=row.category,
        label=row.label,
        description=row.description,
        applies_to=row.applies_to,
        is_done=row.is_done,
        done_at=row.done_at,
        notes=row.notes,
        sort_order=row.sort_order,
        auto_state=(auto.get(row.key) or {}).get("state", "manual"),
        auto_detail=(auto.get(row.key) or {}).get("detail", ""),
    )


# ── Timeline + runbook ─────────────────────────────────────────────────


@router.get("/plans/{plan_id}/events", response_model=list[EventOut])
async def list_events(
    plan_id: uuid.UUID,
    db: DB,
    _user: SuperAdmin,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[EventOut]:
    plan = await _require_plan(db, plan_id)
    rows = list(
        (
            await db.execute(
                select(CutoverEvent)
                .where(CutoverEvent.plan_id == plan.id)
                .order_by(CutoverEvent.at.desc(), CutoverEvent.id)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return [
        EventOut(
            id=e.id,
            item_id=e.item_id,
            at=e.at,
            kind=e.kind,
            summary=e.summary,
            detail=e.detail,
            user_display_name=e.user_display_name,
        )
        for e in rows
    ]


@router.get("/plans/{plan_id}/events/count")
async def count_events(plan_id: uuid.UUID, db: DB, _user: SuperAdmin) -> dict[str, int]:
    plan = await _require_plan(db, plan_id)
    total = (
        await db.execute(
            select(func.count()).select_from(CutoverEvent).where(CutoverEvent.plan_id == plan.id)
        )
    ).scalar_one()
    return {"total": int(total)}


@router.get("/plans/{plan_id}/runbook")
async def get_runbook(plan_id: uuid.UUID, db: DB, _user: SuperAdmin) -> dict[str, str]:
    """The generated operator runbook, as markdown.

    Read-only, built from persisted state — it does not re-pull the source, so
    an operator can produce it for a change ticket without touching the Windows
    box. Parity facts come from each item's last recorded report.
    """
    plan = await _require_plan(db, plan_id)
    items = list(plan.items)

    dns_host: str | None = None
    if plan.source_dns_server_id is not None:
        server = await db.get(DNSServer, plan.source_dns_server_id)
        dns_host = server.host if server else None
    dhcp_host: str | None = None
    if plan.source_dhcp_server_id is not None:
        dhcp_server = await db.get(DHCPServer, plan.source_dhcp_server_id)
        dhcp_host = dhcp_server.host if dhcp_server else None

    # Give the runbook the real per-item recovery numbers. Without them it
    # falls back to an assumed 3600s TTL / 24-hour lease and says so in the
    # operator's change ticket — which both overstates the rollback window and
    # leaks a developer-facing hint into a document someone signs off.
    propagation: dict[str, int] = {}
    for it in items:
        if it.kind == "dns_zone" and it.zone_id is not None:
            zone = await db.get(DNSZone, it.zone_id)
            if zone is not None:
                propagation[str(it.id)] = int(zone.ttl)
        elif it.kind == "dhcp_scope" and it.scope_id is not None:
            scope = await db.get(DHCPScope, it.scope_id)
            if scope is not None:
                propagation[str(it.id)] = int(scope.lease_time)

    markdown = runbook_svc.render_runbook(
        plan,
        items,
        None,
        source_dns_host=dns_host,
        source_dhcp_host=dhcp_host,
        propagation_seconds=propagation,
    )
    return {"markdown": markdown}
