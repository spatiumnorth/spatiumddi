"""SD-WAN overlay CRUD + topology + simulate — issue #95.

Vendor-neutral source of truth for overlay topology and routing
policy *intent*. Vendor config push (vManage / Meraki Dashboard /
FortiManager / Versa Director) and real-time path telemetry are
explicitly out of scope per the issue body.

Endpoints:

* ``/overlays`` — overlay network CRUD.
* ``/overlays/{id}/sites`` — site membership (overlay_site) CRUD.
* ``/overlays/{id}/policies`` — routing policy CRUD.
* ``/overlays/{id}/topology`` — nodes (sites + roles) + edges
  (circuit-shared between site pairs) + policies. Drives the topology
  visualization in the frontend.
* ``/overlays/{id}/simulate`` — pure read-only what-if. Body specifies
  a list of "down" circuit UUIDs; response shows the effective
  resolution for each policy + each site's preferred-circuit fallback
  chain.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.api.v1._common import BulkDeleteResponse
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.circuit import Circuit
from app.models.network import NetworkDevice
from app.models.overlay import (
    DEFAULT_PATH_STRATEGIES,
    OVERLAY_KINDS,
    OVERLAY_SITE_ROLES,
    OVERLAY_STATUSES,
    ROUTING_POLICY_ACTIONS,
    ROUTING_POLICY_MATCH_KINDS,
    ApplicationCategory,
    OverlayNetwork,
    OverlaySite,
    RoutingPolicy,
)
from app.models.ownership import Customer, Site
from app.services.tags import apply_tag_filter

# Single router; sub-paths live as separate decorated handlers below.
# Permission gate applies once at the router level — every endpoint
# requires admin on ``overlay_network`` (the routing-policy mutations
# also re-check ``routing_policy``).
router = APIRouter(
    tags=["overlays"],
    dependencies=[Depends(require_resource_permission("overlay_network"))],
)


# ── Schemas ─────────────────────────────────────────────────────────


OverlayKind = Literal["sdwan", "ipsec_mesh", "wireguard_mesh", "dmvpn", "vxlan_evpn", "gre_mesh"]
OverlayStatus = Literal["active", "building", "suspended", "decom"]
OverlayPathStrategy = Literal["active_active", "active_backup", "load_balance", "app_aware"]
OverlaySiteRole = Literal["hub", "spoke", "transit", "gateway"]
RoutingMatchKind = Literal[
    "application",
    "dscp",
    "source_subnet",
    "destination_subnet",
    "port_range",
    "acl",
]
RoutingAction = Literal[
    "steer_to_circuit",
    "steer_to_transport_class",
    "steer_to_site_via_path",
    "drop",
    "shape",
    "mark_dscp",
]


class OverlayCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    kind: OverlayKind = "sdwan"
    customer_id: uuid.UUID | None = None
    vendor: str | None = Field(default=None, max_length=64)
    encryption_profile: str | None = Field(default=None, max_length=128)
    default_path_strategy: OverlayPathStrategy = "active_backup"
    status: OverlayStatus = "building"
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in OVERLAY_KINDS:
            raise ValueError(f"kind must be one of {sorted(OVERLAY_KINDS)}")
        return v

    @field_validator("status")
    @classmethod
    def _v_status(cls, v: str) -> str:
        if v not in OVERLAY_STATUSES:
            raise ValueError(f"status must be one of {sorted(OVERLAY_STATUSES)}")
        return v

    @field_validator("default_path_strategy")
    @classmethod
    def _v_strategy(cls, v: str) -> str:
        if v not in DEFAULT_PATH_STRATEGIES:
            raise ValueError(
                f"default_path_strategy must be one of {sorted(DEFAULT_PATH_STRATEGIES)}"
            )
        return v


class OverlayUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    kind: OverlayKind | None = None
    customer_id: uuid.UUID | None = None
    vendor: str | None = Field(default=None, max_length=64)
    encryption_profile: str | None = Field(default=None, max_length=128)
    default_path_strategy: OverlayPathStrategy | None = None
    status: OverlayStatus | None = None
    notes: str | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None


class OverlayRead(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    customer_id: uuid.UUID | None
    vendor: str | None
    encryption_profile: str | None
    default_path_strategy: str
    status: str
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime
    site_count: int = 0
    policy_count: int = 0

    model_config = {"from_attributes": True}


class OverlayListResponse(BaseModel):
    items: list[OverlayRead]
    total: int
    limit: int
    offset: int


class OverlayBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


class OverlaySiteCreate(BaseModel):
    site_id: uuid.UUID
    role: OverlaySiteRole = "spoke"
    device_id: uuid.UUID | None = None
    loopback_subnet_id: uuid.UUID | None = None
    preferred_circuits: list[uuid.UUID] = Field(default_factory=list)
    notes: str = ""

    @field_validator("role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        if v not in OVERLAY_SITE_ROLES:
            raise ValueError(f"role must be one of {sorted(OVERLAY_SITE_ROLES)}")
        return v


class OverlaySiteUpdate(BaseModel):
    role: OverlaySiteRole | None = None
    device_id: uuid.UUID | None = None
    loopback_subnet_id: uuid.UUID | None = None
    preferred_circuits: list[uuid.UUID] | None = None
    notes: str | None = None


class OverlaySiteRead(BaseModel):
    id: uuid.UUID
    overlay_network_id: uuid.UUID
    site_id: uuid.UUID
    role: str
    device_id: uuid.UUID | None
    loopback_subnet_id: uuid.UUID | None
    preferred_circuits: list[uuid.UUID]
    notes: str
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class RoutingPolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    priority: int = Field(default=100, ge=0, le=10000)
    match_kind: RoutingMatchKind
    match_value: str = Field(..., min_length=1, max_length=255)
    action: RoutingAction
    action_target: str | None = Field(default=None, max_length=255)
    enabled: bool = True
    notes: str = ""

    @field_validator("match_kind")
    @classmethod
    def _v_match(cls, v: str) -> str:
        if v not in ROUTING_POLICY_MATCH_KINDS:
            raise ValueError(f"match_kind must be one of {sorted(ROUTING_POLICY_MATCH_KINDS)}")
        return v

    @field_validator("action")
    @classmethod
    def _v_action(cls, v: str) -> str:
        if v not in ROUTING_POLICY_ACTIONS:
            raise ValueError(f"action must be one of {sorted(ROUTING_POLICY_ACTIONS)}")
        return v


class RoutingPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    priority: int | None = Field(default=None, ge=0, le=10000)
    match_kind: RoutingMatchKind | None = None
    match_value: str | None = Field(default=None, min_length=1, max_length=255)
    action: RoutingAction | None = None
    action_target: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    notes: str | None = None


class RoutingPolicyRead(BaseModel):
    id: uuid.UUID
    overlay_network_id: uuid.UUID
    name: str
    priority: int
    match_kind: str
    match_value: str
    action: str
    action_target: str | None
    enabled: bool
    notes: str
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


# Topology + simulate payloads.


class TopologyNode(BaseModel):
    overlay_site_id: uuid.UUID
    site_id: uuid.UUID
    site_name: str
    site_code: str | None
    role: str
    device_id: uuid.UUID | None
    device_name: str | None
    preferred_circuits: list[uuid.UUID]


class TopologyEdge(BaseModel):
    """An undirected adjacency between two overlay sites.

    For v1 we surface circuit-shared adjacencies — two sites share an
    edge if their ``preferred_circuits`` lists overlap on any circuit
    UUID. ``shared_circuits`` is the intersection so the UI can colour
    by transport class.
    """

    a_overlay_site_id: uuid.UUID
    z_overlay_site_id: uuid.UUID
    shared_circuits: list[uuid.UUID]


class TopologyResponse(BaseModel):
    overlay: OverlayRead
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    policies: list[RoutingPolicyRead]


class SimulateRequest(BaseModel):
    """Hypothetical underlay state for what-if analysis.

    ``down_circuits`` removes the listed circuits from every site's
    preferred-circuit chain before resolving each policy. The response
    shows the effective resolution per policy + per-site fallback
    chains that survived the simulation.
    """

    down_circuits: list[uuid.UUID] = Field(default_factory=list)


class SimulatedSiteResolution(BaseModel):
    overlay_site_id: uuid.UUID
    site_name: str
    original_preferred_circuits: list[uuid.UUID]
    surviving_preferred_circuits: list[uuid.UUID]
    primary_circuit: uuid.UUID | None
    primary_circuit_name: str | None
    primary_transport_class: str | None
    blackholed: bool


class SimulatedPolicyResolution(BaseModel):
    policy_id: uuid.UUID
    policy_name: str
    action: str
    original_target: str | None
    effective_target: str | None
    impacted: bool
    note: str | None


class SimulateResponse(BaseModel):
    overlay_id: uuid.UUID
    down_circuits: list[uuid.UUID]
    site_resolutions: list[SimulatedSiteResolution]
    policy_resolutions: list[SimulatedPolicyResolution]


# ── Helpers ─────────────────────────────────────────────────────────


async def _get_overlay(db: Any, overlay_id: uuid.UUID) -> OverlayNetwork:
    row = await db.get(OverlayNetwork, overlay_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Overlay not found")
    return row


async def _read_overlay(db: Any, row: OverlayNetwork) -> OverlayRead:
    site_count = await db.scalar(
        select(func.count(OverlaySite.id)).where(OverlaySite.overlay_network_id == row.id)
    )
    policy_count = await db.scalar(
        select(func.count(RoutingPolicy.id)).where(RoutingPolicy.overlay_network_id == row.id)
    )
    return OverlayRead(
        id=row.id,
        name=row.name,
        kind=row.kind,
        customer_id=row.customer_id,
        vendor=row.vendor,
        encryption_profile=row.encryption_profile,
        default_path_strategy=row.default_path_strategy,
        status=row.status,
        notes=row.notes,
        tags=row.tags or {},
        custom_fields=row.custom_fields or {},
        created_at=row.created_at,
        modified_at=row.modified_at,
        site_count=site_count or 0,
        policy_count=policy_count or 0,
    )


async def _validate_match(db: Any, match_kind: str, match_value: str) -> None:
    """Per-kind validation for routing policy match values.

    ``application`` requires the match_value to refer to an existing
    application_category row by name (case-insensitive). The other
    kinds get loose validation (regex / range) — more rigorous shape
    checks are a polish pass.
    """
    if match_kind == "application":
        existing = await db.scalar(
            select(ApplicationCategory).where(
                ApplicationCategory.name == match_value.strip().lower()
            )
        )
        if existing is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"application '{match_value}' not in catalog — "
                    f"create the row under /api/v1/applications first"
                ),
            )
    elif match_kind == "dscp":
        # Allow numeric 0-63 or named DSCP. Loose validator — vendors
        # accept different naming conventions; we don't try to map.
        v = match_value.strip()
        if v.isascii() and v.isdigit():
            iv = int(v)
            if not (0 <= iv <= 63):
                raise HTTPException(status_code=422, detail="dscp value must be 0..63")


# ── Overlay CRUD ────────────────────────────────────────────────────


@router.get("", response_model=OverlayListResponse)
async def list_overlays(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    customer_id: uuid.UUID | None = Query(default=None),
    kind: OverlayKind | None = Query(default=None),
    status: OverlayStatus | None = Query(default=None),
    search: str | None = Query(default=None),
    tag: list[str] = Query(default_factory=list),
) -> OverlayListResponse:
    stmt = select(OverlayNetwork).where(OverlayNetwork.deleted_at.is_(None))
    if customer_id is not None:
        stmt = stmt.where(OverlayNetwork.customer_id == customer_id)
    if kind is not None:
        stmt = stmt.where(OverlayNetwork.kind == kind)
    if status is not None:
        stmt = stmt.where(OverlayNetwork.status == status)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(OverlayNetwork.name.ilike(needle))
    stmt = apply_tag_filter(stmt, OverlayNetwork.tags, tag)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(OverlayNetwork.name.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    items = [await _read_overlay(db, r) for r in rows]
    return OverlayListResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("", response_model=OverlayRead, status_code=status.HTTP_201_CREATED)
async def create_overlay(body: OverlayCreate, db: DB, user: CurrentUser) -> OverlayRead:
    if body.customer_id is not None:
        c = await db.get(Customer, body.customer_id)
        if c is None or c.deleted_at is not None:
            raise HTTPException(status_code=422, detail="customer_id not found")
    if await db.scalar(
        select(OverlayNetwork.id).where(
            OverlayNetwork.name == body.name, OverlayNetwork.deleted_at.is_(None)
        )
    ):
        raise HTTPException(status_code=409, detail=f"Overlay named {body.name!r} already exists")
    row = OverlayNetwork(
        name=body.name,
        kind=body.kind,
        customer_id=body.customer_id,
        vendor=body.vendor,
        encryption_profile=body.encryption_profile,
        default_path_strategy=body.default_path_strategy,
        status=body.status,
        notes=body.notes,
        tags=body.tags or {},
        custom_fields=body.custom_fields or {},
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="overlay_network",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return await _read_overlay(db, row)


@router.get("/{overlay_id:uuid}", response_model=OverlayRead)
async def get_overlay(overlay_id: uuid.UUID, db: DB, _: CurrentUser) -> OverlayRead:
    row = await _get_overlay(db, overlay_id)
    return await _read_overlay(db, row)


@router.put("/{overlay_id:uuid}", response_model=OverlayRead)
async def update_overlay(
    overlay_id: uuid.UUID, body: OverlayUpdate, db: DB, user: CurrentUser
) -> OverlayRead:
    row = await _get_overlay(db, overlay_id)
    if body.customer_id is not None:
        c = await db.get(Customer, body.customer_id)
        if c is None or c.deleted_at is not None:
            raise HTTPException(status_code=422, detail="customer_id not found")
    changes = body.model_dump(exclude_unset=True)
    if "kind" in changes and changes["kind"] not in OVERLAY_KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {sorted(OVERLAY_KINDS)}")
    if "status" in changes and changes["status"] not in OVERLAY_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"status must be one of {sorted(OVERLAY_STATUSES)}"
        )
    if (
        "default_path_strategy" in changes
        and changes["default_path_strategy"] not in DEFAULT_PATH_STRATEGIES
    ):
        raise HTTPException(
            status_code=422,
            detail=(f"default_path_strategy must be one of " f"{sorted(DEFAULT_PATH_STRATEGIES)}"),
        )
    for k, v in changes.items():
        setattr(row, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="overlay_network",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
    )
    await db.commit()
    await db.refresh(row)
    return await _read_overlay(db, row)


async def _trash(db: Any, row: Any, user: Any) -> None:
    """Soft-delete into the Trash (own batch), so it can be restored or purged (#2738)."""
    from app.services.soft_delete import (
        apply_soft_delete,
        collect_soft_delete_batch,
    )  # noqa: PLC0415

    batch = await collect_soft_delete_batch(db, row)
    await apply_soft_delete(db, batch, user.id if user is not None else None)


@router.delete("/{overlay_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_overlay(overlay_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await _get_overlay(db, overlay_id)
    await _trash(db, row, user)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="overlay_network",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.commit()


@router.post("/bulk-delete", response_model=BulkDeleteResponse)
async def bulk_delete_overlays(
    body: OverlayBulkDelete, db: DB, user: CurrentUser
) -> BulkDeleteResponse:
    if not body.ids:
        return BulkDeleteResponse(deleted=0, not_found=[])
    rows = (
        (
            await db.execute(
                select(OverlayNetwork).where(
                    OverlayNetwork.id.in_(body.ids),
                    OverlayNetwork.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    found_ids = {r.id for r in rows}
    not_found = [str(i) for i in body.ids if i not in found_ids]
    for r in rows:
        await _trash(db, r, user)
        write_audit(
            db,
            user=user,
            action="delete",
            resource_type="overlay_network",
            resource_id=str(r.id),
            resource_display=r.name,
        )
    await db.commit()
    return BulkDeleteResponse(deleted=len(rows), not_found=not_found)


# ── Site membership CRUD ────────────────────────────────────────────


async def _validate_overlay_site_fks(
    db: Any, body: OverlaySiteCreate | OverlaySiteUpdate, overlay_id: uuid.UUID
) -> None:
    """Resolve every FK + check the preferred_circuits list.

    Loose: missing circuit IDs in ``preferred_circuits`` are rejected,
    but soft-deleted ones are allowed since operators may want to keep
    a historical entry that the simulate endpoint will treat as "down".
    """
    site_id = getattr(body, "site_id", None)
    if site_id is not None:
        site = await db.get(Site, site_id)
        if site is None:
            raise HTTPException(status_code=422, detail="site_id not found")

    device_id = getattr(body, "device_id", None)
    if device_id is not None:
        dev = await db.get(NetworkDevice, device_id)
        if dev is None:
            raise HTTPException(status_code=422, detail="device_id not found")

    loopback_subnet_id = getattr(body, "loopback_subnet_id", None)
    if loopback_subnet_id is not None:
        from app.models.ipam import Subnet  # noqa: PLC0415

        sn = await db.get(Subnet, loopback_subnet_id)
        if sn is None or getattr(sn, "deleted_at", None) is not None:
            raise HTTPException(status_code=422, detail="loopback_subnet_id not found")

    preferred = getattr(body, "preferred_circuits", None)
    if preferred:
        # Circuit is outside the global soft-delete filter (``app.db``), so
        # a deleted circuit is excluded here by hand: it is "not found" (#3191).
        rows = (
            (
                await db.execute(
                    select(Circuit).where(Circuit.id.in_(preferred), Circuit.deleted_at.is_(None))
                )
            )
            .scalars()
            .all()
        )
        found = {r.id for r in rows}
        missing = [str(c) for c in preferred if c not in found]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"preferred_circuits ids not found: {missing}",
            )

    # Side-effect-free use of overlay_id parameter — caller already
    # asserted the overlay exists; we accept it here so a future
    # cross-overlay validator (e.g. circuit-belongs-to-this-customer)
    # has a hook without changing the signature.
    _ = overlay_id


@router.get("/{overlay_id:uuid}/sites", response_model=list[OverlaySiteRead])
async def list_overlay_sites(
    overlay_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[OverlaySiteRead]:
    await _get_overlay(db, overlay_id)
    rows = (
        (
            await db.execute(
                select(OverlaySite)
                .where(OverlaySite.overlay_network_id == overlay_id)
                .order_by(OverlaySite.role.asc(), OverlaySite.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return [OverlaySiteRead.model_validate(r) for r in rows]


@router.post(
    "/{overlay_id:uuid}/sites",
    response_model=OverlaySiteRead,
    status_code=status.HTTP_201_CREATED,
)
async def attach_site(
    overlay_id: uuid.UUID,
    body: OverlaySiteCreate,
    db: DB,
    user: CurrentUser,
) -> OverlaySiteRead:
    overlay = await _get_overlay(db, overlay_id)
    await _validate_overlay_site_fks(db, body, overlay_id)

    existing = await db.scalar(
        select(OverlaySite).where(
            OverlaySite.overlay_network_id == overlay_id,
            OverlaySite.site_id == body.site_id,
        )
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"site {body.site_id} already attached to overlay '{overlay.name}'",
        )

    row = OverlaySite(
        overlay_network_id=overlay_id,
        site_id=body.site_id,
        role=body.role,
        device_id=body.device_id,
        loopback_subnet_id=body.loopback_subnet_id,
        preferred_circuits=[str(c) for c in body.preferred_circuits],
        notes=body.notes,
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="overlay_site",
        resource_id=str(row.id),
        resource_display=f"{overlay.name}::site::{body.site_id}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return OverlaySiteRead.model_validate(row)


@router.put(
    "/{overlay_id:uuid}/sites/{overlay_site_id:uuid}",
    response_model=OverlaySiteRead,
)
async def update_overlay_site(
    overlay_id: uuid.UUID,
    overlay_site_id: uuid.UUID,
    body: OverlaySiteUpdate,
    db: DB,
    user: CurrentUser,
) -> OverlaySiteRead:
    overlay = await _get_overlay(db, overlay_id)
    row = await db.get(OverlaySite, overlay_site_id)
    if row is None or row.overlay_network_id != overlay_id:
        raise HTTPException(status_code=404, detail="Overlay site not found")
    await _validate_overlay_site_fks(db, body, overlay_id)
    changes = body.model_dump(exclude_unset=True)
    if "role" in changes and changes["role"] not in OVERLAY_SITE_ROLES:
        raise HTTPException(
            status_code=422, detail=f"role must be one of {sorted(OVERLAY_SITE_ROLES)}"
        )
    if "preferred_circuits" in changes and changes["preferred_circuits"] is not None:
        changes["preferred_circuits"] = [str(c) for c in changes["preferred_circuits"]]
    for k, v in changes.items():
        setattr(row, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="overlay_site",
        resource_id=str(row.id),
        resource_display=f"{overlay.name}::site::{row.site_id}",
        changed_fields=list(changes.keys()),
    )
    await db.commit()
    await db.refresh(row)
    return OverlaySiteRead.model_validate(row)


@router.delete(
    "/{overlay_id:uuid}/sites/{overlay_site_id:uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def detach_site(
    overlay_id: uuid.UUID,
    overlay_site_id: uuid.UUID,
    db: DB,
    user: CurrentUser,
) -> None:
    overlay = await _get_overlay(db, overlay_id)
    row = await db.get(OverlaySite, overlay_site_id)
    if row is None or row.overlay_network_id != overlay_id:
        raise HTTPException(status_code=404, detail="Overlay site not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="overlay_site",
        resource_id=str(row.id),
        resource_display=f"{overlay.name}::site::{row.site_id}",
    )
    await db.delete(row)
    await db.commit()


# ── Routing policy CRUD ─────────────────────────────────────────────


@router.get("/{overlay_id:uuid}/policies", response_model=list[RoutingPolicyRead])
async def list_policies(overlay_id: uuid.UUID, db: DB, _: CurrentUser) -> list[RoutingPolicyRead]:
    await _get_overlay(db, overlay_id)
    rows = (
        (
            await db.execute(
                select(RoutingPolicy)
                .where(RoutingPolicy.overlay_network_id == overlay_id)
                .order_by(
                    RoutingPolicy.priority.asc(),
                    RoutingPolicy.created_at.asc(),
                )
            )
        )
        .scalars()
        .all()
    )
    return [RoutingPolicyRead.model_validate(r) for r in rows]


@router.post(
    "/{overlay_id:uuid}/policies",
    response_model=RoutingPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_policy(
    overlay_id: uuid.UUID,
    body: RoutingPolicyCreate,
    db: DB,
    user: CurrentUser,
) -> RoutingPolicyRead:
    overlay = await _get_overlay(db, overlay_id)
    await _validate_match(db, body.match_kind, body.match_value)
    row = RoutingPolicy(
        overlay_network_id=overlay_id,
        name=body.name,
        priority=body.priority,
        match_kind=body.match_kind,
        match_value=body.match_value.strip(),
        action=body.action,
        action_target=body.action_target,
        enabled=body.enabled,
        notes=body.notes,
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="routing_policy",
        resource_id=str(row.id),
        resource_display=f"{overlay.name}::{row.name}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return RoutingPolicyRead.model_validate(row)


@router.put(
    "/{overlay_id:uuid}/policies/{policy_id:uuid}",
    response_model=RoutingPolicyRead,
)
async def update_policy(
    overlay_id: uuid.UUID,
    policy_id: uuid.UUID,
    body: RoutingPolicyUpdate,
    db: DB,
    user: CurrentUser,
) -> RoutingPolicyRead:
    overlay = await _get_overlay(db, overlay_id)
    row = await db.get(RoutingPolicy, policy_id)
    if row is None or row.overlay_network_id != overlay_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    changes = body.model_dump(exclude_unset=True)
    if "match_kind" in changes and changes["match_kind"] not in ROUTING_POLICY_MATCH_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"match_kind must be one of {sorted(ROUTING_POLICY_MATCH_KINDS)}",
        )
    if "action" in changes and changes["action"] not in ROUTING_POLICY_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"action must be one of {sorted(ROUTING_POLICY_ACTIONS)}",
        )
    # Re-validate match if kind or value changed.
    new_match_kind = changes.get("match_kind", row.match_kind)
    new_match_value = changes.get("match_value", row.match_value)
    if "match_kind" in changes or "match_value" in changes:
        await _validate_match(db, new_match_kind, new_match_value)
    for k, v in changes.items():
        setattr(row, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="routing_policy",
        resource_id=str(row.id),
        resource_display=f"{overlay.name}::{row.name}",
        changed_fields=list(changes.keys()),
    )
    await db.commit()
    await db.refresh(row)
    return RoutingPolicyRead.model_validate(row)


@router.delete(
    "/{overlay_id:uuid}/policies/{policy_id:uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_policy(
    overlay_id: uuid.UUID,
    policy_id: uuid.UUID,
    db: DB,
    user: CurrentUser,
) -> None:
    overlay = await _get_overlay(db, overlay_id)
    row = await db.get(RoutingPolicy, policy_id)
    if row is None or row.overlay_network_id != overlay_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="routing_policy",
        resource_id=str(row.id),
        resource_display=f"{overlay.name}::{row.name}",
    )
    await db.delete(row)
    await db.commit()


# ── Topology + simulate ─────────────────────────────────────────────


def _coerce_uuid_list(raw: Any) -> list[uuid.UUID]:
    """``preferred_circuits`` is JSONB on the wire — strings come back
    as ``str``, not ``uuid.UUID``. Coerce defensively + skip malformed
    entries so a stray bad value doesn't blow up topology rendering.
    """
    out: list[uuid.UUID] = []
    if not isinstance(raw, list):
        return out
    for entry in raw:
        try:
            out.append(uuid.UUID(str(entry)))
        except (ValueError, TypeError):
            continue
    return out


@router.get("/{overlay_id:uuid}/topology", response_model=TopologyResponse)
async def get_topology(overlay_id: uuid.UUID, db: DB, _: CurrentUser) -> TopologyResponse:
    overlay = await _get_overlay(db, overlay_id)
    overlay_read = await _read_overlay(db, overlay)

    overlay_sites = (
        (await db.execute(select(OverlaySite).where(OverlaySite.overlay_network_id == overlay_id)))
        .scalars()
        .all()
    )

    # Bulk-fetch sites + devices to avoid N+1.
    site_ids = {os_.site_id for os_ in overlay_sites}
    sites_by_id: dict[uuid.UUID, Site] = {}
    if site_ids:
        sites_by_id = {
            s.id: s
            for s in (await db.execute(select(Site).where(Site.id.in_(site_ids)))).scalars().all()
        }

    device_ids = {os_.device_id for os_ in overlay_sites if os_.device_id is not None}
    devices_by_id: dict[uuid.UUID, NetworkDevice] = {}
    if device_ids:
        devices_by_id = {
            d.id: d
            for d in (
                await db.execute(select(NetworkDevice).where(NetworkDevice.id.in_(device_ids)))
            )
            .scalars()
            .all()
        }

    nodes: list[TopologyNode] = []
    for os_ in overlay_sites:
        site = sites_by_id.get(os_.site_id)
        device = devices_by_id.get(os_.device_id) if os_.device_id else None
        nodes.append(
            TopologyNode(
                overlay_site_id=os_.id,
                site_id=os_.site_id,
                site_name=site.name if site else "<deleted>",
                site_code=site.code if site else None,
                role=os_.role,
                device_id=os_.device_id,
                device_name=device.hostname if device else None,
                preferred_circuits=_coerce_uuid_list(os_.preferred_circuits),
            )
        )

    # Build undirected edges: site pairs whose preferred_circuits sets
    # intersect. Iterate combinations naively — overlay site counts are
    # small (10s, occasionally 100s), not a scaling concern.
    edges: list[TopologyEdge] = []
    for i, a in enumerate(overlay_sites):
        a_circuits = set(_coerce_uuid_list(a.preferred_circuits))
        if not a_circuits:
            continue
        for b in overlay_sites[i + 1 :]:
            b_circuits = set(_coerce_uuid_list(b.preferred_circuits))
            shared = sorted(a_circuits & b_circuits)
            if shared:
                edges.append(
                    TopologyEdge(
                        a_overlay_site_id=a.id,
                        z_overlay_site_id=b.id,
                        shared_circuits=shared,
                    )
                )

    policies = (
        (
            await db.execute(
                select(RoutingPolicy)
                .where(RoutingPolicy.overlay_network_id == overlay_id)
                .order_by(RoutingPolicy.priority.asc())
            )
        )
        .scalars()
        .all()
    )

    return TopologyResponse(
        overlay=overlay_read,
        nodes=nodes,
        edges=edges,
        policies=[RoutingPolicyRead.model_validate(p) for p in policies],
    )


@router.post("/{overlay_id:uuid}/simulate", response_model=SimulateResponse)
async def simulate(
    overlay_id: uuid.UUID,
    body: SimulateRequest,
    db: DB,
    _: CurrentUser,
) -> SimulateResponse:
    """Pure read-only what-if. ``down_circuits`` removes those UUIDs
    from every site's preferred-circuit chain before resolving each
    policy. The simulation never writes — operators get to see
    consequences without touching real config.
    """
    overlay = await _get_overlay(db, overlay_id)
    down: set[uuid.UUID] = set(body.down_circuits)

    overlay_sites = (
        (await db.execute(select(OverlaySite).where(OverlaySite.overlay_network_id == overlay_id)))
        .scalars()
        .all()
    )
    sites_by_id = {os_.site_id: os_ for os_ in overlay_sites}

    site_id_to_site = {
        s.id: s
        for s in (await db.execute(select(Site).where(Site.id.in_(sites_by_id.keys()))))
        .scalars()
        .all()
    }

    # Gather every circuit referenced anywhere in the overlay so we
    # can resolve names / transport classes without N+1.
    all_circuit_ids: set[uuid.UUID] = set()
    for os_ in overlay_sites:
        all_circuit_ids.update(_coerce_uuid_list(os_.preferred_circuits))
    circuits_by_id: dict[uuid.UUID, Circuit] = {}
    if all_circuit_ids:
        circuits_by_id = {
            c.id: c
            for c in (
                await db.execute(
                    # A deleted circuit resolves to no name, as a purged one
                    # does (#3191): Circuit is outside the global filter.
                    select(Circuit).where(
                        Circuit.id.in_(all_circuit_ids), Circuit.deleted_at.is_(None)
                    )
                )
            )
            .scalars()
            .all()
        }

    site_resolutions: list[SimulatedSiteResolution] = []
    for os_ in overlay_sites:
        original = _coerce_uuid_list(os_.preferred_circuits)
        survivors = [c for c in original if c not in down]
        primary = survivors[0] if survivors else None
        primary_circuit = circuits_by_id.get(primary) if primary else None
        site_resolutions.append(
            SimulatedSiteResolution(
                overlay_site_id=os_.id,
                site_name=(
                    site_id_to_site[os_.site_id].name
                    if os_.site_id in site_id_to_site
                    else "<deleted>"
                ),
                original_preferred_circuits=original,
                surviving_preferred_circuits=survivors,
                primary_circuit=primary,
                primary_circuit_name=primary_circuit.name if primary_circuit else None,
                primary_transport_class=(
                    primary_circuit.transport_class if primary_circuit else None
                ),
                blackholed=primary is None and bool(original),
            )
        )

    policies = (
        (
            await db.execute(
                select(RoutingPolicy)
                .where(RoutingPolicy.overlay_network_id == overlay_id)
                .order_by(RoutingPolicy.priority.asc())
            )
        )
        .scalars()
        .all()
    )

    policy_resolutions: list[SimulatedPolicyResolution] = []
    for p in policies:
        impacted = False
        effective_target = p.action_target
        note: str | None = None

        if p.action == "steer_to_circuit" and p.action_target:
            try:
                target_uuid = uuid.UUID(p.action_target)
            except ValueError:
                target_uuid = None
            if target_uuid is not None and target_uuid in down:
                impacted = True
                effective_target = None
                note = (
                    f"target circuit {target_uuid} is down — falls through to "
                    f"default_path_strategy={overlay.default_path_strategy}"
                )

        elif p.action == "steer_to_transport_class":
            # Find the first surviving circuit per site whose transport
            # matches the target class. We only flag the policy as
            # impacted if at least one site's previously-matching
            # circuit is now down (i.e. a real change in resolution).
            target_class = p.action_target
            for os_ in overlay_sites:
                original = _coerce_uuid_list(os_.preferred_circuits)
                # Did we previously match anything?
                prev_match = next(
                    (
                        c
                        for c in original
                        if circuits_by_id.get(c)
                        and circuits_by_id[c].transport_class == target_class
                    ),
                    None,
                )
                if prev_match is None:
                    continue
                survivors = [
                    c
                    for c in original
                    if c not in down
                    and circuits_by_id.get(c)
                    and circuits_by_id[c].transport_class == target_class
                ]
                if prev_match in down and survivors:
                    impacted = True
                    note = (
                        f"site {os_.site_id}: primary {target_class} circuit down, "
                        f"falling to next ({survivors[0]})"
                    )
                    break
                if prev_match in down and not survivors:
                    impacted = True
                    note = (
                        f"site {os_.site_id}: no surviving {target_class} circuit "
                        f"— policy falls through to default_path_strategy"
                    )
                    break

        # drop / shape / mark_dscp / steer_to_site_via_path / acl
        # don't depend on per-circuit availability — leave impacted=False.

        policy_resolutions.append(
            SimulatedPolicyResolution(
                policy_id=p.id,
                policy_name=p.name,
                action=p.action,
                original_target=p.action_target,
                effective_target=effective_target,
                impacted=impacted,
                note=note,
            )
        )

    return SimulateResponse(
        overlay_id=overlay_id,
        down_circuits=sorted(down),
        site_resolutions=site_resolutions,
        policy_resolutions=policy_resolutions,
    )


__all__ = ["router"]
