"""Service catalog CRUD — issue #94.

A ``NetworkService`` bundles a customer-deliverable: a VRF + edge
sites + edge circuits sold to one customer (the L3VPN shape), or any
free-form bag of resources (the ``custom`` shape). Other kinds (DIA,
hosted DNS / DHCP, SD-WAN) reserve names in the application enum and
will gain dedicated summary endpoints + validators in later phases.

Permissions: every endpoint is gated on ``network_service`` (admin via
the seeded Network Editor + IPAM Editor builtin roles; superadmin
always passes). A service also points at rows of other types (VRFs,
circuits, sites, subnets, ...) that each have their own router and
their own ``read`` grant, so attaching one needs read on that row, and
the summary fills a section only with rows the caller may read; the
rest are counted in ``withheld``. Each mutation writes an
``audit_log`` row before commit per CLAUDE.md non-negotiable #4.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.api.v1._common import BulkDeleteResponse
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission, user_has_permission
from app.models.circuit import Circuit
from app.models.dhcp import DHCPScope
from app.models.dns import DNSZone
from app.models.ipam import IPBlock, Subnet
from app.models.network_service import (
    RESOURCE_KINDS,
    SERVICE_KINDS_V1,
    SERVICE_STATUSES,
    NetworkService,
    NetworkServiceResource,
)
from app.models.overlay import OverlayNetwork
from app.models.ownership import Customer, Site
from app.models.vrf import VRF
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["services"],
    dependencies=[Depends(require_resource_permission("network_service"))],
)


ServiceKind = Literal["mpls_l3vpn", "sdwan", "custom"]
ServiceStatus = Literal["active", "provisioning", "suspended", "decom"]
ResourceKind = Literal[
    "vrf",
    "subnet",
    "ip_block",
    "dns_zone",
    "dhcp_scope",
    "circuit",
    "overlay_network",
    "site",
]


# Map resource_kind → SQLAlchemy model. ``overlay_network`` lit up
# alongside #95 — services can now bundle an SD-WAN overlay as the
# central deliverable for ``kind=sdwan`` services.
_KIND_MODEL: dict[str, Any] = {
    "vrf": VRF,
    "subnet": Subnet,
    "ip_block": IPBlock,
    "dns_zone": DNSZone,
    "dhcp_scope": DHCPScope,
    "circuit": Circuit,
    "site": Site,
    "overlay_network": OverlayNetwork,
}


# ── Schemas ─────────────────────────────────────────────────────────


class ServiceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    kind: ServiceKind = "custom"
    customer_id: uuid.UUID
    status: ServiceStatus = "provisioning"
    term_start_date: date | None = None
    term_end_date: date | None = None
    monthly_cost_usd: Decimal | None = None
    currency: str = Field(default="USD", min_length=3, max_length=3)
    sla_tier: str | None = Field(default=None, max_length=32)
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in SERVICE_KINDS_V1:
            raise ValueError(f"kind must be one of {sorted(SERVICE_KINDS_V1)}")
        return v

    @field_validator("status")
    @classmethod
    def _v_status(cls, v: str) -> str:
        if v not in SERVICE_STATUSES:
            raise ValueError(f"status must be one of {sorted(SERVICE_STATUSES)}")
        return v

    @field_validator("currency")
    @classmethod
    def _v_currency(cls, v: str) -> str:
        return v.strip().upper()


class ServiceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    kind: ServiceKind | None = None
    customer_id: uuid.UUID | None = None
    status: ServiceStatus | None = None
    term_start_date: date | None = None
    term_end_date: date | None = None
    monthly_cost_usd: Decimal | None = None
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    sla_tier: str | None = Field(default=None, max_length=32)
    notes: str | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None


class ResourceAttach(BaseModel):
    resource_kind: ResourceKind
    resource_id: uuid.UUID
    role: str | None = Field(default=None, max_length=64)


class ResourceRead(BaseModel):
    id: uuid.UUID
    service_id: uuid.UUID
    resource_kind: str
    resource_id: uuid.UUID
    role: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ServiceRead(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    customer_id: uuid.UUID
    status: str
    term_start_date: date | None
    term_end_date: date | None
    monthly_cost_usd: Decimal | None
    currency: str
    sla_tier: str | None
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime
    resources: list[ResourceRead] = Field(default_factory=list)
    resource_count: int = 0

    model_config = {"from_attributes": True}


class ServiceListResponse(BaseModel):
    items: list[ServiceRead]
    total: int
    limit: int
    offset: int


class ServiceBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


# Summary view payloads. Kind-specific shapes; the router picks one
# based on ``service.kind``.


class L3VPNVrfSummary(BaseModel):
    id: uuid.UUID
    name: str
    route_distinguisher: str | None
    import_targets: list[str]
    export_targets: list[str]


class L3VPNSiteSummary(BaseModel):
    id: uuid.UUID
    name: str
    code: str | None
    role: str | None


class L3VPNCircuitSummary(BaseModel):
    id: uuid.UUID
    name: str
    ckt_id: str | None
    transport_class: str
    bandwidth_mbps_down: int
    bandwidth_mbps_up: int
    role: str | None


class L3VPNSubnetSummary(BaseModel):
    id: uuid.UUID
    cidr: str
    vrf_id: uuid.UUID | None
    role: str | None


L3VPNSection = Literal["vrf", "edge_sites", "edge_circuits", "edge_subnets"]


class L3VPNSummary(BaseModel):
    kind: Literal["mpls_l3vpn"] = "mpls_l3vpn"
    vrf: L3VPNVrfSummary | None
    edge_sites: list[L3VPNSiteSummary]
    edge_circuits: list[L3VPNCircuitSummary]
    edge_subnets: list[L3VPNSubnetSummary]
    warnings: list[str]
    # Section -> number of attached rows left out because the caller has no
    # ``read`` grant on them (``vrf`` / ``site`` / ``circuit`` / ``subnet``).
    # Those rows carry nothing in the answer: no name, id or value. A
    # section absent from the map was shown in full.
    withheld: dict[L3VPNSection, int] = Field(default_factory=dict)


class CustomGroupedSummary(BaseModel):
    kind: Literal["custom"] = "custom"
    by_kind: dict[str, int]
    resources: list[ResourceRead]


# ── Helpers ─────────────────────────────────────────────────────────


async def _check_customer(db: Any, customer_id: uuid.UUID) -> Customer:
    customer = await db.get(Customer, customer_id)
    if customer is None or customer.deleted_at is not None:
        raise HTTPException(status_code=422, detail="customer_id not found")
    return customer


async def _load_resources(db: Any, service_id: uuid.UUID) -> list[NetworkServiceResource]:
    rows = (
        (
            await db.execute(
                select(NetworkServiceResource)
                .where(NetworkServiceResource.service_id == service_id)
                .order_by(NetworkServiceResource.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


def _to_read(svc: NetworkService, resources: list[NetworkServiceResource]) -> ServiceRead:
    return ServiceRead(
        id=svc.id,
        name=svc.name,
        kind=svc.kind,
        customer_id=svc.customer_id,
        status=svc.status,
        term_start_date=svc.term_start_date,
        term_end_date=svc.term_end_date,
        monthly_cost_usd=svc.monthly_cost_usd,
        currency=svc.currency,
        sla_tier=svc.sla_tier,
        notes=svc.notes,
        tags=svc.tags or {},
        custom_fields=svc.custom_fields or {},
        created_at=svc.created_at,
        modified_at=svc.modified_at,
        resources=[ResourceRead.model_validate(r) for r in resources],
        resource_count=len(resources),
    )


async def _validate_attach_target(db: Any, user: Any, kind: str, resource_id: uuid.UUID) -> Any:
    """Resolve the target row for an attach; raise 422 on miss.

    ``overlay_network`` lit up alongside #95 and is now a real attach
    target (services bundle overlays the same way they bundle VRFs /
    circuits).

    The caller must hold ``read`` on the attached row (each resource kind
    is also its permission resource type). Attaching links the row to the
    service, and the service summary shows it back, so a row the caller
    may not read through its own router may not be attached either. The
    grant is checked before the row is looked up, so the answer does not
    say whether an id the caller may not read exists.
    """
    model = _KIND_MODEL.get(kind)
    if model is None:
        raise HTTPException(status_code=422, detail=f"unknown resource_kind: {kind}")
    if not user_has_permission(user, "read", kind, resource_id):
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied: need 'read' on '{kind}' to attach it",
        )
    row = await db.get(model, resource_id)
    if row is None or getattr(row, "deleted_at", None) is not None:
        raise HTTPException(status_code=422, detail=f"{kind} {resource_id} not found")
    return row


async def _enforce_l3vpn_invariants_on_attach(
    db: Any,
    service: NetworkService,
    new_kind: str,
    new_resource_id: uuid.UUID,
) -> None:
    """Hard rule: an ``mpls_l3vpn`` service has at most one VRF.

    The SHOULD checks (≥2 edge sites, edge subnet VRF match) are
    surfaced through ``GET /summary`` as warnings rather than blocked
    here so an operator can stage changes without fighting validation.
    """
    if service.kind != "mpls_l3vpn" or new_kind != "vrf":
        return
    existing = await db.scalar(
        select(func.count(NetworkServiceResource.id)).where(
            NetworkServiceResource.service_id == service.id,
            NetworkServiceResource.resource_kind == "vrf",
            NetworkServiceResource.resource_id != new_resource_id,
        )
    )
    if (existing or 0) >= 1:
        raise HTTPException(
            status_code=422,
            detail="mpls_l3vpn services may have at most one VRF attached",
        )


async def _enforce_l3vpn_invariants_on_kind_change(
    db: Any, service: NetworkService, new_kind: str
) -> None:
    """When kind flips to ``mpls_l3vpn`` the existing resource set
    must already satisfy the at-most-one-VRF rule. We don't auto-prune
    — fail loudly so the operator confirms the data shape."""
    if new_kind != "mpls_l3vpn":
        return
    vrf_count = await db.scalar(
        select(func.count(NetworkServiceResource.id)).where(
            NetworkServiceResource.service_id == service.id,
            NetworkServiceResource.resource_kind == "vrf",
        )
    )
    if (vrf_count or 0) > 1:
        raise HTTPException(
            status_code=422,
            detail=(
                "cannot switch to mpls_l3vpn while >1 VRF is attached — " "detach extra VRFs first"
            ),
        )


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=ServiceListResponse)
async def list_services(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    customer_id: uuid.UUID | None = Query(default=None),
    kind: ServiceKind | None = Query(default=None),
    status: ServiceStatus | None = Query(default=None),
    expiring_within_days: int | None = Query(default=None, ge=0, le=3650),
    search: str | None = Query(default=None, description="Case-insensitive substring on name."),
    tag: list[str] = Query(default_factory=list),
) -> ServiceListResponse:
    stmt = select(NetworkService).where(NetworkService.deleted_at.is_(None))
    if customer_id is not None:
        stmt = stmt.where(NetworkService.customer_id == customer_id)
    if kind is not None:
        stmt = stmt.where(NetworkService.kind == kind)
    if status is not None:
        stmt = stmt.where(NetworkService.status == status)
    if expiring_within_days is not None:
        cutoff = date.today() + timedelta(days=expiring_within_days)
        stmt = stmt.where(NetworkService.term_end_date.is_not(None)).where(
            NetworkService.term_end_date <= cutoff
        )
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(NetworkService.name.ilike(needle))
    stmt = apply_tag_filter(stmt, NetworkService.tags, tag)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(NetworkService.name.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()

    if not rows:
        return ServiceListResponse(items=[], total=total, limit=limit, offset=offset)

    # One bulk fetch of resources keyed by service_id avoids the N+1.
    ids = [r.id for r in rows]
    res_rows = (
        (
            await db.execute(
                select(NetworkServiceResource).where(NetworkServiceResource.service_id.in_(ids))
            )
        )
        .scalars()
        .all()
    )
    by_service: dict[uuid.UUID, list[NetworkServiceResource]] = {}
    for rr in res_rows:
        by_service.setdefault(rr.service_id, []).append(rr)

    return ServiceListResponse(
        items=[_to_read(r, by_service.get(r.id, [])) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=ServiceRead, status_code=status.HTTP_201_CREATED)
async def create_service(body: ServiceCreate, db: DB, user: CurrentUser) -> ServiceRead:
    await _check_customer(db, body.customer_id)

    row = NetworkService(
        name=body.name,
        kind=body.kind,
        customer_id=body.customer_id,
        status=body.status,
        term_start_date=body.term_start_date,
        term_end_date=body.term_end_date,
        monthly_cost_usd=body.monthly_cost_usd,
        currency=body.currency,
        sla_tier=body.sla_tier,
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
        resource_type="network_service",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row, [])


@router.get("/{service_id:uuid}", response_model=ServiceRead)
async def get_service(service_id: uuid.UUID, db: DB, _: CurrentUser) -> ServiceRead:
    row = await db.get(NetworkService, service_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Service not found")
    resources = await _load_resources(db, row.id)
    return _to_read(row, resources)


@router.put("/{service_id:uuid}", response_model=ServiceRead)
async def update_service(
    service_id: uuid.UUID,
    body: ServiceUpdate,
    db: DB,
    user: CurrentUser,
) -> ServiceRead:
    row = await db.get(NetworkService, service_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Service not found")

    if body.kind is not None and body.kind not in SERVICE_KINDS_V1:
        raise HTTPException(
            status_code=422, detail=f"kind must be one of {sorted(SERVICE_KINDS_V1)}"
        )
    if body.status is not None and body.status not in SERVICE_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"status must be one of {sorted(SERVICE_STATUSES)}"
        )
    if body.customer_id is not None:
        await _check_customer(db, body.customer_id)
    if body.kind is not None and body.kind != row.kind:
        await _enforce_l3vpn_invariants_on_kind_change(db, row, body.kind)

    changes = body.model_dump(exclude_unset=True)
    if "currency" in changes and changes["currency"]:
        changes["currency"] = changes["currency"].strip().upper()

    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="network_service",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    resources = await _load_resources(db, row.id)
    return _to_read(row, resources)


@router.delete("/{service_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service(service_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Soft-delete the service. Join rows stay attached so a restore
    via the trash flow brings the bundle back intact; the
    ``service_resource_orphaned`` alert (Wave 2) ignores soft-deleted
    services."""
    row = await db.get(NetworkService, service_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Service not found")

    row.deleted_at = datetime.now(UTC)
    if user is not None:
        row.deleted_by_user_id = user.id

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="network_service",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.commit()


@router.post("/bulk-delete", response_model=BulkDeleteResponse)
async def bulk_delete_services(
    body: ServiceBulkDelete, db: DB, user: CurrentUser
) -> BulkDeleteResponse:
    if not body.ids:
        return BulkDeleteResponse(deleted=0, not_found=[])

    rows = (
        (
            await db.execute(
                select(NetworkService).where(
                    NetworkService.id.in_(body.ids),
                    NetworkService.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    found_ids = {r.id for r in rows}
    not_found = [str(i) for i in body.ids if i not in found_ids]

    now = datetime.now(UTC)
    for r in rows:
        r.deleted_at = now
        if user is not None:
            r.deleted_by_user_id = user.id
        write_audit(
            db,
            user=user,
            action="delete",
            resource_type="network_service",
            resource_id=str(r.id),
            resource_display=r.name,
        )
    await db.commit()
    return BulkDeleteResponse(deleted=len(rows), not_found=not_found)


# ── Resource attach / detach ────────────────────────────────────────


@router.post("/{service_id:uuid}/resources", response_model=ResourceRead)
async def attach_resource(
    service_id: uuid.UUID,
    body: ResourceAttach,
    db: DB,
    user: CurrentUser,
) -> ResourceRead:
    svc = await db.get(NetworkService, service_id)
    if svc is None or svc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Service not found")
    if body.resource_kind not in RESOURCE_KINDS:
        raise HTTPException(status_code=422, detail=f"unknown resource_kind: {body.resource_kind}")

    await _validate_attach_target(db, user, body.resource_kind, body.resource_id)
    await _enforce_l3vpn_invariants_on_attach(db, svc, body.resource_kind, body.resource_id)

    # Idempotent reattach: same (kind, id) returns the existing row.
    existing = await db.scalar(
        select(NetworkServiceResource).where(
            NetworkServiceResource.service_id == service_id,
            NetworkServiceResource.resource_kind == body.resource_kind,
            NetworkServiceResource.resource_id == body.resource_id,
        )
    )
    if existing is not None:
        if body.role is not None and body.role != existing.role:
            existing.role = body.role
            write_audit(
                db,
                user=user,
                action="update",
                resource_type="network_service_resource",
                resource_id=str(existing.id),
                resource_display=f"{svc.name}::{body.resource_kind}::{body.resource_id}",
                changed_fields=["role"],
            )
            await db.commit()
            await db.refresh(existing)
        return ResourceRead.model_validate(existing)

    row = NetworkServiceResource(
        service_id=service_id,
        resource_kind=body.resource_kind,
        resource_id=body.resource_id,
        role=body.role,
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="network_service_resource",
        resource_id=str(row.id),
        resource_display=f"{svc.name}::{body.resource_kind}::{body.resource_id}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return ResourceRead.model_validate(row)


@router.delete(
    "/{service_id:uuid}/resources/{resource_pk:uuid}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def detach_resource(
    service_id: uuid.UUID,
    resource_pk: uuid.UUID,
    db: DB,
    user: CurrentUser,
) -> None:
    """Detach by the join row's primary key (not the target's id) so
    the same target attached multiple times under different roles can
    be detached individually."""
    svc = await db.get(NetworkService, service_id)
    if svc is None or svc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Service not found")
    row = await db.get(NetworkServiceResource, resource_pk)
    if row is None or row.service_id != service_id:
        raise HTTPException(status_code=404, detail="Resource link not found")

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="network_service_resource",
        resource_id=str(row.id),
        resource_display=f"{svc.name}::{row.resource_kind}::{row.resource_id}",
    )
    await db.delete(row)
    await db.commit()


# ── Summary ─────────────────────────────────────────────────────────


@router.get("/{service_id:uuid}/summary")
async def get_service_summary(
    service_id: uuid.UUID, db: DB, user: CurrentUser
) -> L3VPNSummary | CustomGroupedSummary:
    """Kind-aware summary view.

    For ``mpls_l3vpn`` returns the canonical L3VPN shape (VRF + edge
    sites + edge circuits + edge subnets) with warnings for the SHOULD
    invariants. For ``custom`` returns resources grouped by kind plus
    the raw list. Other kinds (DIA / hosted-DNS / SD-WAN) will gain
    their own shapes when those kinds light up.

    The L3VPN sections carry rows of other types; each row is included
    only when the caller may read it through its own router, and the
    rows left out are counted in ``withheld``. The ``custom`` shape
    carries only the service's own link rows (kind + id), which are
    ``network_service`` data.
    """
    svc = await db.get(NetworkService, service_id)
    if svc is None or svc.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Service not found")
    resources = await _load_resources(db, svc.id)

    if svc.kind == "mpls_l3vpn":
        return await _l3vpn_summary(db, user, resources)

    # Default ``custom`` shape (also used as a fallback for kinds that
    # haven't grown their own summary yet).
    by_kind: dict[str, int] = {}
    for r in resources:
        by_kind[r.resource_kind] = by_kind.get(r.resource_kind, 0) + 1
    return CustomGroupedSummary(
        by_kind=by_kind,
        resources=[ResourceRead.model_validate(r) for r in resources],
    )


async def _l3vpn_summary(
    db: Any, user: Any, resources: list[NetworkServiceResource]
) -> L3VPNSummary:
    by_kind: dict[str, list[NetworkServiceResource]] = {}
    for r in resources:
        by_kind.setdefault(r.resource_kind, []).append(r)

    withheld: dict[L3VPNSection, int] = {}

    def _readable(section: L3VPNSection, resource_type: str, rid: uuid.UUID) -> bool:
        if user_has_permission(user, "read", resource_type, rid):
            return True
        withheld[section] = withheld.get(section, 0) + 1
        return False

    warnings: list[str] = []
    vrf_summary: L3VPNVrfSummary | None = None
    vrfs = by_kind.get("vrf", [])
    vrf_obj: VRF | None = None
    if len(vrfs) == 0:
        warnings.append("no VRF attached — L3VPN service must have exactly one VRF")
    elif len(vrfs) > 1:
        # Hard rule should make this unreachable; surface as a warning
        # if it ever does happen so an operator can clean up.
        warnings.append(f"{len(vrfs)} VRFs attached — L3VPN service must have exactly one")
    else:
        vrf_obj = await db.get(VRF, vrfs[0].resource_id)
        if vrf_obj is not None and _readable("vrf", "vrf", vrf_obj.id):
            vrf_summary = L3VPNVrfSummary(
                id=vrf_obj.id,
                name=vrf_obj.name,
                route_distinguisher=vrf_obj.route_distinguisher,
                import_targets=list(vrf_obj.import_targets or []),
                export_targets=list(vrf_obj.export_targets or []),
            )

    edge_sites: list[L3VPNSiteSummary] = []
    for link in by_kind.get("site", []):
        site = await db.get(Site, link.resource_id)
        if site is None:
            continue
        if not _readable("edge_sites", "site", site.id):
            continue
        edge_sites.append(
            L3VPNSiteSummary(id=site.id, name=site.name, code=site.code, role=link.role)
        )
    if len(edge_sites) + withheld.get("edge_sites", 0) < 2:
        warnings.append("fewer than 2 edge sites — single-site L3VPN is unusual")

    edge_circuits: list[L3VPNCircuitSummary] = []
    for link in by_kind.get("circuit", []):
        ckt = await db.get(Circuit, link.resource_id)
        if ckt is None or ckt.deleted_at is not None:
            continue
        if not _readable("edge_circuits", "circuit", ckt.id):
            continue
        edge_circuits.append(
            L3VPNCircuitSummary(
                id=ckt.id,
                name=ckt.name,
                ckt_id=ckt.ckt_id,
                transport_class=ckt.transport_class,
                bandwidth_mbps_down=ckt.bandwidth_mbps_down,
                bandwidth_mbps_up=ckt.bandwidth_mbps_up,
                role=link.role,
            )
        )

    edge_subnets: list[L3VPNSubnetSummary] = []
    for link in by_kind.get("subnet", []):
        sn = await db.get(Subnet, link.resource_id)
        if sn is None or getattr(sn, "deleted_at", None) is not None:
            continue
        if not _readable("edge_subnets", "subnet", sn.id):
            continue
        # If the subnet's enclosing block is in a VRF that doesn't
        # match the service VRF, that's a SHOULD-violation worth
        # flagging. Block.vrf_id lookup avoids loading the block here
        # — keep it lightweight and let the IPAM page show the full
        # picture when the operator clicks through.
        block_vrf_id: uuid.UUID | None = None
        # ``block_id`` — Subnet has no ``ip_block_id``, so this raised
        # AttributeError one line before the ``sn.cidr`` below and the L3VPN
        # summary 500'd for every service with a linked subnet (#923).
        if sn.block_id is not None:
            blk = await db.get(IPBlock, sn.block_id)
            if blk is not None:
                block_vrf_id = getattr(blk, "vrf_id", None)
        if vrf_obj is not None and block_vrf_id is not None and block_vrf_id != vrf_obj.id:
            # ``network``, not ``cidr`` — Subnet has no ``cidr`` column, so
            # this raised AttributeError and the L3VPN summary 500'd for any
            # service with a linked subnet whose block sits in another VRF.
            # Same #923 class as the copilot tools; a router building a
            # response row is a place neither new guard can see.
            warnings.append(f"subnet {sn.network} sits in a different VRF than the service VRF")
        edge_subnets.append(
            L3VPNSubnetSummary(
                id=sn.id,
                cidr=str(sn.network),
                vrf_id=block_vrf_id,
                role=link.role,
            )
        )

    return L3VPNSummary(
        vrf=vrf_summary,
        edge_sites=edge_sites,
        edge_circuits=edge_circuits,
        edge_subnets=edge_subnets,
        warnings=warnings,
        withheld=withheld,
    )


# ── Reverse-lookup convenience endpoint ─────────────────────────────


@router.get("/by-resource/{resource_kind}/{resource_id:uuid}", response_model=list[ServiceRead])
async def list_services_by_resource(
    resource_kind: ResourceKind,
    resource_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
) -> list[ServiceRead]:
    """Services that reference a given resource.

    Powers the right-click "Show services using this resource" entry
    point on VRF / Subnet / Circuit / Site / DNSZone / DHCPScope rows.
    """
    if resource_kind not in RESOURCE_KINDS:
        raise HTTPException(status_code=422, detail=f"unknown resource_kind: {resource_kind}")

    svc_ids = (
        (
            await db.execute(
                select(NetworkServiceResource.service_id).where(
                    NetworkServiceResource.resource_kind == resource_kind,
                    NetworkServiceResource.resource_id == resource_id,
                )
            )
        )
        .scalars()
        .all()
    )
    if not svc_ids:
        return []

    rows = (
        (
            await db.execute(
                select(NetworkService)
                .where(
                    NetworkService.id.in_(svc_ids),
                    NetworkService.deleted_at.is_(None),
                )
                .order_by(NetworkService.name.asc())
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return []

    res_rows = (
        (
            await db.execute(
                select(NetworkServiceResource).where(
                    NetworkServiceResource.service_id.in_([r.id for r in rows])
                )
            )
        )
        .scalars()
        .all()
    )
    by_service: dict[uuid.UUID, list[NetworkServiceResource]] = {}
    for rr in res_rows:
        by_service.setdefault(rr.service_id, []).append(rr)

    return [_to_read(r, by_service.get(r.id, [])) for r in rows]


__all__ = ["router"]
