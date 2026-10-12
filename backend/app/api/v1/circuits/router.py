"""Circuit CRUD — issue #93.

Carrier-supplied WAN circuits. Soft-deletable so ``status='decom'``
operates as the operator-visible end-of-life flag while the row's
history stays restorable for "what carrier did Site-X use in 2024?"
audits.

Permissions: every endpoint is gated on ``circuit`` (admin via the
seeded Network Editor builtin role; superadmin always passes). Each
mutation writes an ``audit_log`` row before commit per CLAUDE.md
non-negotiable #4.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1._common import BulkDeleteResponse
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.core.update_nulls import resolve_update_changes
from app.models.circuit import (
    CIRCUIT_STATUSES,
    TRANSPORT_CLASSES,
    Circuit,
)
from app.models.ownership import Customer, Provider, Site
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["circuits"],
    dependencies=[Depends(require_resource_permission("circuit"))],
)


TransportClass = Literal[
    "mpls",
    "internet_broadband",
    "fiber_direct",
    "wavelength",
    "lte",
    "satellite",
    "direct_connect_aws",
    "express_route_azure",
    "interconnect_gcp",
]
CircuitStatus = Literal["active", "pending", "suspended", "decom"]


# ── Schemas ─────────────────────────────────────────────────────────


class CircuitCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    ckt_id: str | None = Field(default=None, max_length=128)
    provider_id: uuid.UUID
    customer_id: uuid.UUID | None = None
    transport_class: TransportClass = "internet_broadband"
    bandwidth_mbps_down: int = Field(default=0, ge=0)
    bandwidth_mbps_up: int = Field(default=0, ge=0)
    a_end_site_id: uuid.UUID | None = None
    a_end_subnet_id: uuid.UUID | None = None
    z_end_site_id: uuid.UUID | None = None
    z_end_subnet_id: uuid.UUID | None = None
    term_start_date: date | None = None
    term_end_date: date | None = None
    monthly_cost: Decimal | None = None
    currency: str = Field(default="USD", min_length=3, max_length=3)
    status: CircuitStatus = "active"
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("transport_class")
    @classmethod
    def _v_transport(cls, v: str) -> str:
        if v not in TRANSPORT_CLASSES:
            raise ValueError(f"transport_class must be one of {sorted(TRANSPORT_CLASSES)}")
        return v

    @field_validator("status")
    @classmethod
    def _v_status(cls, v: str) -> str:
        if v not in CIRCUIT_STATUSES:
            raise ValueError(f"status must be one of {sorted(CIRCUIT_STATUSES)}")
        return v

    @field_validator("currency")
    @classmethod
    def _v_currency(cls, v: str) -> str:
        return v.strip().upper()


class CircuitUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    ckt_id: str | None = None
    provider_id: uuid.UUID | None = None
    customer_id: uuid.UUID | None = None
    transport_class: TransportClass | None = None
    bandwidth_mbps_down: int | None = Field(default=None, ge=0)
    bandwidth_mbps_up: int | None = Field(default=None, ge=0)
    a_end_site_id: uuid.UUID | None = None
    a_end_subnet_id: uuid.UUID | None = None
    z_end_site_id: uuid.UUID | None = None
    z_end_subnet_id: uuid.UUID | None = None
    term_start_date: date | None = None
    term_end_date: date | None = None
    monthly_cost: Decimal | None = None
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    status: CircuitStatus | None = None
    notes: str | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None


class CircuitRead(BaseModel):
    id: uuid.UUID
    name: str
    ckt_id: str | None
    provider_id: uuid.UUID
    customer_id: uuid.UUID | None
    transport_class: str
    bandwidth_mbps_down: int
    bandwidth_mbps_up: int
    a_end_site_id: uuid.UUID | None
    a_end_subnet_id: uuid.UUID | None
    z_end_site_id: uuid.UUID | None
    z_end_subnet_id: uuid.UUID | None
    term_start_date: date | None
    term_end_date: date | None
    monthly_cost: Decimal | None
    currency: str
    status: str
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    previous_status: str | None
    last_status_change_at: datetime | None
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class CircuitListResponse(BaseModel):
    items: list[CircuitRead]
    total: int
    limit: int
    offset: int


class CircuitBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


# ── Helpers ─────────────────────────────────────────────────────────


async def _check_provider(db: Any, provider_id: uuid.UUID) -> None:
    if (await db.get(Provider, provider_id)) is None:
        raise HTTPException(status_code=422, detail="provider_id not found")


async def _check_optional_fk(db: Any, model: Any, fk_id: uuid.UUID | None, label: str) -> None:
    if fk_id is None:
        return
    if (await db.get(model, fk_id)) is None:
        raise HTTPException(status_code=422, detail=f"{label} not found")


async def _check_fks(db: Any, body: CircuitCreate | CircuitUpdate) -> None:
    """Resolve every FK on the body in one place. ``provider_id`` is
    only checked when the operator actually supplied it (Update path
    leaves it None to mean "don't change"); Create's required-ness is
    enforced by the type system."""
    if body.provider_id is not None:
        await _check_provider(db, body.provider_id)
    await _check_optional_fk(db, Customer, body.customer_id, "customer_id")
    from app.models.ipam import Subnet  # noqa: PLC0415

    await _check_optional_fk(db, Site, body.a_end_site_id, "a_end_site_id")
    await _check_optional_fk(db, Subnet, body.a_end_subnet_id, "a_end_subnet_id")
    await _check_optional_fk(db, Site, body.z_end_site_id, "z_end_site_id")
    await _check_optional_fk(db, Subnet, body.z_end_subnet_id, "z_end_subnet_id")


def _stamp_status_transition(row: Circuit, new_status: str) -> None:
    """When status changes, snapshot the previous value + bump the
    transition timestamp. The deferred ``circuit_status_changed``
    alert rule reads these columns to decide whether to fire."""
    if new_status == row.status:
        return
    row.previous_status = row.status
    row.last_status_change_at = datetime.now(UTC)
    row.status = new_status


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=CircuitListResponse)
async def list_circuits(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    provider_id: uuid.UUID | None = Query(default=None),
    customer_id: uuid.UUID | None = Query(default=None),
    site_id: uuid.UUID | None = Query(
        default=None,
        description="Match either a-end OR z-end at this site.",
    ),
    subnet_id: uuid.UUID | None = Query(
        default=None,
        description="Match either a-end OR z-end on this subnet (the /30 or /31).",
    ),
    transport_class: TransportClass | None = Query(default=None),
    status: CircuitStatus | None = Query(default=None),
    expiring_within_days: int | None = Query(default=None, ge=0, le=3650),
    search: str | None = Query(
        default=None,
        description="Case-insensitive substring on name / ckt_id.",
    ),
    tag: list[str] = Query(default_factory=list),
) -> CircuitListResponse:
    stmt = select(Circuit).where(Circuit.deleted_at.is_(None))
    if provider_id is not None:
        stmt = stmt.where(Circuit.provider_id == provider_id)
    if customer_id is not None:
        stmt = stmt.where(Circuit.customer_id == customer_id)
    if site_id is not None:
        stmt = stmt.where(or_(Circuit.a_end_site_id == site_id, Circuit.z_end_site_id == site_id))
    if subnet_id is not None:
        stmt = stmt.where(
            or_(
                Circuit.a_end_subnet_id == subnet_id,
                Circuit.z_end_subnet_id == subnet_id,
            )
        )
    if transport_class is not None:
        stmt = stmt.where(Circuit.transport_class == transport_class)
    if status is not None:
        stmt = stmt.where(Circuit.status == status)
    if expiring_within_days is not None:
        cutoff = date.today() + timedelta(days=expiring_within_days)
        stmt = stmt.where(Circuit.term_end_date.is_not(None)).where(Circuit.term_end_date <= cutoff)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(or_(Circuit.name.ilike(needle), Circuit.ckt_id.ilike(needle)))
    stmt = apply_tag_filter(stmt, Circuit.tags, tag)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(Circuit.name.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return CircuitListResponse(
        items=[CircuitRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=CircuitRead, status_code=status.HTTP_201_CREATED)
async def create_circuit(body: CircuitCreate, db: DB, user: CurrentUser) -> CircuitRead:
    await _check_fks(db, body)

    row = Circuit(
        name=body.name,
        ckt_id=body.ckt_id,
        provider_id=body.provider_id,
        customer_id=body.customer_id,
        transport_class=body.transport_class,
        bandwidth_mbps_down=body.bandwidth_mbps_down,
        bandwidth_mbps_up=body.bandwidth_mbps_up,
        a_end_site_id=body.a_end_site_id,
        a_end_subnet_id=body.a_end_subnet_id,
        z_end_site_id=body.z_end_site_id,
        z_end_subnet_id=body.z_end_subnet_id,
        term_start_date=body.term_start_date,
        term_end_date=body.term_end_date,
        monthly_cost=body.monthly_cost,
        currency=body.currency,
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
        resource_type="circuit",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return CircuitRead.model_validate(row)


@router.get("/{circuit_id:uuid}", response_model=CircuitRead)
async def get_circuit(circuit_id: uuid.UUID, db: DB, _: CurrentUser) -> CircuitRead:
    row = await db.get(Circuit, circuit_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Circuit not found")
    return CircuitRead.model_validate(row)


@router.put("/{circuit_id:uuid}", response_model=CircuitRead)
async def update_circuit(
    circuit_id: uuid.UUID,
    body: CircuitUpdate,
    db: DB,
    user: CurrentUser,
) -> CircuitRead:
    row = await db.get(Circuit, circuit_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Circuit not found")

    # #1564 — resolve nulls BEFORE _check_fks / the status stamp: a null
    # ``status`` fed to _stamp_status_transition (or a null ``name`` /
    # ``provider_id`` reaching Postgres) was a 500; it is now a 422,
    # while null for a nullable FK / date / cost clears the column.
    changes = resolve_update_changes(
        body,
        clearable={
            "ckt_id",
            "customer_id",
            "a_end_site_id",
            "a_end_subnet_id",
            "z_end_site_id",
            "z_end_subnet_id",
            "term_start_date",
            "term_end_date",
            "monthly_cost",
        },
        non_nullable={
            "name",
            "provider_id",
            "transport_class",
            "bandwidth_mbps_down",
            "bandwidth_mbps_up",
            "currency",
            "status",
            "notes",
            "tags",
            "custom_fields",
        },
    )

    await _check_fks(db, body)

    if "status" in changes and changes["status"] != row.status:
        _stamp_status_transition(row, changes["status"])
        # ``_stamp_status_transition`` already set row.status; remove
        # from the generic setattr loop below to avoid clobbering the
        # transition snapshot.
        changes.pop("status")
    if "currency" in changes and changes["currency"]:
        changes["currency"] = changes["currency"].strip().upper()

    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="circuit",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return CircuitRead.model_validate(row)


@router.delete("/{circuit_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_circuit(circuit_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Soft-delete the row. The ``decom`` status flag is the
    operator-facing end-of-life signal; this endpoint is the harder
    "remove from list views entirely" action that still keeps the
    audit trail."""
    row = await db.get(Circuit, circuit_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Circuit not found")

    row.deleted_at = datetime.now(UTC)
    if user is not None:
        row.deleted_by_user_id = user.id

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="circuit",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.commit()


@router.post("/bulk-delete", response_model=BulkDeleteResponse)
async def bulk_delete_circuits(
    body: CircuitBulkDelete, db: DB, user: CurrentUser
) -> BulkDeleteResponse:
    if not body.ids:
        return BulkDeleteResponse(deleted=0, not_found=[])

    rows = (
        (
            await db.execute(
                select(Circuit).where(Circuit.id.in_(body.ids), Circuit.deleted_at.is_(None))
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
            resource_type="circuit",
            resource_id=str(r.id),
            resource_display=r.name,
        )
    await db.commit()
    return BulkDeleteResponse(deleted=len(rows), not_found=not_found)


# ── Site-scoped convenience endpoint ───────────────────────────────


@router.get("/by-site/{site_id:uuid}", response_model=list[CircuitRead])
async def list_circuits_by_site(site_id: uuid.UUID, db: DB, _: CurrentUser) -> list[CircuitRead]:
    """Circuits with either end at this site.

    Mounted under ``/circuits/by-site/{id}`` rather than
    ``/sites/{id}/circuits`` because the sites router lives in a
    separate module and we'd rather keep all circuit logic in one
    file. The frontend hits this endpoint when the operator opens a
    Site detail page or right-clicks a Site row.
    """
    if (await db.get(Site, site_id)) is None:
        raise HTTPException(status_code=404, detail="Site not found")

    stmt = (
        select(Circuit)
        .where(Circuit.deleted_at.is_(None))
        .where(or_(Circuit.a_end_site_id == site_id, Circuit.z_end_site_id == site_id))
        .order_by(Circuit.name.asc())
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [CircuitRead.model_validate(r) for r in rows]


__all__ = ["router"]
