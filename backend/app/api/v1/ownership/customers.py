"""Customer CRUD — issue #91.

Logical owner of network resources. Soft-deletable (``deleted_at``)
because operators commonly retire a customer but want the history
visible when triaging an "old subnet, who used to own this?" question.

Permissions: every endpoint is gated on ``customer`` (admin via the
seeded IPAM Editor + Network Editor roles; superadmin always passes).
Each mutation writes an ``audit_log`` row before commit per
CLAUDE.md non-negotiable #4.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1._common import BulkDeleteResponse
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.ownership import CUSTOMER_STATUSES, Customer

router = APIRouter(
    tags=["customers"],
    dependencies=[Depends(require_resource_permission("customer"))],
)


# ── Schemas ─────────────────────────────────────────────────────────


class CustomerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    account_number: str | None = Field(default=None, max_length=64)
    contact_email: str | None = Field(default=None, max_length=255)
    contact_phone: str | None = Field(default=None, max_length=64)
    contact_address: str | None = None
    status: Literal["active", "inactive", "decommissioning"] = "active"
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("status")
    @classmethod
    def _v_status(cls, v: str) -> str:
        if v not in CUSTOMER_STATUSES:
            raise ValueError(f"status must be one of {sorted(CUSTOMER_STATUSES)}")
        return v


class CustomerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    account_number: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    contact_address: str | None = None
    status: Literal["active", "inactive", "decommissioning"] | None = None
    notes: str | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None


class CustomerRead(BaseModel):
    id: uuid.UUID
    name: str
    account_number: str | None
    contact_email: str | None
    contact_phone: str | None
    contact_address: str | None
    status: str
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class CustomerListResponse(BaseModel):
    items: list[CustomerRead]
    total: int
    limit: int
    offset: int


class CustomerBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=CustomerListResponse)
async def list_customers(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Literal["active", "inactive", "decommissioning"] | None = Query(default=None),
    search: str | None = Query(
        default=None,
        description="Case-insensitive substring on name / account_number / contact_email.",
    ),
) -> CustomerListResponse:
    stmt = select(Customer).where(Customer.deleted_at.is_(None))
    if status is not None:
        stmt = stmt.where(Customer.status == status)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Customer.name.ilike(needle),
                Customer.account_number.ilike(needle),
                Customer.contact_email.ilike(needle),
            )
        )
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(Customer.name.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return CustomerListResponse(
        items=[CustomerRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=CustomerRead, status_code=status.HTTP_201_CREATED)
async def create_customer(body: CustomerCreate, db: DB, user: CurrentUser) -> CustomerRead:
    # Uniqueness on name is also enforced by ``uq_customer_name`` —
    # the explicit check fires a clean 409 instead of a 500
    # IntegrityError.
    existing = await db.scalar(
        select(Customer).where(Customer.name == body.name, Customer.deleted_at.is_(None))
    )
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Customer named {body.name!r} already exists")

    row = Customer(
        name=body.name,
        account_number=body.account_number,
        contact_email=body.contact_email,
        contact_phone=body.contact_phone,
        contact_address=body.contact_address,
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
        resource_type="customer",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return CustomerRead.model_validate(row)


@router.get("/{customer_id:uuid}", response_model=CustomerRead)
async def get_customer(customer_id: uuid.UUID, db: DB, _: CurrentUser) -> CustomerRead:
    row = await db.get(Customer, customer_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return CustomerRead.model_validate(row)


class CustomerOwnedResources(BaseModel):
    """Counts of what a customer owns, per resource type.

    Soft-deleted rows are excluded where the model supports it — a
    decommission check must not be blocked by resources already in the trash.
    """

    ip_spaces: int
    ip_blocks: int
    subnets: int
    circuits: int
    services: int
    asns: int
    dns_zones: int
    domains: int
    overlays: int


class CustomerSummary(BaseModel):
    """One customer plus everything it owns (issue #917).

    ``GET /customers/{id}`` returns the row; answering "is this customer safe
    to decommission?" from it meant nine list calls against nine routers. The
    copilot could already do this in one turn, which is exactly the asymmetry
    #917 catalogued.
    """

    id: uuid.UUID
    name: str
    account_number: str | None = None
    status: str
    contact_email: str | None = None
    contact_phone: str | None = None
    contact_address: str | None = None
    notes: str | None = None
    owned_resources: CustomerOwnedResources
    #: Sum across every bucket — the single number that answers "is anything
    #: still attached to this customer".
    owned_resource_total: int
    tags: dict[str, Any] = {}
    created_at: datetime | None = None


@router.get("/{customer_id:uuid}/summary", response_model=CustomerSummary)
async def get_customer_summary_route(
    customer_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> CustomerSummary:
    """A customer plus a count of every resource type it owns (#917)."""
    from app.services.ownership.customer_summary import (  # noqa: PLC0415
        build_customer_summary,
    )

    row = await db.get(Customer, customer_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found")
    return CustomerSummary.model_validate(await build_customer_summary(db, row))


@router.put("/{customer_id:uuid}", response_model=CustomerRead)
async def update_customer(
    customer_id: uuid.UUID, body: CustomerUpdate, db: DB, user: CurrentUser
) -> CustomerRead:
    row = await db.get(Customer, customer_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Customer not found")

    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] != row.name:
        clash = await db.scalar(
            select(Customer).where(
                Customer.name == changes["name"],
                Customer.id != customer_id,
                Customer.deleted_at.is_(None),
            )
        )
        if clash is not None:
            raise HTTPException(
                status_code=409, detail=f"Customer named {changes['name']!r} already exists"
            )
    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="customer",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return CustomerRead.model_validate(row)


async def _trash(db: Any, row: Customer, user: Any) -> None:
    """Soft-delete into the Trash (own batch), so it can be restored or purged (#2738)."""
    from app.services.soft_delete import (
        apply_soft_delete,
        collect_soft_delete_batch,
    )  # noqa: PLC0415

    batch = await collect_soft_delete_batch(db, row)
    await apply_soft_delete(db, batch, user.id if user is not None else None)


@router.delete("/{customer_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_customer(customer_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Soft-delete the row into Administration → Trash, where it can be
    restored or purged. Cross-references on subnets / blocks / VRFs
    / zones / ASNs auto-null via ``ON DELETE SET NULL`` once the row
    is *hard*-deleted; until then they keep pointing at the soft-
    deleted row, which is fine — list endpoints filter on
    ``deleted_at IS NULL`` so the operator sees them as "no
    customer".
    """
    row = await db.get(Customer, customer_id)
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Customer not found")
    await _trash(db, row, user)

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="customer",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.commit()


@router.post("/bulk-delete", response_model=BulkDeleteResponse)
async def bulk_delete_customers(
    body: CustomerBulkDelete, db: DB, user: CurrentUser
) -> BulkDeleteResponse:
    if not body.ids:
        return BulkDeleteResponse(deleted=0, not_found=[])

    rows = (
        (
            await db.execute(
                select(Customer).where(Customer.id.in_(body.ids), Customer.deleted_at.is_(None))
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
            resource_type="customer",
            resource_id=str(r.id),
            resource_display=r.name,
        )
    await db.commit()
    return BulkDeleteResponse(deleted=len(rows), not_found=not_found)


__all__ = ["router"]
