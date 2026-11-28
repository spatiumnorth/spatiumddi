"""Tenant CRUD and space assignment (#4263).

Superadmin only: a tenant is the boundary the rest of the permission model sits
inside, so defining one, putting spaces in it and binding groups to it are
platform operations a tenant user can never perform (these routes are not
tenant-aware, so a tenant user is refused before the superadmin check).
Enforcement itself does not depend on this module's feature flag: once a group
is bound to a tenant it is confined whether or not the module is on.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, SuperAdmin
from app.api.v1.ownership._audit import write_audit
from app.models.auth import APIToken, Group
from app.models.ipam import IPSpace
from app.models.ownership import Customer
from app.models.tenant import Tenant
from app.services.api_token_scopes import token_write

router = APIRouter()


class TenantBase(BaseModel):
    description: str = Field(default="", max_length=4000)
    customer_id: uuid.UUID | None = None


class TenantCreate(TenantBase):
    name: str = Field(..., min_length=1, max_length=255)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Tenant name cannot be empty")
        return v


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    customer_id: uuid.UUID | None = None

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("Tenant name cannot be empty")
        return v


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    customer_id: uuid.UUID | None
    space_count: int = 0
    group_count: int = 0
    token_count: int = 0
    created_at: datetime
    modified_at: datetime


class TenantSpaceAssign(BaseModel):
    space_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=500)


async def _counts(db: DB, tenant_ids: list[uuid.UUID]) -> dict[str, dict[uuid.UUID, int]]:
    out: dict[str, dict[uuid.UUID, int]] = {}
    # include_deleted: a trashed space still pins its tenant (RESTRICT FK), so
    # the count has to say so or "delete refused" would look unexplained.
    for key, col in (
        ("space", IPSpace.tenant_id),
        ("group", Group.tenant_id),
        ("token", APIToken.tenant_id),
    ):
        rows = (
            await db.execute(
                select(col, func.count())
                .where(col.in_(tenant_ids))
                .group_by(col)
                .execution_options(include_deleted=True)
            )
        ).all()
        out[key] = {r[0]: r[1] for r in rows}
    return out


async def _to_response(db: DB, rows: list[Tenant]) -> list[TenantResponse]:
    counts = (
        await _counts(db, [r.id for r in rows]) if rows else {"space": {}, "group": {}, "token": {}}
    )
    return [
        TenantResponse(
            id=r.id,
            name=r.name,
            description=r.description,
            customer_id=r.customer_id,
            space_count=counts["space"].get(r.id, 0),
            group_count=counts["group"].get(r.id, 0),
            token_count=counts["token"].get(r.id, 0),
            created_at=r.created_at,
            modified_at=r.modified_at,
        )
        for r in rows
    ]


async def _get(db: DB, tenant_id: uuid.UUID) -> Tenant:
    row = await db.get(Tenant, tenant_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return row


async def _check_customer(db: DB, customer_id: uuid.UUID | None) -> None:
    if customer_id is None:
        return
    cust = await db.get(Customer, customer_id)
    if cust is None or cust.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Customer not found"
        )


def _name_conflict(name: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT, detail=f"A tenant named {name!r} already exists"
    )


async def _name_taken(db: DB, name: str, exclude: uuid.UUID | None = None) -> bool:
    stmt = select(Tenant.id).where(func.lower(Tenant.name) == name.lower())
    if exclude is not None:
        stmt = stmt.where(Tenant.id != exclude)
    return (await db.execute(stmt)).first() is not None


def _snapshot(t: Tenant) -> dict[str, Any]:
    return {"name": t.name, "description": t.description, "customer_id": str(t.customer_id or "")}


@router.get("", response_model=list[TenantResponse])
async def list_tenants(_: SuperAdmin, db: DB) -> list[TenantResponse]:
    rows = list((await db.execute(select(Tenant).order_by(func.lower(Tenant.name)))).scalars())
    return await _to_response(db, rows)


@router.post("", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
@token_write("Creates a tenant row, which is a write to the tenancy configuration.")
async def create_tenant(body: TenantCreate, user: SuperAdmin, db: DB) -> TenantResponse:
    await _check_customer(db, body.customer_id)
    if await _name_taken(db, body.name):
        raise _name_conflict(body.name)
    row = Tenant(name=body.name, description=body.description, customer_id=body.customer_id)
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise _name_conflict(body.name) from exc
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="tenant",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=_snapshot(row),
    )
    await db.commit()
    await db.refresh(row)
    return (await _to_response(db, [row]))[0]


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(tenant_id: uuid.UUID, _: SuperAdmin, db: DB) -> TenantResponse:
    return (await _to_response(db, [await _get(db, tenant_id)]))[0]


@router.put("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: uuid.UUID, body: TenantUpdate, user: SuperAdmin, db: DB
) -> TenantResponse:
    row = await _get(db, tenant_id)
    old = _snapshot(row)
    if body.name is not None and body.name != row.name:
        if await _name_taken(db, body.name, exclude=row.id):
            raise _name_conflict(body.name)
        row.name = body.name
    if body.description is not None:
        row.description = body.description
    if "customer_id" in body.model_fields_set:
        await _check_customer(db, body.customer_id)
        row.customer_id = body.customer_id
    new = _snapshot(row)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="tenant",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=[k for k in new if new[k] != old[k]],
        old_value=old,
        new_value=new,
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise _name_conflict(body.name or row.name) from exc
    await db.refresh(row)
    return (await _to_response(db, [row]))[0]


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(tenant_id: uuid.UUID, user: SuperAdmin, db: DB) -> None:
    """Refused (409) while a space (trashed ones included), a group or an API
    token still belongs to the tenant: deleting it would either strand them or
    silently widen the members of a bound group to the whole install."""
    row = await _get(db, tenant_id)
    counts = await _counts(db, [row.id])
    held = {k: v.get(row.id, 0) for k, v in counts.items()}
    if any(held.values()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Tenant still has "
                f"{held['space']} IP space(s), {held['group']} group(s) and "
                f"{held['token']} API token(s); move or delete them first"
            ),
        )
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="tenant",
        resource_id=str(row.id),
        resource_display=row.name,
        old_value=_snapshot(row),
    )
    await db.delete(row)
    await db.commit()


@router.get("/{tenant_id}/spaces")
async def list_tenant_spaces(tenant_id: uuid.UUID, _: SuperAdmin, db: DB) -> list[dict[str, Any]]:
    await _get(db, tenant_id)
    rows = (
        await db.execute(
            select(IPSpace.id, IPSpace.name)
            .where(IPSpace.tenant_id == tenant_id)
            .order_by(IPSpace.name)
        )
    ).all()
    return [{"id": str(r.id), "name": r.name} for r in rows]


@router.post("/{tenant_id}/spaces", response_model=TenantResponse)
@token_write("Assigns IP spaces to a tenant, changing which tenant owns each space.")
async def assign_spaces(
    tenant_id: uuid.UUID, body: TenantSpaceAssign, user: SuperAdmin, db: DB
) -> TenantResponse:
    """Put IP spaces into the tenant. A space already in another tenant moves
    (its blocks, subnets and addresses move with it: ownership is by
    container). A name already taken inside the tenant is a 409."""
    tenant = await _get(db, tenant_id)
    spaces = list(
        (await db.execute(select(IPSpace).where(IPSpace.id.in_(body.space_ids)))).scalars()
    )
    found = {s.id for s in spaces}
    missing = [str(i) for i in body.space_ids if i not in found]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP space not found: {', '.join(missing)}",
        )
    for space in spaces:
        if space.tenant_id == tenant.id:
            continue
        previous = space.tenant_id
        space.tenant_id = tenant.id
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="ip_space",
            resource_id=str(space.id),
            resource_display=space.name,
            changed_fields=["tenant_id"],
            old_value={"tenant_id": str(previous or "")},
            new_value={"tenant_id": str(tenant.id)},
        )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An IP space with the same name already exists in this tenant",
        ) from exc
    return (await _to_response(db, [tenant]))[0]


@router.delete("/{tenant_id}/spaces/{space_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unassign_space(
    tenant_id: uuid.UUID, space_id: uuid.UUID, user: SuperAdmin, db: DB
) -> None:
    """Take a space out of the tenant; it becomes an ordinary install-wide
    space that tenant users no longer see."""
    await _get(db, tenant_id)
    space = (
        await db.execute(
            select(IPSpace).where(IPSpace.id == space_id, IPSpace.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if space is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP space not found")
    space.tenant_id = None
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="ip_space",
        resource_id=str(space.id),
        resource_display=space.name,
        changed_fields=["tenant_id"],
        old_value={"tenant_id": str(tenant_id)},
        new_value={"tenant_id": ""},
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An install-wide IP space with the same name already exists",
        ) from exc
