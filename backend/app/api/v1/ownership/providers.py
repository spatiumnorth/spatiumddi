"""Provider CRUD — issue #91.

External organisations supplying network capacity / services. The
``registrar`` ``kind`` is the FK successor to today's free-form
``Domain.registrar`` text column; backfill is deferred to a
follow-up so existing operator-curated values aren't silently
mangled.

Permissions: gated on ``provider``. Each mutation writes to
``audit_log`` before commit.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission, user_has_permission
from app.models.asn import ASN
from app.models.circuit import Circuit
from app.models.ownership import PROVIDER_KINDS, Provider

router = APIRouter(
    tags=["providers"],
    dependencies=[
        Depends(
            require_resource_permission(
                "provider",
                # A grant scoped to one provider (#3039) reaches that row's detail
                # and edit and the list, which narrows to the granted rows.
                instance_routes=(
                    "provider",
                    "GET /",
                    frozenset({"GET /{provider_id}"}),
                    frozenset({"PUT /{provider_id}"}),
                ),
                instance_param="provider_id",
                prefix="/providers",
            )
        )
    ],
)


ProviderKind = Literal["transit", "peering", "carrier", "cloud", "registrar", "sdwan_vendor"]


class ProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    kind: ProviderKind = "transit"
    account_number: str | None = Field(default=None, max_length=64)
    contact_email: str | None = Field(default=None, max_length=255)
    contact_phone: str | None = Field(default=None, max_length=64)
    notes: str = ""
    default_asn_id: uuid.UUID | None = None
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in PROVIDER_KINDS:
            raise ValueError(f"kind must be one of {sorted(PROVIDER_KINDS)}")
        return v


class ProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    kind: ProviderKind | None = None
    account_number: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    notes: str | None = None
    default_asn_id: uuid.UUID | None = None
    tags: dict[str, Any] | None = None


class ProviderRead(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    account_number: str | None
    contact_email: str | None
    contact_phone: str | None
    notes: str
    default_asn_id: uuid.UUID | None
    tags: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class ProviderListResponse(BaseModel):
    items: list[ProviderRead]
    total: int
    limit: int
    offset: int


class ProviderBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


@router.get("", response_model=ProviderListResponse)
async def list_providers(
    db: DB,
    user: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    kind: ProviderKind | None = Query(default=None),
    search: str | None = Query(
        default=None,
        description="Case-insensitive substring on name / account_number / contact_email.",
    ),
) -> ProviderListResponse:
    stmt = select(Provider)
    if kind is not None:
        stmt = stmt.where(Provider.kind == kind)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Provider.name.ilike(needle),
                Provider.account_number.ilike(needle),
                Provider.contact_email.ilike(needle),
            )
        )
    # A caller admitted only by grants scoped to individual rows (#3039) sees
    # those rows and no others.
    if not user_has_permission(user, "read", "provider"):
        ids = (await db.execute(select(Provider.id))).scalars().all()
        stmt = stmt.where(
            Provider.id.in_(
                [i for i in ids if user_has_permission(user, "read", "provider", str(i))]
            )
        )
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(Provider.name.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return ProviderListResponse(
        items=[ProviderRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def _check_default_asn(db: Any, asn_id: uuid.UUID | None) -> None:
    if asn_id is None:
        return
    if await db.get(ASN, asn_id) is None:
        raise HTTPException(status_code=404, detail="default_asn_id refers to an unknown ASN")


@router.post("", response_model=ProviderRead, status_code=status.HTTP_201_CREATED)
async def create_provider(body: ProviderCreate, db: DB, user: CurrentUser) -> ProviderRead:
    existing = await db.scalar(select(Provider).where(Provider.name == body.name))
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Provider named {body.name!r} already exists")
    await _check_default_asn(db, body.default_asn_id)

    row = Provider(
        name=body.name,
        kind=body.kind,
        account_number=body.account_number,
        contact_email=body.contact_email,
        contact_phone=body.contact_phone,
        notes=body.notes,
        default_asn_id=body.default_asn_id,
        tags=body.tags or {},
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="provider",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return ProviderRead.model_validate(row)


@router.get("/{provider_id:uuid}", response_model=ProviderRead)
async def get_provider(provider_id: uuid.UUID, db: DB, _: CurrentUser) -> ProviderRead:
    row = await db.get(Provider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ProviderRead.model_validate(row)


@router.put("/{provider_id:uuid}", response_model=ProviderRead)
async def update_provider(
    provider_id: uuid.UUID, body: ProviderUpdate, db: DB, user: CurrentUser
) -> ProviderRead:
    row = await db.get(Provider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Provider not found")

    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] != row.name:
        clash = await db.scalar(
            select(Provider).where(Provider.name == changes["name"], Provider.id != provider_id)
        )
        if clash is not None:
            raise HTTPException(
                status_code=409, detail=f"Provider named {changes['name']!r} already exists"
            )
    # A grant scoped to this provider (#3039) does not reach the ASN it points at.
    if (
        "default_asn_id" in changes
        and changes["default_asn_id"] != row.default_asn_id
        and not user_has_permission(user, "write", "provider")
    ):
        raise HTTPException(
            status_code=403,
            detail="Permission denied: changing 'default_asn_id' needs 'write' on 'provider'",
        )
    if "default_asn_id" in changes:
        await _check_default_asn(db, changes["default_asn_id"])

    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="provider",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return ProviderRead.model_validate(row)


_LIVE_CIRCUITS_409 = (
    "Cannot delete provider while circuits reference it. " "Delete or re-attach the circuits first."
)


async def _release_provider_circuits(db: DB, provider_ids: list[uuid.UUID]) -> None:
    """#2707 — drop the soft-deleted circuits that still pin a provider.

    ``circuit.provider_id`` is ``ON DELETE RESTRICT`` and counts soft-deleted
    rows, but nothing purges a deleted circuit (they are not in Trash and every
    circuit route 404s for one), so a provider whose circuits were all deleted
    could never be deleted. Live circuits still refuse (409); deleted ones are
    removed for good with the provider.
    """
    live = (
        await db.execute(
            select(func.count())
            .select_from(Circuit)
            .where(Circuit.provider_id.in_(provider_ids), Circuit.deleted_at.is_(None))
        )
    ).scalar_one()
    if live:
        raise HTTPException(status_code=409, detail=_LIVE_CIRCUITS_409)
    await db.execute(
        delete(Circuit).where(
            Circuit.provider_id.in_(provider_ids), Circuit.deleted_at.is_not(None)
        )
    )


@router.delete("/{provider_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(provider_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(Provider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Provider not found")

    await _release_provider_circuits(db, [row.id])
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="provider",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.delete(row)
    try:
        await db.commit()
    except IntegrityError as exc:
        # ``circuit.provider_id`` is ``ON DELETE RESTRICT`` (issue
        # #93) — refuses provider deletion while any (incl. soft-
        # deleted) circuit still references it. Surface as a clean
        # 409 with a helpful pointer instead of a bare 500.
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=_LIVE_CIRCUITS_409,
        ) from exc


@router.post("/bulk-delete")
async def bulk_delete_providers(
    body: ProviderBulkDelete, db: DB, user: CurrentUser
) -> dict[str, Any]:
    if not body.ids:
        return {"deleted": 0, "not_found": []}

    rows = (await db.execute(select(Provider).where(Provider.id.in_(body.ids)))).scalars().all()
    found_ids = {r.id for r in rows}
    not_found = [str(i) for i in body.ids if i not in found_ids]

    if rows:
        await _release_provider_circuits(db, [r.id for r in rows])
    for r in rows:
        write_audit(
            db,
            user=user,
            action="delete",
            resource_type="provider",
            resource_id=str(r.id),
            resource_display=r.name,
        )
        await db.delete(r)
    await db.commit()
    return {"deleted": len(rows), "not_found": not_found}


__all__ = ["router"]
