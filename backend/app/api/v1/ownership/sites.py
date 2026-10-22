"""Site CRUD — issue #91.

Physical location resources are deployed at. Hierarchical via
``parent_site_id`` (campus → building → floor) — but flat as a
default; most operators won't nest.

Permissions: gated on ``site``. Each mutation writes to ``audit_log``
before commit.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.dns import DNSPool, DNSPoolMember
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ownership import SITE_KINDS, Site

router = APIRouter(
    tags=["sites"],
    dependencies=[Depends(require_resource_permission("site"))],
)


SiteKind = Literal["datacenter", "branch", "pop", "colo", "cloud_region", "customer_premise"]


# An empty / whitespace ``code`` means "no code", which must be stored
# as NULL — not ``""``. The sibling-uniqueness index treats NULL parents
# as equal (so top-level codes are unique), and that flag would make two
# empty-string codes collide too; normalising to NULL keeps the index's
# ``WHERE code IS NOT NULL`` predicate excluding code-less siblings so
# any number of them can coexist. Shared by create + update.
def _normalize_code(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    return v or None


class SiteCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    code: str | None = Field(default=None, max_length=64)
    kind: SiteKind = "datacenter"
    region: str | None = Field(default=None, max_length=128)
    parent_site_id: uuid.UUID | None = None
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in SITE_KINDS:
            raise ValueError(f"kind must be one of {sorted(SITE_KINDS)}")
        return v

    @field_validator("code")
    @classmethod
    def _v_code(cls, v: str | None) -> str | None:
        return _normalize_code(v)


class SiteUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    code: str | None = None
    kind: SiteKind | None = None
    region: str | None = None
    parent_site_id: uuid.UUID | None = None
    notes: str | None = None
    tags: dict[str, Any] | None = None

    @field_validator("code")
    @classmethod
    def _v_code(cls, v: str | None) -> str | None:
        return _normalize_code(v)


class SiteRead(BaseModel):
    id: uuid.UUID
    name: str
    code: str | None
    kind: str
    region: str | None
    parent_site_id: uuid.UUID | None
    notes: str
    tags: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class SiteListResponse(BaseModel):
    items: list[SiteRead]
    total: int
    limit: int
    offset: int


class SiteBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


@router.get("", response_model=SiteListResponse)
async def list_sites(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    kind: SiteKind | None = Query(default=None),
    region: str | None = Query(default=None),
    parent_site_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(
        default=None,
        description="Case-insensitive substring on name / code / region.",
    ),
) -> SiteListResponse:
    stmt = select(Site)
    if kind is not None:
        stmt = stmt.where(Site.kind == kind)
    if region is not None:
        stmt = stmt.where(Site.region == region)
    if parent_site_id is not None:
        stmt = stmt.where(Site.parent_site_id == parent_site_id)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(Site.name.ilike(needle), Site.code.ilike(needle), Site.region.ilike(needle))
        )
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(Site.name.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return SiteListResponse(
        items=[SiteRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


async def _validate_parent(
    db: Any, parent_site_id: uuid.UUID | None, self_id: uuid.UUID | None
) -> None:
    """Reject parents that don't exist or that would create a cycle.

    Cycle check is the conservative version: we walk up the parent
    chain from the proposed parent and 422 if we hit ``self_id``. The
    chain is shallow enough in practice (campus / building / floor)
    that the linear walk is fine.
    """
    if parent_site_id is None:
        return
    parent = await db.get(Site, parent_site_id)
    if parent is None:
        raise HTTPException(status_code=404, detail="Parent site not found")
    if self_id is None:
        return
    seen = set()
    cursor: Site | None = parent
    while cursor is not None:
        if cursor.id == self_id:
            raise HTTPException(
                status_code=422,
                detail="parent_site_id would create a cycle",
            )
        if cursor.id in seen:
            break
        seen.add(cursor.id)
        if cursor.parent_site_id is None:
            break
        cursor = await db.get(Site, cursor.parent_site_id)


@router.post("", response_model=SiteRead, status_code=status.HTTP_201_CREATED)
async def create_site(body: SiteCreate, db: DB, user: CurrentUser) -> SiteRead:
    await _validate_parent(db, body.parent_site_id, None)

    row = Site(
        name=body.name,
        code=body.code,
        kind=body.kind,
        region=body.region,
        parent_site_id=body.parent_site_id,
        notes=body.notes,
        tags=body.tags or {},
    )
    db.add(row)
    try:
        await db.flush()
    except Exception as exc:  # IntegrityError on the (parent_site_id, code) unique index
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A sibling site with this code already exists",
        ) from exc

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="site",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return SiteRead.model_validate(row)


@router.get("/{site_id:uuid}", response_model=SiteRead)
async def get_site(site_id: uuid.UUID, db: DB, _: CurrentUser) -> SiteRead:
    row = await db.get(Site, site_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return SiteRead.model_validate(row)


@router.put("/{site_id:uuid}", response_model=SiteRead)
async def update_site(site_id: uuid.UUID, body: SiteUpdate, db: DB, user: CurrentUser) -> SiteRead:
    row = await db.get(Site, site_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Site not found")

    changes = body.model_dump(exclude_unset=True)
    if "parent_site_id" in changes:
        await _validate_parent(db, changes["parent_site_id"], site_id)
    for k, v in changes.items():
        setattr(row, k, v)

    try:
        await db.flush()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A sibling site with this code already exists",
        ) from exc

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="site",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return SiteRead.model_validate(row)


async def _pool_member_referrers(db: DB, site_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    """DNS pool members geo-scoped to each site (``site_id`` is SET NULL, so a
    delete would silently turn them into default answers for every client)."""
    rows = (
        await db.execute(
            select(DNSPoolMember.site_id, DNSPool.name, DNSPoolMember.address)
            .join(DNSPool, DNSPool.id == DNSPoolMember.pool_id)
            .where(DNSPoolMember.site_id.in_(site_ids))
            .order_by(DNSPool.name, DNSPoolMember.address)
        )
    ).all()
    out: dict[uuid.UUID, list[str]] = {}
    for sid, pool_name, address in rows:
        out.setdefault(sid, []).append(f"{pool_name} ({address})")
    return out


def _refuse_if_referenced(row_name: str, refs: list[str]) -> None:
    if refs:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Site '{row_name}' is the geo scope of DNS pool member(s): "
                f"{', '.join(refs)}. Re-scope or remove them first."
            ),
        )


async def _refuse_if_e911_bound(db: DB, sites: list[Site]) -> None:
    """409 when any of ``sites`` still carries an E911 ``site_default`` binding.

    ``erl_binding.site_id`` is ``ON DELETE CASCADE``, so deleting the site
    would silently remove the coarsest-fallback location for every phone on
    it (#2298). A wrong or missing emergency location is not something to
    discover on the next conformity pass, so the operator removes the
    binding deliberately (Network -> E911 -> Bindings) and then deletes.
    """
    if not sites:
        return
    by_id = {s.id: s for s in sites}
    rows = (
        await db.execute(
            select(ERLBinding.site_id, EmergencyResponseLocation.name)
            .join(EmergencyResponseLocation, EmergencyResponseLocation.id == ERLBinding.erl_id)
            .where(ERLBinding.site_id.in_(list(by_id)))
            .order_by(EmergencyResponseLocation.name)
        )
    ).all()
    if not rows:
        return
    parts = [f'site "{by_id[sid].name}" -> ERL "{erl}"' for sid, erl in rows]
    raise HTTPException(
        status_code=409,
        detail=(
            "Cannot delete: E911 site-default binding(s) still point at "
            + ("this site" if len(sites) == 1 else "these sites")
            + f" ({'; '.join(parts)}). Deleting would silently remove the "
            "fallback emergency location for every device there. Remove the "
            "binding(s) under Network > E911 > Bindings first."
        ),
    )


@router.delete("/{site_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(site_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Hard-delete (sites aren't soft-deletable). Children re-parent
    to NULL via ``ON DELETE SET NULL``; cross-refs on subnets /
    blocks / network_devices null out the same way. Refused (409) while an
    E911 site-default binding points at the site (#2298).
    """
    row = await db.get(Site, site_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Site not found")
    _refuse_if_referenced(row.name, (await _pool_member_referrers(db, [row.id])).get(row.id, []))

    await _refuse_if_e911_bound(db, [row])

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="site",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.delete(row)
    await db.commit()


@router.post("/bulk-delete")
async def bulk_delete_sites(body: SiteBulkDelete, db: DB, user: CurrentUser) -> dict[str, Any]:
    if not body.ids:
        return {"deleted": 0, "not_found": []}

    rows = (await db.execute(select(Site).where(Site.id.in_(body.ids)))).scalars().all()
    found_ids = {r.id for r in rows}
    not_found = [str(i) for i in body.ids if i not in found_ids]

    refs = await _pool_member_referrers(db, [r.id for r in rows])
    for r in rows:
        _refuse_if_referenced(r.name, refs.get(r.id, []))
    # All-or-nothing: a partial delete would leave the operator guessing
    # which sites went.
    await _refuse_if_e911_bound(db, list(rows))

    for r in rows:
        write_audit(
            db,
            user=user,
            action="delete",
            resource_type="site",
            resource_id=str(r.id),
            resource_display=r.name,
        )
        await db.delete(r)
    await db.commit()
    return {"deleted": len(rows), "not_found": not_found}


__all__ = ["router"]
