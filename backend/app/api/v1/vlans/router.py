"""VLANs API — Routers and their VLANs."""

import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_resource_permission
from app.core.update_nulls import resolve_update_changes
from app.models.audit import AuditLog
from app.models.ipam import Subnet
from app.models.vlans import VLAN, Router

logger = structlog.get_logger(__name__)
router = APIRouter(dependencies=[Depends(require_resource_permission("vlan"))])


# ── helpers ────────────────────────────────────────────────────────────────────


def _audit(
    user: Any,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
    old_value: dict | None = None,
    new_value: dict | None = None,
) -> AuditLog:
    return AuditLog(
        user_id=user.id,
        user_display_name=user.display_name,
        auth_source=user.auth_source,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_display=resource_display,
        old_value=old_value,
        new_value=new_value,
        result="success",
    )


# ── Schemas ────────────────────────────────────────────────────────────────────


class RouterCreate(BaseModel):
    name: str
    description: str = ""
    location: str = ""
    management_ip: str | None = None
    vendor: str | None = None
    model: str | None = None
    notes: str = ""


class RouterUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    location: str | None = None
    management_ip: str | None = None
    vendor: str | None = None
    model: str | None = None
    notes: str | None = None


class RouterResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    location: str
    management_ip: str | None
    vendor: str | None
    model: str | None
    notes: str
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("management_ip", mode="before")
    @classmethod
    def coerce_inet(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class VLANCreate(BaseModel):
    vlan_id: int
    name: str
    description: str = ""

    @field_validator("vlan_id")
    @classmethod
    def validate_vlan_id(cls, v: int) -> int:
        if v < 1 or v > 4094:
            raise ValueError("vlan_id must be between 1 and 4094")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("name is required")
        return v.strip()


class VLANUpdate(BaseModel):
    vlan_id: int | None = None
    name: str | None = None
    description: str | None = None

    @field_validator("vlan_id")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        if v is None:
            return v
        if v < 1 or v > 4094:
            raise ValueError("vlan_id must be between 1 and 4094")
        return v


class VLANResponse(BaseModel):
    id: uuid.UUID
    router_id: uuid.UUID
    vlan_id: int
    name: str
    description: str
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


# ── Router endpoints ───────────────────────────────────────────────────────────


@router.get("/routers", response_model=list[RouterResponse])
async def list_routers(current_user: CurrentUser, db: DB) -> list[Router]:
    result = await db.execute(select(Router).order_by(Router.name))
    return list(result.scalars().all())


@router.post("/routers", response_model=RouterResponse, status_code=status.HTTP_201_CREATED)
async def create_router(body: RouterCreate, current_user: CurrentUser, db: DB) -> Router:
    # Uniqueness on name
    existing = await db.scalar(select(Router).where(Router.name == body.name))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Router with name '{body.name}' already exists",
        )
    r = Router(**body.model_dump())
    db.add(r)
    await db.flush()
    db.add(
        _audit(
            current_user,
            "create",
            "router",
            str(r.id),
            r.name,
            new_value=body.model_dump(mode="json"),
        )
    )
    await db.commit()
    await db.refresh(r)
    return r


@router.get("/routers/{router_id}", response_model=RouterResponse)
async def get_router(router_id: uuid.UUID, current_user: CurrentUser, db: DB) -> Router:
    r = await db.get(Router, router_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")
    return r


@router.put("/routers/{router_id}", response_model=RouterResponse)
async def update_router(
    router_id: uuid.UUID, body: RouterUpdate, current_user: CurrentUser, db: DB
) -> Router:
    r = await db.get(Router, router_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")
    old = {
        "name": r.name,
        "description": r.description,
        "location": r.location,
        "management_ip": str(r.management_ip) if r.management_ip else None,
        "vendor": r.vendor,
        "model": r.model,
        "notes": r.notes,
    }
    # #1564 — null clears the nullable columns (management_ip / vendor /
    # model); null for name / description / location / notes is a 422.
    changes = resolve_update_changes(
        body,
        clearable={"management_ip", "vendor", "model"},
        non_nullable={"name", "description", "location", "notes"},
    )
    if "name" in changes and changes["name"] != r.name:
        dup = await db.scalar(
            select(Router).where(Router.name == changes["name"], Router.id != r.id)
        )
        if dup is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Router with name '{changes['name']}' already exists",
            )
    for field, value in changes.items():
        setattr(r, field, value)
    db.add(
        _audit(
            current_user, "update", "router", str(r.id), r.name, old_value=old, new_value=changes
        )
    )
    await db.commit()
    await db.refresh(r)
    return r


@router.delete("/routers/{router_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_router(router_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    r = await db.get(Router, router_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")
    # Block delete if any VLAN under this router still has subnets referencing it.
    # Deleting the router would CASCADE to the VLANs and SET NULL the subnet
    # references, silently orphaning operational data — refuse instead and let
    # the user reassign first.
    used = await db.scalar(
        select(func.count(Subnet.id))
        .join(VLAN, Subnet.vlan_ref_id == VLAN.id)
        .where(VLAN.router_id == router_id)
    )
    if used:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cannot delete router '{r.name}': {used} subnet"
                f"{'s' if used != 1 else ''} still reference VLANs on this router. "
                "Reassign or clear the VLAN on those subnets first."
            ),
        )
    name = r.name
    db.add(
        _audit(
            current_user,
            "delete",
            "router",
            str(r.id),
            name,
            old_value={"name": name},
        )
    )
    await db.delete(r)
    await db.commit()


# ── VLAN endpoints ─────────────────────────────────────────────────────────────


@router.get("/routers/{router_id}/vlans", response_model=list[VLANResponse])
async def list_vlans(router_id: uuid.UUID, current_user: CurrentUser, db: DB) -> list[VLAN]:
    r = await db.get(Router, router_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")
    result = await db.execute(
        select(VLAN).where(VLAN.router_id == router_id).order_by(VLAN.vlan_id)
    )
    return list(result.scalars().all())


async def _vlan_conflicts(
    db: AsyncSession,
    router_id: uuid.UUID,
    vlan_tag: int | None,
    name: str | None,
    exclude_id: uuid.UUID | None = None,
) -> str | None:
    if vlan_tag is not None:
        q = select(VLAN).where(VLAN.router_id == router_id, VLAN.vlan_id == vlan_tag)
        if exclude_id is not None:
            q = q.where(VLAN.id != exclude_id)
        if await db.scalar(q) is not None:
            return f"VLAN tag {vlan_tag} already exists on this router"
    if name is not None:
        q = select(VLAN).where(VLAN.router_id == router_id, VLAN.name == name)
        if exclude_id is not None:
            q = q.where(VLAN.id != exclude_id)
        if await db.scalar(q) is not None:
            return f"VLAN name '{name}' already exists on this router"
    return None


@router.post(
    "/routers/{router_id}/vlans",
    response_model=VLANResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_vlan(
    router_id: uuid.UUID, body: VLANCreate, current_user: CurrentUser, db: DB
) -> VLAN:
    r = await db.get(Router, router_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")
    conflict = await _vlan_conflicts(db, router_id, body.vlan_id, body.name)
    if conflict:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=conflict)
    v = VLAN(router_id=router_id, **body.model_dump())
    db.add(v)
    await db.flush()
    db.add(
        _audit(
            current_user,
            "create",
            "vlan",
            str(v.id),
            f"{r.name} / VLAN {v.vlan_id} ({v.name})",
            new_value={"router_id": str(router_id), **body.model_dump(mode="json")},
        )
    )
    await db.commit()
    await db.refresh(v)
    return v


@router.get("/vlans/{vlan_id}", response_model=VLANResponse)
async def get_vlan(vlan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> VLAN:
    v = await db.get(VLAN, vlan_id)
    if v is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="VLAN not found")
    return v


@router.put("/vlans/{vlan_id}", response_model=VLANResponse)
async def update_vlan(
    vlan_id: uuid.UUID, body: VLANUpdate, current_user: CurrentUser, db: DB
) -> VLAN:
    v = await db.get(VLAN, vlan_id)
    if v is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="VLAN not found")
    # #1564 — every VLAN column here is NOT NULL, so any explicit null
    # is a 422 rather than the 500 the setattr loop used to produce.
    changes = resolve_update_changes(
        body,
        non_nullable={"vlan_id", "name", "description"},
    )
    conflict = await _vlan_conflicts(
        db,
        v.router_id,
        changes.get("vlan_id") if "vlan_id" in changes else None,
        changes.get("name") if "name" in changes else None,
        exclude_id=v.id,
    )
    if conflict:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=conflict)

    old = {"vlan_id": v.vlan_id, "name": v.name, "description": v.description}
    old_tag = v.vlan_id
    for field, value in changes.items():
        setattr(v, field, value)
    db.add(
        _audit(
            current_user,
            "update",
            "vlan",
            str(v.id),
            f"VLAN {v.vlan_id} ({v.name})",
            old_value=old,
            new_value=changes,
        )
    )

    # If the tag changed, propagate to any subnet referencing this VLAN
    if "vlan_id" in changes and changes["vlan_id"] != old_tag:
        subs = await db.execute(select(Subnet).where(Subnet.vlan_ref_id == v.id))
        for s in subs.scalars().all():
            s.vlan_id = v.vlan_id

    await db.commit()
    await db.refresh(v)
    return v


@router.delete("/vlans/{vlan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vlan(vlan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    v = await db.get(VLAN, vlan_id)
    if v is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="VLAN not found")
    used = await db.scalar(select(func.count(Subnet.id)).where(Subnet.vlan_ref_id == vlan_id))
    if used:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cannot delete VLAN {v.vlan_id} ({v.name}): {used} subnet"
                f"{'s' if used != 1 else ''} still reference it. "
                "Reassign or clear the VLAN on those subnets first."
            ),
        )
    display = f"VLAN {v.vlan_id} ({v.name})"
    db.add(
        _audit(
            current_user,
            "delete",
            "vlan",
            str(v.id),
            display,
            old_value={"vlan_id": v.vlan_id, "name": v.name},
        )
    )
    await db.delete(v)
    await db.commit()
