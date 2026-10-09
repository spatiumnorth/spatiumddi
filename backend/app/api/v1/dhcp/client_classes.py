"""DHCP client class CRUD — group-centric."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPClientClass, DHCPPool, DHCPScope, DHCPServerGroup
from app.services.dhcp.option_validation import normalize_options, validate_class_test

# Which Kea daemons the class renders into (#1229). ``dual`` sends each option
# to whichever family it is valid in (#1295).
ClassFamily = Literal["ipv4", "ipv6", "dual"]

router = APIRouter(
    tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_client_class"))]
)


class ClientClassCreate(BaseModel):
    name: str
    match_expression: str = ""
    description: str = ""
    address_family: ClassFamily = "ipv4"
    options: dict[str, Any] = {}


class ClientClassUpdate(BaseModel):
    name: str | None = None
    match_expression: str | None = None
    description: str | None = None
    address_family: ClassFamily | None = None
    options: dict[str, Any] | None = None


class ClientClassResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    match_expression: str
    description: str
    address_family: ClassFamily
    options: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


def _check_test(expression: str, family: str) -> None:
    try:
        validate_class_test(expression, family)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def class_families(family: str) -> set[str]:
    return {"ipv4", "ipv6"} if family == "dual" else {family}


async def _refuse_orphaned_pools(db: DB, cc: DHCPClientClass, family: str) -> None:
    """Refuse a family change that would leave a pool restricted to a class
    its daemon no longer defines (#1229). Kea accepts the reference, so
    nothing would fail: the pool would simply stop matching anyone."""
    dropped = class_families(cc.address_family) - class_families(family)
    if not dropped:
        return
    rows = (
        await db.execute(
            select(DHCPPool.start_ip, DHCPPool.end_ip, DHCPScope.address_family)
            .join(DHCPScope, DHCPPool.scope_id == DHCPScope.id)
            .where(
                DHCPScope.group_id == cc.group_id,
                DHCPScope.address_family.in_(dropped),
                DHCPPool.class_restriction == cc.name,
            )
        )
    ).all()
    if rows:
        pools = ", ".join(f"{r.start_ip}-{r.end_ip}" for r in rows[:5])
        more = f" and {len(rows) - 5} more" if len(rows) > 5 else ""
        raise HTTPException(
            status_code=409,
            detail=(
                f"Client class '{cc.name}' restricts {len(rows)} pool(s) in "
                f"{'/'.join(sorted(dropped))} scopes ({pools}{more}); after this "
                "change their daemon would not define the class and those pools "
                "would match no client. Clear or change the pools' class first."
            ),
        )


@router.get("/server-groups/{group_id}/client-classes", response_model=list[ClientClassResponse])
async def list_classes(group_id: uuid.UUID, db: DB, _: CurrentUser) -> list[DHCPClientClass]:
    res = await db.execute(select(DHCPClientClass).where(DHCPClientClass.group_id == group_id))
    return list(res.scalars().all())


@router.post(
    "/server-groups/{group_id}/client-classes",
    response_model=ClientClassResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_class(
    group_id: uuid.UUID, body: ClientClassCreate, db: DB, user: SuperAdmin
) -> DHCPClientClass:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")
    existing = await db.execute(
        select(DHCPClientClass).where(
            DHCPClientClass.group_id == group_id, DHCPClientClass.name == body.name
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A client class with that name exists")
    _check_test(body.match_expression, body.address_family)
    body.options = normalize_options(body.options)
    # A client class is rendered by Kea / FortiGate only: the Kea raw-code rule (#1296).
    await validate_dhcp_options(db, body.options, group_id=None, address_family=body.address_family)
    cc = DHCPClientClass(group_id=group_id, **body.model_dump())
    db.add(cc)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
        new_value=body.model_dump(mode="json"),
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    await db.refresh(cc)
    return cc


@router.put("/client-classes/{class_id}", response_model=ClientClassResponse)
async def update_class(
    class_id: uuid.UUID, body: ClientClassUpdate, db: DB, user: SuperAdmin
) -> DHCPClientClass:
    cc = await db.get(DHCPClientClass, class_id)
    if cc is None:
        raise HTTPException(status_code=404, detail="Client class not found")
    changes = body.model_dump(exclude_none=True)
    family = changes.get("address_family", cc.address_family)
    family_changed = family != cc.address_family
    if family_changed:
        await _refuse_orphaned_pools(db, cc, family)
    if family_changed or "match_expression" in changes:
        _check_test(changes.get("match_expression", cc.match_expression), family)
    if "options" in changes or family_changed:
        # Validate only changed options (#597, #1228) vs the stored value —
        # unless the family changed, which makes every option new to it.
        options = (
            normalize_options(changes["options"]) if "options" in changes else cc.options or {}
        )
        await validate_dhcp_options(
            db,
            options,
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family=family,
            previous=None if family_changed else cc.options or {},
        )
        if "options" in changes:
            changes["options"] = options
    for k, v in changes.items():
        setattr(cc, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    collect_wake(dhcp_group_channel(cc.group_id))
    await db.commit()
    await db.refresh(cc)
    return cc


@router.delete("/client-classes/{class_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_class(class_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    cc = await db.get(DHCPClientClass, class_id)
    if cc is None:
        raise HTTPException(status_code=404, detail="Client class not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
    )
    collect_wake(dhcp_group_channel(cc.group_id))
    await db.delete(cc)
    await db.commit()
