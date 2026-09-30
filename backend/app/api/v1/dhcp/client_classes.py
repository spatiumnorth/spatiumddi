"""DHCP client class CRUD — group-centric."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPClientClass, DHCPServerGroup
from app.services.dhcp.option_validation import normalize_options

router = APIRouter(
    tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_client_class"))]
)


class ClientClassCreate(BaseModel):
    name: str
    match_expression: str = ""
    description: str = ""
    options: dict[str, Any] = {}


class ClientClassUpdate(BaseModel):
    name: str | None = None
    match_expression: str | None = None
    description: str | None = None
    options: dict[str, Any] | None = None


class ClientClassResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    match_expression: str
    description: str
    options: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


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
    # A client class always renders into Dhcp4 (and into Dhcp6 when the
    # group has v6 scopes); "any" checks it as the Dhcp4 it must load in.
    body.options = normalize_options(body.options)
    # A client class is rendered by Kea / FortiGate only: the Kea raw-code rule (#1296).
    await validate_dhcp_options(db, body.options, group_id=None, address_family="any")
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
    if "options" in changes:
        # Validate only changed options (#597, #1228) vs the stored value.
        changes["options"] = normalize_options(changes["options"])
        await validate_dhcp_options(
            db,
            changes["options"],
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family="any",
            previous=cc.options or {},
        )
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
