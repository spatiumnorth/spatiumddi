"""Subnet holds CRUD (#4492).

A hold sets a CIDR aside for a future project with an owner, a reason and an
expiry. It creates no subnet, placeholder addresses, reverse zone or DHCP
scope; subnet creation refuses overlapping space until the hold is released
or converted (``app.services.ipam.holds``). An expired hold keeps holding and
is listed as ``expired`` - it is never deleted by itself.

Permissions reuse the ``subnet`` resource type: ``read`` to list, ``write`` to
create / update / release / convert. Every mutation writes an ``AuditLog`` row
before commit.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_permission, token_scope_allows, user_has_permission
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace
from app.models.subnet_hold import SubnetHold
from app.services.api_token_scopes import token_write

router = APIRouter()


class HoldResponse(BaseModel):
    id: uuid.UUID
    space_id: uuid.UUID
    block_id: uuid.UUID | None
    network: str
    reason: str
    status: str
    expires_at: datetime | None
    expired: bool
    owner_user_id: uuid.UUID | None
    owner_group_id: uuid.UUID | None
    customer_id: uuid.UUID | None
    converted_subnet_id: uuid.UUID | None
    created_at: datetime
    modified_at: datetime


class HoldCreate(BaseModel):
    space_id: uuid.UUID
    network: str
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime | None = None
    owner_user_id: uuid.UUID | None = None
    owner_group_id: uuid.UUID | None = None
    customer_id: uuid.UUID | None = None


class HoldUpdate(BaseModel):
    reason: str | None = Field(default=None, min_length=1, max_length=2000)
    expires_at: datetime | None = None
    clear_expiry: bool = False
    owner_user_id: uuid.UUID | None = None
    owner_group_id: uuid.UUID | None = None
    customer_id: uuid.UUID | None = None


class HoldConvert(BaseModel):
    name: str = ""
    description: str = ""


def hold_is_expired(row: SubnetHold, now: datetime | None = None) -> bool:
    return (
        row.status == "active"
        and row.expires_at is not None
        and row.expires_at <= (now or datetime.now(UTC))
    )


def _to_response(row: SubnetHold) -> HoldResponse:
    return HoldResponse(
        id=row.id,
        space_id=row.space_id,
        block_id=row.block_id,
        network=str(row.network),
        reason=row.reason,
        status=row.status,
        expires_at=row.expires_at,
        expired=hold_is_expired(row),
        owner_user_id=row.owner_user_id,
        owner_group_id=row.owner_group_id,
        customer_id=row.customer_id,
        converted_subnet_id=row.converted_subnet_id,
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


def _snapshot(row: SubnetHold) -> dict[str, Any]:
    return {
        "space_id": str(row.space_id),
        "block_id": str(row.block_id) if row.block_id else None,
        "network": str(row.network),
        "reason": row.reason,
        "status": row.status,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "owner_user_id": str(row.owner_user_id) if row.owner_user_id else None,
        "owner_group_id": str(row.owner_group_id) if row.owner_group_id else None,
        "customer_id": str(row.customer_id) if row.customer_id else None,
    }


def _audit(
    db: DB,
    user: User,
    action: str,
    row: SubnetHold,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type="subnet_hold",
            resource_id=str(row.id),
            resource_display=str(row.network),
            old_value=old_value,
            new_value=new_value,
        )
    )


def _need(user: User, action: str) -> None:
    # A hold is a space-level object, so a token bound to specific subnets
    # (or to another resource type) is refused; only a wildcard ``subnet``
    # grant, a plain token or a session passes.
    if not token_scope_allows(user, "subnet", None):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API token is bound to specific resources; holds are space-level",
        )
    if not user_has_permission(user, action, "subnet"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need '{action}' on 'subnet'",
        )


async def _get(db: DB, hold_id: uuid.UUID) -> SubnetHold:
    row = await db.get(SubnetHold, hold_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hold not found")
    return row


def _require_active(row: SubnetHold) -> None:
    if row.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=f"Hold is already {row.status}"
        )


@router.get(
    "",
    response_model=list[HoldResponse],
    dependencies=[Depends(require_permission("read", "subnet"))],
)
async def list_holds(
    current_user: CurrentUser,
    db: DB,
    space_id: uuid.UUID | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    expired: bool | None = None,
    expiring_within_days: int | None = Query(default=None, ge=0, le=3650),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[HoldResponse]:
    _need(current_user, "read")
    stmt = select(SubnetHold)
    if space_id is not None:
        stmt = stmt.where(SubnetHold.space_id == space_id)
    if status_filter:
        stmt = stmt.where(SubnetHold.status == status_filter)
    now = datetime.now(UTC)
    if expired is True:
        stmt = stmt.where(
            SubnetHold.status == "active",
            SubnetHold.expires_at.is_not(None),
            SubnetHold.expires_at <= now,
        )
    elif expired is False:
        stmt = stmt.where(
            (SubnetHold.expires_at.is_(None)) | (SubnetHold.expires_at > now),
        )
    if expiring_within_days is not None:
        from datetime import timedelta  # noqa: PLC0415

        stmt = stmt.where(
            SubnetHold.status == "active",
            SubnetHold.expires_at.is_not(None),
            SubnetHold.expires_at <= now + timedelta(days=expiring_within_days),
        )
    stmt = stmt.order_by(SubnetHold.network, SubnetHold.id).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(r) for r in rows]


@router.get(
    "/{hold_id}",
    response_model=HoldResponse,
    dependencies=[Depends(require_permission("read", "subnet"))],
)
async def get_hold(hold_id: uuid.UUID, current_user: CurrentUser, db: DB) -> HoldResponse:
    _need(current_user, "read")
    return _to_response(await _get(db, hold_id))


@router.post("", response_model=HoldResponse, status_code=status.HTTP_201_CREATED)
@token_write("Creates a hold that blocks subnet allocation in the CIDR")
async def create_hold(body: HoldCreate, current_user: CurrentUser, db: DB) -> HoldResponse:
    _need(current_user, "write")  # also holds a bound token out via token_scope_allows(
    if await db.get(IPSpace, body.space_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP space not found")
    try:
        net = ipaddress.ip_network(body.network, strict=False)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid CIDR: {exc}"
        ) from exc
    canonical = str(net)
    if body.expires_at is not None and body.expires_at.tzinfo is None:
        body.expires_at = body.expires_at.replace(tzinfo=UTC)
    if body.expires_at is not None and body.expires_at <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expires_at must be in the future",
        )
    # Must sit inside a block of the space (the most specific one wins) and
    # must not overlap an existing subnet or another active hold.
    block = await _containing_block(db, body.space_id, canonical)
    if block is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"No block in this space contains {canonical}",
        )
    from app.api.v1.ipam.router import _assert_no_overlap  # noqa: PLC0415

    await _assert_no_overlap(db, body.space_id, canonical)  # subnets + holds
    row = SubnetHold(
        space_id=body.space_id,
        block_id=block.id,
        network=canonical,
        reason=body.reason,
        status="active",
        expires_at=body.expires_at,
        owner_user_id=body.owner_user_id,
        owner_group_id=body.owner_group_id,
        customer_id=body.customer_id,
    )
    db.add(row)
    await db.flush()
    _audit(db, current_user, "create", row, new_value=_snapshot(row))
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


async def _containing_block(db: DB, space_id: uuid.UUID, network: str) -> IPBlock | None:
    blocks = (
        (
            await db.execute(
                select(IPBlock).where(IPBlock.space_id == space_id, IPBlock.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    net = ipaddress.ip_network(network)
    best: IPBlock | None = None
    for b in blocks:
        bn = ipaddress.ip_network(str(b.network))
        if bn.version == net.version and net.subnet_of(bn):  # type: ignore[arg-type]
            if best is None or bn.prefixlen > ipaddress.ip_network(str(best.network)).prefixlen:
                best = b
    return best


@router.put("/{hold_id}", response_model=HoldResponse)
@token_write("Edits a hold (reason, expiry, owner)")
async def update_hold(
    hold_id: uuid.UUID, body: HoldUpdate, current_user: CurrentUser, db: DB
) -> HoldResponse:
    _need(current_user, "write")
    row = await _get(db, hold_id)
    _require_active(row)
    old = _snapshot(row)
    if body.reason is not None:
        row.reason = body.reason
    if body.clear_expiry:
        row.expires_at = None
    elif body.expires_at is not None:
        exp = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=UTC)
        if exp <= datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="expires_at must be in the future",
            )
        row.expires_at = exp
    for f in ("owner_user_id", "owner_group_id", "customer_id"):
        v = getattr(body, f)
        if v is not None:
            setattr(row, f, v)
    _audit(db, current_user, "update", row, old_value=old, new_value=_snapshot(row))
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.post("/{hold_id}/release", response_model=HoldResponse)
@token_write("Releases a hold, freeing the CIDR for allocation")
async def release_hold(hold_id: uuid.UUID, current_user: CurrentUser, db: DB) -> HoldResponse:
    _need(current_user, "write")
    row = await _get(db, hold_id)
    _require_active(row)
    old = _snapshot(row)
    row.status = "released"
    _audit(db, current_user, "release", row, old_value=old, new_value=_snapshot(row))
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.post("/{hold_id}/convert", response_model=HoldResponse)
@token_write("Turns a hold into a normal subnet (usual create steps)")
async def convert_hold(
    hold_id: uuid.UUID, body: HoldConvert, current_user: CurrentUser, db: DB
) -> HoldResponse:
    """Release the hold and create the subnet through the normal create path.

    ``create_subnet`` commits; if it refuses, the hold stays active."""
    _need(current_user, "write")
    row = await _get(db, hold_id)
    _require_active(row)
    if row.block_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The hold's block no longer exists; release it and create the subnet by hand",
        )
    from app.api.v1.ipam.router import SubnetCreate, create_subnet  # noqa: PLC0415

    old = _snapshot(row)
    row.status = "converted"
    await db.flush()
    try:
        subnet = await create_subnet(
            SubnetCreate(
                space_id=row.space_id,
                block_id=row.block_id,
                network=str(row.network),
                name=body.name,
                description=body.description or row.reason,
                customer_id=row.customer_id,
            ),
            current_user,
            db,
        )
    except HTTPException:
        await db.rollback()
        raise
    row.converted_subnet_id = subnet.id
    _audit(db, current_user, "convert", row, old_value=old, new_value=_snapshot(row))
    await db.commit()
    await db.refresh(row)
    return _to_response(row)
