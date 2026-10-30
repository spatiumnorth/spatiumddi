"""DHCP MAC blocklist CRUD — group-centric, enriched reads.

Blocks a MAC address from getting a lease anywhere in the group. Kea
picks this up via the rendered ``DROP`` class (ConfigBundle → agent);
Windows DHCP picks it up via a beat-driven ``sync_mac_blocks`` call
that reconciles the server-level deny filter list.

List reads join OUI vendor lookups and an IPAM cross-reference so the
UI can surface both the device vendor (if known) and any IPAM row
currently tied to the blocked MAC.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp._mac import canonicalize_mac
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.core.update_nulls import changed_keys, snapshot
from app.models.dhcp import DHCPMACBlock, DHCPServerGroup
from app.models.ipam import IPAddress, Subnet
from app.services.oui import bulk_lookup_vendors, normalize_mac_key


def _kick_windows_sync() -> None:
    """Fire the Windows DHCP deny-list reconciler as a background task.

    Kea picks up blocklist changes through the normal ConfigBundle +
    ETag long-poll, so it doesn't need this kick. Windows does — its
    deny filter list only changes when the beat task (or this on-demand
    trigger) runs. We fire-and-forget via Celery so the HTTP response
    doesn't wait on WinRM round-trips, and the periodic 60 s beat still
    acts as a safety net for any trigger that's lost (worker restart,
    broker blip). Task is idempotent — safe to call after every write.
    """
    # Deferred import — a hot reload of the router shouldn't pay the
    # cost of importing celery just to register the dependency.
    from app.tasks.dhcp_mac_blocks import (  # noqa: PLC0415
        sync_dhcp_mac_blocks,
    )

    try:
        sync_dhcp_mac_blocks.delay()
    except Exception:  # noqa: BLE001
        # Broker down shouldn't break the API write — beat will catch up.
        pass


router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_mac_block"))],
)

# ── MAC normalization ────────────────────────────────────────────────
# The canonicalizer moved to `_mac.py` unchanged so the static-assignment
# endpoint can apply the identical rule (it had none, and a malformed MAC
# reached the MACADDR column as a 500). Re-bound under its original private
# name so the schemas below read exactly as they did.

_canonicalize_mac = canonicalize_mac
_VALID_REASONS = frozenset({"rogue", "lost_stolen", "quarantine", "policy", "other"})


# ── Pydantic schemas ────────────────────────────────────────────────


class MACBlockCreate(BaseModel):
    mac_address: str
    reason: Literal["rogue", "lost_stolen", "quarantine", "policy", "other"] = "other"
    description: str = ""
    enabled: bool = True
    expires_at: datetime | None = None

    @field_validator("mac_address")
    @classmethod
    def _norm_mac(cls, v: str) -> str:
        return _canonicalize_mac(v)


class MACBlockUpdate(BaseModel):
    # ``mac_address`` is immutable once created — change means "delete
    # the row and add a new one" so the audit trail for each MAC stays
    # linear. Everything else can be toggled.
    # A block made from New Devices carries the operator's free text, so an
    # update must accept the reason the block already holds (#3083); any
    # other value is still held to the five codes in the handler.
    reason: str | None = Field(default=None, max_length=20)
    description: str | None = None
    enabled: bool | None = None
    expires_at: datetime | None = None


class IPAMCrossRef(BaseModel):
    ip_address: str
    subnet_cidr: str
    hostname: str = ""
    description: str = ""


class MACBlockResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    mac_address: str
    reason: str
    description: str
    enabled: bool
    expires_at: datetime | None
    created_at: datetime
    modified_at: datetime
    created_by_user_id: uuid.UUID | None
    updated_by_user_id: uuid.UUID | None
    last_match_at: datetime | None
    match_count: int
    vendor: str | None = None
    ipam_matches: list[IPAMCrossRef] = []

    model_config = {"from_attributes": True}


# ── Read-side enrichment ────────────────────────────────────────────


async def _build_response(db: Any, rows: list[DHCPMACBlock]) -> list[MACBlockResponse]:
    """Attach OUI vendor name + IPAM cross-ref rows to each block.

    One ``bulk_lookup_vendors`` query covers the full page; one joined
    ``IPAddress`` query covers every MAC → IP mapping we know about.
    Both short-circuit cleanly when the underlying feature is off /
    unused, so listing a group with zero blocks is a single SQL call.
    """
    if not rows:
        return []

    mac_strs = [str(r.mac_address) for r in rows]
    vendors = await bulk_lookup_vendors(
        db, [str(r.mac_address) if r.mac_address else None for r in rows]
    )

    # IPAM cross-ref: find every IPAddress whose MAC matches one of ours.
    # Postgres MACADDR comparison is canonical so the JOIN key just works.
    by_mac: dict[str, list[IPAMCrossRef]] = {}
    res = await db.execute(
        select(IPAddress, Subnet.network)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(IPAddress.mac_address.in_(mac_strs))
    )
    for ip, network in res.all():
        key = str(ip.mac_address).lower()
        by_mac.setdefault(key, []).append(
            IPAMCrossRef(
                ip_address=str(ip.address),
                subnet_cidr=str(network) if network else "",
                hostname=ip.hostname or "",
                description=ip.description or "",
            )
        )

    out: list[MACBlockResponse] = []
    for r in rows:
        raw = str(r.mac_address)
        key = normalize_mac_key(raw) or ""
        resp = MACBlockResponse.model_validate(r)
        resp.vendor = vendors.get(key) if vendors else None
        resp.ipam_matches = by_mac.get(raw.lower(), [])
        out.append(resp)
    return out


# ── Endpoints ───────────────────────────────────────────────────────


@router.get(
    "/server-groups/{group_id}/mac-blocks",
    response_model=list[MACBlockResponse],
)
async def list_mac_blocks(group_id: uuid.UUID, db: DB, _: CurrentUser) -> list[MACBlockResponse]:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")
    res = await db.execute(
        select(DHCPMACBlock)
        .where(DHCPMACBlock.group_id == group_id)
        .order_by(DHCPMACBlock.mac_address)
    )
    rows = list(res.scalars().all())
    return await _build_response(db, rows)


@router.post(
    "/server-groups/{group_id}/mac-blocks",
    response_model=MACBlockResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_mac_block(
    group_id: uuid.UUID, body: MACBlockCreate, db: DB, user: CurrentUser
) -> MACBlockResponse:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")

    existing = await db.execute(
        select(DHCPMACBlock).where(
            DHCPMACBlock.group_id == group_id,
            DHCPMACBlock.mac_address == body.mac_address,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="This MAC is already blocked in the group")

    block = DHCPMACBlock(
        group_id=group_id,
        mac_address=body.mac_address,
        reason=body.reason,
        description=body.description,
        enabled=body.enabled,
        expires_at=body.expires_at,
        created_by_user_id=user.id,
        updated_by_user_id=user.id,
    )
    db.add(block)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_mac_block",
        resource_id=str(block.id),
        resource_display=body.mac_address,
        new_value=body.model_dump(mode="json"),
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    await db.refresh(block)
    _kick_windows_sync()
    rows = await _build_response(db, [block])
    return rows[0]


@router.put(
    "/mac-blocks/{block_id}",
    response_model=MACBlockResponse,
)
async def update_mac_block(
    block_id: uuid.UUID, body: MACBlockUpdate, db: DB, user: CurrentUser
) -> MACBlockResponse:
    block = await db.get(DHCPMACBlock, block_id)
    if block is None:
        raise HTTPException(status_code=404, detail="MAC block not found")

    changes = body.model_dump(exclude_unset=True)
    if changes.get("reason") is None:
        changes.pop("reason", None)  # NOT NULL column: null means "leave it"
    elif changes["reason"] not in _VALID_REASONS and changes["reason"] != block.reason:
        raise HTTPException(
            status_code=422,
            detail="reason must be one of rogue, lost_stolen, quarantine, policy or other "
            "(or the reason the block already holds)",
        )
    before = snapshot(block, changes)
    for k, v in changes.items():
        setattr(block, k, v)
    block.updated_by_user_id = user.id

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_mac_block",
        resource_id=str(block.id),
        resource_display=str(block.mac_address),
        changed_fields=changed_keys(before, changes),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    collect_wake(dhcp_group_channel(block.group_id))
    await db.commit()
    await db.refresh(block)
    _kick_windows_sync()
    rows = await _build_response(db, [block])
    return rows[0]


@router.delete("/mac-blocks/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mac_block(block_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    block = await db.get(DHCPMACBlock, block_id)
    if block is None:
        raise HTTPException(status_code=404, detail="MAC block not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_mac_block",
        resource_id=str(block.id),
        resource_display=str(block.mac_address),
    )
    collect_wake(dhcp_group_channel(block.group_id))
    await db.delete(block)
    await db.commit()
    _kick_windows_sync()


__all__ = ["router"]
