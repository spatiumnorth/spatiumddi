"""DHCP static assignment CRUD + conflict detection."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp._mac import canonicalize_mac
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.dns_names import validate_hostname
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.ipam import Subnet
from app.services.dhcp.option_validation import normalize_options
from app.services.dhcp.static_ipam import (
    detach_ipam_for_static,
    publish_handover_ddns,
    upsert_ipam_for_static,
)
from app.services.dhcp.windows_writethrough import push_static_change
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_static"))]
)


def _validate_optional_hostname(v: str | None) -> str | None:
    """Reservation hostname is optional; validate the RFC 1123 form when set.

    Operator-entered (not client-supplied), so a malformed value is rejected
    rather than sanitized (issue #597). ``""`` / ``None`` pass through.
    """
    if v is None or v.strip() == "":
        return v
    return validate_hostname(v)


def _no_scope_move(v: uuid.UUID | None) -> uuid.UUID | None:
    """Reject a body-supplied ``scope_id`` on reservation create/update (#619).

    A reservation belongs to its scope — uniqueness is keyed on it and Kea renders
    the reservation nested inside that scope's ``subnet4`` stanza, so there is no
    renderable form of a relocated row. On create the scope comes from the path;
    on update it cannot change at all. Either way, a value here means the caller
    expects something we will not do, so say so instead of silently ignoring it.
    """
    if v is not None:
        raise ValueError(
            "scope_id cannot be set from the request body. A reservation belongs to "
            "its scope; to move one, delete it and re-create it under the target scope."
        )
    return v


class StaticCreate(BaseModel):
    ip_address: str
    mac_address: str
    hostname: str = ""
    description: str = ""
    client_id: str | None = None
    # DHCPv6 DUID (issue #368) — on a v6 scope the reservation is keyed on
    # this instead of the MAC. The MAC stays required at the model level.
    duid: str | None = None
    options_override: dict[str, Any] | None = None
    ip_address_id: uuid.UUID | None = None
    tags: dict[str, Any] = Field(default_factory=dict)

    # Declared only so a body ``scope_id`` is REJECTED rather than silently
    # dropped (#619) — it is a path parameter here, and Pydantic's default
    # ``extra="ignore"`` would swallow it with a 200 and no effect. Blanket
    # ``extra="forbid"`` would do that too, but it would also 422 the common
    # GET → edit → PUT round-trip (StaticResponse carries ``id`` /
    # ``created_at`` / ``modified_at``), so reject the one field that means
    # something and keep ignoring the server-owned ones.
    scope_id: uuid.UUID | None = None

    _reject_scope_id = field_validator("scope_id")(_no_scope_move)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        return _validate_optional_hostname(v) or ""

    @field_validator("mac_address")
    @classmethod
    def _mac(cls, v: str) -> str:
        # The column is MACADDR and ``_conflict_check`` compares against it, so
        # an unvalidated value reached Postgres as a cast failure and surfaced
        # to the operator as a 500 "Internal Server Error" in the reservation
        # form — for a typo. Same canonicalization the MAC-blocklist endpoint
        # has always applied, so ``AA-BB-CC-DD-EE-01`` is accepted and stored
        # as ``aa:bb:cc:dd:ee:01``.
        return canonicalize_mac(v)


class StaticUpdate(BaseModel):
    ip_address: str | None = None
    mac_address: str | None = None
    hostname: str | None = None
    description: str | None = None
    client_id: str | None = None
    duid: str | None = None
    options_override: dict[str, Any] | None = None
    ip_address_id: uuid.UUID | None = None
    tags: dict[str, Any] | None = None

    # A reservation cannot be re-pointed at another scope: the scope is part of
    # its identity (uniqueness is keyed on it, and Kea renders the reservation
    # nested inside the scope's ``subnet4`` stanza), so there is no renderable
    # form of a relocated row. Declared here purely to REJECT it — sending one
    # used to be a silent 200-no-op (#619). See the note on StaticCreate for why
    # this is a field validator and not ``extra="forbid"``.
    scope_id: uuid.UUID | None = None

    _reject_scope_id = field_validator("scope_id")(_no_scope_move)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str | None) -> str | None:
        return _validate_optional_hostname(v)

    @field_validator("mac_address")
    @classmethod
    def _mac(cls, v: str | None) -> str | None:
        # ``None`` means "not being changed" on a PATCH-shaped update body.
        return canonicalize_mac(v) if v is not None else None


class StaticResponse(BaseModel):
    id: uuid.UUID
    scope_id: uuid.UUID
    ip_address: str
    mac_address: str
    hostname: str
    description: str
    client_id: str | None
    duid: str | None = None
    options_override: dict[str, Any] | None
    ip_address_id: uuid.UUID | None
    tags: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("ip_address", "mac_address", mode="before")
    @classmethod
    def _inet_mac_to_str(cls, v: Any) -> Any:
        return str(v) if v is not None else v


async def _conflict_check(
    db, scope: DHCPScope, ip: str, mac: str, exclude_id: uuid.UUID | None = None
) -> None:
    """Conflict: same MAC on same group (across scopes), IP inside a reserved/dynamic pool on another scope+group."""
    # MAC dup across every scope served by the same group
    same_mac = await db.execute(
        select(DHCPStaticAssignment)
        .join(DHCPScope, DHCPStaticAssignment.scope_id == DHCPScope.id)
        .where(
            DHCPScope.group_id == scope.group_id,
            DHCPStaticAssignment.mac_address == mac,
        )
    )
    for row in same_mac.scalars().all():
        if exclude_id is not None and row.id == exclude_id:
            continue
        raise HTTPException(
            status_code=409,
            detail=f"MAC {mac} already reserved in this group in scope {row.scope_id}",
        )

    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid IP: {e}") from e

    # The reservation's IP must fall inside the scope's subnet. Kea renders the
    # reservation *nested inside* that subnet's stanza
    # (``"subnet4": [{"subnet": "<cidr>", "reservations": [...]}]``) and Windows
    # keys reservations by the scope's network address, so an out-of-CIDR
    # reservation ships structurally invalid config to the backend. Catch it
    # here as a legible 422 instead of a downstream agent failure (#619).
    subnet_row = await db.get(Subnet, scope.subnet_id)
    if subnet_row is not None:
        try:
            network = ipaddress.ip_network(str(subnet_row.network), strict=False)
        except ValueError:  # pragma: no cover — a malformed subnet CIDR can't be validated against
            network = None
        if network is not None and ip_addr not in network:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"IP {ip} is outside the scope's subnet {network}. "
                    "A reservation must fall inside the subnet its scope serves."
                ),
            )

    # NOTE: a reservation whose IP lands inside a *dynamic* pool is explicitly
    # allowed. Pinning a MAC inside the range is the standard idiom on every
    # driver we ship — Kea honours it (default ``reservations-out-of-pool:
    # false`` runs the in-pool check and won't hand the address to another
    # client), FortiGate renders ``reserved-address`` independently of
    # ``ip-range``, and Windows *requires* the reservation to fall inside the
    # scope's StartRange–EndRange (which is derived from the dynamic pool). The
    # old in-pool 409 had no driver basis, its "exclude it first" workaround was
    # a no-op or actively harmful, and it looked like it broke Windows statics
    # outright (#631). Pool occupancy accounts for these reservations separately
    # (``services/dhcp/pool_occupancy.py``).


@router.get("/scopes/{scope_id}/statics", response_model=list[StaticResponse])
async def list_statics(
    scope_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    tag: list[str] = Query(default_factory=list),
) -> list[DHCPStaticAssignment]:
    stmt = select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope_id)
    stmt = apply_tag_filter(stmt, DHCPStaticAssignment.tags, tag)
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.post(
    "/scopes/{scope_id}/statics",
    response_model=StaticResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_static(
    scope_id: uuid.UUID, body: StaticCreate, db: DB, user: SuperAdmin
) -> DHCPStaticAssignment:
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    if body.options_override:
        body.options_override = normalize_options(body.options_override)
        validate_dhcp_options(body.options_override, address_family=scope.address_family or "ipv4")
    await _conflict_check(db, scope, body.ip_address, body.mac_address)
    st = DHCPStaticAssignment(
        scope_id=scope_id,
        created_by_user_id=user.id,
        **body.model_dump(exclude={"scope_id"}),
    )
    db.add(st)
    await db.flush()
    await push_static_change(db, st, action="create")
    collect_wake(dhcp_group_channel(scope.group_id))
    await upsert_ipam_for_static(db, scope, st)
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_static_assignment",
        resource_id=str(st.id),
        resource_display=f"{body.mac_address}->{body.ip_address}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(st)
    return st


@router.put("/statics/{static_id}", response_model=StaticResponse)
async def update_static(
    static_id: uuid.UUID, body: StaticUpdate, db: DB, user: SuperAdmin
) -> DHCPStaticAssignment:
    st = await db.get(DHCPStaticAssignment, static_id)
    if st is None:
        raise HTTPException(status_code=404, detail="Static assignment not found")
    scope = await db.get(DHCPScope, st.scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    # Capture the old MAC + IP before mutating so the write-through can
    # remove-then-add on Windows if either changed (#426 — Windows can't
    # relocate a reservation's IP via Set-).
    prev_mac = str(st.mac_address)
    prev_ip = str(st.ip_address)
    changes = body.model_dump(exclude_none=True)
    if changes.get("options_override"):
        changes["options_override"] = normalize_options(changes["options_override"])
        validate_dhcp_options(
            changes["options_override"],
            address_family=scope.address_family or "ipv4",
            previous=st.options_override or {},
        )
    new_ip = changes.get("ip_address", str(st.ip_address))
    new_mac = changes.get("mac_address", str(st.mac_address))
    if "ip_address" in changes or "mac_address" in changes:
        await _conflict_check(db, scope, new_ip, new_mac, exclude_id=st.id)
    for k, v in changes.items():
        setattr(st, k, v)
    await db.flush()
    await push_static_change(db, st, action="update", prev_mac=prev_mac, prev_ip=prev_ip)
    collect_wake(dhcp_group_channel(scope.group_id))
    await upsert_ipam_for_static(db, scope, st, action="update")
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_static_assignment",
        resource_id=str(st.id),
        resource_display=f"{st.mac_address}->{st.ip_address}",
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    await db.commit()
    await db.refresh(st)
    return st


@router.delete("/statics/{static_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_static(static_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    st = await db.get(DHCPStaticAssignment, static_id)
    if st is None:
        raise HTTPException(status_code=404, detail="Static assignment not found")
    scope = await db.get(DHCPScope, st.scope_id)
    if scope is not None:
        collect_wake(dhcp_group_channel(scope.group_id))
    await push_static_change(db, st, action="delete")
    handovers = await detach_ipam_for_static(db, st)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_static_assignment",
        resource_id=str(st.id),
        resource_display=f"{st.mac_address}->{st.ip_address}",
    )
    await db.delete(st)
    # #1274 — a row handed to a live lease gets its DDNS back, but only once
    # the reservation is gone: DDNS lets a reservation's hostname win.
    await db.flush()
    await publish_handover_ddns(db, handovers)
    await db.commit()
