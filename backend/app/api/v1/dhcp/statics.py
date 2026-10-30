"""DHCP static assignment CRUD + conflict detection."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp._mac import canonicalize_mac
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.dns_names import validate_optional_hostname
from app.core.permissions import require_resource_permission
from app.core.update_nulls import resolve_update_changes
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.ipam import Subnet
from app.services.dhcp.normalize import norm_duid, norm_ip, norm_mac
from app.services.dhcp.option_validation import normalize_options
from app.services.dhcp.static_conflicts import check_static_conflicts as _conflict_check
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
    rather than sanitized (issue #597). ``None`` passes through; a blank or
    whitespace-only value becomes ``""`` (no hostname) rather than being kept
    verbatim, where the IPAM mirror would publish it as a record owner.
    """
    return validate_optional_hostname(v)


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


def _comparable(field: str, v: Any) -> Any:
    """The form of a static's field that a no-op update is detected in (#3076).

    Spellings of one value compare equal: a MAC in any case or separator, an
    address in any IP notation (the column is INET, so it reads back as an
    ``ipaddress`` object), a hostname with or without its root dot or capitals,
    a DUID with or without separators, and ``None`` / ``""`` for the optional
    text fields.
    """
    if v is None or (isinstance(v, str) and v.strip() == ""):
        return None
    if isinstance(v, (dict, list)):
        return v
    text = str(v).strip()
    if field == "mac_address":
        return norm_mac(text)
    if field == "ip_address":
        return norm_ip(text.split("/", 1)[0])
    if field == "duid":
        return norm_duid(text)
    if field == "hostname":
        return text.rstrip(".").lower()
    return text


def _same_value(field: str, current: Any, sent: Any) -> bool:
    """True when ``sent`` is the stored ``current`` value, however spelled."""
    return bool(_comparable(field, current) == _comparable(field, sent))


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


async def _recount_subnet(db: DB, subnet_id: uuid.UUID) -> None:
    """Refresh the cached allocated counts a static's IPAM mirror changed.

    The mirror row counts toward the subnet's ``allocated_ips`` and its
    block's rollup; without this they stay stale until the hourly recount
    (#2533). Flush first so the counts see the mirror write, and again
    before the block sums the subnet's new count.
    """
    from app.api.v1.ipam.router import (  # noqa: PLC0415
        _update_block_utilization,
        _update_utilization,
    )

    await db.flush()
    await _update_utilization(db, subnet_id)
    await db.flush()
    subnet = await db.get(Subnet, subnet_id)
    if subnet is not None:
        await _update_block_utilization(db, subnet.block_id)


@router.post(
    "/scopes/{scope_id}/statics",
    response_model=StaticResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_static(
    scope_id: uuid.UUID, body: StaticCreate, db: DB, user: CurrentUser
) -> DHCPStaticAssignment:
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    if body.options_override:
        body.options_override = normalize_options(body.options_override)
        await validate_dhcp_options(
            db,
            body.options_override,
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family=scope.address_family or "ipv4",
        )
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
    await _recount_subnet(db, scope.subnet_id)
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
    static_id: uuid.UUID, body: StaticUpdate, db: DB, user: CurrentUser
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
    # #1563 — explicit null clears client_id / duid / options_override /
    # ip_address_id; null for a NOT NULL column is a 422.
    changes = resolve_update_changes(
        body,
        clearable={"client_id", "duid", "options_override", "ip_address_id"},
        non_nullable={"ip_address", "mac_address", "hostname", "description", "tags"},
    )
    if changes.get("options_override"):
        changes["options_override"] = normalize_options(changes["options_override"])
        await validate_dhcp_options(
            db,
            changes["options_override"],
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family=scope.address_family or "ipv4",
            previous=st.options_override or {},
        )
    # #3076 — a field sent back at the value the row already holds is not a
    # change. A dialog opened on a stale row resends every field, and writing
    # them through would revert whatever another surface (an IPAM inline
    # edit) stored since.
    changes = {k: v for k, v in changes.items() if not _same_value(k, getattr(st, k), v)}
    new_ip = changes.get("ip_address", str(st.ip_address))
    new_mac = changes.get("mac_address", str(st.mac_address))
    if "ip_address" in changes or "mac_address" in changes:
        await _conflict_check(db, scope, new_ip, new_mac, exclude_id=st.id)
    for k, v in changes.items():
        setattr(st, k, v)
    await db.flush()
    if not changes:
        # Nothing differs from what is stored: no push, no IPAM / DNS write.
        await db.refresh(st)
        return st
    await push_static_change(db, st, action="update", prev_mac=prev_mac, prev_ip=prev_ip)
    collect_wake(dhcp_group_channel(scope.group_id))
    await upsert_ipam_for_static(db, scope, st, action="update")
    await _recount_subnet(db, scope.subnet_id)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_static_assignment",
        resource_id=str(st.id),
        resource_display=f"{st.mac_address}->{st.ip_address}",
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(st)
    return st


@router.delete("/statics/{static_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_static(static_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
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
    if scope is not None:
        await _recount_subnet(db, scope.subnet_id)
    await publish_handover_ddns(db, handovers)
    await db.commit()
