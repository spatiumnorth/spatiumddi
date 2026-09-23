"""DHCP server group CRUD.

Server groups are the primary configuration container under the group-
centric model: scopes, pools, statics, and client classes all live here,
and HA tuning (mode, heartbeat, max-response / max-ack / max-unacked,
auto-failover) lives on the group too. A group with two Kea members is
implicitly a Kea HA pair; a single-member group is standalone.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp._failover_schemas import (
    FailoverActionResponse,
    FailoverRelationshipCreate,
    FailoverRelationshipUpdate,
    FailoverReplicate,
    FailoverScopesChange,
    GroupFailoverResponse,
)
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPServerGroup
from app.services.ai.operations import get_operation
from app.services.ai.operations_risky import DeleteGroupArgs
from app.services.approvals.gate import gate_or_execute
from app.services.dhcp import windows_failover_manage as fo_manage
from app.services.dhcp.windows_failover_report import group_failover_report

router = APIRouter(
    prefix="/server-groups",
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_server"))],
)

VALID_MODES = {"standalone", "load-balancing", "hot-standby"}
# Issue #365 — Kea dhcp-socket-type selector. "direct" → raw sockets
# (receives broadcast DISCOVERs from directly-attached clients), "relay"
# → udp sockets (relay-only).
VALID_SOCKET_MODES = {"direct", "relay"}

# #637 — nullable group fields an operator must be able to CLEAR. ``exclude_none``
# alone would silently swallow an explicit ``null``, making "uncap the lease cache"
# impossible once a max-age had been set. Mirrors NULLABLE_CLEARABLE_SCOPE_FIELDS
# in scopes.py.
NULLABLE_CLEARABLE_GROUP_FIELDS = {"lease_cache_max_age"}


class GroupCreate(BaseModel):
    name: str
    description: str = ""
    mode: str = "hot-standby"
    dhcp_socket_mode: str = "direct"
    heartbeat_delay_ms: int = 10000
    max_response_delay_ms: int = 60000
    max_ack_delay_ms: int = 10000
    max_unacked_clients: int = 5
    auto_failover: bool = True
    # #637 — Kea lease cache. 0.0 disables (the pre-Kea-3.0 behaviour and our
    # default); Kea 3.0's own default is 0.25. See models/dhcp.py for why we
    # do not simply inherit it.
    lease_cache_threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    lease_cache_max_age: int | None = Field(default=None, ge=1)
    # #980 — Kea packet-worker pool size. 1 (the default) measured 1.7x-2.9x
    # more packets served than Kea's own auto-sizing on every CPU allocation
    # tested; ``0`` hands sizing back to Kea (one worker per HOST cpu,
    # regardless of the container's cgroup share). Capped at 64 because this
    # is a pool-size knob, not a free-form integer, and a four-digit value is
    # a typo that renders a config Kea accepts and then thrashes on.
    kea_thread_pool_size: int = Field(default=1, ge=0, le=64)
    # #980 — True (default) keeps today's per-packet log detail. False
    # silences DHCP4_PACKET_RECEIVED / _SEND for ~1.30x more packets served.
    kea_packet_logging: bool = True

    @field_validator("mode")
    @classmethod
    def _m(cls, v: str) -> str:
        if v not in VALID_MODES:
            raise ValueError(f"mode must be one of {sorted(VALID_MODES)}")
        return v

    @field_validator("dhcp_socket_mode")
    @classmethod
    def _sm(cls, v: str) -> str:
        if v not in VALID_SOCKET_MODES:
            raise ValueError(f"dhcp_socket_mode must be one of {sorted(VALID_SOCKET_MODES)}")
        return v


class GroupUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    mode: str | None = None
    dhcp_socket_mode: str | None = None
    heartbeat_delay_ms: int | None = None
    max_response_delay_ms: int | None = None
    max_ack_delay_ms: int | None = None
    max_unacked_clients: int | None = None
    auto_failover: bool | None = None
    lease_cache_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    lease_cache_max_age: int | None = Field(default=None, ge=1)
    kea_thread_pool_size: int | None = Field(default=None, ge=0, le=64)
    kea_packet_logging: bool | None = None

    @field_validator("mode")
    @classmethod
    def _m(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_MODES:
            raise ValueError(f"mode must be one of {sorted(VALID_MODES)}")
        return v

    @field_validator("dhcp_socket_mode")
    @classmethod
    def _sm(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_SOCKET_MODES:
            raise ValueError(f"dhcp_socket_mode must be one of {sorted(VALID_SOCKET_MODES)}")
        return v


class ServerSummary(BaseModel):
    id: uuid.UUID
    name: str
    driver: str
    host: str
    status: str
    ha_state: str | None
    ha_peer_url: str
    agent_approved: bool


class GroupResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    mode: str
    dhcp_socket_mode: str
    heartbeat_delay_ms: int
    max_response_delay_ms: int
    max_ack_delay_ms: int
    max_unacked_clients: int
    auto_failover: bool
    lease_cache_threshold: float
    lease_cache_max_age: int | None
    kea_thread_pool_size: int
    kea_packet_logging: bool
    # Computed: count of Kea servers currently in the group. ≥ 2 means
    # the group renders the libdhcp_ha.so hook on every peer.
    kea_member_count: int = 0
    # Member servers rolled up so the UI can render a group detail page
    # without a second round-trip. Empty when nothing's registered.
    servers: list[ServerSummary] = []
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


def _group_to_response(g: DHCPServerGroup) -> GroupResponse:
    kea = [s for s in (g.servers or []) if s.driver == "kea"]
    return GroupResponse(
        id=g.id,
        name=g.name,
        description=g.description,
        mode=g.mode,
        dhcp_socket_mode=g.dhcp_socket_mode,
        heartbeat_delay_ms=g.heartbeat_delay_ms,
        max_response_delay_ms=g.max_response_delay_ms,
        max_ack_delay_ms=g.max_ack_delay_ms,
        max_unacked_clients=g.max_unacked_clients,
        auto_failover=g.auto_failover,
        lease_cache_threshold=g.lease_cache_threshold,
        lease_cache_max_age=g.lease_cache_max_age,
        kea_thread_pool_size=g.kea_thread_pool_size,
        kea_packet_logging=g.kea_packet_logging,
        kea_member_count=len(kea),
        servers=[
            ServerSummary(
                id=s.id,
                name=s.name,
                driver=s.driver,
                host=s.host,
                status=s.status,
                ha_state=s.ha_state,
                ha_peer_url=s.ha_peer_url or "",
                agent_approved=s.agent_approved,
            )
            for s in (g.servers or [])
        ],
        created_at=g.created_at,
        modified_at=g.modified_at,
    )


@router.get("", response_model=list[GroupResponse])
async def list_groups(db: DB, _: CurrentUser) -> list[GroupResponse]:
    res = await db.execute(select(DHCPServerGroup).order_by(DHCPServerGroup.name))
    return [_group_to_response(g) for g in res.unique().scalars().all()]


@router.post("", response_model=GroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(body: GroupCreate, db: DB, user: SuperAdmin) -> GroupResponse:
    existing = await db.execute(select(DHCPServerGroup).where(DHCPServerGroup.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A DHCP server group with that name exists")
    g = DHCPServerGroup(**body.model_dump())
    db.add(g)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_server_group",
        resource_id=str(g.id),
        resource_display=g.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(g)
    return _group_to_response(g)


@router.get("/{group_id}", response_model=GroupResponse)
async def get_group(group_id: uuid.UUID, db: DB, _: CurrentUser) -> GroupResponse:
    g = await db.get(DHCPServerGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="Server group not found")
    return _group_to_response(g)


@router.get("/{group_id}/failover", response_model=GroupFailoverResponse)
async def get_group_failover(group_id: uuid.UUID, db: DB, _: CurrentUser) -> GroupFailoverResponse:
    """Windows DHCP failover as the group's members report it (#1110).

    The failover relationships each Windows member reports (merged across
    the two partners), whether each member's view is current, and how every
    scope a member holds is served — by one server, by a failover pair, or
    by several servers that do not coordinate. Read from what the topology
    poll stored, never live; ``members[].failover_observed_at`` /
    ``scopes_observed_at`` say how old it is. A group with no Windows
    members answers with empty lists.
    """
    g = await db.get(DHCPServerGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="Server group not found")
    return GroupFailoverResponse.model_validate(await group_failover_report(db, g))


# ── Windows failover relationship management (#1110 Phase 2) ──────────
#
# Each action runs one ``*-DhcpServerv4Failover*`` cmdlet on one member,
# which acts on both partners from there — so the member's WinRM transport
# must be CredSSP (refused with a 422 otherwise, before anything is sent).
# Superadmin, like every other group write: these create and delete scopes
# on the partner server and carry the relationship's shared secret. The
# secret reaches Windows and nothing else — not the audit row, not a log.


async def _group_or_404(db: DB, group_id: uuid.UUID) -> DHCPServerGroup:
    g = await db.get(DHCPServerGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="Server group not found")
    return g


async def _action_response(
    db: DB,
    g: DHCPServerGroup,
    user: SuperAdmin,
    result: fo_manage.FailoverActionResult,
    audit_fields: dict[str, object],
) -> FailoverActionResponse:
    write_audit(
        db,
        user=user,
        action=f"failover_{result.action}",
        resource_type="dhcp_server_group",
        resource_id=str(g.id),
        resource_display=f"{g.name}:{result.relationship}",
        new_value={
            "relationship": result.relationship,
            "ran_on": result.ran_on.name,
            "partner": result.partner.name if result.partner else None,
            "scope_ids": result.scope_ids,
            "warnings": result.warnings,
            **audit_fields,
        },
    )
    await db.commit()
    return FailoverActionResponse(
        action=result.action,  # type: ignore[arg-type]
        relationship=result.relationship,
        ran_on_server_id=result.ran_on.id,
        ran_on_server_name=result.ran_on.name,
        partner_server_id=result.partner.id if result.partner else None,
        partner_server_name=result.partner.name if result.partner else None,
        scope_ids=result.scope_ids,
        warnings=result.warnings,
        failover=GroupFailoverResponse.model_validate(await group_failover_report(db, g)),
    )


def _tuning_audit(
    body: FailoverRelationshipCreate | FailoverRelationshipUpdate,
) -> dict[str, object]:
    fields = body.model_dump(mode="json", exclude={"shared_secret"}, exclude_none=True)
    fields["shared_secret_set"] = body.shared_secret is not None
    return fields


@router.post(
    "/{group_id}/failover/relationships",
    response_model=FailoverActionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_failover_relationship(
    group_id: uuid.UUID, body: FailoverRelationshipCreate, db: DB, user: SuperAdmin
) -> FailoverActionResponse:
    """Create a Windows DHCP failover relationship between two members.

    ``Add-DhcpServerv4Failover`` runs on ``server_id``, which must hold every
    scope in ``scope_ids``; Windows copies them to ``partner_server_id``,
    which must hold none of them. Checked live before anything is sent.
    """
    g = await _group_or_404(db, group_id)
    result = await fo_manage.create_relationship(
        db,
        g,
        name=body.name,
        server_id=body.server_id,
        partner_server_id=body.partner_server_id,
        scope_ids=body.scope_ids,
        mode=body.mode,
        load_balance_percent=body.load_balance_percent,
        server_role=body.server_role,
        reserve_percent=body.reserve_percent,
        max_client_lead_time_seconds=body.max_client_lead_time_seconds,
        auto_state_transition=body.auto_state_transition,
        state_switch_interval_seconds=body.state_switch_interval_seconds,
        shared_secret=body.shared_secret,
    )
    return await _action_response(db, g, user, result, _tuning_audit(body))


@router.patch(
    "/{group_id}/failover/relationships/{name}",
    response_model=FailoverActionResponse,
)
async def update_failover_relationship(
    group_id: uuid.UUID, name: str, body: FailoverRelationshipUpdate, db: DB, user: SuperAdmin
) -> FailoverActionResponse:
    """Change a relationship's mode or tuning (``Set-DhcpServerv4Failover``).
    Fields left out are left as they are."""
    g = await _group_or_404(db, group_id)
    result = await fo_manage.update_relationship(
        db,
        g,
        name,
        changes=body.model_dump(exclude_unset=True, exclude={"server_id"}),
        server_id=body.server_id,
    )
    return await _action_response(db, g, user, result, _tuning_audit(body))


@router.delete(
    "/{group_id}/failover/relationships/{name}",
    response_model=FailoverActionResponse,
)
async def delete_failover_relationship(
    group_id: uuid.UUID,
    name: str,
    db: DB,
    user: SuperAdmin,
    keep_server_id: uuid.UUID | None = None,
) -> FailoverActionResponse:
    """Delete a relationship (``Remove-DhcpServerv4Failover``).

    Windows deletes the PARTNER's copy of every scope the relationship
    covered; ``keep_server_id`` — default the hot-standby Active side, else
    the lowest-named — keeps its copies and serves them alone.
    """
    g = await _group_or_404(db, group_id)
    result = await fo_manage.delete_relationship(db, g, name, keep_server_id=keep_server_id)
    return await _action_response(db, g, user, result, {})


@router.post(
    "/{group_id}/failover/relationships/{name}/scopes",
    response_model=FailoverActionResponse,
)
async def add_failover_scopes(
    group_id: uuid.UUID, name: str, body: FailoverScopesChange, db: DB, user: SuperAdmin
) -> FailoverActionResponse:
    """Add scopes to a relationship (``Add-DhcpServerv4FailoverScope``).

    Each scope must be held by exactly one side, which is where the cmdlet
    runs; Windows copies it to the other.
    """
    g = await _group_or_404(db, group_id)
    result = await fo_manage.add_scopes(db, g, name, scope_ids=body.scope_ids)
    return await _action_response(db, g, user, result, {})


@router.delete(
    "/{group_id}/failover/relationships/{name}/scopes/{scope_id}",
    response_model=FailoverActionResponse,
)
async def remove_failover_scope(
    group_id: uuid.UUID,
    name: str,
    scope_id: str,
    db: DB,
    user: SuperAdmin,
    keep_server_id: uuid.UUID | None = None,
) -> FailoverActionResponse:
    """Take a scope out of a relationship (``Remove-DhcpServerv4FailoverScope``).

    Windows deletes the PARTNER's copy; ``keep_server_id`` keeps serving it.
    """
    g = await _group_or_404(db, group_id)
    result = await fo_manage.remove_scopes(
        db, g, name, scope_ids=[scope_id], keep_server_id=keep_server_id
    )
    return await _action_response(db, g, user, result, {})


@router.post(
    "/{group_id}/failover/relationships/{name}/replicate",
    response_model=FailoverActionResponse,
)
async def replicate_failover_relationship(
    group_id: uuid.UUID, name: str, body: FailoverReplicate, db: DB, user: SuperAdmin
) -> FailoverActionResponse:
    """Copy one side's scope configuration over the partner's
    (``Invoke-DhcpServerv4FailoverReplication``) — for drift made on Windows."""
    g = await _group_or_404(db, group_id)
    result = await fo_manage.replicate(
        db, g, name, source_server_id=body.source_server_id, scope_ids=body.scope_ids
    )
    return await _action_response(
        db, g, user, result, {"source_server_id": str(body.source_server_id)}
    )


@router.put("/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: uuid.UUID, body: GroupUpdate, db: DB, user: SuperAdmin
) -> GroupResponse:
    g = await db.get(DHCPServerGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="Server group not found")
    changes = {
        k: v
        for k, v in body.model_dump(exclude_unset=True).items()
        if v is not None or k in NULLABLE_CLEARABLE_GROUP_FIELDS
    }
    for k, v in changes.items():
        setattr(g, k, v)
    # HA tuning (mode / heartbeat / delays / auto-failover), the Kea socket
    # mode (#365) and the packet-worker pool size (#980) all render into
    # every member's bundle, so wake the group channel — the bundle ETag
    # shifts and agents re-render promptly.
    collect_wake(dhcp_group_channel(g.id))
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_server_group",
        resource_id=str(g.id),
        resource_display=g.name,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    await db.commit()
    await db.refresh(g)
    return _group_to_response(g)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_group(
    group_id: uuid.UUID, db: DB, user: SuperAdmin, request: Request
) -> JSONResponse | None:
    """Delete a DHCP server group (refused if it still holds servers).

    Two-person approval (#62): when the ``governance.approvals`` module is on
    and a ``delete:dhcp_server_group`` policy matches, returns ``202`` with a
    pending change-request; otherwise executes inline via ``operation.apply``
    exactly as before (route stays SuperAdmin-gated).
    """
    op = get_operation("delete_group")
    assert op is not None  # registered at import
    args = DeleteGroupArgs(group_id=group_id)
    pending = await gate_or_execute(db, user, request, operation=op, args=args)
    if pending is not None:
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=pending.as_dict())
    await op.apply(db, user, args)
    return None
