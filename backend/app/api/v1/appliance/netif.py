"""Additional network interfaces on an appliance (#4428).

Static addresses, 802.1Q VLAN sub-interfaces, static routes, MTU and
link up/down for every NIC except the primary one, per appliance.

Desired state lives on the appliance row and rides the supervisor
heartbeat to the host runner ``spatiumddi-netif-reload`` over the same
trigger-file plane as every other host-config plane — so these endpoints
validate, stamp and wake; they never wait for the host. The runner
applies with a rollback: if the node cannot reach the control plane
afterwards it restores the previous profiles, and says so
(``state: reverted``).

Validation lives in ``app.services.appliance.netif`` and is shared with
the copilot tools. Every refusal is a 422 carrying the reason; a node
that has never reported its inventory is a 409, because every check needs
to know what the node already has.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.deps import DB, CurrentUser
from app.core.agent_wake import appliance_channel, publish_wake
from app.core.permissions import require_permission
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.services.appliance import netif as netif_svc
from app.services.appliance.netif import NetifError

router = APIRouter(tags=["appliance-network"])


# ── Schemas ──────────────────────────────────────────────────────────


class RouteIn(BaseModel):
    destination: str
    gateway: str
    metric: int | None = None


class InterfaceIn(BaseModel):
    #: ``ethernet`` (a physical port the node reports) or ``vlan``.
    kind: str = "ethernet"
    #: Required for ``ethernet``. For ``vlan`` it defaults to
    #: ``<parent>.<vlan_id>``.
    name: str | None = None
    parent: str | None = None
    vlan_id: int | None = None
    addresses: list[str] = Field(default_factory=list)
    mtu: int | None = None
    up: bool = True
    routes: list[RouteIn] = Field(default_factory=list)
    description: str | None = None


class InterfacesRequest(BaseModel):
    """The WHOLE desired set. ``[]`` removes every managed interface."""

    interfaces: list[InterfaceIn]


class RouteOut(BaseModel):
    destination: str
    gateway: str | None = None
    metric: int | None = None


class InterfaceOut(BaseModel):
    name: str
    kind: str
    parent: str | None = None
    vlan_id: int | None = None
    addresses: list[str]
    mtu: int | None = None
    up: bool
    routes: list[RouteOut]
    description: str | None = None
    #: active / inactive / confirming / pending / reverted / failed /
    #: unreported — see ``netif.merge_state``.
    state: str
    detail: str | None = None
    live_addresses: list[str] = Field(default_factory=list)
    live_state: str | None = None
    live_carrier: bool | None = None


class NicOut(BaseModel):
    """One interface the node reports, managed or not."""

    name: str
    kind: str
    parent: str | None = None
    vlan_id: int | None = None
    master: str | None = None
    state: str
    carrier: bool | None = None
    mtu: int | None = None
    mac: str | None = None
    addresses: list[str]
    #: True for an interface this feature manages.
    managed: bool = False
    #: Set when it cannot be managed here, with the reason.
    protected_reason: str | None = None


class NetworkInterfacesResponse(BaseModel):
    #: False when the node has not reported its inventory (offline, or a
    #: supervisor that predates this feature). Unknown, never "empty".
    reported: bool
    hostname: str
    interfaces: list[InterfaceOut]
    nics: list[NicOut]
    #: ``applied`` / ``pending-confirm`` / ``reverted`` / ``failed`` /
    #: None when the runner has never run.
    apply_state: str | None = None
    apply_error: str | None = None
    revert_seconds: int = netif_svc.REVERT_SECONDS


class ValidationResponse(BaseModel):
    ok: bool = True
    interfaces: list[dict[str, Any]]
    revert_seconds: int = netif_svc.REVERT_SECONDS


# ── Helpers ──────────────────────────────────────────────────────────


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _load(db: DB, appliance_id: uuid.UUID, *, lock: bool = False) -> Appliance:
    row = await db.get(Appliance, appliance_id, with_for_update=lock)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Appliance not found.")
    if row.revoked_at is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{row.hostname} has been revoked; its network cannot be managed.",
        )
    if row.state != APPLIANCE_STATE_APPROVED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{row.hostname} is not approved yet; approve it before managing its network.",
        )
    return row


def context_for(row: Appliance, names: set[str]) -> netif_svc.NetifContext:
    return netif_svc.build_context(
        row.cluster_health,
        node_ips=[*(row.node_ips or []), *([row.node_ip] if row.node_ip else [])],
        pod_cidr=row.pod_cidr,
        service_cidr=row.service_cidr,
        managed_names=names,
    )


def validate_for(row: Appliance, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shared by the routes and the copilot proposal tool."""
    names = {str(e.get("name") or "") for e in entries if isinstance(e, dict)}
    # A VLAN's derived name is not in the request; the DESIRED set's names
    # are, so include them too or re-saving would refuse its own addresses.
    names |= {str(e.get("name")) for e in (row.desired_network_interfaces or [])}
    # Only interfaces the node reports as ours count as "managed" when
    # their addresses are compared: the live address of an interface we are
    # about to rewrite is not a conflict.
    ctx = context_for(row, names)
    return netif_svc.validate_desired(entries, ctx)


def _response(row: Appliance) -> NetworkInterfacesResponse:
    ch = row.cluster_health
    ctx = context_for(row, {str(e.get("name")) for e in (row.desired_network_interfaces or [])})
    managed = {str(e.get("name")) for e in (row.desired_network_interfaces or [])}
    status_block = netif_svc.apply_status(ch)
    err = None
    if status_block and status_block.get("state") in ("failed", "reverted"):
        err = str(status_block.get("error") or "")[:500] or None
    nics = [
        NicOut(
            **n,
            managed=n["name"] in managed,
            protected_reason=ctx.protected.get(n["name"]),
        )
        for n in netif_svc.inventory_nics(ch)
        if n["name"]
    ]
    return NetworkInterfacesResponse(
        reported=netif_svc.has_inventory(ch),
        hostname=row.hostname,
        interfaces=[
            InterfaceOut(**m) for m in netif_svc.merge_state(row.desired_network_interfaces, ch)
        ],
        nics=nics,
        apply_state=(
            str(status_block["state"])[:32] if status_block and status_block.get("state") else None
        ),
        apply_error=err,
    )


def _refuse(exc: NetifError) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


def _require_inventory(row: Appliance) -> None:
    if not netif_svc.has_inventory(row.cluster_health):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{row.hostname} has not reported its network interfaces yet. It may be "
            "offline, or running a supervisor that predates this feature — every check "
            "needs to know what the node already has, so nothing is changed blind.",
        )


def _dump(body: InterfacesRequest) -> list[dict[str, Any]]:
    return [i.model_dump() for i in body.interfaces]


async def _commit(
    db: DB,
    request: Request,
    user: Any,
    row: Appliance,
    *,
    action: str,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> None:
    row.desired_network_interfaces = after
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name or user.username,
            auth_source=user.auth_source or "local",
            source_ip=_client_ip(request),
            action=action,
            resource_type="appliance",
            resource_id=str(row.id),
            resource_display=row.hostname,
            result="ok",
            old_value={"interfaces": before},
            new_value={"interfaces": after, "at": datetime.now(UTC).isoformat(), **(extra or {})},
        )
    )
    await db.commit()
    await db.refresh(row)
    # #358 — wake the heartbeat long-poll so the change lands in ~0 s.
    await publish_wake(appliance_channel(row.id))


# ── Routes ───────────────────────────────────────────────────────────


@router.get(
    "/appliances/{appliance_id}/network-interfaces",
    response_model=NetworkInterfacesResponse,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Additional network interfaces on an appliance (#4428)",
)
async def get_network_interfaces(appliance_id: uuid.UUID, db: DB) -> NetworkInterfacesResponse:
    """Desired interfaces joined with what the node reports, plus every NIC
    the node can see (with the reason when it cannot be managed). The
    reading rides the node's heartbeat, so it is at most one interval old.
    """
    return _response(await _load(db, appliance_id))


@router.post(
    "/appliances/{appliance_id}/network-interfaces/validate",
    response_model=ValidationResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Dry-run a network interface change (#4428)",
)
async def validate_network_interfaces(
    appliance_id: uuid.UUID, body: InterfacesRequest, db: DB
) -> ValidationResponse:
    """Runs every check ``PUT`` runs and writes nothing."""
    row = await _load(db, appliance_id)
    entries = _dump(body)
    if entries:
        _require_inventory(row)
    try:
        rows = validate_for(row, entries)
    except NetifError as exc:
        raise _refuse(exc) from exc
    return ValidationResponse(interfaces=rows)


@router.put(
    "/appliances/{appliance_id}/network-interfaces",
    response_model=NetworkInterfacesResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Replace the additional network interfaces on an appliance (#4428)",
)
async def put_network_interfaces(
    appliance_id: uuid.UUID,
    body: InterfacesRequest,
    request: Request,
    db: DB,
    current_user: CurrentUser,
) -> NetworkInterfacesResponse:
    """Replace the whole desired set. Audited; applied by the node with a
    rollback if it loses the control plane. ``interfaces: []`` removes
    everything this feature manages (and needs no inventory, since removing
    configuration cannot cut a node off a path it never had).
    """
    # FOR UPDATE: two operators editing one node's interfaces must not
    # interleave — the second validates against the first's result.
    row = await _load(db, appliance_id, lock=True)
    entries = _dump(body)
    if entries:
        _require_inventory(row)
    try:
        rows = validate_for(row, entries)
    except NetifError as exc:
        raise _refuse(exc) from exc
    before = list(row.desired_network_interfaces or [])
    await _commit(
        db, request, current_user, row, action="appliance.network.update", before=before, after=rows
    )
    return _response(row)


@router.delete(
    "/appliances/{appliance_id}/network-interfaces/{name}",
    response_model=NetworkInterfacesResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Remove one managed network interface (#4428)",
)
async def delete_network_interface(
    appliance_id: uuid.UUID,
    name: str,
    request: Request,
    db: DB,
    current_user: CurrentUser,
) -> NetworkInterfacesResponse:
    row = await _load(db, appliance_id, lock=True)
    current = list(row.desired_network_interfaces or [])
    remaining = [e for e in current if str(e.get("name")) != name]
    if len(remaining) == len(current):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"{row.hostname} has no managed interface named {name!r}."
        )
    # Shape only: removing configuration needs no knowledge of the node,
    # but removing a VLAN's parent while the VLAN stays is still a mistake.
    orphans = [e["name"] for e in remaining if e.get("kind") == "vlan" and e.get("parent") == name]
    if orphans:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{name} is the parent of {', '.join(orphans)}; remove those first.",
        )
    try:
        rows = netif_svc.normalise_desired(remaining)
    except NetifError as exc:
        raise _refuse(exc) from exc
    await _commit(
        db,
        request,
        current_user,
        row,
        action="appliance.network.remove",
        before=current,
        after=rows,
        extra={"removed": name},
    )
    return _response(row)
