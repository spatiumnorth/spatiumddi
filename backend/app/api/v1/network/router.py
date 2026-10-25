"""Network discovery API.

Mounted at ``/api/v1/network-devices``. CRUD on ``NetworkDevice`` plus
synchronous Test Connection, async Poll Now, and the per-device
``/interfaces`` / ``/arp`` / ``/fdb`` listings. The IPAM-side
``/api/v1/ipam/addresses/{address_id}/network-context`` endpoint
hangs off the existing IPAM router (mounted in ``router.py``); it's
defined here for cohesion and re-exported.

All endpoints are gated by the ``manage_network_devices`` permission
on every method (read + write) — read access is just as sensitive
because it exposes interface lists / ARP cache contents that aid
network reconnaissance. Granular split can land in a follow-up.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.api.pagination import MAX_PAGE
from app.core.celery_dispatch import dispatch
from app.core.crypto import encrypt_str
from app.core.permissions import require_permission, user_has_permission
from app.models.audit import AuditLog
from app.models.ipam import IPSpace
from app.models.network import (
    NetworkArpEntry,
    NetworkDevice,
    NetworkFdbEntry,
    NetworkInterface,
    NetworkNeighbour,
)
from app.services.snmp.errors import (
    SNMPAuthError,
    SNMPProtocolError,
    SNMPTimeoutError,
    SNMPTransportError,
)
from app.services.tags import apply_tag_filter

from .schemas import (
    NetworkArpListResponse,
    NetworkArpRead,
    NetworkDeviceCreate,
    NetworkDeviceListResponse,
    NetworkDeviceRead,
    NetworkDeviceUpdate,
    NetworkFdbListResponse,
    NetworkFdbRead,
    NetworkInterfaceListResponse,
    NetworkInterfaceRead,
    NetworkNeighbourListResponse,
    NetworkNeighbourRead,
    PollNowResult,
    TestConnectionResult,
)

logger = structlog.get_logger(__name__)

PERMISSION = "manage_network_devices"

router = APIRouter(
    tags=["network"],
    dependencies=[Depends(require_permission("read", PERMISSION))],
)


# ── Helpers ─────────────────────────────────────────────────────────


def _to_read(device: NetworkDevice, ip_space_name: str | None) -> NetworkDeviceRead:
    return NetworkDeviceRead(
        id=device.id,
        name=device.name,
        hostname=device.hostname,
        ip_address=str(device.ip_address),
        device_type=device.device_type,
        vendor=device.vendor,
        sys_descr=device.sys_descr,
        sys_object_id=device.sys_object_id,
        sys_name=device.sys_name,
        sys_uptime_seconds=device.sys_uptime_seconds,
        description=device.description,
        snmp_version=device.snmp_version,
        snmp_port=device.snmp_port,
        snmp_timeout_seconds=device.snmp_timeout_seconds,
        snmp_retries=device.snmp_retries,
        has_community=bool(device.community_encrypted),
        v3_security_name=device.v3_security_name,
        v3_security_level=device.v3_security_level,
        v3_auth_protocol=device.v3_auth_protocol,
        has_auth_key=bool(device.v3_auth_key_encrypted),
        v3_priv_protocol=device.v3_priv_protocol,
        has_priv_key=bool(device.v3_priv_key_encrypted),
        v3_context_name=device.v3_context_name,
        poll_interval_seconds=device.poll_interval_seconds,
        poll_arp=device.poll_arp,
        poll_fdb=device.poll_fdb,
        poll_interfaces=device.poll_interfaces,
        poll_lldp=device.poll_lldp,
        auto_create_discovered=device.auto_create_discovered,
        last_poll_at=device.last_poll_at,
        next_poll_at=device.next_poll_at,
        last_poll_status=device.last_poll_status,
        last_poll_error=device.last_poll_error,
        last_poll_arp_count=device.last_poll_arp_count,
        last_poll_fdb_count=device.last_poll_fdb_count,
        last_poll_interface_count=device.last_poll_interface_count,
        last_poll_neighbour_count=device.last_poll_neighbour_count,
        ip_space_id=device.ip_space_id,
        ip_space_name=ip_space_name,
        site_id=device.site_id,
        is_active=device.is_active,
        tags=device.tags or {},
        created_at=device.created_at,
        modified_at=device.modified_at,
    )


async def _resolve_space_name(db: Any, space_id: uuid.UUID) -> str | None:
    space = await db.get(IPSpace, space_id)
    return space.name if space is not None else None


async def _audit(
    db: Any,
    *,
    user: Any,
    action: str,
    device_id: uuid.UUID,
    device_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=getattr(user, "auth_source", "local") or "local",
            action=action,
            resource_type="network_device",
            resource_id=str(device_id),
            resource_display=device_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


def _classify_test_error(exc: Exception) -> str:
    if isinstance(exc, SNMPTimeoutError):
        return "timeout"
    if isinstance(exc, SNMPAuthError):
        return "auth_failure"
    if isinstance(exc, SNMPTransportError):
        return "transport_error"
    if isinstance(exc, SNMPProtocolError):
        return "no_response"
    return "internal"


# ── CRUD ────────────────────────────────────────────────────────────


@router.get("/network-devices", response_model=NetworkDeviceListResponse)
async def list_devices(
    db: DB,
    current_user: CurrentUser,
    active: bool | None = Query(None),
    device_type: str | None = Query(None),
    last_poll_status: str | None = Query(None),
    site_id: uuid.UUID | None = Query(None),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(50, ge=1, le=500),
    tag: list[str] = Query(default_factory=list),
) -> NetworkDeviceListResponse:
    if not user_has_permission(current_user, "read", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")

    base = select(NetworkDevice)
    if active is not None:
        base = base.where(NetworkDevice.is_active.is_(active))
    if device_type is not None:
        base = base.where(NetworkDevice.device_type == device_type)
    if last_poll_status is not None:
        base = base.where(NetworkDevice.last_poll_status == last_poll_status)
    if site_id is not None:
        base = base.where(NetworkDevice.site_id == site_id)
    base = apply_tag_filter(base, NetworkDevice.tags, tag)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = int((await db.execute(count_stmt)).scalar_one())

    stmt = base.order_by(NetworkDevice.name).limit(page_size).offset((page - 1) * page_size)
    rows = list((await db.execute(stmt)).scalars().all())
    space_ids = {r.ip_space_id for r in rows}
    space_name_by_id: dict[uuid.UUID, str] = {}
    if space_ids:
        for s in (
            (await db.execute(select(IPSpace).where(IPSpace.id.in_(space_ids)))).scalars().all()
        ):
            space_name_by_id[s.id] = s.name
    items = [_to_read(r, space_name_by_id.get(r.ip_space_id)) for r in rows]
    return NetworkDeviceListResponse(items=items, total=total, page=page, page_size=page_size)


@router.post(
    "/network-devices",
    response_model=NetworkDeviceRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_device(
    body: NetworkDeviceCreate, db: DB, current_user: CurrentUser
) -> NetworkDeviceRead:
    if not user_has_permission(current_user, "write", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")

    space = await db.get(IPSpace, body.ip_space_id)
    if space is None:
        raise HTTPException(status_code=422, detail="ip_space_id not found")

    existing = await db.execute(select(NetworkDevice).where(NetworkDevice.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409, detail="A network device with that name already exists"
        )

    dev = NetworkDevice(
        name=body.name,
        hostname=body.hostname,
        ip_address=body.ip_address,
        device_type=body.device_type,
        description=body.description,
        snmp_version=body.snmp_version,
        snmp_port=body.snmp_port,
        snmp_timeout_seconds=body.snmp_timeout_seconds,
        snmp_retries=body.snmp_retries,
        community_encrypted=encrypt_str(body.community) if body.community else None,
        v3_security_name=body.v3_security_name,
        v3_security_level=body.v3_security_level,
        v3_auth_protocol=body.v3_auth_protocol,
        v3_auth_key_encrypted=(encrypt_str(body.v3_auth_key) if body.v3_auth_key else None),
        v3_priv_protocol=body.v3_priv_protocol,
        v3_priv_key_encrypted=(encrypt_str(body.v3_priv_key) if body.v3_priv_key else None),
        v3_context_name=body.v3_context_name,
        poll_interval_seconds=body.poll_interval_seconds,
        poll_arp=body.poll_arp,
        poll_fdb=body.poll_fdb,
        poll_interfaces=body.poll_interfaces,
        poll_lldp=body.poll_lldp,
        auto_create_discovered=body.auto_create_discovered,
        ip_space_id=body.ip_space_id,
        site_id=body.site_id,
        is_active=body.is_active,
        tags=body.tags or {},
    )
    db.add(dev)
    await db.flush()
    await _audit(
        db,
        user=current_user,
        action="create",
        device_id=dev.id,
        device_name=dev.name,
        new_value=body.model_dump(
            mode="json",
            exclude={"community", "v3_auth_key", "v3_priv_key"},
        ),
    )
    await db.commit()
    await db.refresh(dev)
    return _to_read(dev, space.name)


@router.get("/network-devices/{device_id}", response_model=NetworkDeviceRead)
async def get_device(device_id: uuid.UUID, db: DB, current_user: CurrentUser) -> NetworkDeviceRead:
    if not user_has_permission(current_user, "read", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    dev = await db.get(NetworkDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Network device not found")
    space_name = await _resolve_space_name(db, dev.ip_space_id)
    return _to_read(dev, space_name)


@router.patch("/network-devices/{device_id}", response_model=NetworkDeviceRead)
async def update_device(
    device_id: uuid.UUID,
    body: NetworkDeviceUpdate,
    db: DB,
    current_user: CurrentUser,
) -> NetworkDeviceRead:
    if not user_has_permission(current_user, "write", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")

    dev = await db.get(NetworkDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Network device not found")

    changes = body.model_dump(exclude_unset=True)
    if "ip_space_id" in changes:
        if (await db.get(IPSpace, changes["ip_space_id"])) is None:
            raise HTTPException(status_code=422, detail="ip_space_id not found")

    secret_keys = {"community", "v3_auth_key", "v3_priv_key"}
    encrypted_attrs = {
        "community": "community_encrypted",
        "v3_auth_key": "v3_auth_key_encrypted",
        "v3_priv_key": "v3_priv_key_encrypted",
    }

    for k, v in changes.items():
        if k in secret_keys:
            attr = encrypted_attrs[k]
            if v:
                setattr(dev, attr, encrypt_str(v))
            elif v == "":
                # Empty string explicitly clears the secret.
                setattr(dev, attr, None)
            # ``None`` (not provided) → keep existing.
        else:
            setattr(dev, k, v)

    await _audit(
        db,
        user=current_user,
        action="update",
        device_id=dev.id,
        device_name=dev.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k not in secret_keys},
    )
    await db.commit()
    await db.refresh(dev)
    space_name = await _resolve_space_name(db, dev.ip_space_id)
    return _to_read(dev, space_name)


@router.delete("/network-devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    if not user_has_permission(current_user, "delete", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    dev = await db.get(NetworkDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Network device not found")
    await _audit(
        db,
        user=current_user,
        action="delete",
        device_id=dev.id,
        device_name=dev.name,
    )
    await db.delete(dev)
    await db.commit()


# ── Test connection (synchronous probe) ─────────────────────────────


@router.post("/network-devices/{device_id}/test", response_model=TestConnectionResult)
async def test_device_connection(
    device_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> TestConnectionResult:
    if not user_has_permission(current_user, "write", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    dev = await db.get(NetworkDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Network device not found")

    # Deferred import — lets module import succeed without pysnmp.
    from app.services.snmp.poller import test_connection as _probe  # noqa: PLC0415

    started = time.monotonic()
    try:
        sys_info = await _probe(dev)
    except Exception as exc:  # noqa: BLE001 — we classify
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return TestConnectionResult(
            success=False,
            error_kind=_classify_test_error(exc),  # type: ignore[arg-type]
            error_message=str(exc),
            elapsed_ms=elapsed_ms,
        )

    elapsed_ms = int((time.monotonic() - started) * 1000)
    # Stash sys metadata + vendor heuristic so the operator sees fresh
    # info without waiting for the next scheduled poll.
    dev.sys_descr = sys_info.sys_descr
    dev.sys_object_id = sys_info.sys_object_id
    dev.sys_name = sys_info.sys_name
    dev.sys_uptime_seconds = sys_info.sys_uptime_seconds
    if sys_info.vendor and not dev.vendor:
        dev.vendor = sys_info.vendor
    await db.commit()

    return TestConnectionResult(
        success=True,
        sys_descr=sys_info.sys_descr,
        sys_object_id=sys_info.sys_object_id,
        sys_name=sys_info.sys_name,
        vendor=sys_info.vendor,
        elapsed_ms=elapsed_ms,
    )


# ── Poll Now (async) ────────────────────────────────────────────────


@router.post(
    "/network-devices/{device_id}/poll-now",
    response_model=PollNowResult,
    status_code=status.HTTP_202_ACCEPTED,
)
async def poll_device_now(device_id: uuid.UUID, db: DB, current_user: CurrentUser) -> PollNowResult:
    if not user_has_permission(current_user, "write", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    dev = await db.get(NetworkDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Network device not found")

    from app.tasks.snmp_poll import poll_device  # noqa: PLC0415

    queued_at = datetime.now(UTC)
    try:
        result = await dispatch(poll_device, str(dev.id))
        task_id = result.id
    except Exception as exc:  # noqa: BLE001 — broker down
        logger.warning("snmp_poll_now_broker_unavailable", error=str(exc))
        task_id = ""

    return PollNowResult(task_id=task_id, queued_at=queued_at)


# ── Per-device list endpoints ────────────────────────────────────────


async def _ensure_device(db: Any, device_id: uuid.UUID) -> NetworkDevice:
    dev = await db.get(NetworkDevice, device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail="Network device not found")
    return dev


@router.get(
    "/network-devices/{device_id}/interfaces",
    response_model=NetworkInterfaceListResponse,
)
async def list_interfaces(
    device_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(50, ge=1, le=2000),
) -> NetworkInterfaceListResponse:
    if not user_has_permission(current_user, "read", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    await _ensure_device(db, device_id)
    base = select(NetworkInterface).where(NetworkInterface.device_id == device_id)
    total = int((await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    rows = list(
        (
            await db.execute(
                base.order_by(NetworkInterface.if_index)
                .limit(page_size)
                .offset((page - 1) * page_size)
            )
        )
        .scalars()
        .all()
    )
    items = [NetworkInterfaceRead.model_validate(r, from_attributes=True) for r in rows]
    return NetworkInterfaceListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/network-devices/{device_id}/arp",
    response_model=NetworkArpListResponse,
)
async def list_arp(
    device_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    ip: str | None = Query(None),
    mac: str | None = Query(None),
    vrf: str | None = Query(None),
    state: str | None = Query(None),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(50, ge=1, le=2000),
) -> NetworkArpListResponse:
    if not user_has_permission(current_user, "read", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    await _ensure_device(db, device_id)
    base = select(NetworkArpEntry).where(NetworkArpEntry.device_id == device_id)
    if ip:
        base = base.where(NetworkArpEntry.ip_address == ip)
    if mac:
        base = base.where(NetworkArpEntry.mac_address == mac.lower())
    if vrf:
        base = base.where(NetworkArpEntry.vrf_name == vrf)
    if state:
        base = base.where(NetworkArpEntry.state == state)
    total = int((await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    stmt = (
        base.order_by(NetworkArpEntry.last_seen.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    # Hydrate interface_name in one query rather than per-row joins.
    if_ids = {r.interface_id for r in rows if r.interface_id is not None}
    name_by_if: dict[uuid.UUID, str] = {}
    if if_ids:
        for ifrow in (
            (await db.execute(select(NetworkInterface).where(NetworkInterface.id.in_(if_ids))))
            .scalars()
            .all()
        ):
            name_by_if[ifrow.id] = ifrow.name
    items = [
        NetworkArpRead.model_validate(
            {
                **{c.name: getattr(r, c.name) for c in r.__table__.columns},
                "interface_name": name_by_if.get(r.interface_id) if r.interface_id else None,
            }
        )
        for r in rows
    ]
    return NetworkArpListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/network-devices/{device_id}/fdb",
    response_model=NetworkFdbListResponse,
)
async def list_fdb(
    device_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    mac: str | None = Query(None),
    vlan_id: int | None = Query(None),
    interface_id: uuid.UUID | None = Query(None),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(50, ge=1, le=2000),
) -> NetworkFdbListResponse:
    if not user_has_permission(current_user, "read", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    await _ensure_device(db, device_id)
    base = select(NetworkFdbEntry).where(NetworkFdbEntry.device_id == device_id)
    if mac:
        base = base.where(NetworkFdbEntry.mac_address == mac.lower())
    if vlan_id is not None:
        base = base.where(NetworkFdbEntry.vlan_id == vlan_id)
    if interface_id is not None:
        base = base.where(NetworkFdbEntry.interface_id == interface_id)
    total = int((await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    stmt = (
        base.order_by(NetworkFdbEntry.last_seen.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    if_ids = {r.interface_id for r in rows}
    name_by_if: dict[uuid.UUID, str] = {}
    if if_ids:
        for ifrow in (
            (await db.execute(select(NetworkInterface).where(NetworkInterface.id.in_(if_ids))))
            .scalars()
            .all()
        ):
            name_by_if[ifrow.id] = ifrow.name
    items = [
        NetworkFdbRead.model_validate(
            {
                **{c.name: getattr(r, c.name) for c in r.__table__.columns},
                "interface_name": name_by_if.get(r.interface_id),
            }
        )
        for r in rows
    ]
    return NetworkFdbListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/network-devices/{device_id}/neighbours",
    response_model=NetworkNeighbourListResponse,
)
async def list_neighbours(
    device_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    sys_name: str | None = Query(None),
    chassis_id: str | None = Query(None),
    interface_id: uuid.UUID | None = Query(None),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(50, ge=1, le=2000),
) -> NetworkNeighbourListResponse:
    """List LLDP neighbours discovered on this device.

    Mirrors the FDB / ARP listing shape — paginated envelope, filter
    knobs for the columns most operators search by, interface-name
    join hydrated server-side so the frontend doesn't have to
    fan-out per row.
    """
    if not user_has_permission(current_user, "read", PERMISSION):
        raise HTTPException(status_code=403, detail="Permission denied")
    await _ensure_device(db, device_id)
    base = select(NetworkNeighbour).where(NetworkNeighbour.device_id == device_id)
    if sys_name:
        base = base.where(NetworkNeighbour.remote_sys_name.ilike(f"%{sys_name}%"))
    if chassis_id:
        base = base.where(NetworkNeighbour.remote_chassis_id == chassis_id.lower())
    if interface_id is not None:
        base = base.where(NetworkNeighbour.interface_id == interface_id)
    total = int((await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one())
    stmt = (
        base.order_by(NetworkNeighbour.last_seen.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    if_ids = {r.interface_id for r in rows if r.interface_id is not None}
    name_by_if: dict[uuid.UUID, str] = {}
    if if_ids:
        for ifrow in (
            (await db.execute(select(NetworkInterface).where(NetworkInterface.id.in_(if_ids))))
            .scalars()
            .all()
        ):
            name_by_if[ifrow.id] = ifrow.name
    items = [
        NetworkNeighbourRead.model_validate(
            {
                **{c.name: getattr(r, c.name) for c in r.__table__.columns},
                "interface_name": (name_by_if.get(r.interface_id) if r.interface_id else None),
            }
        )
        for r in rows
    ]
    return NetworkNeighbourListResponse(items=items, total=total, page=page, page_size=page_size)


__all__ = ["router"]
