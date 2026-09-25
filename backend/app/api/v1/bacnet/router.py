"""BACnet/IP device registry CRUD — issue #541 Phase 1.

Endpoints under ``/bacnet``:

* ``/devices`` — device list / create
* ``/devices/{id}`` — read / patch / delete
* ``/bbmds`` — the Broadcast Distribution Devices, with the subnet each
  one serves and its BDT/FDT sizes. "Exactly one BBMD per subnet" is
  the rule that makes or breaks broadcast reachability on a
  multi-subnet BACnet/IP network, so the operator needs it as a list
  they can eyeball, not as a field buried on N device rows.
* ``/by-address/{ip_address_id}`` — the device anchored to an IPAM
  address. Drives the IP-detail modal's BACnet section, which treats a
  404 as "not a BACnet device" and renders nothing.
* ``/next-instance`` — lowest free device instance at or above a
  starting point, for the commissioning form's suggest button.

Permissions: every endpoint is gated on ``bacnet_device`` at the
router level (GET→read, POST/PATCH→write, DELETE→delete; superadmin
always passes). Each mutation writes an ``audit_log`` row before
commit per CLAUDE.md non-negotiable #4.

Server-side validation in this layer, beyond the field bounds mirrored
from ``app.models.bacnet``:

* ``device_instance`` uniqueness is pre-checked for a friendly 409 that
  names the conflicting device, and the resulting ``IntegrityError`` is
  re-mapped to the same 409 so a lost race doesn't surface as a 500.
* A device is a BBMD, a foreign device, or neither — never both.
* BDT/FDT snapshots are refused on a non-BBMD row, because nothing
  reads or renders them there.

Zero network I/O: this surface never talks BACnet. Rows arrive from
operators and importers; the ``Who-Is`` sweep that would populate them
from the wire is deferred (see ``app.services.bacnet``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import ColumnElement, Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.auth import User
from app.models.bacnet import (
    BACNET_DEFAULT_PORT,
    BACNET_DEVICE_SOURCES,
    BACNET_INSTANCE_MAX,
    BACNET_INSTANCE_MIN,
    BACNET_NETWORK_MAX,
    BACNET_NETWORK_MIN,
    BACNET_SEGMENTATION,
    BACnetDevice,
)
from app.models.ipam import IPAddress, Subnet
from app.services.bacnet.registry import (
    DeviceInstanceConflict,
    assert_instance_available,
    next_available_instance,
    sync_subnet_id,
)
from app.services.bacnet.vendors import resolve_vendor_label
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["bacnet"],
    dependencies=[Depends(require_resource_permission("bacnet_device"))],
)

BACnetSegmentation = Literal["both", "transmit", "receive", "no-segmentation"]
BACnetDeviceSource = Literal["manual", "whois", "mirror", "import"]

# ASHRAE vendor ids are ``Unsigned16`` in the ``I-Am`` APDU.
_VENDOR_ID_MAX = 65535

# Max APDU length accepted, in octets. ASHRAE 135 floors the value at
# 50; the ceiling is the field's own 16-bit width. BACnet/IP devices
# report 1476, MS/TP-bridged ones commonly 128/206/480 — all valid, and
# the smaller values are operationally useful to see, so the range is
# not narrowed to the BACnet/IP norm.
_MAX_APDU_MIN = 50
_MAX_APDU_MAX = 65535


# ── Schemas ─────────────────────────────────────────────────────────


class BACnetDeviceCreate(BaseModel):
    ip_address_id: uuid.UUID
    device_instance: int = Field(..., ge=BACNET_INSTANCE_MIN, le=BACNET_INSTANCE_MAX)
    vendor_id: int | None = Field(default=None, ge=0, le=_VENDOR_ID_MAX)
    vendor_name: str = Field(default="", max_length=255)
    device_name: str = Field(default="", max_length=255)
    model_name: str = Field(default="", max_length=255)
    firmware_rev: str = Field(default="", max_length=128)
    location: str = Field(default="", max_length=255)
    max_apdu: int | None = Field(default=None, ge=_MAX_APDU_MIN, le=_MAX_APDU_MAX)
    segmentation_supported: BACnetSegmentation | None = None
    network_number: int | None = Field(default=None, ge=BACNET_NETWORK_MIN, le=BACNET_NETWORK_MAX)
    udp_port: int = Field(default=BACNET_DEFAULT_PORT, ge=1, le=65535)
    is_bbmd: bool = False
    is_foreign_device: bool = False
    bdt: list[Any] = Field(default_factory=list)
    fdt: list[Any] = Field(default_factory=list)
    seen_via: BACnetDeviceSource = "manual"
    last_seen_at: datetime | None = None
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    # House belt-and-braces convention (see ``models/multicast.py``).
    # Note what these actually catch: pydantic rejects an unknown value
    # against the ``Literal`` alias *before* an after-validator runs, so
    # these never fire for bad client input. They guard the reverse
    # drift — an alias widened past the model frozenset — which keeps
    # the frozenset the single source of truth rather than the alias.
    @field_validator("segmentation_supported")
    @classmethod
    def _v_segmentation(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in BACNET_SEGMENTATION:
            raise ValueError(f"segmentation_supported must be one of {sorted(BACNET_SEGMENTATION)}")
        return v

    @field_validator("seen_via")
    @classmethod
    def _v_seen_via(cls, v: str) -> str:
        if v not in BACNET_DEVICE_SOURCES:
            raise ValueError(f"seen_via must be one of {sorted(BACNET_DEVICE_SOURCES)}")
        return v


class BACnetDeviceUpdate(BaseModel):
    """PATCH body — every field optional, ``exclude_unset`` semantics.

    ``ip_address_id`` is re-parentable: a controller that gets
    readdressed keeps its identity (its device instance) and moves to
    the new IPAM row, which is exactly the case where losing the
    history would hurt. The handler re-syncs ``subnet_id`` when it
    changes.
    """

    ip_address_id: uuid.UUID | None = None
    device_instance: int | None = Field(
        default=None, ge=BACNET_INSTANCE_MIN, le=BACNET_INSTANCE_MAX
    )
    vendor_id: int | None = Field(default=None, ge=0, le=_VENDOR_ID_MAX)
    vendor_name: str | None = Field(default=None, max_length=255)
    device_name: str | None = Field(default=None, max_length=255)
    model_name: str | None = Field(default=None, max_length=255)
    firmware_rev: str | None = Field(default=None, max_length=128)
    location: str | None = Field(default=None, max_length=255)
    max_apdu: int | None = Field(default=None, ge=_MAX_APDU_MIN, le=_MAX_APDU_MAX)
    segmentation_supported: BACnetSegmentation | None = None
    network_number: int | None = Field(default=None, ge=BACNET_NETWORK_MIN, le=BACNET_NETWORK_MAX)
    udp_port: int | None = Field(default=None, ge=1, le=65535)
    is_bbmd: bool | None = None
    is_foreign_device: bool | None = None
    bdt: list[Any] | None = None
    fdt: list[Any] | None = None
    seen_via: BACnetDeviceSource | None = None
    last_seen_at: datetime | None = None
    notes: str | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None

    @field_validator("segmentation_supported")
    @classmethod
    def _v_segmentation(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in BACNET_SEGMENTATION:
            raise ValueError(f"segmentation_supported must be one of {sorted(BACNET_SEGMENTATION)}")
        return v

    @field_validator("seen_via")
    @classmethod
    def _v_seen_via(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in BACNET_DEVICE_SOURCES:
            raise ValueError(f"seen_via must be one of {sorted(BACNET_DEVICE_SOURCES)}")
        return v


class BACnetDeviceRead(BaseModel):
    """Wire model for a device row.

    ``address`` / ``hostname`` / ``vendor_label`` are joined-in or
    derived rather than stored: every operator-facing read of this
    registry is "which box, at which IP, from which manufacturer", and
    making the caller round-trip per row for that turns a 200-device
    list into 201 requests.
    """

    id: uuid.UUID
    ip_address_id: uuid.UUID
    subnet_id: uuid.UUID | None
    address: str | None = None
    hostname: str | None = None
    device_instance: int
    vendor_id: int | None
    vendor_name: str
    vendor_label: str | None = None
    device_name: str
    model_name: str
    firmware_rev: str
    location: str
    max_apdu: int | None
    segmentation_supported: str | None
    network_number: int | None
    udp_port: int
    is_bbmd: bool
    is_foreign_device: bool
    bdt: list[Any]
    fdt: list[Any]
    seen_via: str
    last_seen_at: datetime | None
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime


class BACnetDeviceListResponse(BaseModel):
    items: list[BACnetDeviceRead]
    total: int
    limit: int
    offset: int


class BACnetBBMDRead(BaseModel):
    """One BBMD, with the subnet it broadcasts for.

    ``subnet_id`` repeats across rows when a subnet has more than one
    BBMD — which is the misconfiguration this list exists to make
    visible (two BBMDs on a subnet duplicate every forwarded
    broadcast), so it is surfaced as data rather than filtered out.
    """

    id: uuid.UUID
    ip_address_id: uuid.UUID
    address: str | None
    device_instance: int
    device_name: str
    vendor_label: str | None
    udp_port: int
    subnet_id: uuid.UUID | None
    subnet_network: str | None
    subnet_name: str | None
    bdt_entries: int
    fdt_entries: int
    last_seen_at: datetime | None


class NextInstanceResponse(BaseModel):
    """Suggestion for the commissioning form.

    ``device_instance`` is ``None`` when every number from ``start`` to
    the 22-bit ceiling is taken — in practice a ``start`` chosen too
    close to the top, not an exhausted internetwork.
    """

    start: int
    device_instance: int | None


# ── Helpers ─────────────────────────────────────────────────────────


def _to_read(device: BACnetDevice, ip: IPAddress | None) -> BACnetDeviceRead:
    """Assemble the wire model from the row plus its IPAM anchor."""
    return BACnetDeviceRead(
        id=device.id,
        ip_address_id=device.ip_address_id,
        subnet_id=device.subnet_id,
        # ``IPAddress.address`` is INET — asyncpg hands back an
        # ``ipaddress`` object, which Pydantic won't accept as ``str``.
        address=str(ip.address) if ip is not None else None,
        hostname=ip.hostname if ip is not None else None,
        device_instance=device.device_instance,
        vendor_id=device.vendor_id,
        vendor_name=device.vendor_name,
        vendor_label=resolve_vendor_label(device.vendor_id, device.vendor_name),
        device_name=device.device_name,
        model_name=device.model_name,
        firmware_rev=device.firmware_rev,
        location=device.location,
        max_apdu=device.max_apdu,
        segmentation_supported=device.segmentation_supported,
        network_number=device.network_number,
        udp_port=device.udp_port,
        is_bbmd=device.is_bbmd,
        is_foreign_device=device.is_foreign_device,
        bdt=list(device.bdt or []),
        fdt=list(device.fdt or []),
        seen_via=device.seen_via,
        last_seen_at=device.last_seen_at,
        notes=device.notes,
        tags=device.tags,
        custom_fields=device.custom_fields,
        created_at=device.created_at,
        modified_at=device.modified_at,
    )


def _jsonable(value: Any) -> Any:
    """JSON-safe copy of a model attribute for the audit row.

    ``old_value`` lands in a JSONB column, so UUID and datetime values
    have to be stringified; every other column on ``BACnetDevice`` is
    already a JSON primitive or a JSONB list/dict.
    """
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _validate_topology_flags(
    *,
    is_bbmd: bool,
    is_foreign_device: bool,
    bdt: list[Any],
    fdt: list[Any],
) -> None:
    """422 on BBMD / foreign-device states that cannot exist on the wire.

    A device registers as a Foreign Device *because* its subnet has no
    local BBMD to hear its broadcasts, so being both is a contradiction
    rather than an unusual-but-valid deployment.

    BDT and FDT are a BBMD's own tables. Accepting them on a non-BBMD
    row would store topology that nothing reads, renders, or checks —
    it would look recorded while being invisible, which is worse than
    being rejected.
    """
    if is_bbmd and is_foreign_device:
        raise HTTPException(
            status_code=422,
            detail="A device is a BBMD or a foreign device, not both",
        )
    if not is_bbmd and (bdt or fdt):
        raise HTTPException(
            status_code=422,
            detail="bdt / fdt entries are only meaningful on a BBMD — set is_bbmd first",
        )


async def _load_ip(db: AsyncSession, ip_address_id: uuid.UUID, user: User) -> IPAddress:
    """Fetch the anchoring IPAM address, 422 when it doesn't exist.

    Also applies the resource-scoped API-token gate (#374): a token
    bound to one subnet must not attach devices to addresses in
    another just because the router-level ``bacnet_device`` grant
    passed. Deferred import — ``app.api.v1.ipam.router`` is a large
    module and importing it at module scope would create a cycle
    through the shared IPAM helpers.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope

    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(status_code=422, detail="ip_address_id not found")
    _enforce_subnet_token_scope(user, ip.subnet_id)
    return ip


async def _load_anchor(db: AsyncSession, device: BACnetDevice, user: User) -> IPAddress | None:
    """Load a device's current IPAM anchor, enforcing the token gate.

    The router-level ``bacnet_device`` grant is unscoped, so without
    this a subnet-bound token (#374) could read and edit devices
    anywhere in the tree via the sidecar. No-op for sessions and plain
    tokens. Returns ``None`` only if the anchor row vanished
    concurrently — the FK is ``ON DELETE CASCADE``, so in practice the
    device would be gone with it.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope

    ip = await db.get(IPAddress, device.ip_address_id)
    if ip is not None:
        _enforce_subnet_token_scope(user, ip.subnet_id)
    return ip


async def _get_device(db: AsyncSession, device_id: uuid.UUID) -> BACnetDevice:
    row = await db.get(BACnetDevice, device_id)
    if row is None:
        raise HTTPException(status_code=404, detail="BACnet device not found")
    return row


def _instance_conflict(exc: DeviceInstanceConflict) -> HTTPException:
    """409 naming the device that already holds the instance number.

    Device-instance uniqueness is internetwork-wide by specification,
    so the conflicting row is very often on a different subnet, in a
    different building, owned by a different trade — which is exactly
    why the response has to name it instead of saying "already in use".
    """
    return HTTPException(
        status_code=409,
        detail=str(exc),
        headers={"X-Conflicting-Device-Id": str(exc.existing_id)},
    )


def _token_subnet_scope(user: Any) -> set[uuid.UUID] | None:
    """Subnets a resource-scoped token may enumerate, or ``None`` for all.

    The list-endpoint counterpart to :func:`_enforce_subnet_scope` (#523).
    The router-level ``require_resource_permission`` grant is unscoped, so
    without this a subnet-bound token could read the entire plant's BACnet
    inventory through ``GET /devices`` or ``GET /bbmds`` even though every
    by-id read is gated. An empty set means "scoped to other resource
    types only" and must yield nothing — hence callers test ``is not
    None`` rather than truthiness.
    """
    from app.api.v1.ipam.router import _token_subnet_scope_uuids  # noqa: PLC0415

    return _token_subnet_scope_uuids(user)


def _apply_device_filters[*Ts](
    stmt: Select[*Ts],
    *,
    token_scope: set[uuid.UUID] | None,
    tag: list[str],
    subnet_id: uuid.UUID | None,
    ip_address_id: uuid.UUID | None,
    vendor_id: int | None,
    is_bbmd: bool | None,
    seen_via: str | None,
    q: str | None,
) -> Select[*Ts]:
    """Shared WHERE construction for the list page and its count.

    Kept in one place so the ``total`` can never drift from the rows
    actually returned — the classic pagination bug where a filter is
    added to one query and not the other. The token scope rides the same
    helper for the same reason: a scope applied to the rows but not the
    count would report totals the caller is not allowed to see.
    """
    if token_scope is not None:
        stmt = stmt.where(BACnetDevice.subnet_id.in_(token_scope))
    stmt = apply_tag_filter(stmt, BACnetDevice.tags, tag)
    if subnet_id is not None:
        stmt = stmt.where(BACnetDevice.subnet_id == subnet_id)
    if ip_address_id is not None:
        stmt = stmt.where(BACnetDevice.ip_address_id == ip_address_id)
    if vendor_id is not None:
        stmt = stmt.where(BACnetDevice.vendor_id == vendor_id)
    if is_bbmd is not None:
        stmt = stmt.where(BACnetDevice.is_bbmd.is_(is_bbmd))
    if seen_via is not None:
        stmt = stmt.where(BACnetDevice.seen_via == seen_via)
    if q:
        needle = f"%{q.strip()}%"
        clauses: list[ColumnElement[bool]] = [
            BACnetDevice.device_name.ilike(needle),
            BACnetDevice.model_name.ilike(needle),
            BACnetDevice.vendor_name.ilike(needle),
        ]
        # A bare number is nearly always an operator pasting a device
        # instance out of a BAS tool while chasing a duplicate, so match
        # it exactly as well. Range-guarded because the column is a
        # 22-bit value and Python ints are unbounded — a 40-digit
        # "search term" must not reach the query as an integer compare.
        digits = q.strip()
        if digits.isdigit():
            value = int(digits)
            if BACNET_INSTANCE_MIN <= value <= BACNET_INSTANCE_MAX:
                clauses.append(BACnetDevice.device_instance == value)
        stmt = stmt.where(or_(*clauses))
    return stmt


# ── Device endpoints ────────────────────────────────────────────────


@router.get("/devices", response_model=BACnetDeviceListResponse)
async def list_devices(
    db: DB,
    user: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    subnet_id: uuid.UUID | None = Query(default=None),
    ip_address_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Every device anchored to one IPAM address. A BACnet/IP "
            "router or MS/TP gateway fronts several device instances "
            "at a single IP, so this can legitimately return more "
            "than one row."
        ),
    ),
    vendor_id: int | None = Query(default=None, ge=0, le=_VENDOR_ID_MAX),
    is_bbmd: bool | None = Query(default=None),
    seen_via: BACnetDeviceSource | None = Query(default=None),
    tag: list[str] = Query(default_factory=list),
    q: str | None = Query(
        default=None,
        description=(
            "Case-insensitive substring on device name / model / "
            "vendor name. A purely numeric term additionally matches "
            "the device instance exactly."
        ),
    ),
) -> BACnetDeviceListResponse:
    """List devices in ascending device-instance order, with their IPAM anchor."""
    token_scope = _token_subnet_scope(user)
    count_stmt = _apply_device_filters(
        select(func.count(BACnetDevice.id)),
        token_scope=token_scope,
        tag=tag,
        subnet_id=subnet_id,
        ip_address_id=ip_address_id,
        vendor_id=vendor_id,
        is_bbmd=is_bbmd,
        seen_via=seen_via,
        q=q,
    )
    total = (await db.execute(count_stmt)).scalar_one()

    stmt = _apply_device_filters(
        select(BACnetDevice, IPAddress).join(IPAddress, IPAddress.id == BACnetDevice.ip_address_id),
        token_scope=token_scope,
        tag=tag,
        subnet_id=subnet_id,
        ip_address_id=ip_address_id,
        vendor_id=vendor_id,
        is_bbmd=is_bbmd,
        seen_via=seen_via,
        q=q,
    )
    rows = (
        await db.execute(
            stmt.order_by(BACnetDevice.device_instance.asc()).limit(limit).offset(offset)
        )
    ).all()
    return BACnetDeviceListResponse(
        items=[_to_read(device, ip) for device, ip in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("/devices", response_model=BACnetDeviceRead, status_code=status.HTTP_201_CREATED)
async def create_device(body: BACnetDeviceCreate, db: DB, user: CurrentUser) -> BACnetDeviceRead:
    """Register a device. 409 when its instance number is already taken."""
    ip = await _load_ip(db, body.ip_address_id, user)
    _validate_topology_flags(
        is_bbmd=body.is_bbmd,
        is_foreign_device=body.is_foreign_device,
        bdt=body.bdt,
        fdt=body.fdt,
    )
    try:
        await assert_instance_available(db, body.device_instance)
    except DeviceInstanceConflict as exc:
        raise _instance_conflict(exc) from exc

    row = BACnetDevice(
        ip_address_id=body.ip_address_id,
        device_instance=body.device_instance,
        vendor_id=body.vendor_id,
        vendor_name=body.vendor_name,
        device_name=body.device_name,
        model_name=body.model_name,
        firmware_rev=body.firmware_rev,
        location=body.location,
        max_apdu=body.max_apdu,
        segmentation_supported=body.segmentation_supported,
        network_number=body.network_number,
        udp_port=body.udp_port,
        is_bbmd=body.is_bbmd,
        is_foreign_device=body.is_foreign_device,
        bdt=body.bdt,
        fdt=body.fdt,
        seen_via=body.seen_via,
        last_seen_at=body.last_seen_at,
        notes=body.notes,
        tags=body.tags or {},
        custom_fields=body.custom_fields or {},
    )
    # Denormalised copy of the anchor's subnet — the BBMD-per-subnet
    # grouping reads it, so it is stamped at every point the anchor can
    # move rather than being derived on read.
    await sync_subnet_id(db, row)
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        # Lost the race against a concurrent create between the
        # availability check and the INSERT. ``uq_bacnet_device_instance``
        # is the real guard; answer with the same 409 the pre-check
        # would have produced rather than leaking a 500.
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"BACnet device instance {body.device_instance} is already registered",
        ) from exc

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="bacnet_device",
        resource_id=str(row.id),
        resource_display=row.device_name or str(row.device_instance),
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row, ip)


@router.get("/devices/{device_id:uuid}", response_model=BACnetDeviceRead)
async def get_device(device_id: uuid.UUID, db: DB, user: CurrentUser) -> BACnetDeviceRead:
    row = await _get_device(db, device_id)
    ip = await _load_anchor(db, row, user)
    return _to_read(row, ip)


@router.patch("/devices/{device_id:uuid}", response_model=BACnetDeviceRead)
async def update_device(
    device_id: uuid.UUID,
    body: BACnetDeviceUpdate,
    db: DB,
    user: CurrentUser,
) -> BACnetDeviceRead:
    """Patch a device. 409 when a new instance number is already taken."""
    row = await _get_device(db, device_id)
    # Gate on the device's *current* anchor before touching anything —
    # a subnet-bound token must not be able to re-parent a device out
    # of its own scope.
    ip = await _load_anchor(db, row, user)

    changes = body.model_dump(exclude_unset=True)
    if not changes:
        return _to_read(row, ip)

    old_value = {key: _jsonable(getattr(row, key)) for key in changes}

    if "ip_address_id" in changes and changes["ip_address_id"] != row.ip_address_id:
        ip = await _load_ip(db, changes["ip_address_id"], user)
        reparented = True
    else:
        reparented = False
    if "device_instance" in changes and changes["device_instance"] != row.device_instance:
        try:
            await assert_instance_available(db, changes["device_instance"], exclude_id=row.id)
        except DeviceInstanceConflict as exc:
            raise _instance_conflict(exc) from exc

    for key, value in changes.items():
        setattr(row, key, value)

    # Validate the *post-update* state so clearing ``is_bbmd`` while
    # leaving a populated BDT behind, or flipping on
    # ``is_foreign_device`` over an existing BBMD, fails cleanly instead
    # of persisting a shape the wire can't produce.
    _validate_topology_flags(
        is_bbmd=row.is_bbmd,
        is_foreign_device=row.is_foreign_device,
        bdt=list(row.bdt or []),
        fdt=list(row.fdt or []),
    )

    if reparented:
        await sync_subnet_id(db, row)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"BACnet device instance {row.device_instance} is already registered",
        ) from exc

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="bacnet_device",
        resource_id=str(row.id),
        resource_display=row.device_name or str(row.device_instance),
        changed_fields=list(changes.keys()),
        old_value=old_value,
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row, ip)


@router.delete("/devices/{device_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Hard-delete the registry row.

    Deleting a device frees its instance number for re-use, which is
    the point — the registry tracks what is deployed, not what once
    was. The IPAM address itself is untouched.
    """
    row = await _get_device(db, device_id)
    await _load_anchor(db, row, user)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="bacnet_device",
        resource_id=str(row.id),
        resource_display=row.device_name or str(row.device_instance),
        old_value={
            "device_instance": row.device_instance,
            "ip_address_id": str(row.ip_address_id),
            "is_bbmd": row.is_bbmd,
        },
    )
    await db.delete(row)
    await db.commit()


# ── BBMD topology ───────────────────────────────────────────────────


@router.get("/bbmds", response_model=list[BACnetBBMDRead])
async def list_bbmds(db: DB, user: CurrentUser) -> list[BACnetBBMDRead]:
    """Every registered BBMD, ordered by subnet then device instance.

    BACnet broadcasts don't cross IP routers, so each subnet in a
    multi-subnet BACnet/IP network needs exactly one Broadcast
    Distribution Device: zero and devices are invisible across subnets,
    two and every forwarded broadcast is duplicated. Ordering by subnet
    puts a duplicate pair on adjacent rows, so the failure is visible
    by eye here as well as by the conformity check.

    BDT/FDT are returned as sizes rather than contents — the tables are
    only populated when an operator or importer has documented them,
    and the number of entries is what tells you whether the BBMD has
    been configured at all.
    """
    stmt = (
        select(BACnetDevice, IPAddress, Subnet)
        .join(IPAddress, IPAddress.id == BACnetDevice.ip_address_id)
        .outerjoin(Subnet, Subnet.id == BACnetDevice.subnet_id)
        .where(BACnetDevice.is_bbmd.is_(True))
    )
    token_scope = _token_subnet_scope(user)
    if token_scope is not None:
        stmt = stmt.where(BACnetDevice.subnet_id.in_(token_scope))
    rows = (
        await db.execute(
            stmt.order_by(BACnetDevice.subnet_id.asc(), BACnetDevice.device_instance.asc())
        )
    ).all()
    return [
        BACnetBBMDRead(
            id=device.id,
            ip_address_id=device.ip_address_id,
            address=str(ip.address) if ip is not None else None,
            device_instance=device.device_instance,
            device_name=device.device_name,
            vendor_label=resolve_vendor_label(device.vendor_id, device.vendor_name),
            udp_port=device.udp_port,
            subnet_id=device.subnet_id,
            subnet_network=str(subnet.network) if subnet is not None else None,
            subnet_name=subnet.name if subnet is not None else None,
            bdt_entries=len(device.bdt) if isinstance(device.bdt, list) else 0,
            fdt_entries=len(device.fdt) if isinstance(device.fdt, list) else 0,
            last_seen_at=device.last_seen_at,
        )
        for device, ip, subnet in rows
    ]


# ── Per-IPAM-address lookup ─────────────────────────────────────────


@router.get("/by-address/{ip_address_id:uuid}", response_model=BACnetDeviceRead)
async def get_device_by_address(
    ip_address_id: uuid.UUID, db: DB, user: CurrentUser
) -> BACnetDeviceRead:
    """The BACnet device anchored to an IPAM address, or 404.

    Drives the IP-detail modal's BACnet section, which treats the 404
    as "this IP isn't a BACnet device" and renders nothing — so a 404
    here is a normal answer, not an error condition.

    The same 404 covers "no such address" and "address carries no
    device": to the caller those are one answer, and distinguishing
    them would leak the existence of addresses outside a scoped
    token's reach.

    A BACnet/IP router or MS/TP gateway can front several device
    instances at one IP. This returns the lowest-numbered one (the
    router's own device object, conventionally); the full set is
    ``GET /bacnet/devices?ip_address_id=…``.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope

    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(
            status_code=404,
            detail="No BACnet device recorded for this IP address",
        )
    # Resource-scoped API tokens (#374) are bound to a subnet; one
    # scoped elsewhere must not read this address's sidecar just
    # because the router-level ``bacnet_device`` grant passed.
    _enforce_subnet_token_scope(user, ip.subnet_id)

    device = (
        (
            await db.execute(
                select(BACnetDevice)
                .where(BACnetDevice.ip_address_id == ip_address_id)
                .order_by(BACnetDevice.device_instance.asc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if device is None:
        raise HTTPException(
            status_code=404,
            detail="No BACnet device recorded for this IP address",
        )
    return _to_read(device, ip)


# ── Instance allocation helper ──────────────────────────────────────


@router.get("/next-instance", response_model=NextInstanceResponse)
async def get_next_instance(
    db: DB,
    _: CurrentUser,
    start: int = Query(
        BACNET_INSTANCE_MIN,
        ge=BACNET_INSTANCE_MIN,
        le=BACNET_INSTANCE_MAX,
        description=(
            "Search from here upwards. Sites commonly block-allocate "
            "instances per building or per trade, so pass the base of "
            "the block to get the next free number inside it."
        ),
    ),
) -> NextInstanceResponse:
    """Suggest the lowest free device instance at or above ``start``.

    Advisory only: the suggestion is not reserved, so two operators
    commissioning at once can both be handed the same number and the
    second create returns the 409. That is the correct trade — holding
    a reservation would need a lease and an expiry for a number the
    installer may never actually use.
    """
    return NextInstanceResponse(
        start=start,
        device_instance=await next_available_instance(db, start),
    )
