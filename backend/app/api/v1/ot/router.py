"""Industrial / OT device + Purdue zoning CRUD — issue #542 (part of #543).

Endpoints under ``/ot``:

* ``/devices`` — the OT descriptor of an IPAM address (1:1 sidecar):
  protocol, role, PROFINET device name, vendor / product / serial /
  firmware, declared Purdue level and cell.
* ``/by-address/{ip_address_id}`` — the descriptor for one address, plus
  the zone it sits in and whether the two Purdue levels disagree. This
  is what the IP-detail surface reads.
* ``/zones`` — Purdue zoning, one row per subnet. Segmentation in OT is
  documentation, and the subnet is where it is actually drawn.
* ``/devices/import/{preview,commit}`` — CSV ingest of an engineering
  tool export (TIA Portal / Studio 5000 style). Rows key on IP address
  and that address **must already exist in IPAM**; unknown addresses are
  reported as row errors rather than silently created. This importer
  enriches inventory, it does not invent it.

**Safety posture — read-only identification only.** Nothing in this
router talks to a device. There is no probe, no scan, no control
protocol read and emphatically no control protocol *write*. Every value
here was typed by an operator or came out of a file they exported. See
``app.services.ot`` for why that is a structural property rather than a
convention.

Permissions: one router-level gate on the ``ot_device`` resource type
(GET → read, POST/PUT → write, DELETE → delete). Zones share it — a
zone is OT metadata about a subnet, not a subnet edit, and splitting the
two would mean an OT engineer needed subnet-write to label a cell. Every
mutation writes an ``audit_log`` row before commit per CLAUDE.md
non-negotiable #4.

Enum values mirror the frozensets in ``app.models.ot`` as ``Literal``
aliases with a belt-and-braces ``field_validator``. The ``Literal``
rejects unknown client input first — an after-validator never sees it —
so the validators exist to catch the reverse drift: an alias widened
past the model frozenset. The frozenset stays the source of truth.
``purdue_level`` travels the wire as a canonical string (``"3.5"``) and
lands in a ``Numeric(2, 1)`` column, so level 3.5 (the manufacturing /
enterprise DMZ) is a real level rather than a spelling convention.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.ipam import IPAddress, IPSpace, Subnet
from app.models.ot import (
    OT_DEVICE_SOURCES,
    OT_PROTOCOLS,
    OT_ROLES,
    PURDUE_LEVELS,
    OTDevice,
    OTZone,
)
from app.services.api_token_scopes import read_only_post
from app.services.ot.importer import (
    MAX_IMPORT_ROWS,
    OTImportError,
    PlannedRow,
    apply_plan,
    parse_rows,
    plan_import,
)
from app.services.ot.zones import effective_zone_for_address, purdue_mismatch, purdue_to_str
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["ot"],
    dependencies=[Depends(require_resource_permission("ot_device"))],
)

OTProtocol = Literal[
    "profinet",
    "ethernet_ip",
    "modbus_tcp",
    "opc_ua",
    "s7comm",
    "bacnet_ip",
    "dnp3",
    "iec61850",
    "other",
]
OTRole = Literal[
    "plc",
    "io_device",
    "hmi",
    "drive",
    "gateway",
    "sensor",
    "historian",
    "ews",
    "switch",
    "other",
]
OTDeviceSource = Literal["manual", "import", "enip", "dcp", "modbus", "opcua", "profiling"]
PurdueLevel = Literal["0", "1", "2", "3", "3.5", "4", "5"]

ImportAction = Literal["create", "update", "skip", "error"]


def _purdue_str(value: Decimal | None) -> str | None:
    """Canonical wire form of a stored level — see :func:`purdue_to_str`.

    Thin alias so this module reads naturally; the implementation is
    shared with the CSV importer and the Copilot tools so all three
    surfaces render a level identically.
    """
    return purdue_to_str(value)


def _purdue_decimal(value: str | None) -> Decimal | None:
    """Wire string → the ``Numeric(2,1)`` value stored on the row."""
    return None if value is None else Decimal(value)


# ── Device schemas ──────────────────────────────────────────────────


class OTDeviceCreate(BaseModel):
    ip_address_id: uuid.UUID
    ot_protocol: OTProtocol
    ot_role: OTRole | None = None
    profinet_device_name: str = Field(default="", max_length=255)
    ot_vendor: str = Field(default="", max_length=255)
    ot_product: str = Field(default="", max_length=255)
    ot_serial: str = Field(default="", max_length=128)
    firmware_rev: str = Field(default="", max_length=128)
    purdue_level: PurdueLevel | None = None
    cell_area: str = Field(default="", max_length=255)
    seen_via: OTDeviceSource = "manual"
    last_seen_at: datetime | None = None
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ot_protocol")
    @classmethod
    def _v_protocol(cls, v: str) -> str:
        if v not in OT_PROTOCOLS:
            raise ValueError(f"ot_protocol must be one of {sorted(OT_PROTOCOLS)}")
        return v

    @field_validator("ot_role")
    @classmethod
    def _v_role(cls, v: str | None) -> str | None:
        if v is not None and v not in OT_ROLES:
            raise ValueError(f"ot_role must be one of {sorted(OT_ROLES)}")
        return v

    @field_validator("seen_via")
    @classmethod
    def _v_seen_via(cls, v: str) -> str:
        if v not in OT_DEVICE_SOURCES:
            raise ValueError(f"seen_via must be one of {sorted(OT_DEVICE_SOURCES)}")
        return v

    @field_validator("purdue_level")
    @classmethod
    def _v_purdue(cls, v: str | None) -> str | None:
        if v is not None and v not in PURDUE_LEVELS:
            raise ValueError(f"purdue_level must be one of {sorted(PURDUE_LEVELS)}")
        return v


class OTDeviceUpdate(BaseModel):
    """Partial update. ``ip_address_id`` is deliberately absent.

    The descriptor *is* the OT identity of one address and dies with it
    (``ON DELETE CASCADE`` + ``UNIQUE`` on ``ip_address_id``). Re-pointing
    it at a different address would silently rewrite two devices' history
    in one PUT; moving a descriptor is a delete plus a create.
    """

    ot_protocol: OTProtocol | None = None
    ot_role: OTRole | None = None
    profinet_device_name: str | None = Field(default=None, max_length=255)
    ot_vendor: str | None = Field(default=None, max_length=255)
    ot_product: str | None = Field(default=None, max_length=255)
    ot_serial: str | None = Field(default=None, max_length=128)
    firmware_rev: str | None = Field(default=None, max_length=128)
    purdue_level: PurdueLevel | None = None
    cell_area: str | None = Field(default=None, max_length=255)
    seen_via: OTDeviceSource | None = None
    last_seen_at: datetime | None = None
    notes: str | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None

    @field_validator("ot_protocol")
    @classmethod
    def _v_protocol(cls, v: str | None) -> str | None:
        if v is not None and v not in OT_PROTOCOLS:
            raise ValueError(f"ot_protocol must be one of {sorted(OT_PROTOCOLS)}")
        return v

    @field_validator("ot_role")
    @classmethod
    def _v_role(cls, v: str | None) -> str | None:
        if v is not None and v not in OT_ROLES:
            raise ValueError(f"ot_role must be one of {sorted(OT_ROLES)}")
        return v

    @field_validator("seen_via")
    @classmethod
    def _v_seen_via(cls, v: str | None) -> str | None:
        if v is not None and v not in OT_DEVICE_SOURCES:
            raise ValueError(f"seen_via must be one of {sorted(OT_DEVICE_SOURCES)}")
        return v

    @field_validator("purdue_level")
    @classmethod
    def _v_purdue(cls, v: str | None) -> str | None:
        if v is not None and v not in PURDUE_LEVELS:
            raise ValueError(f"purdue_level must be one of {sorted(PURDUE_LEVELS)}")
        return v


class OTDeviceRead(BaseModel):
    """Descriptor plus the address context every caller needs anyway.

    ``address`` / ``subnet_id`` are joined in rather than left to a
    per-row round-trip: an OT inventory list is read by IP first and by
    device name second, and a table that can't show the IP is useless.
    """

    id: uuid.UUID
    ip_address_id: uuid.UUID
    address: str
    subnet_id: uuid.UUID
    ot_protocol: str
    ot_role: str | None
    profinet_device_name: str
    ot_vendor: str
    ot_product: str
    ot_serial: str
    firmware_rev: str
    purdue_level: str | None
    cell_area: str
    seen_via: str
    last_seen_at: datetime | None
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime


class OTDeviceDescriptor(OTDeviceRead):
    """By-address view: the descriptor plus its zone verdict.

    ``purdue_mismatch`` is tri-state on purpose — ``null`` when either
    the device or its zone has no declared level. An unknown is not a
    violation, and collapsing it into ``false`` would silently pass a
    plant nobody has classified yet.
    """

    zone_id: uuid.UUID | None = None
    zone_name: str = ""
    zone_cell_area: str = ""
    zone_purdue_level: str | None = None
    purdue_mismatch: bool | None = None


class OTDeviceListResponse(BaseModel):
    items: list[OTDeviceRead]
    total: int
    limit: int
    offset: int


# ── Zone schemas ────────────────────────────────────────────────────


class OTZoneCreate(BaseModel):
    subnet_id: uuid.UUID
    purdue_level: PurdueLevel
    cell_area: str = Field(default="", max_length=255)
    name: str = Field(default="", max_length=255)
    description: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("purdue_level")
    @classmethod
    def _v_purdue(cls, v: str) -> str:
        if v not in PURDUE_LEVELS:
            raise ValueError(f"purdue_level must be one of {sorted(PURDUE_LEVELS)}")
        return v


class OTZoneUpdate(BaseModel):
    """Partial update. ``subnet_id`` is absent — the zone *is* a property
    of its subnet (``UNIQUE`` + ``ON DELETE CASCADE``), so re-pointing it
    would move a segmentation record between two subnets in one PUT and
    leave both mislabelled. Delete and re-create instead."""

    purdue_level: PurdueLevel | None = None
    cell_area: str | None = Field(default=None, max_length=255)
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    tags: dict[str, Any] | None = None

    @field_validator("purdue_level")
    @classmethod
    def _v_purdue(cls, v: str | None) -> str | None:
        if v is not None and v not in PURDUE_LEVELS:
            raise ValueError(f"purdue_level must be one of {sorted(PURDUE_LEVELS)}")
        return v


class OTZoneRead(BaseModel):
    id: uuid.UUID
    subnet_id: uuid.UUID
    subnet_network: str
    purdue_level: str
    cell_area: str
    name: str
    description: str
    tags: dict[str, Any]
    device_count: int
    created_at: datetime
    modified_at: datetime


# ── Import schemas ──────────────────────────────────────────────────


class OTDeviceImportColumnMap(BaseModel):
    """Which CSV header feeds which descriptor field.

    Engineering tools name their columns locally and inconsistently
    ("IP address", "Adresse", "Device name", "Article no."), so the
    operator supplies the mapping instead of us guessing. Header matching
    is case- and separator-insensitive, and a mapped column that isn't in
    the file is a hard 422 — a typo'd mapping must not look like a
    successful import that quietly dropped a column.

    Mirrors ``app.services.ot.importer.IMPORTABLE_FIELDS``.
    """

    address: str = Field(..., min_length=1, max_length=255)
    ot_protocol: str | None = Field(default=None, max_length=255)
    ot_role: str | None = Field(default=None, max_length=255)
    profinet_device_name: str | None = Field(default=None, max_length=255)
    ot_vendor: str | None = Field(default=None, max_length=255)
    ot_product: str | None = Field(default=None, max_length=255)
    ot_serial: str | None = Field(default=None, max_length=255)
    firmware_rev: str | None = Field(default=None, max_length=255)
    purdue_level: str | None = Field(default=None, max_length=255)
    cell_area: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=255)


class OTDeviceImportRequest(BaseModel):
    """Same body for preview and commit — the server holds no state
    between the two calls, so there is no preview token to expire and a
    concurrent change surfaces as a plan difference rather than a stale
    write."""

    csv_text: str = Field(..., min_length=1)
    column_map: OTDeviceImportColumnMap
    delimiter: Literal[",", ";", "\t", "|"] = ","
    default_ot_protocol: OTProtocol | None = Field(
        default=None,
        description=(
            "Applied to rows whose protocol cell is blank, or when no "
            "protocol column is mapped at all. Exports from a single-vendor "
            "line usually omit the column entirely."
        ),
    )
    default_cell_area: str = Field(default="", max_length=255)
    overwrite_existing: bool = Field(
        default=False,
        description=(
            "When false, an address that already carries an OT descriptor "
            "is skipped. When true, its mapped fields are overwritten."
        ),
    )
    space_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Restrict address matching to one IPSpace. Needed when the same "
            "RFC 1918 plan is repeated across plants and an IP would "
            "otherwise match several IPAM rows."
        ),
    )

    @field_validator("default_ot_protocol")
    @classmethod
    def _v_protocol(cls, v: str | None) -> str | None:
        if v is not None and v not in OT_PROTOCOLS:
            raise ValueError(f"default_ot_protocol must be one of {sorted(OT_PROTOCOLS)}")
        return v


class OTDeviceImportRow(BaseModel):
    """One planned (preview) or applied (commit) row."""

    line: int
    address: str
    action: ImportAction
    reason: str = ""
    ip_address_id: uuid.UUID | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class OTDeviceImportPreviewResponse(BaseModel):
    rows: list[OTDeviceImportRow]
    create_count: int
    update_count: int
    skip_count: int
    error_count: int
    max_rows: int = MAX_IMPORT_ROWS


class OTDeviceImportCommitResponse(BaseModel):
    rows: list[OTDeviceImportRow]
    created: int
    updated: int
    skipped: int
    errors: int
    device_ids: list[uuid.UUID]


# ── Helpers ─────────────────────────────────────────────────────────


def _device_read(device: OTDevice, ip: IPAddress) -> OTDeviceRead:
    return OTDeviceRead(
        id=device.id,
        ip_address_id=device.ip_address_id,
        address=str(ip.address),
        subnet_id=ip.subnet_id,
        ot_protocol=device.ot_protocol,
        ot_role=device.ot_role,
        profinet_device_name=device.profinet_device_name,
        ot_vendor=device.ot_vendor,
        ot_product=device.ot_product,
        ot_serial=device.ot_serial,
        firmware_rev=device.firmware_rev,
        purdue_level=_purdue_str(device.purdue_level),
        cell_area=device.cell_area,
        seen_via=device.seen_via,
        last_seen_at=device.last_seen_at,
        notes=device.notes,
        tags=device.tags,
        custom_fields=device.custom_fields,
        created_at=device.created_at,
        modified_at=device.modified_at,
    )


def _zone_read(zone: OTZone, subnet_network: str, device_count: int) -> OTZoneRead:
    return OTZoneRead(
        id=zone.id,
        subnet_id=zone.subnet_id,
        subnet_network=subnet_network,
        purdue_level=_purdue_str(zone.purdue_level) or "",
        cell_area=zone.cell_area,
        name=zone.name,
        description=zone.description,
        tags=zone.tags,
        device_count=device_count,
        created_at=zone.created_at,
        modified_at=zone.modified_at,
    )


async def _load_device_with_address(
    db: AsyncSession, user: Any, device_id: uuid.UUID
) -> tuple[OTDevice, IPAddress]:
    """Fetch a descriptor together with its address, or 404.

    The subnet token-scope gate runs here rather than in each handler so
    every by-id path — read, update, delete — is covered by construction.
    A descriptor is a view onto an address, so a token scoped to one
    subnet must not reach descriptors belonging to another.
    """
    row = (
        await db.execute(
            select(OTDevice, IPAddress)
            .join(IPAddress, IPAddress.id == OTDevice.ip_address_id)
            .where(OTDevice.id == device_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="OT device not found")
    device, ip = row
    _enforce_subnet_scope(user, ip.subnet_id)
    return device, ip


async def _load_address_for_write(
    db: AsyncSession, user: Any, ip_address_id: uuid.UUID
) -> IPAddress:
    """Resolve the target IPAM address for a create, or 422.

    A missing FK target is operator input error rather than a missing
    endpoint, so it is a 422 (matching the multicast router's
    ``_check_space``). The subnet token-scope gate runs here so a
    resource-scoped API token (#374) can't attach a descriptor to an
    address outside its subnet.
    """
    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(status_code=422, detail="ip_address_id not found")
    _enforce_subnet_scope(user, ip.subnet_id)
    return ip


def _enforce_subnet_scope(user: Any, subnet_id: uuid.UUID) -> None:
    """Apply the IPAM subnet token-scope gate.

    Imported inside the call to keep this module clear of the IPAM
    router's very large import graph (and any circular-import risk with
    it) — the same deferred-import idiom the IPAM router uses for its own
    cross-module helpers.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope  # noqa: PLC0415

    _enforce_subnet_token_scope(user, subnet_id)


def _token_subnet_scope(user: Any) -> set[uuid.UUID] | None:
    """Subnets a resource-scoped token may enumerate, or ``None`` for all.

    The list-endpoint counterpart to :func:`_enforce_subnet_scope` (#523).
    Without it a subnet-bound token could read the whole plant inventory
    through ``GET /ot/devices`` even though every by-id read is gated.
    An empty set means "scoped to other resource types only" and yields
    nothing — which is why the caller tests for ``is not None`` rather
    than truthiness.
    """
    from app.api.v1.ipam.router import _token_subnet_scope_uuids  # noqa: PLC0415

    return _token_subnet_scope_uuids(user)


async def _check_subnet(db: AsyncSession, subnet_id: uuid.UUID) -> Subnet:
    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        raise HTTPException(status_code=422, detail="subnet_id not found")
    return subnet


async def _device_counts_by_subnet(
    db: AsyncSession, subnet_ids: list[uuid.UUID]
) -> dict[uuid.UUID, int]:
    """How many OT descriptors live in each of these subnets.

    One grouped query for the whole page rather than a count per zone —
    same shape as the multicast domain list's ``group_count``.
    """
    if not subnet_ids:
        return {}
    rows = (
        await db.execute(
            select(IPAddress.subnet_id, func.count(OTDevice.id))
            .join(OTDevice, OTDevice.ip_address_id == IPAddress.id)
            .where(IPAddress.subnet_id.in_(subnet_ids))
            .group_by(IPAddress.subnet_id)
        )
    ).all()
    return {subnet_id: int(count) for subnet_id, count in rows}


# ── Device endpoints ────────────────────────────────────────────────


@router.get("/devices", response_model=OTDeviceListResponse)
async def list_devices(
    db: DB,
    user: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ot_protocol: OTProtocol | None = Query(default=None),
    ot_role: OTRole | None = Query(default=None),
    purdue_level: PurdueLevel | None = Query(default=None),
    cell_area: str | None = Query(
        default=None,
        description="Case-insensitive exact match on the free-text cell / area label.",
    ),
    subnet_id: uuid.UUID | None = Query(default=None),
    q: str | None = Query(
        default=None,
        description=(
            "Case-insensitive substring across profinet_device_name, "
            "ot_vendor, ot_product and ot_serial — the four fields an OT "
            "engineer searches a plant inventory by."
        ),
    ),
    tag: list[str] = Query(default_factory=list),
) -> OTDeviceListResponse:
    """List OT descriptors in address order, with the usual filters.

    The join to ``ip_address`` is not optional: the response carries the
    address and its subnet, and ``subnet_id`` filtering rides the same
    join rather than a second query.
    """
    stmt = select(OTDevice, IPAddress).join(IPAddress, IPAddress.id == OTDevice.ip_address_id)
    token_scope = _token_subnet_scope(user)
    if token_scope is not None:
        stmt = stmt.where(IPAddress.subnet_id.in_(token_scope))
    if ot_protocol is not None:
        stmt = stmt.where(OTDevice.ot_protocol == ot_protocol)
    if ot_role is not None:
        stmt = stmt.where(OTDevice.ot_role == ot_role)
    if purdue_level is not None:
        stmt = stmt.where(OTDevice.purdue_level == _purdue_decimal(purdue_level))
    if cell_area:
        stmt = stmt.where(OTDevice.cell_area.ilike(cell_area.strip()))
    if subnet_id is not None:
        stmt = stmt.where(IPAddress.subnet_id == subnet_id)
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                OTDevice.profinet_device_name.ilike(needle),
                OTDevice.ot_vendor.ilike(needle),
                OTDevice.ot_product.ilike(needle),
                OTDevice.ot_serial.ilike(needle),
            )
        )
    stmt = apply_tag_filter(stmt, OTDevice.tags, tag)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(IPAddress.address.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    return OTDeviceListResponse(
        items=[_device_read(device, ip) for device, ip in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/devices", response_model=OTDeviceRead, status_code=status.HTTP_201_CREATED)
async def create_device(body: OTDeviceCreate, db: DB, user: CurrentUser) -> OTDeviceRead:
    """Attach an OT descriptor to an existing IPAM address.

    409 when the address already has one — the sidecar is 1:1 by
    construction (``uq_ot_device_ip_address``), and an operator who meant
    to change the existing descriptor wants a PUT, not a second row.
    """
    ip = await _load_address_for_write(db, user, body.ip_address_id)

    clash = await db.scalar(select(OTDevice.id).where(OTDevice.ip_address_id == body.ip_address_id))
    if clash is not None:
        raise HTTPException(
            status_code=409,
            detail=f"{ip.address} already has an OT descriptor ({clash})",
        )

    row = OTDevice(
        ip_address_id=body.ip_address_id,
        ot_protocol=body.ot_protocol,
        ot_role=body.ot_role,
        profinet_device_name=body.profinet_device_name,
        ot_vendor=body.ot_vendor,
        ot_product=body.ot_product,
        ot_serial=body.ot_serial,
        firmware_rev=body.firmware_rev,
        purdue_level=_purdue_decimal(body.purdue_level),
        cell_area=body.cell_area,
        seen_via=body.seen_via,
        last_seen_at=body.last_seen_at,
        notes=body.notes,
        tags=body.tags or {},
        custom_fields=body.custom_fields or {},
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="ot_device",
        resource_id=str(row.id),
        resource_display=f"{ip.address} ({body.ot_protocol})",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return _device_read(row, ip)


@router.get("/devices/{device_id:uuid}", response_model=OTDeviceRead)
async def get_device(device_id: uuid.UUID, db: DB, user: CurrentUser) -> OTDeviceRead:
    device, ip = await _load_device_with_address(db, user, device_id)
    return _device_read(device, ip)


@router.put("/devices/{device_id:uuid}", response_model=OTDeviceRead)
async def update_device(
    device_id: uuid.UUID, body: OTDeviceUpdate, db: DB, user: CurrentUser
) -> OTDeviceRead:
    device, ip = await _load_device_with_address(db, user, device_id)

    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "purdue_level":
            device.purdue_level = _purdue_decimal(value)
        else:
            setattr(device, key, value)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="ot_device",
        resource_id=str(device.id),
        resource_display=f"{ip.address} ({device.ot_protocol})",
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(device)
    return _device_read(device, ip)


@router.delete("/devices/{device_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Drop the OT descriptor. The IPAM address itself is untouched —
    deleting the descriptor says "this is no longer an OT device", not
    "this address is free"."""
    device, ip = await _load_device_with_address(db, user, device_id)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="ot_device",
        resource_id=str(device.id),
        resource_display=f"{ip.address} ({device.ot_protocol})",
    )
    await db.delete(device)
    await db.commit()


@router.get("/by-address/{ip_address_id:uuid}", response_model=OTDeviceDescriptor)
async def get_device_by_address(
    ip_address_id: uuid.UUID, db: DB, user: CurrentUser
) -> OTDeviceDescriptor:
    """The OT descriptor for one IPAM address, plus its zone verdict.

    404 both when the address doesn't exist and when it carries no OT
    descriptor — to the caller (the IP-detail surface) those are the same
    "nothing to show here", and the distinction would leak the existence
    of addresses outside a scoped token's reach.
    """
    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="No OT descriptor for this address")
    _enforce_subnet_scope(user, ip.subnet_id)

    device = (
        await db.execute(select(OTDevice).where(OTDevice.ip_address_id == ip_address_id))
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=404, detail="No OT descriptor for this address")

    zone = await effective_zone_for_address(db, ip_address_id)
    base = _device_read(device, ip)
    return OTDeviceDescriptor(
        **base.model_dump(),
        zone_id=zone.id if zone else None,
        zone_name=zone.name if zone else "",
        zone_cell_area=zone.cell_area if zone else "",
        zone_purdue_level=_purdue_str(zone.purdue_level) if zone else None,
        purdue_mismatch=purdue_mismatch(device, zone),
    )


# ── Zone endpoints ──────────────────────────────────────────────────


@router.get("/zones", response_model=list[OTZoneRead])
async def list_zones(
    db: DB,
    user: CurrentUser,
    purdue_level: PurdueLevel | None = Query(default=None),
    cell_area: str | None = Query(
        default=None,
        description="Case-insensitive exact match on the free-text cell / area label.",
    ),
) -> list[OTZoneRead]:
    """Every zoned subnet, ordered by Purdue level then network.

    Unpaginated on purpose: a zone is one row per subnet and only for
    subnets an operator has actually classified, so the list is bounded
    by the site's segmentation plan rather than by device count.
    """
    stmt = select(OTZone, Subnet).join(Subnet, Subnet.id == OTZone.subnet_id)
    token_scope = _token_subnet_scope(user)
    if token_scope is not None:
        stmt = stmt.where(OTZone.subnet_id.in_(token_scope))
    if purdue_level is not None:
        stmt = stmt.where(OTZone.purdue_level == _purdue_decimal(purdue_level))
    if cell_area:
        stmt = stmt.where(OTZone.cell_area.ilike(cell_area.strip()))
    rows = (await db.execute(stmt.order_by(OTZone.purdue_level.asc(), Subnet.network.asc()))).all()
    counts = await _device_counts_by_subnet(db, [zone.subnet_id for zone, _subnet in rows])
    return [
        _zone_read(zone, str(subnet.network), counts.get(zone.subnet_id, 0))
        for zone, subnet in rows
    ]


@router.post("/zones", response_model=OTZoneRead, status_code=status.HTTP_201_CREATED)
async def create_zone(body: OTZoneCreate, db: DB, user: CurrentUser) -> OTZoneRead:
    """Declare a subnet's Purdue level. One zone per subnet (409 on a
    duplicate) — the zone is the subnet's classification, and two
    conflicting classifications would make every boundary report
    ambiguous."""
    subnet = await _check_subnet(db, body.subnet_id)
    _enforce_subnet_scope(user, body.subnet_id)
    clash = await db.scalar(select(OTZone.id).where(OTZone.subnet_id == body.subnet_id))
    if clash is not None:
        raise HTTPException(
            status_code=409,
            detail=f"{subnet.network} already has an OT zone ({clash})",
        )

    row = OTZone(
        subnet_id=body.subnet_id,
        purdue_level=_purdue_decimal(body.purdue_level),
        cell_area=body.cell_area,
        name=body.name,
        description=body.description,
        tags=body.tags or {},
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="ot_zone",
        resource_id=str(row.id),
        resource_display=f"{subnet.network} (Purdue {body.purdue_level})",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    counts = await _device_counts_by_subnet(db, [row.subnet_id])
    return _zone_read(row, str(subnet.network), counts.get(row.subnet_id, 0))


@router.get("/zones/by-subnet/{subnet_id:uuid}", response_model=OTZoneRead)
async def get_zone_by_subnet(subnet_id: uuid.UUID, db: DB, user: CurrentUser) -> OTZoneRead:
    """The zone governing one subnet, or 404 when it is unzoned."""
    _enforce_subnet_scope(user, subnet_id)
    row = (
        await db.execute(
            select(OTZone, Subnet)
            .join(Subnet, Subnet.id == OTZone.subnet_id)
            .where(OTZone.subnet_id == subnet_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No OT zone for this subnet")
    zone, subnet = row
    counts = await _device_counts_by_subnet(db, [subnet_id])
    return _zone_read(zone, str(subnet.network), counts.get(subnet_id, 0))


@router.get("/zones/{zone_id:uuid}", response_model=OTZoneRead)
async def get_zone(zone_id: uuid.UUID, db: DB, user: CurrentUser) -> OTZoneRead:
    zone, subnet = await _load_zone_with_subnet(db, user, zone_id)
    counts = await _device_counts_by_subnet(db, [zone.subnet_id])
    return _zone_read(zone, str(subnet.network), counts.get(zone.subnet_id, 0))


@router.put("/zones/{zone_id:uuid}", response_model=OTZoneRead)
async def update_zone(
    zone_id: uuid.UUID, body: OTZoneUpdate, db: DB, user: CurrentUser
) -> OTZoneRead:
    zone, subnet = await _load_zone_with_subnet(db, user, zone_id)

    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "purdue_level":
            if value is None:
                # ``purdue_level`` is NOT NULL — a zone with no level is
                # not a zone. Clearing it is a delete.
                raise HTTPException(
                    status_code=422,
                    detail="purdue_level cannot be cleared; delete the zone instead",
                )
            zone.purdue_level = _purdue_decimal(value)
        else:
            setattr(zone, key, value)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="ot_zone",
        resource_id=str(zone.id),
        resource_display=f"{subnet.network} (Purdue {_purdue_str(zone.purdue_level)})",
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(zone)
    counts = await _device_counts_by_subnet(db, [zone.subnet_id])
    return _zone_read(zone, str(subnet.network), counts.get(zone.subnet_id, 0))


@router.delete("/zones/{zone_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_zone(zone_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Un-zone a subnet. Devices inside keep their own declared levels;
    they simply stop having a zone to be compared against, which reads as
    "unknown" rather than "conforming"."""
    zone, subnet = await _load_zone_with_subnet(db, user, zone_id)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="ot_zone",
        resource_id=str(zone.id),
        resource_display=f"{subnet.network} (Purdue {_purdue_str(zone.purdue_level)})",
    )
    await db.delete(zone)
    await db.commit()


async def _load_zone_with_subnet(
    db: AsyncSession, user: Any, zone_id: uuid.UUID
) -> tuple[OTZone, Subnet]:
    """Fetch a zone with its subnet, or 404. Gates the token subnet scope
    here so every by-id zone path is covered the same way
    :func:`_load_device_with_address` covers the device paths."""
    row = (
        await db.execute(
            select(OTZone, Subnet)
            .join(Subnet, Subnet.id == OTZone.subnet_id)
            .where(OTZone.id == zone_id)
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="OT zone not found")
    _enforce_subnet_scope(user, row[0].subnet_id)
    zone, subnet = row
    return zone, subnet


# ── Engineering-export import ───────────────────────────────────────
#
# Preview and commit take the same request body. The commit re-parses and
# re-plans rather than trusting a plan the client hands back, so a client
# cannot smuggle in an ip_address_id the preview never resolved — the
# only thing that decides what gets written is the CSV plus the column
# map, evaluated server-side both times.


async def _build_plan(db: AsyncSession, user: Any, body: OTDeviceImportRequest) -> list[PlannedRow]:
    # A resource-scoped API token (#374) is bound to specific subnets,
    # but an import addresses rows by IP literal across the whole plan —
    # there is no honest way to scope it row-by-row without silently
    # dropping the operator's data. Refuse the whole call instead; a
    # scoped token can still write descriptors one at a time, where the
    # per-address gate applies.
    if _token_subnet_scope(user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Bulk OT import is not available to a resource-scoped API token",
        )
    if body.space_id is not None and (await db.get(IPSpace, body.space_id)) is None:
        raise HTTPException(status_code=422, detail="space_id not found")
    try:
        parsed = parse_rows(
            body.csv_text,
            column_map=body.column_map.model_dump(exclude_none=True),
            delimiter=body.delimiter,
            default_ot_protocol=body.default_ot_protocol,
            default_cell_area=body.default_cell_area,
        )
    except OTImportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await plan_import(
        db,
        parsed,
        overwrite_existing=body.overwrite_existing,
        space_id=body.space_id,
    )


def _rows_out(plan: list[PlannedRow]) -> list[OTDeviceImportRow]:
    return [
        OTDeviceImportRow(
            line=row.line,
            address=row.address,
            action=row.action,  # type: ignore[arg-type]
            reason=row.reason,
            ip_address_id=row.ip_address_id,
            fields=row.fields,
        )
        for row in plan
    ]


@router.post("/devices/import/preview", response_model=OTDeviceImportPreviewResponse)
@read_only_post
async def import_preview(
    body: OTDeviceImportRequest, db: DB, user: CurrentUser
) -> OTDeviceImportPreviewResponse:
    """Parse + plan the CSV without writing anything.

    Returns one row per CSV data row: what would be created, what would
    be updated, what would be skipped, and — per row, with a reason — what
    is unusable. Unknown IP addresses are errors, not silent creates:
    this importer enriches IPAM, it never invents it.
    """
    plan = await _build_plan(db, user, body)
    return OTDeviceImportPreviewResponse(
        rows=_rows_out(plan),
        create_count=sum(1 for r in plan if r.action == "create"),
        update_count=sum(1 for r in plan if r.action == "update"),
        skip_count=sum(1 for r in plan if r.action == "skip"),
        error_count=sum(1 for r in plan if r.action == "error"),
    )


@router.post(
    "/devices/import/commit",
    response_model=OTDeviceImportCommitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def import_commit(
    body: OTDeviceImportRequest, db: DB, user: CurrentUser
) -> OTDeviceImportCommitResponse:
    """Apply the import. Valid rows land; invalid rows are reported.

    Deliberately not all-or-nothing at the *row* level — an operator
    fixing a plant inventory wants the 397 good rows in and the 3 bad
    ones named. It is all-or-nothing at the *transaction* level: one
    commit, so a failure part-way leaves nothing half-applied.

    Audit rows are written per created / updated descriptor by the
    importer before the commit (non-negotiable #4).
    """
    plan = await _build_plan(db, user, body)
    outcome = await apply_plan(db, plan, user=user)
    await db.commit()
    return OTDeviceImportCommitResponse(
        rows=_rows_out(plan),
        created=outcome.created,
        updated=outcome.updated,
        skipped=outcome.skipped,
        errors=outcome.errors,
        device_ids=outcome.device_ids,
    )
