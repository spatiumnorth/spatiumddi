"""DICOM AE Title registry CRUD — issue #723 Phase 1.

Endpoints under ``/dicom``:

* ``/aes`` — Application Entity list / create
* ``/aes/{id}`` — read / patch / delete
* ``/aes/import/{preview,commit}`` — CSV ingest of the estate's existing
  AE table, keyed on the title
* ``/peers`` — the configured AE→AE association edges, list / create
* ``/peers/{id}`` — delete
* ``/by-address/{ip_address_id}`` — the AE anchored to an IPAM address.
  Drives the IP-detail modal's DICOM section, which treats a 404 as
  "not a DICOM node" and renders nothing.
* ``/aes/{id}/impact`` — what a renumber or decommission of this AE
  would break, i.e. its peer edges in both directions. The question
  every PACS administrator actually asks.

Permissions: every endpoint is gated on ``dicom_ae`` at the router level
(GET→read, POST/PATCH→write, DELETE→delete; superadmin always passes).
Each mutation writes an ``audit_log`` row before commit per CLAUDE.md
non-negotiable #4.

Server-side validation beyond the field bounds mirrored from
``app.models.dicom``:

* ``ae_title`` goes through the PS3.5 ``AE`` value-representation rules
  in ``services/dicom/titles`` — 16 **bytes**, spaces legal as padding,
  all-space forbidden, no backslash, no control characters. Deliberately
  not alphanumeric-only: rejecting titles real devices use would make
  the registry record a plan that fails at commissioning.
* Title uniqueness is pre-checked for a friendly 409 that names the
  conflicting AE, and the resulting ``IntegrityError`` is re-mapped to
  the same 409 so a lost race doesn't surface as a 500.

Zero network I/O: this surface never speaks DICOM. Rows arrive from
operators and the importer; the C-ECHO verification probe is deferred
(see ``app.services.dicom``).

**No PHI.** ``notes`` is a network-configuration field and is documented
as such on the wire. Nothing on this surface accepts or returns
patient-identifiable data.
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
from sqlalchemy.orm import aliased

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.auth import User
from app.models.dicom import (
    DICOM_AE_ROLES,
    DICOM_AE_SOURCES,
    DICOM_DEFAULT_PORT,
    DICOM_DEVICE_CLASSES,
    DICOMApplicationEntity,
    DICOMPeer,
)
from app.models.ipam import IPAddress, IPSpace
from app.services.dicom.importer import (
    MAX_IMPORT_ROWS,
    DICOMImportError,
    PlannedRow,
    apply_plan,
    parse_rows,
    plan_import,
)
from app.services.dicom.registry import (
    AETitleConflict,
    assert_title_available,
    sync_subnet_id,
)
from app.services.dicom.titles import AETitleError, is_vendor_default, validate_ae_title
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["dicom"],
    dependencies=[Depends(require_resource_permission("dicom_ae"))],
)

DICOMRole = Literal["scp", "scu", "both"]
DICOMDeviceClass = Literal[
    "modality",
    "pacs",
    "workstation",
    "archive",
    "router",
    "worklist",
    "printer",
    "other",
]
DICOMAESource = Literal["manual", "import", "echo"]
ImportAction = Literal["create", "update", "skip", "error"]

# Raw-input ceiling for ``ae_title`` before validation. Generous: the
# real rule is 16 bytes *after* trimming padding, enforced by
# ``validate_ae_title``. This only stops an unbounded string from
# reaching it, and is loose enough that a title made entirely of legal
# pad space still gets the specific "empty or all spaces" message rather
# than a generic length one.
_MAX_TITLE_INPUT = 128

# Network-configuration notes. Named in the field description too — an
# unlabelled free-text box is the surest way to end up storing PHI.
_NOTES_DESCRIPTION = (
    "Network-configuration notes. Do NOT record patient-identifiable "
    "information here — this registry stores network identity only."
)


# ── Schemas ─────────────────────────────────────────────────────────


def _validated_title(v: str) -> str:
    """Shared ``ae_title`` validator body.

    Raises ``ValueError`` (which pydantic renders as a 422 naming the
    field) rather than an ``HTTPException``, so the message about *which*
    VR rule was broken reaches the operator attached to the field they
    typed it in.
    """
    try:
        return validate_ae_title(v)
    except AETitleError as exc:
        raise ValueError(str(exc)) from exc


class DICOMAECreate(BaseModel):
    # Deliberately NO ``max_length``: pydantic's length check counts
    # *characters* and runs on the *untrimmed* value, so a legal
    # 16-byte title carrying pad space ("QRSTUVWXYZABCDEF ") would be
    # rejected before ``_validated_title`` ever trimmed it. Spaces are
    # non-significant padding per PS3.5, so the ceiling has to be
    # measured after trimming and in bytes — which is exactly what
    # ``validate_ae_title`` does. ``_MAX_TITLE_INPUT`` still bounds the
    # raw input so an unbounded string can't reach the validator.
    ae_title: str = Field(..., min_length=1, max_length=_MAX_TITLE_INPUT)
    # Nullable on purpose: an AE with no address is a *reservation* — a
    # title still in peer configuration whose host is gone. Registering
    # those is the point, not an edge case.
    ip_address_id: uuid.UUID | None = None
    port: int = Field(default=DICOM_DEFAULT_PORT, ge=1, le=65535)
    tls_enabled: bool = False
    role: DICOMRole = "both"
    device_class: DICOMDeviceClass = "other"
    vendor: str = Field(default="", max_length=255)
    model_name: str = Field(default="", max_length=255)
    department: str = Field(default="", max_length=255)
    location: str = Field(default="", max_length=255)
    seen_via: DICOMAESource = "manual"
    last_seen_at: datetime | None = None
    notes: str = Field(default="", description=_NOTES_DESCRIPTION)
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ae_title")
    @classmethod
    def _v_title(cls, v: str) -> str:
        return _validated_title(v)

    # House belt-and-braces convention (see ``models/multicast.py``).
    # Pydantic rejects an unknown value against the ``Literal`` alias
    # before an after-validator runs, so these never fire for bad client
    # input — they guard the reverse drift, an alias widened past the
    # model frozenset, keeping the frozenset the single source of truth.
    @field_validator("role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        if v not in DICOM_AE_ROLES:
            raise ValueError(f"role must be one of {sorted(DICOM_AE_ROLES)}")
        return v

    @field_validator("device_class")
    @classmethod
    def _v_class(cls, v: str) -> str:
        if v not in DICOM_DEVICE_CLASSES:
            raise ValueError(f"device_class must be one of {sorted(DICOM_DEVICE_CLASSES)}")
        return v

    @field_validator("seen_via")
    @classmethod
    def _v_seen_via(cls, v: str) -> str:
        if v not in DICOM_AE_SOURCES:
            raise ValueError(f"seen_via must be one of {sorted(DICOM_AE_SOURCES)}")
        return v


class DICOMAEUpdate(BaseModel):
    """PATCH body — every field optional, ``exclude_unset`` semantics.

    ``ip_address_id`` is re-parentable *and* explicitly clearable: a
    modality that moves keeps its title and gains a new anchor, and a
    decommissioned one keeps its title with no anchor at all. Both are
    normal lifecycle events for an AE Title, which is why the field is
    handled through ``model_fields_set`` rather than an
    ``exclude_none`` dump — otherwise clearing it would be indis-
    tinguishable from not mentioning it.
    """

    # See DICOMAECreate.ae_title on why this is not bounded at 16.
    ae_title: str | None = Field(default=None, max_length=_MAX_TITLE_INPUT)
    ip_address_id: uuid.UUID | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    tls_enabled: bool | None = None
    role: DICOMRole | None = None
    device_class: DICOMDeviceClass | None = None
    vendor: str | None = Field(default=None, max_length=255)
    model_name: str | None = Field(default=None, max_length=255)
    department: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    seen_via: DICOMAESource | None = None
    last_seen_at: datetime | None = None
    notes: str | None = Field(default=None, description=_NOTES_DESCRIPTION)
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None

    @field_validator("ae_title")
    @classmethod
    def _v_title(cls, v: str | None) -> str | None:
        return None if v is None else _validated_title(v)


class DICOMAERead(BaseModel):
    """Wire model for an AE row.

    ``address`` / ``hostname`` are joined in rather than stored, and
    ``is_vendor_default`` is derived: every operator-facing read of this
    registry is "which title, on which box, and has anyone actually
    configured it", and making the caller round-trip per row for that
    turns a 300-AE list into 301 requests.
    """

    id: uuid.UUID
    ae_title: str
    ip_address_id: uuid.UUID | None
    subnet_id: uuid.UUID | None
    address: str | None = None
    hostname: str | None = None
    port: int
    tls_enabled: bool
    role: str
    device_class: str
    vendor: str
    model_name: str
    department: str
    location: str
    seen_via: str
    last_seen_at: datetime | None
    notes: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    # True when the title is still a known vendor default. Advisory —
    # it is not invalid, it is just the most common cause of the
    # estate-wide collisions this registry exists to prevent.
    is_vendor_default: bool = False
    # True when the title has no IPAM anchor: a reservation held so the
    # name is not re-issued while peers still send to it.
    is_reservation: bool = False
    created_at: datetime
    modified_at: datetime


class DICOMAEListResponse(BaseModel):
    items: list[DICOMAERead]
    total: int
    limit: int
    offset: int


class DICOMPeerCreate(BaseModel):
    source_ae_id: uuid.UUID
    target_ae_id: uuid.UUID
    # Free-text DICOM services this edge carries (C-STORE, C-FIND,
    # C-MOVE, MPPS, …). Unconstrained because SOP class support is
    # genuinely open-ended and an operator documenting their estate
    # should never be blocked on our taxonomy being complete.
    services: list[str] = Field(default_factory=list)
    notes: str = Field(default="", description=_NOTES_DESCRIPTION)


class DICOMPeerRead(BaseModel):
    """One configured association, with both endpoints' titles inlined.

    The titles are what a data-flow map is drawn from, so returning ids
    alone would make every render an N+1.
    """

    id: uuid.UUID
    source_ae_id: uuid.UUID
    source_ae_title: str
    target_ae_id: uuid.UUID
    target_ae_title: str
    services: list[str]
    notes: str
    created_at: datetime
    modified_at: datetime


class DICOMImpactResponse(BaseModel):
    """What a renumber / decommission of one AE would disturb.

    Split by direction because the consequences differ: the AE's
    *outbound* edges stop sending, its *inbound* edges stop being able to
    reach it. A PACS administrator planning a host move needs both lists
    and needs to know which is which.
    """

    ae_id: uuid.UUID
    ae_title: str
    address: str | None
    outbound: list[DICOMPeerRead]
    inbound: list[DICOMPeerRead]
    total_peers: int


class DICOMAEImportColumnMap(BaseModel):
    """Which CSV header feeds which AE field.

    Institutions name their AE-table columns locally ("AET", "AE Title",
    "Called AE", "Host", "IP", "Port"), so the operator supplies the
    mapping instead of us guessing. Header matching is case- and
    separator-insensitive, and a mapped column that isn't in the file is
    a hard 422 — a typo'd mapping must not look like a successful import
    that quietly dropped a column.

    Mirrors ``app.services.dicom.importer.IMPORTABLE_FIELDS``.
    """

    ae_title: str = Field(..., min_length=1, max_length=255)
    address: str | None = Field(default=None, max_length=255)
    port: str | None = Field(default=None, max_length=255)
    tls_enabled: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, max_length=255)
    device_class: str | None = Field(default=None, max_length=255)
    vendor: str | None = Field(default=None, max_length=255)
    model_name: str | None = Field(default=None, max_length=255)
    department: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=255)


class DICOMAEImportRequest(BaseModel):
    """Same body for preview and commit — the server holds no state
    between the two calls, so there is no preview token to expire and a
    concurrent change surfaces as a plan difference rather than a stale
    write."""

    csv_text: str = Field(..., min_length=1)
    column_map: DICOMAEImportColumnMap
    delimiter: Literal[",", ";", "\t", "|"] = ","
    default_port: int = Field(
        default=DICOM_DEFAULT_PORT,
        ge=1,
        le=65535,
        description=(
            "Applied to rows whose port cell is blank, or when no port "
            "column is mapped. 11112 is the IANA-registered ``dicom`` port; "
            "104 is the historical ``acr-nema`` registration and is still "
            "widely configured."
        ),
    )
    default_department: str = Field(default="", max_length=255)
    overwrite_existing: bool = Field(
        default=False,
        description=(
            "When false, an AE Title that is already registered is skipped. "
            "When true, its mapped fields are overwritten."
        ),
    )
    space_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Restrict address matching to one IPSpace. Needed when the same "
            "RFC 1918 plan is repeated across sites and an IP would "
            "otherwise match several IPAM rows."
        ),
    )


class DICOMAEImportRow(BaseModel):
    """One planned (preview) or applied (commit) row."""

    line: int
    ae_title: str
    action: ImportAction
    reason: str = ""
    address: str = ""
    ip_address_id: uuid.UUID | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class DICOMAEImportPreviewResponse(BaseModel):
    rows: list[DICOMAEImportRow]
    create_count: int
    update_count: int
    skip_count: int
    error_count: int
    max_rows: int = MAX_IMPORT_ROWS


class DICOMAEImportCommitResponse(BaseModel):
    rows: list[DICOMAEImportRow]
    created: int
    updated: int
    skipped: int
    errors: int
    ae_ids: list[uuid.UUID]


# ── Helpers ─────────────────────────────────────────────────────────


def _to_read(ae: DICOMApplicationEntity, ip: IPAddress | None) -> DICOMAERead:
    return DICOMAERead(
        id=ae.id,
        ae_title=ae.ae_title,
        ip_address_id=ae.ip_address_id,
        subnet_id=ae.subnet_id,
        # ``IPAddress.address`` is INET — asyncpg hands back an
        # ``ipaddress`` object, which Pydantic won't accept as ``str``.
        address=str(ip.address) if ip is not None else None,
        hostname=ip.hostname if ip is not None else None,
        port=ae.port,
        tls_enabled=ae.tls_enabled,
        role=ae.role,
        device_class=ae.device_class,
        vendor=ae.vendor,
        model_name=ae.model_name,
        department=ae.department,
        location=ae.location,
        seen_via=ae.seen_via,
        last_seen_at=ae.last_seen_at,
        notes=ae.notes,
        tags=ae.tags,
        custom_fields=ae.custom_fields,
        is_vendor_default=is_vendor_default(ae.ae_title),
        is_reservation=ae.ip_address_id is None,
        created_at=ae.created_at,
        modified_at=ae.modified_at,
    )


def _peer_read(peer: DICOMPeer, source_title: str, target_title: str) -> DICOMPeerRead:
    return DICOMPeerRead(
        id=peer.id,
        source_ae_id=peer.source_ae_id,
        source_ae_title=source_title,
        target_ae_id=peer.target_ae_id,
        target_ae_title=target_title,
        services=[str(s) for s in (peer.services or [])],
        notes=peer.notes,
        created_at=peer.created_at,
        modified_at=peer.modified_at,
    )


def _jsonable(value: Any) -> Any:
    """JSON-safe copy of a model attribute for the audit row.

    ``old_value`` lands in a JSONB column, so UUID and datetime values
    have to be stringified; every other column on ``DICOMApplicationEntity``
    is already a JSON primitive or a JSONB list/dict.
    """
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _integrity_error(exc: IntegrityError, *, ae_title: str) -> HTTPException:
    """Map a flush failure to the right status, not just to 409.

    ``uq_dicom_ae_title`` is the constraint this surface expects to trip,
    but it is not the only one on the table — a NOT NULL or a CHECK
    (port range, AE-title length) can fail here too, and reporting those
    as "AE Title already registered" sends the operator hunting for a
    duplicate that does not exist. Match on the constraint name and fall
    back to a 422 that says what actually happened.
    """
    detail = str(getattr(exc, "orig", exc))
    if "uq_dicom_ae_title" in detail:
        return HTTPException(
            status_code=409,
            detail=f"AE Title {ae_title!r} is already registered",
        )
    return HTTPException(
        status_code=422,
        detail=f"The application entity could not be saved: {detail}",
    )


def _title_conflict(exc: AETitleConflict) -> HTTPException:
    """409 naming the AE that already holds the title.

    AE Title uniqueness is institution-wide by specification, so the
    conflicting row is very often in a different department, owned by a
    different vendor's service engineer — which is exactly why the
    response has to name it instead of saying "already in use".
    """
    return HTTPException(
        status_code=409,
        detail=str(exc),
        headers={"X-Conflicting-Ae-Id": str(exc.existing_id)},
    )


async def _load_ip(db: AsyncSession, ip_address_id: uuid.UUID, user: User) -> IPAddress:
    """Fetch the anchoring IPAM address, 422 when it doesn't exist.

    Also applies the resource-scoped API-token gate (#374): a token bound
    to one subnet must not attach AEs to addresses in another just
    because the router-level ``dicom_ae`` grant passed. Deferred import —
    ``app.api.v1.ipam.router`` is a large module and importing it at
    module scope would create a cycle through the shared IPAM helpers.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope  # noqa: PLC0415

    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(status_code=422, detail="ip_address_id not found")
    _enforce_subnet_token_scope(user, ip.subnet_id)
    return ip


async def _load_anchor(
    db: AsyncSession, ae: DICOMApplicationEntity, user: User
) -> IPAddress | None:
    """Load an AE's current IPAM anchor, enforcing the token gate.

    Returns ``None`` for an unbound reservation — the normal state for a
    title whose host was decommissioned — as well as for the rare case
    where the anchor row vanished concurrently. Both are "no address to
    scope against", so a scoped token is not blocked from reading a
    reservation it can otherwise see through the list.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope  # noqa: PLC0415

    if ae.ip_address_id is None:
        return None
    ip = await db.get(IPAddress, ae.ip_address_id)
    if ip is not None:
        _enforce_subnet_token_scope(user, ip.subnet_id)
    return ip


async def _get_ae(db: AsyncSession, ae_id: uuid.UUID) -> DICOMApplicationEntity:
    row = await db.get(DICOMApplicationEntity, ae_id)
    if row is None:
        raise HTTPException(status_code=404, detail="DICOM application entity not found")
    return row


def _token_subnet_scope(user: Any) -> set[uuid.UUID] | None:
    """Subnets a resource-scoped token may enumerate, or ``None`` for all.

    The list-endpoint counterpart to the per-row gate (#523). An empty
    set means "scoped to other resource types only" and must yield
    nothing — hence callers test ``is not None`` rather than truthiness.
    """
    from app.api.v1.ipam.router import _token_subnet_scope_uuids  # noqa: PLC0415

    return _token_subnet_scope_uuids(user)


def _apply_ae_filters[*Ts](
    stmt: Select[*Ts],
    *,
    token_scope: set[uuid.UUID] | None,
    tag: list[str],
    subnet_id: uuid.UUID | None,
    ip_address_id: uuid.UUID | None,
    device_class: str | None,
    role: str | None,
    tls_enabled: bool | None,
    unbound: bool | None,
    q: str | None,
) -> Select[*Ts]:
    """Shared WHERE construction for the list page and its count.

    Kept in one place so the ``total`` can never drift from the rows
    actually returned — the classic pagination bug where a filter is
    added to one query and not the other. The token scope rides the same
    helper for the same reason.

    One asymmetry worth naming: a scoped token sees no unbound
    reservations at all, because a row with ``subnet_id IS NULL`` is not
    in any subnet the token is bound to. That is the conservative
    reading, and the alternative — showing every reservation to every
    scoped token — would leak the institution-wide title namespace to a
    token deliberately confined to one subnet.
    """
    if token_scope is not None:
        stmt = stmt.where(DICOMApplicationEntity.subnet_id.in_(token_scope))
    stmt = apply_tag_filter(stmt, DICOMApplicationEntity.tags, tag)
    if subnet_id is not None:
        stmt = stmt.where(DICOMApplicationEntity.subnet_id == subnet_id)
    if ip_address_id is not None:
        stmt = stmt.where(DICOMApplicationEntity.ip_address_id == ip_address_id)
    if device_class is not None:
        stmt = stmt.where(DICOMApplicationEntity.device_class == device_class)
    if role is not None:
        stmt = stmt.where(DICOMApplicationEntity.role == role)
    if tls_enabled is not None:
        stmt = stmt.where(DICOMApplicationEntity.tls_enabled.is_(tls_enabled))
    if unbound is not None:
        stmt = stmt.where(
            DICOMApplicationEntity.ip_address_id.is_(None)
            if unbound
            else DICOMApplicationEntity.ip_address_id.is_not(None)
        )
    if q:
        needle = f"%{q.strip()}%"
        clauses: list[ColumnElement[bool]] = [
            DICOMApplicationEntity.ae_title.ilike(needle),
            DICOMApplicationEntity.vendor.ilike(needle),
            DICOMApplicationEntity.model_name.ilike(needle),
            DICOMApplicationEntity.department.ilike(needle),
            DICOMApplicationEntity.location.ilike(needle),
        ]
        stmt = stmt.where(or_(*clauses))
    return stmt


# ── AE endpoints ────────────────────────────────────────────────────


@router.get("/aes", response_model=DICOMAEListResponse)
async def list_aes(
    db: DB,
    user: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    subnet_id: uuid.UUID | None = Query(default=None),
    ip_address_id: uuid.UUID | None = Query(
        default=None,
        description=(
            "Every AE anchored to one IPAM address. A single PACS host "
            "commonly fronts several AE Titles (one per service), so "
            "this can legitimately return more than one row."
        ),
    ),
    device_class: DICOMDeviceClass | None = Query(default=None),
    role: DICOMRole | None = Query(default=None),
    tls_enabled: bool | None = Query(default=None),
    unbound: bool | None = Query(
        default=None,
        description=(
            "True = only reservations (titles with no IPAM anchor), " "False = only bound AEs."
        ),
    ),
    tag: list[str] = Query(default_factory=list),
    q: str | None = Query(
        default=None,
        description="Case-insensitive substring on title / vendor / model / department / location.",
    ),
) -> DICOMAEListResponse:
    """List AEs in title order, with their IPAM anchor where they have one."""
    token_scope = _token_subnet_scope(user)
    filters: dict[str, Any] = {
        "token_scope": token_scope,
        "tag": tag,
        "subnet_id": subnet_id,
        "ip_address_id": ip_address_id,
        "device_class": device_class,
        "role": role,
        "tls_enabled": tls_enabled,
        "unbound": unbound,
        "q": q,
    }
    total = (
        await db.execute(
            _apply_ae_filters(select(func.count(DICOMApplicationEntity.id)), **filters)
        )
    ).scalar_one()

    # OUTER join — an unbound reservation has no address row, and an
    # inner join would silently hide exactly the rows the registry most
    # needs to keep visible.
    stmt = _apply_ae_filters(
        select(DICOMApplicationEntity, IPAddress).outerjoin(
            IPAddress, IPAddress.id == DICOMApplicationEntity.ip_address_id
        ),
        **filters,
    )
    rows = (
        await db.execute(
            stmt.order_by(DICOMApplicationEntity.ae_title.asc()).limit(limit).offset(offset)
        )
    ).all()
    return DICOMAEListResponse(
        items=[_to_read(ae, ip) for ae, ip in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("/aes", response_model=DICOMAERead, status_code=status.HTTP_201_CREATED)
async def create_ae(body: DICOMAECreate, db: DB, user: CurrentUser) -> DICOMAERead:
    """Register an AE Title. 409 when the title is already taken."""
    ip = await _load_ip(db, body.ip_address_id, user) if body.ip_address_id else None
    try:
        await assert_title_available(db, body.ae_title)
    except AETitleConflict as exc:
        raise _title_conflict(exc) from exc

    row = DICOMApplicationEntity(
        ae_title=body.ae_title,
        ip_address_id=body.ip_address_id,
        port=body.port,
        tls_enabled=body.tls_enabled,
        role=body.role,
        device_class=body.device_class,
        vendor=body.vendor,
        model_name=body.model_name,
        department=body.department,
        location=body.location,
        seen_via=body.seen_via,
        last_seen_at=body.last_seen_at,
        notes=body.notes,
        tags=body.tags or {},
        custom_fields=body.custom_fields or {},
    )
    await sync_subnet_id(db, row)
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        # Lost the race against a concurrent create between the
        # availability check and the INSERT. ``uq_dicom_ae_title`` is the
        # real guard; answer with the same 409 the pre-check would have
        # produced rather than leaking a 500.
        await db.rollback()
        raise _integrity_error(exc, ae_title=body.ae_title) from exc

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dicom_ae",
        resource_id=str(row.id),
        resource_display=row.ae_title,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row, ip)


@router.get("/aes/{ae_id:uuid}", response_model=DICOMAERead)
async def get_ae(ae_id: uuid.UUID, db: DB, user: CurrentUser) -> DICOMAERead:
    row = await _get_ae(db, ae_id)
    ip = await _load_anchor(db, row, user)
    return _to_read(row, ip)


@router.patch("/aes/{ae_id:uuid}", response_model=DICOMAERead)
async def update_ae(
    ae_id: uuid.UUID, body: DICOMAEUpdate, db: DB, user: CurrentUser
) -> DICOMAERead:
    """Patch an AE. 409 when a new title is already taken."""
    row = await _get_ae(db, ae_id)
    # Gate on the AE's *current* anchor before touching anything — a
    # subnet-bound token must not re-parent an AE out of its own scope.
    ip = await _load_anchor(db, row, user)

    changes = body.model_dump(exclude_unset=True)
    if not changes:
        return _to_read(row, ip)

    old_value = {key: _jsonable(getattr(row, key)) for key in changes}

    # ``ip_address_id`` is present in ``changes`` whenever the caller
    # mentioned it, including as an explicit null — which is how a
    # decommissioned host demotes its title to a reservation.
    reparented = "ip_address_id" in changes and changes["ip_address_id"] != row.ip_address_id
    if reparented:
        new_anchor = changes["ip_address_id"]
        ip = await _load_ip(db, new_anchor, user) if new_anchor is not None else None
    if "ae_title" in changes and changes["ae_title"] != row.ae_title:
        try:
            await assert_title_available(db, changes["ae_title"], exclude_id=row.id)
        except AETitleConflict as exc:
            raise _title_conflict(exc) from exc

    for key, value in changes.items():
        setattr(row, key, value)
    # Snapshot before the flush: the failure path rolls back, which
    # expires every ORM instance, so reading ``row.ae_title`` inside the
    # handler would trigger a lazy refresh and raise MissingGreenlet
    # instead of the intended response.
    new_title = row.ae_title

    if reparented:
        await sync_subnet_id(db, row)

    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise _integrity_error(exc, ae_title=new_title) from exc

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dicom_ae",
        resource_id=str(row.id),
        resource_display=row.ae_title,
        changed_fields=list(changes.keys()),
        old_value=old_value,
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row, ip)


@router.delete("/aes/{ae_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ae(ae_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Delete the registry row, freeing its title for re-use.

    That is the intended effect, and it is why the response body records
    the peer count in the audit row: deleting an AE that still has
    configured peers is exactly the action that re-issues a name other
    devices are still sending to. Use ``GET /aes/{id}/impact`` first —
    this endpoint deliberately does not refuse, because the registry
    tracks what is deployed and an operator decommissioning a modality
    is right to remove it.
    """
    row = await _get_ae(db, ae_id)
    await _load_anchor(db, row, user)
    peer_count = (
        await db.execute(
            select(func.count(DICOMPeer.id)).where(
                or_(DICOMPeer.source_ae_id == row.id, DICOMPeer.target_ae_id == row.id)
            )
        )
    ).scalar_one()
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dicom_ae",
        resource_id=str(row.id),
        resource_display=row.ae_title,
        old_value={
            "ae_title": row.ae_title,
            "ip_address_id": str(row.ip_address_id) if row.ip_address_id else None,
            "device_class": row.device_class,
            # Recorded because the cascade silently removes these edges
            # with the row; without the count nothing downstream can tell
            # how much of the data-flow map went with it.
            "peer_edges_removed": int(peer_count),
        },
    )
    await db.delete(row)
    await db.commit()


@router.get("/aes/{ae_id:uuid}/impact", response_model=DICOMImpactResponse)
async def get_ae_impact(ae_id: uuid.UUID, db: DB, user: CurrentUser) -> DICOMImpactResponse:
    """What a renumber or decommission of this AE would disturb.

    The question a PACS administrator asks before touching anything, and
    the reason ``dicom_peer`` exists as a directed edge: an AE's outbound
    associations stop sending, its inbound ones stop being able to reach
    it, and those are different remediation lists.
    """
    row = await _get_ae(db, ae_id)
    ip = await _load_anchor(db, row, user)

    source = aliased(DICOMApplicationEntity, name="source_ae")
    target = aliased(DICOMApplicationEntity, name="target_ae")
    edges = (
        await db.execute(
            select(DICOMPeer, source.ae_title, target.ae_title)
            .join(source, source.id == DICOMPeer.source_ae_id)
            .join(target, target.id == DICOMPeer.target_ae_id)
            .where(or_(DICOMPeer.source_ae_id == row.id, DICOMPeer.target_ae_id == row.id))
            .order_by(source.ae_title.asc(), target.ae_title.asc())
        )
    ).all()

    outbound = [
        _peer_read(peer, src, dst) for peer, src, dst in edges if peer.source_ae_id == row.id
    ]
    inbound = [
        _peer_read(peer, src, dst) for peer, src, dst in edges if peer.target_ae_id == row.id
    ]
    return DICOMImpactResponse(
        ae_id=row.id,
        ae_title=row.ae_title,
        address=str(ip.address) if ip is not None else None,
        outbound=outbound,
        inbound=inbound,
        total_peers=len(outbound) + len(inbound),
    )


# ── Per-IPAM-address lookup ─────────────────────────────────────────


@router.get("/by-address/{ip_address_id:uuid}", response_model=DICOMAERead)
async def get_ae_by_address(ip_address_id: uuid.UUID, db: DB, user: CurrentUser) -> DICOMAERead:
    """The DICOM AE anchored to an IPAM address, or 404.

    Drives the IP-detail modal's DICOM section, which treats the 404 as
    "this IP isn't a DICOM node" and renders nothing — so a 404 here is a
    normal answer, not an error condition.

    The same 404 covers "no such address" and "address carries no AE": to
    the caller those are one answer, and distinguishing them would leak
    the existence of addresses outside a scoped token's reach.

    A PACS host can front several AE Titles. This returns the
    lowest-titled one; the full set is ``GET /dicom/aes?ip_address_id=…``.
    """
    from app.api.v1.ipam.router import _enforce_subnet_token_scope  # noqa: PLC0415

    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(
            status_code=404,
            detail="No DICOM application entity recorded for this IP address",
        )
    _enforce_subnet_token_scope(user, ip.subnet_id)

    ae = (
        (
            await db.execute(
                select(DICOMApplicationEntity)
                .where(DICOMApplicationEntity.ip_address_id == ip_address_id)
                .order_by(DICOMApplicationEntity.ae_title.asc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    if ae is None:
        raise HTTPException(
            status_code=404,
            detail="No DICOM application entity recorded for this IP address",
        )
    return _to_read(ae, ip)


# ── Peer edges ──────────────────────────────────────────────────────


@router.get("/peers", response_model=list[DICOMPeerRead])
async def list_peers(
    db: DB,
    _: CurrentUser,
    ae_id: uuid.UUID | None = Query(
        default=None, description="Restrict to edges touching this AE, in either direction."
    ),
) -> list[DICOMPeerRead]:
    """Every configured AE→AE association, ordered by source then target.

    These are *configured* relationships as documented by the operator or
    imported from the estate's AE table — never associations inferred
    from captured traffic, which would mean parsing DICOM that carries
    PHI.
    """
    source = aliased(DICOMApplicationEntity, name="source_ae")
    target = aliased(DICOMApplicationEntity, name="target_ae")
    stmt = (
        select(DICOMPeer, source.ae_title, target.ae_title)
        .join(source, source.id == DICOMPeer.source_ae_id)
        .join(target, target.id == DICOMPeer.target_ae_id)
        .order_by(source.ae_title.asc(), target.ae_title.asc())
    )
    if ae_id is not None:
        stmt = stmt.where(or_(DICOMPeer.source_ae_id == ae_id, DICOMPeer.target_ae_id == ae_id))
    return [_peer_read(peer, src, dst) for peer, src, dst in (await db.execute(stmt)).all()]


@router.post("/peers", response_model=DICOMPeerRead, status_code=status.HTTP_201_CREATED)
async def create_peer(body: DICOMPeerCreate, db: DB, user: CurrentUser) -> DICOMPeerRead:
    """Document an association from one AE to another."""
    if body.source_ae_id == body.target_ae_id:
        raise HTTPException(
            status_code=422,
            detail="An AE cannot be configured as a peer of itself",
        )
    source_ae = await _get_ae(db, body.source_ae_id)
    target_ae = await _get_ae(db, body.target_ae_id)
    # Snapshot the titles as plain strings *before* the flush. The
    # conflict path rolls back, which expires every ORM instance in the
    # session — touching ``source_ae.ae_title`` afterwards would trigger
    # a lazy refresh from inside the exception handler and raise
    # MissingGreenlet instead of the 409.
    source_title, target_title = source_ae.ae_title, target_ae.ae_title

    row = DICOMPeer(
        source_ae_id=body.source_ae_id,
        target_ae_id=body.target_ae_id,
        services=list(body.services),
        notes=body.notes,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        # ``uq_dicom_peer_pair`` — re-documenting the same association is
        # an update, not a second edge.
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                f"An association from {source_title!r} to "
                f"{target_title!r} is already documented"
            ),
        ) from exc

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dicom_peer",
        resource_id=str(row.id),
        resource_display=f"{source_ae.ae_title} → {target_ae.ae_title}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return _peer_read(row, source_title, target_title)


@router.delete("/peers/{peer_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_peer(peer_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(DICOMPeer, peer_id)
    if row is None:
        raise HTTPException(status_code=404, detail="DICOM peer association not found")
    source_ae = await db.get(DICOMApplicationEntity, row.source_ae_id)
    target_ae = await db.get(DICOMApplicationEntity, row.target_ae_id)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dicom_peer",
        resource_id=str(row.id),
        resource_display=(
            f"{source_ae.ae_title if source_ae else row.source_ae_id} → "
            f"{target_ae.ae_title if target_ae else row.target_ae_id}"
        ),
        old_value={"services": [str(s) for s in (row.services or [])]},
    )
    await db.delete(row)
    await db.commit()


# ── AE-table import ─────────────────────────────────────────────────
#
# Preview and commit take the same request body. The commit re-parses and
# re-plans rather than trusting a plan the client hands back, so a client
# cannot smuggle in an ip_address_id the preview never resolved — the only
# thing that decides what gets written is the CSV plus the column map,
# evaluated server-side both times.


async def _build_plan(db: AsyncSession, user: Any, body: DICOMAEImportRequest) -> list[PlannedRow]:
    # A resource-scoped API token (#374) is bound to specific subnets,
    # but an import addresses rows by AE Title across the whole
    # institution — there is no honest way to scope it row-by-row without
    # silently dropping the operator's data. Refuse the whole call
    # instead; a scoped token can still write AEs one at a time, where
    # the per-address gate applies.
    if _token_subnet_scope(user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Bulk DICOM AE import is not available to a resource-scoped API token",
        )
    if body.space_id is not None and (await db.get(IPSpace, body.space_id)) is None:
        raise HTTPException(status_code=422, detail="space_id not found")
    try:
        parsed = parse_rows(
            body.csv_text,
            column_map=body.column_map.model_dump(exclude_none=True),
            delimiter=body.delimiter,
            default_port=body.default_port,
            default_department=body.default_department,
        )
    except DICOMImportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await plan_import(
        db,
        parsed,
        overwrite_existing=body.overwrite_existing,
        space_id=body.space_id,
    )


def _rows_out(plan: list[PlannedRow]) -> list[DICOMAEImportRow]:
    return [
        DICOMAEImportRow(
            line=row.line,
            ae_title=row.ae_title,
            action=row.action,  # type: ignore[arg-type]
            reason=row.reason,
            address=row.address,
            ip_address_id=row.ip_address_id,
            fields=row.fields,
        )
        for row in plan
    ]


@router.post("/aes/import/preview", response_model=DICOMAEImportPreviewResponse)
async def import_preview(
    body: DICOMAEImportRequest, db: DB, user: CurrentUser
) -> DICOMAEImportPreviewResponse:
    """Parse + plan the CSV without writing anything.

    Returns one row per CSV data row: what would be created, what would
    be updated, what would be skipped, and — per row, with a reason —
    what is unusable. A duplicate AE Title inside the file is reported
    rather than resolved by last-write-wins, because that duplicate is
    the exact collision this registry exists to surface.
    """
    plan = await _build_plan(db, user, body)
    return DICOMAEImportPreviewResponse(
        rows=_rows_out(plan),
        create_count=sum(1 for r in plan if r.action == "create"),
        update_count=sum(1 for r in plan if r.action == "update"),
        skip_count=sum(1 for r in plan if r.action == "skip"),
        error_count=sum(1 for r in plan if r.action == "error"),
    )


@router.post(
    "/aes/import/commit",
    response_model=DICOMAEImportCommitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def import_commit(
    body: DICOMAEImportRequest, db: DB, user: CurrentUser
) -> DICOMAEImportCommitResponse:
    """Apply the import. Valid rows land; invalid rows are reported.

    Deliberately not all-or-nothing at the *row* level — an operator
    migrating an AE table wants the good rows in and the bad ones named.
    It is all-or-nothing at the *transaction* level: one commit, so a
    failure part-way leaves nothing half-applied.

    Audit rows are written per created / updated AE by the importer
    before the commit (non-negotiable #4).
    """
    plan = await _build_plan(db, user, body)
    outcome = await apply_plan(db, plan, user=user)
    await db.commit()
    return DICOMAEImportCommitResponse(
        rows=_rows_out(plan),
        created=outcome.created,
        updated=outcome.updated,
        skipped=outcome.skipped,
        errors=outcome.errors,
        ae_ids=outcome.ae_ids,
    )
