"""AV / Audio-Video-over-IP CRUD — issue #540 (part of #543).

Endpoints under ``/av``:

* ``/reserved-ranges`` — operator-declared per-protocol multicast
  ranges. Full CRUD; this table is what makes the AV conformity
  checks and the allocation guard enforceable rather than folklore.
* ``/flows`` — the AV descriptors, always joined to their parent
  ``MulticastGroup`` so a list row carries the address + IPAM name
  without a second round-trip.
* ``/flows/{group_id}`` — ``PUT`` upserts the descriptor for a group,
  ``DELETE`` removes it. **The group survives either way**: the AV
  identity is a sidecar, so dropping it demotes a Dante flow back to
  a plain multicast group rather than deleting the address record.
  Deleting the *group* is still the multicast router's job.
* ``/allocation-preview`` — read-only "may I put this address here?"
  check against the declared ranges. ``POST`` because the question
  carries a body, not because it writes anything.
* ``/presets`` — protocol vocabulary + well-known default ranges for
  the UI dropdown. No DB access.

Deliberately absent: any device I/O. #540 Phase 1 is a registry
extension of #126 with zero new network traffic — Dante discovery
(mDNS) and the NMOS IS-04 mirror are separate, deferred phases.

Permissions: every endpoint is gated on ``av_flow`` at the router
level (GET → read, POST/PUT → write, DELETE → delete), the same
one-gate-covers-the-family shape the multicast router uses. Note this
puts ``/allocation-preview`` behind ``write`` despite being read-only,
exactly as multicast's ``bulk-allocate/preview`` sits behind ``write``
— a preview is a step in a write workflow, and the alternative would
be an endpoint a read-only user can reach but never act on.

Each mutation writes an ``audit_log`` row before commit per CLAUDE.md
non-negotiable #4.

Server-side validation in this layer:

* ``cidr`` must parse as a network **in canonical prefix form** (host
  bits zeroed — the Postgres ``CIDR`` column rejects them anyway, and
  a clean 422 beats an ``IntegrityError``) and sit inside
  ``224.0.0.0/4`` (IPv4) or ``ff00::/8`` (IPv6), mirroring
  ``ck_av_reserved_range_multicast``.
* ``av_protocol`` / ``seen_via`` are ``Literal`` aliases over the
  model frozensets, re-checked by a ``field_validator``. The alias
  rejects unknown client input before the validator runs, so the
  re-check guards the reverse drift — an alias widened past the
  frozenset — keeping the frozenset authoritative.
* ``ptp_domain`` is bounded to a single octet, mirroring
  ``ck_av_flow_profile_ptp_domain``.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.av import (
    AV_FLOW_SOURCES,
    AV_PROTOCOLS,
    PTP_DOMAIN_MAX,
    PTP_DOMAIN_MIN,
    AVFlowProfile,
    AVReservedRange,
)
from app.models.ipam import IPSpace
from app.models.multicast import MulticastGroup
from app.models.vlans import VLAN
from app.services.api_token_scopes import read_only_post
from app.services.av.ranges import (
    AllocationConflictReport,
    check_allocation_conflict,
    suggest_default_range,
)
from app.services.tags import apply_tag_filter

router = APIRouter(
    tags=["av"],
    dependencies=[Depends(require_resource_permission("av_flow"))],
)

AVProtocol = Literal[
    "dante",
    "aes67",
    "smpte2110_video",
    "smpte2110_audio",
    "smpte2110_anc",
    "ndi",
    "ravenna",
    "other",
]
AVFlowSource = Literal["manual", "mdns", "nmos"]

# Operator-facing names for the protocol ids, in the order an AV
# engineer expects to see them (ecosystems first, then the 2110
# essence split, then the odd ones out) rather than alphabetically.
#
# Not authoritative: ``AV_PROTOCOLS`` in the model is. ``/presets``
# appends any protocol missing from this map with its raw id as the
# label, so adding a protocol to the model can never silently drop it
# out of the UI dropdown.
_PROTOCOL_LABELS: dict[str, str] = {
    "dante": "Dante (Audinate)",
    "aes67": "AES67",
    "ravenna": "RAVENNA",
    "smpte2110_video": "SMPTE ST 2110-20 (video)",
    "smpte2110_audio": "SMPTE ST 2110-30 (audio)",
    "smpte2110_anc": "SMPTE ST 2110-40 (ancillary)",
    "ndi": "NDI",
    "other": "Other / site-specific",
}

# IANA-blessed multicast ranges — a reserved AV range only makes sense
# inside them. The DB CHECK (``ck_av_reserved_range_multicast``)
# enforces the same; validating here turns a 500 on IntegrityError
# into a 422 that says what's wrong.
_IPV4_MULTICAST = ipaddress.IPv4Network("224.0.0.0/4")
_IPV6_MULTICAST = ipaddress.IPv6Network("ff00::/8")


def _validate_reserved_cidr(value: str) -> str:
    """Normalise + range-check an operator-supplied reserved range."""
    text = value.strip()
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        # ``strict=True`` is deliberate: the column is Postgres ``CIDR``,
        # which refuses a value with host bits set. Catching it here
        # means "239.69.0.5/16" produces a message naming the fix
        # instead of a database error page.
        raise ValueError(
            f"cidr must be a network in prefix form with host bits zeroed: {exc}"
        ) from exc
    # ``isinstance`` rather than ``net.version == 4`` so mypy narrows the
    # union — ``subnet_of`` is family-specific and rejects a mismatch.
    if isinstance(net, ipaddress.IPv4Network) and net.subnet_of(_IPV4_MULTICAST):
        return str(net)
    if isinstance(net, ipaddress.IPv6Network) and net.subnet_of(_IPV6_MULTICAST):
        return str(net)
    raise ValueError("cidr must sit inside 224.0.0.0/4 (IPv4) or ff00::/8 (IPv6)")


def _validate_protocol(value: str) -> str:
    if value not in AV_PROTOCOLS:
        raise ValueError(f"av_protocol must be one of {sorted(AV_PROTOCOLS)}")
    return value


# ── Reserved-range schemas ──────────────────────────────────────────


class AVReservedRangeCreate(BaseModel):
    space_id: uuid.UUID
    cidr: str = Field(..., min_length=1, max_length=49)
    av_protocol: AVProtocol
    name: str = Field(default="", max_length=255)
    description: str = ""
    exclusive: bool = True
    vlan_id: uuid.UUID | None = None
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cidr")
    @classmethod
    def _v_cidr(cls, v: str) -> str:
        return _validate_reserved_cidr(v)

    @field_validator("av_protocol")
    @classmethod
    def _v_protocol(cls, v: str) -> str:
        return _validate_protocol(v)


class AVReservedRangeUpdate(BaseModel):
    """Partial update. ``space_id`` is absent on purpose — a range is
    scoped to the multicast space it carves up, and re-homing one is a
    delete + create, not an edit."""

    cidr: str | None = Field(default=None, min_length=1, max_length=49)
    av_protocol: AVProtocol | None = None
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    exclusive: bool | None = None
    vlan_id: uuid.UUID | None = None
    tags: dict[str, Any] | None = None

    @field_validator("cidr")
    @classmethod
    def _v_cidr(cls, v: str | None) -> str | None:
        return None if v is None else _validate_reserved_cidr(v)

    @field_validator("av_protocol")
    @classmethod
    def _v_protocol(cls, v: str | None) -> str | None:
        return None if v is None else _validate_protocol(v)


class AVReservedRangeRead(BaseModel):
    id: uuid.UUID
    space_id: uuid.UUID
    cidr: str
    av_protocol: str
    name: str
    description: str
    exclusive: bool
    vlan_id: uuid.UUID | None
    tags: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    # asyncpg returns CIDR columns as ``ipaddress.IPv4Network`` /
    # ``IPv6Network`` rather than ``str``; coerce so the wire shape
    # matches the declared field type. Same fix the multicast router
    # applies to its INET ``address`` column.
    @field_validator("cidr", mode="before")
    @classmethod
    def _cidr_to_str(cls, v: Any) -> str:
        return str(v) if v is not None else ""


# ── Flow schemas ────────────────────────────────────────────────────


class AVFlowUpsert(BaseModel):
    """The AV identity to stamp onto a multicast group.

    Full-document semantics, not a patch: ``PUT /flows/{group_id}``
    replaces the descriptor wholesale, so an omitted ``ptp_domain``
    clears it. That keeps "the operator blanked the clock domain"
    expressible, which matters because a missing PTP domain is a
    finding the AV conformity checks are meant to surface.
    """

    av_protocol: AVProtocol
    av_flow_label: str = Field(default="", max_length=255)
    ptp_domain: int | None = Field(default=None, ge=PTP_DOMAIN_MIN, le=PTP_DOMAIN_MAX)
    seen_via: AVFlowSource = "manual"
    notes: str = ""
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("av_protocol")
    @classmethod
    def _v_protocol(cls, v: str) -> str:
        return _validate_protocol(v)

    @field_validator("seen_via")
    @classmethod
    def _v_seen_via(cls, v: str) -> str:
        if v not in AV_FLOW_SOURCES:
            raise ValueError(f"seen_via must be one of {sorted(AV_FLOW_SOURCES)}")
        return v


class AVFlowRead(BaseModel):
    """An AV descriptor plus the slice of its group operators identify
    it by. The full group stays fetchable at ``/multicast/groups/{id}``
    — this carries only what a flow list has to render."""

    id: uuid.UUID
    group_id: uuid.UUID
    av_protocol: str
    av_flow_label: str
    ptp_domain: int | None
    seen_via: str
    notes: str
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    # Denormalised from the parent MulticastGroup.
    group_address: str
    group_name: str
    group_application: str
    space_id: uuid.UUID
    vlan_id: uuid.UUID | None


class AVFlowListResponse(BaseModel):
    items: list[AVFlowRead]
    total: int
    limit: int
    offset: int


def _flow_read(profile: AVFlowProfile, group: MulticastGroup) -> AVFlowRead:
    return AVFlowRead(
        id=profile.id,
        group_id=profile.group_id,
        av_protocol=profile.av_protocol,
        av_flow_label=profile.av_flow_label,
        ptp_domain=profile.ptp_domain,
        seen_via=profile.seen_via,
        notes=profile.notes,
        custom_fields=profile.custom_fields,
        created_at=profile.created_at,
        modified_at=profile.modified_at,
        # ``address`` is INET — asyncpg hands back an ipaddress object.
        group_address=str(group.address),
        group_name=group.name,
        group_application=group.application,
        space_id=group.space_id,
        vlan_id=group.vlan_id,
    )


# ── Allocation-preview schemas ──────────────────────────────────────


class AVAllocationPreviewRequest(BaseModel):
    space_id: uuid.UUID
    address_or_cidr: str = Field(..., min_length=1, max_length=49)
    av_protocol: AVProtocol

    @field_validator("av_protocol")
    @classmethod
    def _v_protocol(cls, v: str) -> str:
        return _validate_protocol(v)


class AVReservedRangeMatchRead(BaseModel):
    range_id: uuid.UUID
    cidr: str
    av_protocol: str
    exclusive: bool
    name: str
    # ``inside`` when the proposal sits wholly within the range,
    # ``overlaps`` when it straddles the boundary.
    relation: str


class AVAllocationPreviewResponse(BaseModel):
    space_id: uuid.UUID
    target: str
    av_protocol: str
    # ``ok`` | ``informational`` | ``conflict`` — see
    # app.services.av.ranges for what each verdict means.
    status: str
    conflicts: list[AVReservedRangeMatchRead]
    advisories: list[AVReservedRangeMatchRead]
    own_ranges: list[AVReservedRangeMatchRead]
    outside_declared_range: bool
    suggested_range: str | None
    detail: str


def _preview_response(report: AllocationConflictReport) -> AVAllocationPreviewResponse:
    def _matches(rows: list[Any]) -> list[AVReservedRangeMatchRead]:
        return [
            AVReservedRangeMatchRead(
                range_id=m.range_id,
                cidr=m.cidr,
                av_protocol=m.av_protocol,
                exclusive=m.exclusive,
                name=m.name,
                relation=m.relation,
            )
            for m in rows
        ]

    return AVAllocationPreviewResponse(
        space_id=report.space_id,
        target=report.target,
        av_protocol=report.av_protocol,
        status=report.status,
        conflicts=_matches(report.conflicts),
        advisories=_matches(report.advisories),
        own_ranges=_matches(report.own_ranges),
        outside_declared_range=report.outside_declared_range,
        suggested_range=report.suggested_range,
        detail=report.detail,
    )


# ── Preset schemas ──────────────────────────────────────────────────


class AVProtocolPreset(BaseModel):
    av_protocol: str
    label: str
    # ``None`` where the protocol has no vendor default — SMPTE 2110
    # plants carve their own ranges, which is the whole reason ranges
    # are operator-declared rather than seeded.
    default_cidr: str | None


class AVPresetsResponse(BaseModel):
    protocols: list[AVProtocolPreset]
    flow_sources: list[str]
    ptp_domain_min: int
    ptp_domain_max: int


# ── Helpers ─────────────────────────────────────────────────────────


async def _get_range(db: Any, range_id: uuid.UUID) -> AVReservedRange:
    row = await db.get(AVReservedRange, range_id)
    if row is None:
        raise HTTPException(status_code=404, detail="AV reserved range not found")
    return row


async def _get_group(db: Any, group_id: uuid.UUID) -> MulticastGroup:
    row = await db.get(MulticastGroup, group_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Multicast group not found")
    return row


async def _check_space(db: Any, space_id: uuid.UUID) -> None:
    if (await db.get(IPSpace, space_id)) is None:
        raise HTTPException(status_code=422, detail="space_id not found")


async def _check_vlan(db: Any, vlan_id: uuid.UUID | None) -> None:
    if vlan_id is None:
        return
    if (await db.get(VLAN, vlan_id)) is None:
        raise HTTPException(status_code=422, detail="vlan_id not found")


async def _check_cidr_free(
    db: Any,
    space_id: uuid.UUID,
    cidr: str,
    *,
    exclude_id: uuid.UUID | None = None,
) -> None:
    """Pre-empt ``uq_av_reserved_range_space_cidr``.

    The constraint would fire anyway, but as an opaque 500 on the
    IntegrityError; the operator deserves to be told which range they
    already declared."""
    stmt = select(AVReservedRange.id).where(
        AVReservedRange.space_id == space_id,
        AVReservedRange.cidr == cidr,
    )
    if exclude_id is not None:
        stmt = stmt.where(AVReservedRange.id != exclude_id)
    if (await db.execute(stmt)).first() is not None:
        raise HTTPException(
            status_code=409,
            detail=f"{cidr} is already declared as a reserved range in this IPSpace",
        )


# ── Reserved-range endpoints ────────────────────────────────────────


@router.get("/reserved-ranges", response_model=list[AVReservedRangeRead])
async def list_reserved_ranges(
    db: DB,
    _: CurrentUser,
    space_id: uuid.UUID | None = Query(default=None),
    av_protocol: str | None = Query(
        default=None, description="Exact protocol id; see GET /av/presets."
    ),
    vlan_id: uuid.UUID | None = Query(default=None),
    exclusive: bool | None = Query(
        default=None,
        description="Filter to exclusive (true) or shared (false) ranges.",
    ),
    tag: list[str] = Query(default_factory=list),
) -> list[AVReservedRangeRead]:
    """List declared AV ranges.

    Unpaginated by design: this table is operator-authored address-plan
    documentation — single digits per space in practice, a few dozen in
    a large 2110 plant — and every consumer (the range editor, the
    allocation guard, the conformity checks) wants all of them.
    """
    if av_protocol is not None and av_protocol not in AV_PROTOCOLS:
        raise HTTPException(
            status_code=422,
            detail=f"av_protocol must be one of {sorted(AV_PROTOCOLS)}",
        )
    stmt = select(AVReservedRange)
    if space_id is not None:
        stmt = stmt.where(AVReservedRange.space_id == space_id)
    if av_protocol is not None:
        stmt = stmt.where(AVReservedRange.av_protocol == av_protocol)
    if vlan_id is not None:
        stmt = stmt.where(AVReservedRange.vlan_id == vlan_id)
    if exclusive is not None:
        stmt = stmt.where(AVReservedRange.exclusive.is_(exclusive))
    stmt = apply_tag_filter(stmt, AVReservedRange.tags, tag)

    rows = (await db.execute(stmt.order_by(AVReservedRange.cidr.asc()))).scalars().all()
    return [AVReservedRangeRead.model_validate(r) for r in rows]


@router.post(
    "/reserved-ranges",
    response_model=AVReservedRangeRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_reserved_range(
    body: AVReservedRangeCreate, db: DB, user: CurrentUser
) -> AVReservedRangeRead:
    """Declare a multicast range as belonging to an AV protocol.

    Overlap with an existing declaration is *not* refused: nesting is
    the normal shape (a Dante ``239.69.0.0/16`` carve-out inside an
    AES67 ``239.0.0.0/8``), and longest-prefix wins at resolution time.
    Only an exact duplicate CIDR in the same space is rejected.
    """
    await _check_space(db, body.space_id)
    await _check_vlan(db, body.vlan_id)
    await _check_cidr_free(db, body.space_id, body.cidr)

    row = AVReservedRange(
        space_id=body.space_id,
        cidr=body.cidr,
        av_protocol=body.av_protocol,
        name=body.name,
        description=body.description,
        exclusive=body.exclusive,
        vlan_id=body.vlan_id,
        tags=body.tags or {},
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="av_reserved_range",
        resource_id=str(row.id),
        resource_display=f"{body.av_protocol} {body.cidr}",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return AVReservedRangeRead.model_validate(row)


@router.get("/reserved-ranges/{range_id:uuid}", response_model=AVReservedRangeRead)
async def get_reserved_range(range_id: uuid.UUID, db: DB, _: CurrentUser) -> AVReservedRangeRead:
    row = await _get_range(db, range_id)
    return AVReservedRangeRead.model_validate(row)


@router.put("/reserved-ranges/{range_id:uuid}", response_model=AVReservedRangeRead)
async def update_reserved_range(
    range_id: uuid.UUID, body: AVReservedRangeUpdate, db: DB, user: CurrentUser
) -> AVReservedRangeRead:
    row = await _get_range(db, range_id)
    display_before = f"{row.av_protocol} {row.cidr}"

    changes = body.model_dump(exclude_unset=True)
    if "vlan_id" in changes:
        await _check_vlan(db, changes["vlan_id"])
    if "cidr" in changes and changes["cidr"] is not None:
        await _check_cidr_free(db, row.space_id, changes["cidr"], exclude_id=row.id)
    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="av_reserved_range",
        resource_id=str(row.id),
        resource_display=display_before,
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return AVReservedRangeRead.model_validate(row)


@router.delete("/reserved-ranges/{range_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_reserved_range(range_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Undeclare a range. Nothing cascades — the range is documentation
    about an address plan, so the groups and flows living inside it are
    untouched. They simply stop being checkable against it."""
    row = await _get_range(db, range_id)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="av_reserved_range",
        resource_id=str(row.id),
        resource_display=f"{row.av_protocol} {row.cidr}",
    )
    await db.delete(row)
    await db.commit()


# ── Flow endpoints ──────────────────────────────────────────────────


@router.get("/flows", response_model=AVFlowListResponse)
async def list_flows(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    av_protocol: str | None = Query(
        default=None, description="Exact protocol id; see GET /av/presets."
    ),
    ptp_domain: int | None = Query(default=None, ge=PTP_DOMAIN_MIN, le=PTP_DOMAIN_MAX),
    space_id: uuid.UUID | None = Query(
        default=None, description="Filter by the parent group's IPSpace."
    ),
    vlan_id: uuid.UUID | None = Query(
        default=None, description="Filter by the parent group's VLAN."
    ),
    q: str | None = Query(
        default=None,
        description=(
            "Case-insensitive substring on the AV flow label or the parent "
            "group's IPAM name — an operator searching 'Cam7' may know the "
            "stream by either."
        ),
    ),
) -> AVFlowListResponse:
    """List AV flow descriptors joined to their multicast groups.

    Ordered by group address so the list reads like the address plan
    it documents.
    """
    if av_protocol is not None and av_protocol not in AV_PROTOCOLS:
        raise HTTPException(
            status_code=422,
            detail=f"av_protocol must be one of {sorted(AV_PROTOCOLS)}",
        )

    stmt = select(AVFlowProfile, MulticastGroup).join(
        MulticastGroup, AVFlowProfile.group_id == MulticastGroup.id
    )
    if av_protocol is not None:
        stmt = stmt.where(AVFlowProfile.av_protocol == av_protocol)
    if ptp_domain is not None:
        stmt = stmt.where(AVFlowProfile.ptp_domain == ptp_domain)
    if space_id is not None:
        stmt = stmt.where(MulticastGroup.space_id == space_id)
    if vlan_id is not None:
        stmt = stmt.where(MulticastGroup.vlan_id == vlan_id)
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                AVFlowProfile.av_flow_label.ilike(needle),
                MulticastGroup.name.ilike(needle),
            )
        )

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = stmt.order_by(MulticastGroup.address.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).all()
    return AVFlowListResponse(
        items=[_flow_read(profile, group) for profile, group in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.put("/flows/{group_id:uuid}", response_model=AVFlowRead)
async def upsert_flow(
    group_id: uuid.UUID, body: AVFlowUpsert, db: DB, user: CurrentUser
) -> AVFlowRead:
    """Stamp (or restamp) the AV identity of a multicast group.

    Keyed on ``group_id`` rather than the profile id because that is
    what the caller has: the operator is looking at a group and saying
    "this is a Dante flow". ``uq_av_flow_profile_group`` guarantees
    there is at most one row to find, so the upsert is a plain
    load-or-create with no race window beyond the usual transaction.

    Returns 200 on both create and update — a PUT to a known URL is
    idempotent, and the caller can tell which happened from
    ``created_at`` vs ``modified_at`` if it cares.
    """
    group = await _get_group(db, group_id)
    row = (
        await db.execute(select(AVFlowProfile).where(AVFlowProfile.group_id == group_id))
    ).scalar_one_or_none()

    action = "update" if row is not None else "create"
    if row is None:
        row = AVFlowProfile(group_id=group_id)
        db.add(row)
    row.av_protocol = body.av_protocol
    row.av_flow_label = body.av_flow_label
    row.ptp_domain = body.ptp_domain
    row.seen_via = body.seen_via
    row.notes = body.notes
    row.custom_fields = body.custom_fields or {}
    await db.flush()

    write_audit(
        db,
        user=user,
        action=action,
        resource_type="av_flow_profile",
        resource_id=str(row.id),
        resource_display=f"{body.av_flow_label or body.av_protocol} ({group.address})",
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return _flow_read(row, group)


@router.delete("/flows/{group_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_flow(group_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    """Drop the AV identity, keep the group.

    The descriptor is a sidecar: removing it demotes the row back to a
    plain multicast group rather than deleting the address record. A
    404 here means "this group has no AV descriptor" (or no such
    group) — both are "nothing to remove"."""
    row = (
        await db.execute(select(AVFlowProfile).where(AVFlowProfile.group_id == group_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="AV flow profile not found for this group")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="av_flow_profile",
        resource_id=str(row.id),
        resource_display=f"{row.av_flow_label or row.av_protocol} (group {group_id})",
    )
    await db.delete(row)
    await db.commit()


# ── Allocation preview + presets ────────────────────────────────────


@router.post("/allocation-preview", response_model=AVAllocationPreviewResponse)
@read_only_post
async def allocation_preview(
    body: AVAllocationPreviewRequest, db: DB, _: CurrentUser
) -> AVAllocationPreviewResponse:
    """Would this allocation step on another protocol's reserved range?

    The widened collision guard from #540. Plain IPAM can only tell an
    operator that an address is unused, which is the wrong question in
    an AoIP plant: the Dante auto-assign pool is "free" right up until
    Dante tries to use it.

    Read-only — nothing is written, no row is reserved, and calling it
    twice is identical to calling it once. The UI runs this before
    creating a multicast group so the operator sees the verdict while
    they can still change the address.
    """
    await _check_space(db, body.space_id)
    try:
        report = await check_allocation_conflict(
            db, body.space_id, body.address_or_cidr, body.av_protocol
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"address_or_cidr must be an IP literal or CIDR: {exc}",
        ) from exc
    return _preview_response(report)


@router.get("/presets", response_model=AVPresetsResponse)
async def list_presets(_: CurrentUser) -> AVPresetsResponse:
    """Protocol vocabulary + well-known default ranges for the UI.

    Served from the model constants rather than hardcoded in the
    frontend so a protocol added to ``AV_PROTOCOLS`` shows up in the
    dropdown without a frontend release. Protocols with no vendor
    default return ``default_cidr: null`` — that is the honest answer
    for SMPTE 2110 and NDI, not a gap.

    No DB access; the response is a pure function of the model
    constants.
    """
    ordered = [p for p in _PROTOCOL_LABELS if p in AV_PROTOCOLS]
    # Anything the model knows about but the label map doesn't, so a
    # future protocol can never silently vanish from the dropdown.
    ordered += sorted(AV_PROTOCOLS - set(ordered))
    return AVPresetsResponse(
        protocols=[
            AVProtocolPreset(
                av_protocol=p,
                label=_PROTOCOL_LABELS.get(p, p),
                default_cidr=suggest_default_range(p),
            )
            for p in ordered
        ],
        flow_sources=sorted(AV_FLOW_SOURCES),
        ptp_domain_min=PTP_DOMAIN_MIN,
        ptp_domain_max=PTP_DOMAIN_MAX,
    )
