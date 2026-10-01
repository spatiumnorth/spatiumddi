"""E911 Location Information Server — ERLs, bindings, and the lookup (#972).

Endpoints under ``/e911``:

* ``/erls`` — Emergency Response Location list / create
* ``/erls/{id}`` — read / patch / delete
* ``/erls/{id}/validation`` — record an address-validation verdict
* ``/bindings`` — network identity → ERL rules, list / create
* ``/bindings/{id}`` — patch / delete
* ``/location`` — **the point of the feature.** Given an IP, MAC, or LLDP
  chassis+port, return the dispatchable location with its provenance.

Permissions: every endpoint is gated on ``e911_location`` at the router
level (GET→read, POST/PATCH→write, DELETE→delete; superadmin always
passes). The intended shape for a third-party caller — a PBX, Cisco
Emergency Responder, RedSky, an ops script — is an existing API token
(#74) scoped to ``allowed_paths=["/api/v1/e911"]`` with that one read
permission: read-only, revocable, audited, and no new credential
mechanism.

**Every ``/location`` answer writes an ``e911_resolution_log`` row.** It
is a lookup of which desk a named person sits at; the trail is not
optional. Mutations additionally write ``audit_log`` per non-negotiable
#4.

**We are not the 911 service provider.** Nothing here routes a call,
uploads to an ALI database, provisions an ELIN, or talks to a PSAP. The
operator's duty under 47 CFR §9.16 is theirs.

**Address validation is recorded, never asserted.** ``POST
/erls/{id}/validation`` stores a verdict the operator obtained from their
E911 provider (RedSky, Intrado and Bandwidth all expose a validation call
against the MSAG / NG911 LVF). SpatiumDDI makes no outbound call here —
that is a separate PR precisely because it would be a new outbound
connection under non-negotiable #17 and needs a ``docs/PRIVACY.md`` row.
Marking an address valid on our own say-so is the one thing that would
make this feature actively dangerous.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, ValidationInfo, field_validator, model_validator
from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.content_disposition import content_disposition
from app.core.mac import canonicalize_mac
from app.core.permissions import require_resource_permission
from app.core.responses import CsvResponse, IosConfigResponse
from app.models.e911 import (
    CIVIC_COLUMNS,
    DISPATCHABLE_DETAIL_COLUMNS,
    ERL_RULE_PRECEDENCE,
    ERL_RULE_TARGET_COLUMN,
    E911ResolutionLog,
    EmergencyResponseLocation,
    ERLBinding,
)
from app.models.network import NetworkDevice, NetworkInterface
from app.services.e911.exports import render_csv, render_ios_snippets
from app.services.e911.resolver import Resolution, resolve_location
from app.services.search.ranking import escape_like

router = APIRouter(
    tags=["e911"],
    dependencies=[Depends(require_resource_permission("e911_location"))],
)

RuleKind = Literal["switch_port", "wireless_ap", "mac", "ip", "subnet", "vlan", "site_default"]
ValidationState = Literal["unvalidated", "validated", "rejected"]

#: The resource_type used in ``audit_log`` rows for both tables. One
#: string, because an operator auditing "who changed our dispatchable
#: locations" wants ERLs and the bindings that point at them together.
AUDIT_RESOURCE = "e911"


# ══════════════════════════════════════════════════════════════════════
# Schemas
# ══════════════════════════════════════════════════════════════════════


class CivicAddress(BaseModel):
    """The RFC 5139 civic-address elements.

    Declared explicitly rather than generated from ``CIVIC_ELEMENTS``: a
    ``pydantic.create_model`` would keep one source of truth but costs the
    readability of the most-reviewed schema in the feature. The single
    source of truth is enforced by a test instead
    (``test_e911_schema_covers_every_civic_element``), which is this
    repository's own idiom — a guard over cleverness.
    """

    country: str | None = Field(default=None, max_length=2, description="ISO 3166-1 alpha-2")
    a1: str | None = Field(default=None, max_length=255, description="State / province")
    a2: str | None = Field(default=None, max_length=255, description="County")
    a3: str | None = Field(default=None, max_length=255, description="City")
    a4: str | None = Field(default=None, max_length=255, description="City division")
    a5: str | None = Field(default=None, max_length=255, description="Neighbourhood")
    a6: str | None = Field(default=None, max_length=255, description="Street (legacy; prefer rd)")
    prd: str | None = Field(default=None, max_length=64, description="Leading street direction")
    pod: str | None = Field(default=None, max_length=64, description="Trailing street suffix")
    sts: str | None = Field(default=None, max_length=64, description="Street suffix / type")
    hno: str | None = Field(default=None, max_length=64, description="House number")
    hns: str | None = Field(default=None, max_length=64, description="House number suffix")
    lmk: str | None = Field(default=None, max_length=255, description="Landmark")
    loc: str | None = Field(default=None, max_length=255, description="Additional location info")
    nam: str | None = Field(default=None, max_length=255, description="Occupant / business name")
    pc: str | None = Field(default=None, max_length=32, description="Postal code")
    bld: str | None = Field(default=None, max_length=255, description="Building")
    unit: str | None = Field(default=None, max_length=64, description="Unit / suite")
    flr: str | None = Field(default=None, max_length=64, description="Floor")
    room: str | None = Field(default=None, max_length=64, description="Room")
    plc: str | None = Field(default=None, max_length=64, description="Place type")
    pcn: str | None = Field(default=None, max_length=255, description="Postal community name")
    pobox: str | None = Field(default=None, max_length=64, description="Post office box")
    addcode: str | None = Field(default=None, max_length=64, description="Additional code")
    seat: str | None = Field(default=None, max_length=64, description="Seat / desk")
    rd: str | None = Field(default=None, max_length=255, description="Primary road name")
    rdsec: str | None = Field(default=None, max_length=255, description="Road section")
    rdbr: str | None = Field(default=None, max_length=255, description="Road branch")
    rdsubbr: str | None = Field(default=None, max_length=255, description="Road sub-branch")
    prm: str | None = Field(default=None, max_length=64, description="Road pre-modifier")
    pom: str | None = Field(default=None, max_length=64, description="Road post-modifier")


class GeoPoint(BaseModel):
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    altitude: float | None = None
    altitude_unit: Literal["m", "f"] | None = Field(
        default=None, description="RFC 6225 altitude type: metres or floors"
    )

    @model_validator(mode="after")
    def _point_is_complete(self) -> GeoPoint:
        # Mirrors ``ck_erl_point_is_complete``. A half-point is not a
        # coarse location, it is a wrong one — and a 422 naming the field
        # beats a 500 from the CHECK.
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be given together, or neither")
        return self


def _clean_elins(v: list[str]) -> list[str]:
    """Normalise an ELIN list, refusing only obvious junk.

    Deliberately permissive: an ELIN is a DID in whatever form the
    operator's carrier wrote it on the PS-ALI paperwork, and refusing an
    extension-style short number would reject a real configuration.

    A module-level function rather than a classmethod shared through
    ``__func__``, so both the create and the update body get the same rule
    without a binding trick that would break quietly.
    """
    out: list[str] = []
    for raw in v:
        e = raw.strip()
        if not e:
            continue
        if len(e) > 32 or not any(c.isdigit() for c in e):
            raise ValueError(f"{raw!r} does not look like a dialable number")
        out.append(e)
    return out


class ERLCreate(CivicAddress, GeoPoint):
    name: str = Field(min_length=1, max_length=255)
    site_id: uuid.UUID | None = None
    elins: list[str] = Field(default_factory=list)
    is_active: bool = True
    notes: str = ""

    @field_validator("elins")
    @classmethod
    def _check_elins(cls, v: list[str]) -> list[str]:
        return _clean_elins(v)


class ERLUpdate(CivicAddress, GeoPoint):
    """PATCH body. ``exclude_unset`` means an absent key is left alone.

    An explicit ``null`` is a different thing from an absent key and must
    not reach a NOT NULL column: without the validator below,
    ``{"name": null}`` set the column to None and surfaced as a bogus 409
    "that name is already taken", and ``{"is_active": null}`` 500'd. This is
    the #700 ``exclude_unset``-plus-explicit-null shape. A null on a
    *nullable* civic element still clears it, which is how an operator
    corrects a wrong floor.
    """

    name: str | None = Field(default=None, min_length=1, max_length=255)
    site_id: uuid.UUID | None = None
    elins: list[str] | None = None
    is_active: bool | None = None
    notes: str | None = None

    @field_validator("name", "elins", "is_active", "notes")
    @classmethod
    def _no_explicit_null(cls, v: object, info: ValidationInfo) -> object:
        if v is None:
            raise ValueError(
                f"{info.field_name} cannot be null — omit the key to leave it unchanged"
            )
        return v

    @field_validator("elins")
    @classmethod
    def _check_elins(cls, v: list[str] | None) -> list[str] | None:
        # Same rule as ERLCreate. The create path validating and the update
        # path not is how a list nobody checked reaches the column.
        return None if v is None else _clean_elins(v)


class ERLRead(CivicAddress, GeoPoint):
    id: uuid.UUID
    name: str
    site_id: uuid.UUID | None
    elins: list[str]
    validation_state: ValidationState
    validated_at: datetime | None
    validation_source: str | None
    validation_detail: str | None
    #: Does this ERL say anything beyond the street door? RAY BAUM'S asks
    #: for "room number, floor number, or similar"; an ERL carrying none of
    #: those is an address, not a dispatchable location. Derived, so it
    #: cannot drift from the columns.
    is_dispatchable: bool
    is_active: bool
    notes: str
    binding_count: int
    created_at: datetime
    modified_at: datetime


class ERLListResponse(BaseModel):
    items: list[ERLRead]
    total: int
    limit: int
    offset: int


class ValidationVerdict(BaseModel):
    """A verdict obtained from the operator's E911 provider, recorded here.

    ``source`` is free text because it names whoever answered — a provider
    product name, a ticket reference, or the 911 coordinator who checked it
    against the MSAG by hand.
    """

    state: ValidationState
    source: str | None = Field(default=None, max_length=64)
    detail: str | None = None


class BindingCreate(BaseModel):
    erl_id: uuid.UUID
    rule_kind: RuleKind
    network_interface_id: uuid.UUID | None = None
    bssid: str | None = Field(default=None, max_length=64)
    subnet_id: uuid.UUID | None = None
    vlan_ref_id: uuid.UUID | None = None
    mac_address: str | None = None
    ip_address_id: uuid.UUID | None = None
    site_id: uuid.UUID | None = None
    is_active: bool = True
    notes: str = ""

    @field_validator("mac_address")
    @classmethod
    def _canon_mac(cls, v: str | None) -> str | None:
        return canonicalize_mac(v) if v else None

    @model_validator(mode="after")
    def _exactly_the_right_target(self) -> BindingCreate:
        """Mirror the two DB CHECKs, so a wrong shape is a 422 naming the
        field rather than a 500 out of Postgres.

        The "exactly one" half alone is not enough: a ``subnet`` rule
        carrying a ``mac_address`` satisfies it and then matches nothing,
        and a rule that silently matches nothing is worse than a refused
        one.
        """
        wanted = ERL_RULE_TARGET_COLUMN[self.rule_kind]
        present = [c for c in ERL_RULE_TARGET_COLUMN.values() if getattr(self, c) is not None]
        if present != [wanted]:
            got = ", ".join(sorted(present)) or "none"
            raise ValueError(
                f"rule_kind {self.rule_kind!r} needs exactly {wanted} set (got: {got})"
            )
        return self


class BindingUpdate(BaseModel):
    """Only the mutable fields. A binding's target and kind are its
    identity — repointing one would silently move every device it covers,
    so that is a delete and a create, which leaves two audit rows."""

    erl_id: uuid.UUID | None = None
    is_active: bool | None = None
    notes: str | None = None

    @field_validator("erl_id", "is_active", "notes")
    @classmethod
    def _no_explicit_null(cls, v: object, info: ValidationInfo) -> object:
        # Same reason as ERLUpdate: `is_active` and `notes` are NOT NULL, so
        # an explicit null is a 23502 the #922 handler deliberately re-raises
        # — a 500 for what is plainly a client error.
        if v is None:
            raise ValueError(
                f"{info.field_name} cannot be null — omit the key to leave it unchanged"
            )
        return v


class BindingRead(BaseModel):
    id: uuid.UUID
    erl_id: uuid.UUID
    erl_name: str
    rule_kind: RuleKind
    #: Which precedence level this rule sits at, 1 = most specific. Sent
    #: because the ordering is fixed in code and an operator reading a list
    #: of bindings otherwise has no way to see which one would win.
    precedence: int
    network_interface_id: uuid.UUID | None
    bssid: str | None
    subnet_id: uuid.UUID | None
    vlan_ref_id: uuid.UUID | None
    mac_address: str | None
    ip_address_id: uuid.UUID | None
    site_id: uuid.UUID | None
    is_active: bool
    notes: str
    created_at: datetime
    modified_at: datetime


class BindingListResponse(BaseModel):
    items: list[BindingRead]
    total: int
    limit: int
    offset: int


class EvidenceRead(BaseModel):
    kind: str
    observed_at: datetime | None
    age_seconds: int | None
    window_seconds: int | None
    stale: bool
    detail: str


class LocationResponse(BaseModel):
    """A dispatchable location, and why we believe it.

    ``erl`` is null when nothing matched. There is deliberately no shape in
    which this returns an address with no provenance: ``rule_matched`` and
    ``confidence`` are always present, and ``confidence="degraded"`` means
    a more precise answer existed and was REFUSED because its evidence was
    stale — see ``degraded_reason``.
    """

    identity_kind: str
    identity_value: str
    found: bool
    confidence: Literal["none", "degraded", "observed"]
    rule_matched: RuleKind | None
    degraded_reason: str | None
    observed_at: datetime | None
    evidence_age_seconds: int | None
    erl: ERLRead | None
    evidence: list[EvidenceRead]


# ══════════════════════════════════════════════════════════════════════
# Serialisation
# ══════════════════════════════════════════════════════════════════════


def _is_dispatchable(row: EmergencyResponseLocation) -> bool:
    return any(getattr(row, c) for c in DISPATCHABLE_DETAIL_COLUMNS)


def _erl_read(row: EmergencyResponseLocation, binding_count: int = 0) -> ERLRead:
    civic = {c: getattr(row, c) for c in CIVIC_COLUMNS}
    return ERLRead(
        id=row.id,
        name=row.name,
        site_id=row.site_id,
        elins=list(row.elins or []),
        latitude=float(row.latitude) if row.latitude is not None else None,
        longitude=float(row.longitude) if row.longitude is not None else None,
        altitude=float(row.altitude) if row.altitude is not None else None,
        altitude_unit=row.altitude_unit,  # type: ignore[arg-type]
        validation_state=row.validation_state,  # type: ignore[arg-type]
        validated_at=row.validated_at,
        validation_source=row.validation_source,
        validation_detail=row.validation_detail,
        is_dispatchable=_is_dispatchable(row),
        is_active=row.is_active,
        notes=row.notes,
        binding_count=binding_count,
        created_at=row.created_at,
        modified_at=row.modified_at,
        **civic,
    )


def _binding_read(row: ERLBinding, erl_name: str) -> BindingRead:
    return BindingRead(
        id=row.id,
        erl_id=row.erl_id,
        erl_name=erl_name,
        rule_kind=row.rule_kind,  # type: ignore[arg-type]
        precedence=ERL_RULE_PRECEDENCE.index(row.rule_kind) + 1,
        network_interface_id=row.network_interface_id,
        bssid=row.bssid,
        subnet_id=row.subnet_id,
        vlan_ref_id=row.vlan_ref_id,
        mac_address=str(row.mac_address) if row.mac_address else None,
        ip_address_id=row.ip_address_id,
        site_id=row.site_id,
        is_active=row.is_active,
        notes=row.notes,
        created_at=row.created_at,
        modified_at=row.modified_at,
    )


def _is_unique_violation(exc: IntegrityError) -> bool:
    """True only for a 23505 unique violation.

    Everything else — above all 23503, a foreign key naming a target that
    does not exist — must propagate to the #922 global handler, which
    classifies it against the values the request actually carried and
    answers 422 or 409 accordingly. A blanket ``except IntegrityError``
    reported every one of them as "already exists", which on
    ``create_binding`` is the likeliest failure of all: five of its seven
    targets are UUIDs an operator pastes by hand.

    ``exc.orig`` is SQLAlchemy's asyncpg wrapper, which re-exports
    ``sqlstate`` — unlike ``detail``, which hangs off ``__cause__`` (the
    trap #922 documents).
    """
    return getattr(exc.orig, "sqlstate", None) == "23505"


async def _load_erl(db: AsyncSession, erl_id: uuid.UUID) -> EmergencyResponseLocation:
    row = (
        await db.execute(
            select(EmergencyResponseLocation).where(EmergencyResponseLocation.id == erl_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ERL not found")
    return row


async def _binding_counts(db: AsyncSession, erl_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    """One query for the whole page. Counting per row would be the N+1 the
    #917 sweep found in the vendor-device lookup."""
    if not erl_ids:
        return {}
    rows = (
        await db.execute(
            select(ERLBinding.erl_id, func.count(ERLBinding.id))
            .where(ERLBinding.erl_id.in_(erl_ids))
            .group_by(ERLBinding.erl_id)
        )
    ).all()
    return {erl_id: int(n) for erl_id, n in rows}


# ══════════════════════════════════════════════════════════════════════
# ERLs
# ══════════════════════════════════════════════════════════════════════


def _apply_erl_filters(
    stmt: Select[Any],
    *,
    site_id: uuid.UUID | None,
    validation_state: str | None,
    is_active: bool | None,
    dispatchable: bool | None,
    q: str | None,
) -> Select[Any]:
    if site_id is not None:
        stmt = stmt.where(EmergencyResponseLocation.site_id == site_id)
    if validation_state is not None:
        stmt = stmt.where(EmergencyResponseLocation.validation_state == validation_state)
    if is_active is not None:
        stmt = stmt.where(EmergencyResponseLocation.is_active.is_(is_active))
    if dispatchable is not None:
        # `!= ""` as well as `IS NOT NULL`: the Python side tests
        # truthiness, so an empty string counted as absent there and present
        # here — the serialised `is_dispatchable` then contradicted the
        # filter, and the RAY BAUM'S gap report under-counted. The API
        # converts "" to NULL on write; this covers rows that predate it or
        # arrived another way.
        detail = or_(
            *[
                and_(
                    getattr(EmergencyResponseLocation, c).is_not(None),
                    getattr(EmergencyResponseLocation, c) != "",
                )
                for c in DISPATCHABLE_DETAIL_COLUMNS
            ]
        )
        stmt = stmt.where(detail if dispatchable else ~detail)
    if q:
        # escape_like, or a needle of `50%` matches every row — #879.
        like = f"%{escape_like(q)}%"
        stmt = stmt.where(
            or_(
                EmergencyResponseLocation.name.ilike(like),
                EmergencyResponseLocation.bld.ilike(like),
                EmergencyResponseLocation.flr.ilike(like),
                EmergencyResponseLocation.room.ilike(like),
                EmergencyResponseLocation.rd.ilike(like),
                EmergencyResponseLocation.a3.ilike(like),
            )
        )
    return stmt


@router.get("/erls", response_model=ERLListResponse)
async def list_erls(
    db: DB,
    user: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    site_id: uuid.UUID | None = Query(default=None),
    validation_state: ValidationState | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    dispatchable: bool | None = Query(
        default=None,
        description=(
            "True = only ERLs carrying detail beyond the street door (building, "
            "floor, unit, room, seat or additional location info). False = only "
            "the street-address-only ones, which is the RAY BAUM'S gap."
        ),
    ),
    q: str | None = Query(
        default=None, description="Substring on name / building / floor / room / street / city."
    ),
) -> ERLListResponse:
    """List Emergency Response Locations, name order."""
    # Annotated dict[str, Any] so the ``**filters`` splat type-checks — the
    # same shape the DICOM list route uses.
    filters: dict[str, Any] = {
        "site_id": site_id,
        "validation_state": validation_state,
        "is_active": is_active,
        "dispatchable": dispatchable,
        "q": q,
    }
    total = (
        await db.execute(
            _apply_erl_filters(select(func.count(EmergencyResponseLocation.id)), **filters)
        )
    ).scalar_one()
    rows = (
        (
            await db.execute(
                _apply_erl_filters(select(EmergencyResponseLocation), **filters)
                .order_by(EmergencyResponseLocation.name.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    counts = await _binding_counts(db, [r.id for r in rows])
    return ERLListResponse(
        items=[_erl_read(r, counts.get(r.id, 0)) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("/erls", response_model=ERLRead, status_code=status.HTTP_201_CREATED)
async def create_erl(body: ERLCreate, db: DB, user: CurrentUser) -> ERLRead:
    row = EmergencyResponseLocation(**body.model_dump())
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        if not _is_unique_violation(exc):
            raise
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An ERL named {body.name!r} already exists",
        ) from exc
    write_audit(
        db,
        user=user,
        action="create",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={"name": row.name, "site_id": str(row.site_id) if row.site_id else None},
    )
    await db.commit()
    await db.refresh(row)
    return _erl_read(row)


@router.get("/erls/{erl_id}", response_model=ERLRead)
async def get_erl(erl_id: uuid.UUID, db: DB, user: CurrentUser) -> ERLRead:
    row = await _load_erl(db, erl_id)
    counts = await _binding_counts(db, [row.id])
    return _erl_read(row, counts.get(row.id, 0))


@router.patch("/erls/{erl_id}", response_model=ERLRead)
async def update_erl(erl_id: uuid.UUID, body: ERLUpdate, db: DB, user: CurrentUser) -> ERLRead:
    row = await _load_erl(db, erl_id)
    # exclude_unset, so PATCHing one field does not null the other 40 —
    # and an explicit null still clears a nullable civic element, which is
    # how an operator corrects a wrong floor.
    changes = body.model_dump(exclude_unset=True)
    old = {k: getattr(row, k) for k in changes}

    # Which civic elements actually MOVED. Keyed on the value and not on the
    # key being present, because the edit form sends all 31 elements on
    # every save — so a presence test would throw away a provider's verdict
    # for a rename or a notes tweak, which is both wrong and invisible.
    civic_changed = [
        k for k in changes if k in CIVIC_COLUMNS and (changes[k] or None) != (old[k] or None)
    ]

    for field, value in changes.items():
        setattr(row, field, value)

    # A real address edit invalidates a provider's verdict about the OLD
    # address. Silently keeping `validated` would leave the estate reporting
    # a validated address nobody has ever checked — and the
    # e911_erl_validated conformity check would stay quiet about it.
    if civic_changed and row.validation_state != "unvalidated":
        row.validation_state = "unvalidated"
        row.validated_at = None
        # Cleared too. Leaving it made the list render "unvalidated  RedSky
        # Horizon", which reads as a provider that validated THIS address.
        row.validation_source = None
        row.validation_detail = (
            "reset: " + ", ".join(sorted(civic_changed)) + " changed after validation"
        )
        changes["validation_state"] = "unvalidated"

    try:
        await db.flush()
    except IntegrityError as exc:
        if not _is_unique_violation(exc):
            raise
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="That ERL name is already taken"
        ) from exc
    write_audit(
        db,
        user=user,
        action="update",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=sorted(changes),
        old_value={k: str(v) for k, v in old.items()},
        new_value={k: str(v) for k, v in changes.items()},
    )
    await db.commit()
    await db.refresh(row)
    return _erl_read(row)


@router.post("/erls/{erl_id}/validation", response_model=ERLRead)
async def record_validation(
    erl_id: uuid.UUID, body: ValidationVerdict, db: DB, user: CurrentUser
) -> ERLRead:
    """Record an address-validation verdict obtained from the provider.

    SpatiumDDI makes no outbound call here and never decides this itself.
    """
    row = await _load_erl(db, erl_id)
    row.validation_state = body.state
    row.validation_source = body.source
    row.validation_detail = body.detail
    row.validated_at = datetime.now(UTC) if body.state != "unvalidated" else None
    write_audit(
        db,
        user=user,
        action="update",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=["validation_state"],
        new_value={"validation_state": body.state, "validation_source": body.source or ""},
    )
    await db.commit()
    await db.refresh(row)
    return _erl_read(row)


@router.delete("/erls/{erl_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_erl(erl_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await _load_erl(db, erl_id)
    counts = await _binding_counts(db, [row.id])
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=row.name,
        old_value={"name": row.name, "bindings_removed": str(counts.get(row.id, 0))},
    )
    # Bindings CASCADE. That fails safe: the resolver then degrades to the
    # next-coarser rule rather than pointing at a location that is gone.
    await db.delete(row)
    await db.commit()


# ══════════════════════════════════════════════════════════════════════
# Bindings
# ══════════════════════════════════════════════════════════════════════


@router.get("/bindings", response_model=BindingListResponse)
async def list_bindings(
    db: DB,
    user: CurrentUser,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    erl_id: uuid.UUID | None = Query(default=None),
    rule_kind: RuleKind | None = Query(default=None),
    is_active: bool | None = Query(default=None),
) -> BindingListResponse:
    """List bindings, most-specific rule kind first then ERL name.

    Ordered by precedence rather than by creation time because the
    question an operator has in front of this list is "which rule wins".
    """
    stmt = select(ERLBinding, EmergencyResponseLocation.name).join(
        EmergencyResponseLocation, EmergencyResponseLocation.id == ERLBinding.erl_id
    )
    count_stmt = select(func.count(ERLBinding.id))
    if erl_id is not None:
        stmt = stmt.where(ERLBinding.erl_id == erl_id)
        count_stmt = count_stmt.where(ERLBinding.erl_id == erl_id)
    if rule_kind is not None:
        stmt = stmt.where(ERLBinding.rule_kind == rule_kind)
        count_stmt = count_stmt.where(ERLBinding.rule_kind == rule_kind)
    if is_active is not None:
        stmt = stmt.where(ERLBinding.is_active.is_(is_active))
        count_stmt = count_stmt.where(ERLBinding.is_active.is_(is_active))

    total = (await db.execute(count_stmt)).scalar_one()
    # Precedence order expressed in SQL so it survives pagination: sorting
    # each page in Python would order the pages independently, and a reader
    # would find switch_port rules appearing on page 3. Built from the same
    # constant the resolver walks, so the list cannot disagree with the
    # behaviour it describes.
    ordering = case(
        {kind: i for i, kind in enumerate(ERL_RULE_PRECEDENCE)},
        value=ERLBinding.rule_kind,
        else_=len(ERL_RULE_PRECEDENCE),
    )
    rows = (
        await db.execute(
            stmt.order_by(ordering.asc(), EmergencyResponseLocation.name.asc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return BindingListResponse(
        items=[_binding_read(b, name) for b, name in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.post("/bindings", response_model=BindingRead, status_code=status.HTTP_201_CREATED)
async def create_binding(body: BindingCreate, db: DB, user: CurrentUser) -> BindingRead:
    erl = await _load_erl(db, body.erl_id)
    row = ERLBinding(**body.model_dump())
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        # A 23503 here means the pasted target id does not exist; the global
        # handler turns that into a 422 naming the field, which is what the
        # operator needs rather than "already exists".
        if not _is_unique_violation(exc):
            raise
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A {body.rule_kind} binding already exists for that target. "
                "One ERL per target per kind: a tie would otherwise be resolved "
                "by whichever row the database returned first."
            ),
        ) from exc
    write_audit(
        db,
        user=user,
        action="create",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=f"{body.rule_kind} → {erl.name}",
        new_value={"rule_kind": body.rule_kind, "erl": erl.name},
    )
    await db.commit()
    await db.refresh(row)
    return _binding_read(row, erl.name)


@router.patch("/bindings/{binding_id}", response_model=BindingRead)
async def update_binding(
    binding_id: uuid.UUID, body: BindingUpdate, db: DB, user: CurrentUser
) -> BindingRead:
    row = (
        await db.execute(select(ERLBinding).where(ERLBinding.id == binding_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found")
    changes = body.model_dump(exclude_unset=True)
    if "erl_id" in changes and changes["erl_id"] is not None:
        await _load_erl(db, changes["erl_id"])
    old = {k: getattr(row, k) for k in changes}
    for field, value in changes.items():
        setattr(row, field, value)
    await db.flush()
    erl = await _load_erl(db, row.erl_id)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=f"{row.rule_kind} → {erl.name}",
        changed_fields=sorted(changes),
        old_value={k: str(v) for k, v in old.items()},
        new_value={k: str(v) for k, v in changes.items()},
    )
    await db.commit()
    await db.refresh(row)
    return _binding_read(row, erl.name)


@router.delete("/bindings/{binding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_binding(binding_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = (
        await db.execute(select(ERLBinding).where(ERLBinding.id == binding_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type=AUDIT_RESOURCE,
        resource_id=str(row.id),
        resource_display=f"{row.rule_kind} binding",
        old_value={"rule_kind": row.rule_kind, "erl_id": str(row.erl_id)},
    )
    await db.delete(row)
    await db.commit()


# ══════════════════════════════════════════════════════════════════════
# The lookup
# ══════════════════════════════════════════════════════════════════════


def log_resolution(
    db: AsyncSession,
    resolution: Resolution,
    *,
    user_id: uuid.UUID | None,
    api_token_id: uuid.UUID | None,
    source_ip: str | None,
    actor_kind: str | None = None,
) -> None:
    """Record one lookup. Shared with the HELD surface.

    Exported rather than private because the protocol a caller used changes
    nothing about the fact that somebody asked where a person sits — and two
    copies of this would be two places for the trail to quietly stop being
    written.

    ``actor_kind`` is derivable for an authenticated caller and is not for
    the Phase 2 device self-query, where there is no user at all.
    """
    db.add(
        E911ResolutionLog(
            queried_at=datetime.now(UTC),
            identity_kind=resolution.identity_kind,
            identity_value=resolution.identity_value[:255],
            actor_kind=actor_kind or ("api_token" if api_token_id else "user"),
            actor_id=api_token_id or user_id,
            source_ip=source_ip,
            erl_id=resolution.erl.id if resolution.erl else None,
            rule_matched=resolution.rule_matched,
            confidence=resolution.confidence,
            degraded_reason=resolution.degraded_reason,
            evidence_age_seconds=resolution.evidence_age_seconds,
        )
    )


@router.get("/location", response_model=LocationResponse)
async def get_location(
    request: Request,
    db: DB,
    user: CurrentUser,
    ip: str | None = Query(default=None, description="The device's IP address."),
    mac: str | None = Query(default=None, description="Any common separator."),
    chassis_id: str | None = Query(
        default=None, description="LLDP chassis-id; a Cisco phone's is its MAC."
    ),
    port_id: str | None = Query(default=None, description="LLDP port-id. Needs chassis_id."),
) -> LocationResponse:
    """Resolve a network identity to a dispatchable location.

    At least one identity is required. ``confidence="degraded"`` means a
    more precise answer existed and was refused because its evidence was
    stale — a stale precise answer is worse than a fresh coarse one.
    """
    if not any((ip, mac, chassis_id)):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Give at least one of ip, mac, or chassis_id (+ port_id).",
        )
    if port_id and not chassis_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="port_id identifies a port on a chassis; give chassis_id too.",
        )
    if mac:
        try:
            mac = canonicalize_mac(mac)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

    resolution = await resolve_location(db, ip=ip, mac=mac, chassis_id=chassis_id, port_id=port_id)

    # The trail is written whether or not anything was found: "nobody could
    # tell me where this phone was" is exactly the query an after-action
    # review needs to see.
    log_resolution(
        db,
        resolution,
        user_id=user.id,
        api_token_id=getattr(request.state, "api_token_id", None),
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()

    return LocationResponse(
        identity_kind=resolution.identity_kind,
        identity_value=resolution.identity_value,
        found=resolution.found,
        confidence=resolution.confidence,  # type: ignore[arg-type]
        rule_matched=resolution.rule_matched,  # type: ignore[arg-type]
        degraded_reason=resolution.degraded_reason,
        observed_at=resolution.observed_at,
        evidence_age_seconds=resolution.evidence_age_seconds,
        erl=_erl_read(resolution.erl) if resolution.erl else None,
        evidence=[
            EvidenceRead(
                kind=e.kind,
                observed_at=e.observed_at,
                age_seconds=e.age_seconds,
                window_seconds=e.window_seconds,
                stale=e.stale,
                detail=e.detail,
            )
            for e in resolution.evidence
        ],
    )


# ══════════════════════════════════════════════════════════════════════
# Exports (#972 Phase 3)
# ══════════════════════════════════════════════════════════════════════


async def _export_rows(
    db: AsyncSession, *, site_id: uuid.UUID | None
) -> list[tuple[EmergencyResponseLocation, list[ERLBinding]]]:
    """Every ERL with its bindings, in two queries rather than one per row."""
    stmt = select(EmergencyResponseLocation).order_by(EmergencyResponseLocation.name)
    if site_id is not None:
        stmt = stmt.where(EmergencyResponseLocation.site_id == site_id)
    erls = list((await db.execute(stmt)).scalars().all())
    if not erls:
        return []
    bindings = list(
        (await db.execute(select(ERLBinding).where(ERLBinding.erl_id.in_([e.id for e in erls]))))
        .scalars()
        .all()
    )
    by_erl: dict[uuid.UUID, list[ERLBinding]] = {}
    for b in bindings:
        by_erl.setdefault(b.erl_id, []).append(b)
    return [(e, by_erl.get(e.id, [])) for e in erls]


@router.get("/export.csv", response_class=CsvResponse)
async def export_csv(
    db: DB,
    user: CurrentUser,
    site_id: uuid.UUID | None = Query(default=None),
) -> Response:
    """Every ERL and its bindings as CSV.

    For bulk review, for the spreadsheet an auditor asked for, and as the
    thing a shop already running Cisco Emergency Responder maps into CER's
    own ERL bulk load — CER's columns differ between versions, so the
    operator does the mapping rather than us guessing it.

    Values that look like spreadsheet formulas are quoted, because a building
    named ``=cmd|' /C calc'!A0`` executes when the file is opened.
    """
    rows = await _export_rows(db, site_id=site_id)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    write_audit(
        db,
        user=user,
        action="export",
        resource_type=AUDIT_RESOURCE,
        resource_id="export.csv",
        resource_display=f"{len(rows)} ERL(s)",
    )
    await db.commit()
    return Response(
        content=render_csv(rows),
        media_type="text/csv",
        headers={"Content-Disposition": content_disposition(f"e911-erls-{stamp}.csv")},
    )


@router.get("/export/ios-lldp-med.txt", response_class=IosConfigResponse)
async def export_ios_snippets(
    db: DB,
    user: CurrentUser,
    site_id: uuid.UUID | None = Query(default=None),
) -> Response:
    """LLDP-MED ``location civic-location`` stanzas, as text to review.

    LLDP-MED is the one delivery mechanism that needs no HELD, no DHCP option
    and no phone-side configuration — the switch announces the location to the
    handset per port.

    **SpatiumDDI configures no switches.** This is generated text the operator
    reads and applies; the snippet says so in its own header. Per-interface
    lines are emitted for ERLs reached by a ``switch_port`` binding, because
    that is the only rule that names a port.
    """
    rows = await _export_rows(db, site_id=site_id)

    # interface_id → (device name, "Gi3/0/12"), for the per-interface stanzas.
    # The device name is carried because Gi3/0/12 exists on every switch in the
    # estate and a bare list gives the operator no way to tell which lines
    # belong to the switch in front of them. One query.
    port_names: dict[str, list[tuple[str, str]]] = {}
    port_bound = [
        (erl, b)
        for erl, bindings in rows
        for b in bindings
        if b.rule_kind == "switch_port" and b.network_interface_id
    ]
    if port_bound:
        names: dict[uuid.UUID, tuple[str, str]] = {
            iface_id: (str(device_name or "(unknown switch)"), str(iface_name))
            for iface_id, iface_name, device_name in (
                await db.execute(
                    select(
                        NetworkInterface.id,
                        NetworkInterface.name,
                        NetworkDevice.name,
                    )
                    .join(NetworkDevice, NetworkDevice.id == NetworkInterface.device_id)
                    .where(
                        NetworkInterface.id.in_([b.network_interface_id for _e, b in port_bound])
                    )
                )
            ).all()
        }
        for erl, b in port_bound:
            # `network_interface_id` is non-None by construction — port_bound
            # filters on it — but mypy cannot see that through the
            # comprehension, and an assert here would be a runtime cost on a
            # path that is already proven.
            pair = names.get(b.network_interface_id) if b.network_interface_id else None
            if pair:
                port_names.setdefault(str(erl.id), []).append(pair)

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    write_audit(
        db,
        user=user,
        action="export",
        resource_type=AUDIT_RESOURCE,
        resource_id="export/ios-lldp-med.txt",
        resource_display=f"{len(rows)} ERL(s)",
    )
    await db.commit()
    return Response(
        content=render_ios_snippets(rows, interface_names=port_names),
        media_type="text/plain",
        headers={"Content-Disposition": content_disposition(f"e911-ios-lldp-med-{stamp}.txt")},
    )
