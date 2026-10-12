"""ASN management CRUD — Phase 1 of issue #85.

The autonomous-system row is the foundation; the RDAP refresh job,
RPKI ROA pull job, dashboard summary widget, alert rules, and the
BGP-relationship FKs on Router / IPSpace / IPBlock / VRF all land in
follow-up issues. This router ships only the writeable AS surface
plus list filtering — everything else can layer on without breaking
the API contract.

Permissions: every endpoint is gated on the ``manage_asns``
resource permission (admin-only via the seeded ``Network Editor``
builtin role; superadmins always pass). Each mutation writes an
``audit_log`` row before commit per CLAUDE.md non-negotiable #4.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import String, func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1._common import BulkDeleteResponse
from app.api.v1.asns._audit import write_audit
from app.core.permissions import require_resource_permission
from app.core.update_nulls import resolve_update_changes
from app.models.asn import ASN, ASNRpkiRoa, BGPCommunity, BGPPeering
from app.services.asns.classifier import REGISTRIES, classify_asn
from app.services.tags import apply_tag_filter

logger = structlog.get_logger(__name__)

# Router-level permission gate — covers GET (read), POST/PUT (write),
# DELETE on every endpoint mounted below.
router = APIRouter(
    tags=["asns"],
    dependencies=[Depends(require_resource_permission("manage_asns"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


# 1..2_147_483_647 fits in a signed int32 (16-bit AS range plus the
# lower half of 32-bit AS space); 2_147_483_648..4_294_967_295 needs
# a Python int — Pydantic v2 happily accepts either when the field
# is typed ``int``. Range validation is in the validator below so
# the error message lists the valid bounds in one place.
_AS_MIN = 1
_AS_MAX = 4_294_967_295

_WHOIS_STATES = frozenset({"ok", "drift", "unreachable", "n/a"})


class ASNCreate(BaseModel):
    number: int = Field(..., description="32-bit AS number (1..4_294_967_295)")
    name: str = Field("", max_length=255)
    description: str = ""
    holder_org: str | None = Field(default=None, max_length=512)
    customer_id: uuid.UUID | None = None
    provider_id: uuid.UUID | None = None
    tags: dict[str, Any] = Field(default_factory=dict)
    custom_fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("number")
    @classmethod
    def _v_number(cls, v: int) -> int:
        if not (_AS_MIN <= v <= _AS_MAX):
            raise ValueError(
                f"AS number must be between {_AS_MIN} and {_AS_MAX} (32-bit range; "
                "0 is reserved per RFC 7607 and not allowed)"
            )
        return v


class ASNUpdate(BaseModel):
    """Partial update.

    ``number`` is immutable — a different AS is a different row, full
    stop, and changing it would invalidate every cached classification
    + WHOIS snapshot. ``kind`` and ``registry`` are derived; rejecting
    edits on them keeps the data clean. ``whois_*`` is owned by the
    refresh job — surfaced read-only here.
    """

    name: str | None = None
    description: str | None = None
    holder_org: str | None = None
    customer_id: uuid.UUID | None = None
    provider_id: uuid.UUID | None = None
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None


class ASNRead(BaseModel):
    id: uuid.UUID
    number: int
    name: str
    description: str
    kind: str
    holder_org: str | None
    registry: str
    whois_last_checked_at: datetime | None
    whois_data: dict[str, Any] | None
    whois_state: str
    customer_id: uuid.UUID | None
    provider_id: uuid.UUID | None
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class ASNListResponse(BaseModel):
    items: list[ASNRead]
    total: int
    limit: int
    offset: int


class ASNBulkDelete(BaseModel):
    ids: list[uuid.UUID] = Field(..., max_length=500)


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("", response_model=ASNListResponse)
async def list_asns(
    db: DB,
    _: CurrentUser,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    kind: Literal["public", "private"] | None = Query(default=None),
    registry: str | None = Query(default=None, description="RIR code, or `unknown`"),
    whois_state: Literal["ok", "drift", "unreachable", "n/a"] | None = Query(default=None),
    customer_id: uuid.UUID | None = Query(default=None),
    provider_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(
        default=None,
        description="Free-text match against number / name / holder_org (case-insensitive substring).",
    ),
    tag: list[str] = Query(default_factory=list),
) -> ASNListResponse:
    if registry is not None and registry not in REGISTRIES:
        raise HTTPException(
            status_code=422,
            detail=f"registry must be one of {sorted(REGISTRIES)}",
        )

    stmt = select(ASN)
    if kind is not None:
        stmt = stmt.where(ASN.kind == kind)
    if registry is not None:
        stmt = stmt.where(ASN.registry == registry)
    if whois_state is not None:
        stmt = stmt.where(ASN.whois_state == whois_state)
    if customer_id is not None:
        stmt = stmt.where(ASN.customer_id == customer_id)
    if provider_id is not None:
        stmt = stmt.where(ASN.provider_id == provider_id)
    if search:
        # Case-insensitive substring on the three operator-facing
        # fields. ``number`` is BigInteger so we cast to text for the
        # ILIKE match — small price for not having to remember whether
        # to type "AS65001" or just "65001" in the filter box.
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                func.cast(ASN.number, type_=String).ilike(needle),
                ASN.name.ilike(needle),
                ASN.holder_org.ilike(needle),
            )
        )
    stmt = apply_tag_filter(stmt, ASN.tags, tag)

    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    stmt = stmt.order_by(ASN.number.asc()).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()

    return ASNListResponse(
        items=[ASNRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=ASNRead, status_code=status.HTTP_201_CREATED)
async def create_asn(body: ASNCreate, db: DB, user: CurrentUser) -> ASNRead:
    existing = await db.scalar(select(ASN).where(ASN.number == body.number))
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"AS{body.number} is already tracked (id={existing.id})",
        )

    kind, registry = classify_asn(body.number)
    # Public rows land as ``n/a`` until the RDAP refresh job (follow-up
    # issue) flips them to ``ok`` / ``drift`` / ``unreachable``. Private
    # rows stay ``n/a`` permanently — the refresh job skips them.
    whois_state = "n/a"

    row = ASN(
        number=body.number,
        name=body.name,
        description=body.description,
        kind=kind,
        registry=registry,
        holder_org=body.holder_org,
        whois_state=whois_state,
        customer_id=body.customer_id,
        provider_id=body.provider_id,
        tags=body.tags or {},
        custom_fields=body.custom_fields or {},
    )
    db.add(row)
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="asn",
        resource_id=str(row.id),
        resource_display=f"AS{row.number}" + (f" ({row.name})" if row.name else ""),
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)

    # #278 follow-up — kick a one-shot RDAP (+ RPKI for public ASNs)
    # refresh so the row is populated within seconds instead of sitting at
    # whois_state "n/a" until the next refresh_due_asns beat tick. Private
    # ASNs short-circuit inside the task (no RDAP/ROAs issued for them).
    # Fire-and-forget: a broker hiccup must not fail the 201 — the
    # scheduled sweep still picks the row up (next_check_at IS NULL).
    try:
        from app.tasks.asn_whois_refresh import refresh_one_asn_by_id

        refresh_one_asn_by_id.delay(str(row.id))
    except Exception as exc:  # noqa: BLE001
        logger.warning("asn_whois_refresh_dispatch_failed", asn=row.number, error=str(exc))

    return ASNRead.model_validate(row)


@router.get("/{asn_id:uuid}", response_model=ASNRead)
async def get_asn(asn_id: uuid.UUID, db: DB, _: CurrentUser) -> ASNRead:
    row = await db.get(ASN, asn_id)
    if row is None:
        raise HTTPException(status_code=404, detail="ASN not found")
    return ASNRead.model_validate(row)


@router.put("/{asn_id:uuid}", response_model=ASNRead)
async def update_asn(asn_id: uuid.UUID, body: ASNUpdate, db: DB, user: CurrentUser) -> ASNRead:
    row = await db.get(ASN, asn_id)
    if row is None:
        raise HTTPException(status_code=404, detail="ASN not found")

    # #1564 — same null contract as device_policies: clear nullable
    # columns, 422 on null for the NOT NULL set instead of a 500.
    changes = resolve_update_changes(
        body,
        clearable={"holder_org", "customer_id", "provider_id"},
        non_nullable={"name", "description", "tags", "custom_fields"},
    )
    for k, v in changes.items():
        setattr(row, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="asn",
        resource_id=str(row.id),
        resource_display=f"AS{row.number}",
        changed_fields=list(changes.keys()),
        new_value=body.model_dump(mode="json", exclude_unset=True),
    )
    await db.commit()
    await db.refresh(row)
    return ASNRead.model_validate(row)


@router.delete("/{asn_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asn(asn_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(ASN, asn_id)
    if row is None:
        raise HTTPException(status_code=404, detail="ASN not found")

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="asn",
        resource_id=str(row.id),
        resource_display=f"AS{row.number}",
    )
    # CASCADE removes ``asn_rpki_roa`` rows; the BGP-relationship FKs
    # land in follow-ups with their own ON-DELETE policy decisions.
    await db.delete(row)
    await db.commit()


@router.post("/{asn_id:uuid}/refresh-whois", response_model=ASNRead)
async def refresh_asn_whois(asn_id: uuid.UUID, db: DB, user: CurrentUser) -> ASNRead:
    """Synchronous "Refresh now" — fetch RDAP for this AS and stamp the
    result back to the row. Same per-row state machine as the scheduled
    task, just driven by an operator click instead of the beat tick.

    Returns 400 for ``kind="private"`` since RIRs don't delegate
    private numbers and there's nothing to refresh.

    Permission gate is the router-level ``manage_asns`` already; no
    extra check needed here.
    """
    row = await db.get(ASN, asn_id)
    if row is None:
        raise HTTPException(status_code=404, detail="ASN not found")
    if row.kind == "private":
        raise HTTPException(status_code=400, detail="private ASN — no public WHOIS")

    # Deferred imports — keep the router-import path light.
    from datetime import UTC, timedelta  # noqa: PLC0415
    from datetime import datetime as _dt  # noqa: PLC0415

    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.services.rdap_asn import lookup_asn  # noqa: PLC0415

    ps = await db.get(PlatformSettings, 1)
    interval_hours = 24
    if ps is not None:
        interval_hours = max(1, min(168, int(ps.asn_whois_interval_hours or 24)))

    now = _dt.now(UTC)
    previous_state = row.whois_state
    previous_holder = (row.holder_org or "").strip()

    payload = await lookup_asn(int(row.number))
    existing_data = row.whois_data if isinstance(row.whois_data, dict) else {}
    consecutive_failures = int(existing_data.get("consecutive_failures") or 0)

    if payload is None:
        consecutive_failures += 1
        row.whois_state = "unreachable"
        row.whois_last_checked_at = now
        row.next_check_at = now + timedelta(hours=interval_hours)
        merged = dict(existing_data)
        merged["consecutive_failures"] = consecutive_failures
        merged["last_error_at"] = now.isoformat()
        row.whois_data = merged
    else:
        new_holder = (payload.get("holder_org") or "").strip() or None
        if new_holder is not None and previous_holder and previous_holder != new_holder:
            new_state = "drift"
        else:
            new_state = "ok"
        row.holder_org = new_holder
        row.whois_state = new_state
        row.whois_last_checked_at = now
        row.next_check_at = now + timedelta(hours=interval_hours)
        last_modified = payload.get("last_modified_at")
        row.whois_data = {
            "holder_org": new_holder,
            "registry": payload.get("registry"),
            "name": payload.get("name"),
            "last_modified_at": last_modified.isoformat() if last_modified else None,
            "raw": payload.get("raw"),
            "consecutive_failures": 0,
        }

    new_value: dict[str, Any] = {
        "whois_state": row.whois_state,
        "old_state": previous_state,
    }
    if row.whois_state == "unreachable":
        new_value["consecutive_failures"] = consecutive_failures

    write_audit(
        db,
        user=user,
        action="refresh_whois",
        resource_type="asn",
        resource_id=str(row.id),
        resource_display=f"AS{row.number}",
        changed_fields=["whois_state", "whois_data"],
        new_value=new_value,
    )

    await db.commit()
    await db.refresh(row)
    return ASNRead.model_validate(row)


class ASNRpkiRoaRead(BaseModel):
    id: uuid.UUID
    asn_id: uuid.UUID
    prefix: str
    max_length: int
    valid_from: datetime | None
    valid_to: datetime | None
    trust_anchor: str
    state: str
    last_checked_at: datetime | None

    model_config = {"from_attributes": True}

    @field_validator("prefix", mode="before")
    @classmethod
    def _coerce_prefix(cls, v: Any) -> Any:
        # asyncpg returns CIDR columns as ``IPv4Network`` /
        # ``IPv6Network`` instances. Coerce to ``str`` so JSON
        # serialisation has something to work with.
        return str(v) if v is not None else v


@router.get("/{asn_id:uuid}/rpki-roas", response_model=list[ASNRpkiRoaRead])
async def list_asn_rpki_roas(asn_id: uuid.UUID, db: DB, _: CurrentUser) -> list[ASNRpkiRoaRead]:
    """List ROAs the AS is authorised to originate.

    Sorted by state (expired first, then expiring, then valid) and
    by ``valid_to`` ascending so the most-urgent rows surface at the
    top. Empty list when the parent AS has no ROAs yet — the
    detail-page UI renders an empty-state in that case.
    """
    asn = await db.get(ASN, asn_id)
    if asn is None:
        raise HTTPException(status_code=404, detail="ASN not found")

    rows = (
        (
            await db.execute(
                select(ASNRpkiRoa)
                .where(ASNRpkiRoa.asn_id == asn_id)
                .order_by(ASNRpkiRoa.prefix, ASNRpkiRoa.max_length)
            )
        )
        .scalars()
        .all()
    )
    return [ASNRpkiRoaRead.model_validate(r) for r in rows]


class RefreshRpkiResult(BaseModel):
    asn_id: uuid.UUID
    asn_number: int
    added: int
    updated: int
    removed: int
    transitions: int


@router.post("/{asn_id:uuid}/refresh-rpki", response_model=RefreshRpkiResult)
async def refresh_asn_rpki(asn_id: uuid.UUID, db: DB, user: CurrentUser) -> RefreshRpkiResult:
    """Synchronous "Refresh RPKI now" — pulls the global ROA dump and
    reconciles ROAs for this AS only. Same per-row state machine as the
    scheduled task; just driven by an operator click.

    Returns 400 for ``kind="private"`` since RIRs don't issue ROAs for
    private AS numbers and there's nothing to fetch. Permission gate
    is the router-level ``manage_asns`` already.
    """
    row = await db.get(ASN, asn_id)
    if row is None:
        raise HTTPException(status_code=404, detail="ASN not found")
    if row.kind == "private":
        raise HTTPException(status_code=400, detail="private ASN — no RPKI ROAs issued")

    from datetime import UTC  # noqa: PLC0415
    from datetime import datetime as _dt  # noqa: PLC0415

    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.tasks.rpki_roa_refresh import _refresh_one_asn  # noqa: PLC0415

    ps = await db.get(PlatformSettings, 1)
    interval_hours = 4
    source = "cloudflare"
    if ps is not None:
        interval_hours = max(1, min(168, int(ps.rpki_roa_refresh_interval_hours or 4)))
        candidate = (ps.rpki_roa_source or "cloudflare").lower()
        if candidate in {"cloudflare", "ripe"}:
            source = candidate

    now = _dt.now(UTC)
    summary = await _refresh_one_asn(db, row, source, interval_hours, now)

    write_audit(
        db,
        user=user,
        action="refresh_rpki",
        resource_type="asn",
        resource_id=str(row.id),
        resource_display=f"AS{row.number}",
        new_value={
            "added": summary["added"],
            "updated": summary["updated"],
            "removed": summary["removed"],
            "transitions": summary["transitions"],
            "source": source,
        },
    )
    await db.commit()
    return RefreshRpkiResult(
        asn_id=row.id,
        asn_number=row.number,
        added=summary["added"],
        updated=summary["updated"],
        removed=summary["removed"],
        transitions=summary["transitions"],
    )


@router.post("/bulk-delete", response_model=BulkDeleteResponse)
async def bulk_delete_asns(body: ASNBulkDelete, db: DB, user: CurrentUser) -> BulkDeleteResponse:
    """Delete up to 500 ASNs in a single round-trip.

    Returns a small summary so the UI can render a bulk-results
    modal — same shape used by other bulk endpoints in the project.
    Missing IDs (already deleted, or never existed) come back in
    ``not_found`` rather than 404-ing the whole call so the operator
    isn't punished for a partial selection.
    """
    if not body.ids:
        return BulkDeleteResponse(deleted=0, not_found=[])

    rows = (await db.execute(select(ASN).where(ASN.id.in_(body.ids)))).scalars().all()
    found_ids = {r.id for r in rows}
    not_found = [str(i) for i in body.ids if i not in found_ids]

    for r in rows:
        write_audit(
            db,
            user=user,
            action="delete",
            resource_type="asn",
            resource_id=str(r.id),
            resource_display=f"AS{r.number}",
        )
        await db.delete(r)

    await db.commit()
    return BulkDeleteResponse(deleted=len(rows), not_found=not_found)


# ── BGP peering ─────────────────────────────────────────────────────

_BGP_RELATIONSHIPS = frozenset({"peer", "customer", "provider", "sibling"})


class BGPPeeringRead(BaseModel):
    id: uuid.UUID
    local_asn_id: uuid.UUID
    peer_asn_id: uuid.UUID
    relationship_type: Literal["peer", "customer", "provider", "sibling"]
    description: str
    local_asn_number: int
    local_asn_name: str
    peer_asn_number: int
    peer_asn_name: str
    created_at: datetime
    modified_at: datetime


class BGPPeeringCreate(BaseModel):
    local_asn_id: uuid.UUID
    peer_asn_id: uuid.UUID
    relationship_type: Literal["peer", "customer", "provider", "sibling"]
    description: str = ""

    @field_validator("peer_asn_id")
    @classmethod
    def _no_self_peering(cls, v: uuid.UUID, info: Any) -> uuid.UUID:  # type: ignore[override]
        local = info.data.get("local_asn_id")
        if local is not None and v == local:
            raise ValueError("local_asn_id and peer_asn_id must differ")
        return v


class BGPPeeringUpdate(BaseModel):
    relationship_type: Literal["peer", "customer", "provider", "sibling"] | None = None
    description: str | None = None


def _serialize_peering(p: BGPPeering) -> BGPPeeringRead:
    return BGPPeeringRead(
        id=p.id,
        local_asn_id=p.local_asn_id,
        peer_asn_id=p.peer_asn_id,
        relationship_type=p.relationship_type,  # type: ignore[arg-type]
        description=p.description,
        local_asn_number=p.local_asn.number,
        local_asn_name=p.local_asn.name,
        peer_asn_number=p.peer_asn.number,
        peer_asn_name=p.peer_asn.name,
        created_at=p.created_at,
        modified_at=p.modified_at,
    )


@router.get("/peerings", response_model=list[BGPPeeringRead])
async def list_peerings(
    db: DB,
    asn_id: uuid.UUID | None = Query(
        None,
        description="Filter to peerings where this ASN is local OR peer.",
    ),
    relationship_type: str | None = Query(None),
) -> list[BGPPeeringRead]:
    stmt = select(BGPPeering)
    if asn_id is not None:
        stmt = stmt.where(
            or_(
                BGPPeering.local_asn_id == asn_id,
                BGPPeering.peer_asn_id == asn_id,
            )
        )
    if relationship_type is not None:
        if relationship_type not in _BGP_RELATIONSHIPS:
            raise HTTPException(
                status_code=422, detail=f"unknown relationship_type: {relationship_type}"
            )
        stmt = stmt.where(BGPPeering.relationship_type == relationship_type)
    rows = (await db.execute(stmt)).scalars().all()
    return [_serialize_peering(r) for r in rows]


def _peering_display(p: BGPPeering) -> str:
    return f"AS{p.local_asn.number} → AS{p.peer_asn.number} ({p.relationship_type})"


@router.post("/peerings", response_model=BGPPeeringRead, status_code=status.HTTP_201_CREATED)
async def create_peering(body: BGPPeeringCreate, db: DB, user: CurrentUser) -> BGPPeeringRead:
    asn_ids = {body.local_asn_id, body.peer_asn_id}
    found = (await db.execute(select(ASN.id).where(ASN.id.in_(asn_ids)))).scalars().all()
    missing = asn_ids - set(found)
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"ASN(s) not found: {sorted(str(m) for m in missing)}",
        )

    peering = BGPPeering(
        local_asn_id=body.local_asn_id,
        peer_asn_id=body.peer_asn_id,
        relationship_type=body.relationship_type,
        description=body.description,
    )
    db.add(peering)
    try:
        await db.flush()
    except Exception as exc:  # IntegrityError on uq_bgp_peering
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A peering with this (local, peer, relationship_type) already exists.",
        ) from exc

    await db.refresh(peering)
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="bgp_peering",
        resource_id=str(peering.id),
        resource_display=_peering_display(peering),
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(peering)
    return _serialize_peering(peering)


@router.patch("/peerings/{peering_id}", response_model=BGPPeeringRead)
async def update_peering(
    peering_id: uuid.UUID,
    body: BGPPeeringUpdate,
    db: DB,
    user: CurrentUser,
) -> BGPPeeringRead:
    peering = await db.get(BGPPeering, peering_id)
    if peering is None:
        raise HTTPException(status_code=404, detail="Peering not found")

    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(peering, k, v)

    if changes:
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="bgp_peering",
            resource_id=str(peering_id),
            resource_display=_peering_display(peering),
            changed_fields=list(changes.keys()),
            new_value=changes,
        )
    await db.commit()
    await db.refresh(peering)
    return _serialize_peering(peering)


@router.delete("/peerings/{peering_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_peering(peering_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    peering = await db.get(BGPPeering, peering_id)
    if peering is None:
        raise HTTPException(status_code=404, detail="Peering not found")
    display = _peering_display(peering)
    await db.delete(peering)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="bgp_peering",
        resource_id=str(peering_id),
        resource_display=display,
    )
    await db.commit()


# ── BGP communities ─────────────────────────────────────────────────

_REGULAR_COMMUNITY_RE = re.compile(r"^\d+:\d+$")
_LARGE_COMMUNITY_RE = re.compile(r"^\d+:\d+:\d+$")
_STANDARD_NAMES = frozenset(
    {
        "no-export",
        "no-advertise",
        "no-export-subconfed",
        "local-as",
        "graceful-shutdown",
        "blackhole",
        "accept-own",
    }
)


class BGPCommunityRead(BaseModel):
    id: uuid.UUID
    asn_id: uuid.UUID | None
    value: str
    kind: Literal["standard", "regular", "large"]
    name: str
    description: str
    inbound_action: str
    outbound_action: str
    tags: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class BGPCommunityCreate(BaseModel):
    value: str
    kind: Literal["standard", "regular", "large"] = "regular"
    name: str = ""
    description: str = ""
    inbound_action: str = ""
    outbound_action: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def _v_value(cls, v: str, info: Any) -> str:  # type: ignore[override]
        v = v.strip()
        if not v:
            raise ValueError("value is required")
        kind = info.data.get("kind", "regular")
        if kind == "standard":
            if v not in _STANDARD_NAMES:
                raise ValueError(f"standard community must be one of: {sorted(_STANDARD_NAMES)}")
        elif kind == "regular":
            if not _REGULAR_COMMUNITY_RE.match(v):
                raise ValueError("regular community must be ASN:N (e.g. 65000:100)")
        elif kind == "large":
            if not _LARGE_COMMUNITY_RE.match(v):
                raise ValueError("large community must be ASN:N:M (e.g. 65000:100:200)")
        return v


class BGPCommunityUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    inbound_action: str | None = None
    outbound_action: str | None = None
    tags: dict[str, Any] | None = None


def _community_display(c: BGPCommunity, asn: ASN | None) -> str:
    prefix = f"AS{asn.number} " if asn is not None else "[platform] "
    return f"{prefix}{c.value}" + (f" ({c.name})" if c.name else "")


@router.get("/communities/standard", response_model=list[BGPCommunityRead])
async def list_standard_communities(db: DB, _: CurrentUser) -> list[BGPCommunityRead]:
    """Read-only well-known catalog (RFC 1997 / 7611 / 7999). Seeded
    on first boot from ``app.services.bgp_communities.STANDARD_COMMUNITIES``."""
    rows = (
        (
            await db.execute(
                select(BGPCommunity)
                .where(BGPCommunity.asn_id.is_(None))
                .order_by(BGPCommunity.value)
            )
        )
        .scalars()
        .all()
    )
    return [BGPCommunityRead.model_validate(r) for r in rows]


@router.get("/{asn_id:uuid}/communities", response_model=list[BGPCommunityRead])
async def list_asn_communities(asn_id: uuid.UUID, db: DB, _: CurrentUser) -> list[BGPCommunityRead]:
    """List operator-defined communities for the given AS."""
    asn = await db.get(ASN, asn_id)
    if asn is None:
        raise HTTPException(status_code=404, detail="ASN not found")
    rows = (
        (
            await db.execute(
                select(BGPCommunity)
                .where(BGPCommunity.asn_id == asn_id)
                .order_by(BGPCommunity.kind, BGPCommunity.value)
            )
        )
        .scalars()
        .all()
    )
    return [BGPCommunityRead.model_validate(r) for r in rows]


@router.post(
    "/{asn_id:uuid}/communities",
    response_model=BGPCommunityRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_asn_community(
    asn_id: uuid.UUID,
    body: BGPCommunityCreate,
    db: DB,
    user: CurrentUser,
) -> BGPCommunityRead:
    asn = await db.get(ASN, asn_id)
    if asn is None:
        raise HTTPException(status_code=404, detail="ASN not found")

    row = BGPCommunity(
        asn_id=asn_id,
        value=body.value,
        kind=body.kind,
        name=body.name,
        description=body.description,
        inbound_action=body.inbound_action,
        outbound_action=body.outbound_action,
        tags=body.tags or {},
    )
    db.add(row)
    try:
        await db.flush()
    except Exception as exc:  # IntegrityError on uq_bgp_community_value
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Community {body.value} already defined for this ASN",
        ) from exc

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="bgp_community",
        resource_id=str(row.id),
        resource_display=_community_display(row, asn),
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return BGPCommunityRead.model_validate(row)


@router.patch("/communities/{community_id:uuid}", response_model=BGPCommunityRead)
async def update_asn_community(
    community_id: uuid.UUID,
    body: BGPCommunityUpdate,
    db: DB,
    user: CurrentUser,
) -> BGPCommunityRead:
    row = await db.get(BGPCommunity, community_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Community not found")
    if row.asn_id is None:
        raise HTTPException(
            status_code=400,
            detail="Standard / well-known communities are read-only.",
        )

    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(row, k, v)

    if changes:
        asn = await db.get(ASN, row.asn_id) if row.asn_id else None
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="bgp_community",
            resource_id=str(row.id),
            resource_display=_community_display(row, asn),
            changed_fields=list(changes.keys()),
            new_value=changes,
        )
    await db.commit()
    await db.refresh(row)
    return BGPCommunityRead.model_validate(row)


@router.delete("/communities/{community_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asn_community(community_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(BGPCommunity, community_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Community not found")
    if row.asn_id is None:
        raise HTTPException(
            status_code=400,
            detail="Standard / well-known communities cannot be deleted.",
        )
    asn = await db.get(ASN, row.asn_id) if row.asn_id else None
    display = _community_display(row, asn)
    await db.delete(row)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="bgp_community",
        resource_id=str(community_id),
        resource_display=display,
    )
    await db.commit()


# ══════════════════════════════════════════════════════════════════════
# BGP prefix-hijack monitoring (issue #527)
# ══════════════════════════════════════════════════════════════════════


class TrackedPrefixRead(BaseModel):
    id: uuid.UUID
    asn_id: uuid.UUID
    prefix: str
    expected_origin_asn: int
    source: str
    enabled: bool
    allowed_origins: list[int]
    last_seen_origins: list[int] | None
    last_checked_at: datetime | None
    next_check_at: datetime | None

    model_config = {"from_attributes": True}

    @field_validator("prefix", mode="before")
    @classmethod
    def _coerce_prefix(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class TrackedPrefixCreate(BaseModel):
    prefix: str = Field(..., description="IPv4/IPv6 CIDR to monitor.")
    enabled: bool = True
    allowed_origins: list[int] = Field(default_factory=list)

    @field_validator("prefix")
    @classmethod
    def _v_prefix(cls, v: str) -> str:
        import ipaddress as _ip  # noqa: PLC0415

        try:
            return str(_ip.ip_network(v.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid prefix: {exc}") from exc


class HijackDetectionRead(BaseModel):
    id: uuid.UUID
    asn_id: uuid.UUID
    tracked_prefix_id: uuid.UUID | None
    tracked_prefix: str
    observed_prefix: str
    expected_origin_asn: int
    observed_origin_asn: int
    detection_kind: str
    rpki_status: str
    severity: str
    source: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    acknowledged: bool
    detail: dict[str, Any] | None
    notes: str

    model_config = {"from_attributes": True}

    @field_validator("tracked_prefix", "observed_prefix", mode="before")
    @classmethod
    def _coerce_prefix(cls, v: Any) -> Any:
        return str(v) if v is not None else v


@router.get("/bgp/tracked-prefixes", response_model=list[TrackedPrefixRead])
async def list_tracked_prefixes(
    db: DB,
    _: CurrentUser,
    asn_id: uuid.UUID | None = Query(default=None),
    enabled: bool | None = Query(default=None),
) -> list[TrackedPrefixRead]:
    """List the prefixes SpatiumDDI monitors on the public routing table."""
    from app.models.bgp_monitor import BGPTrackedPrefix  # noqa: PLC0415

    stmt = select(BGPTrackedPrefix)
    if asn_id is not None:
        stmt = stmt.where(BGPTrackedPrefix.asn_id == asn_id)
    if enabled is not None:
        stmt = stmt.where(BGPTrackedPrefix.enabled.is_(enabled))
    stmt = stmt.order_by(BGPTrackedPrefix.prefix)
    rows = (await db.execute(stmt)).scalars().all()
    return [TrackedPrefixRead.model_validate(r) for r in rows]


@router.post(
    "/{asn_id:uuid}/bgp/tracked-prefixes",
    response_model=TrackedPrefixRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_tracked_prefix(
    asn_id: uuid.UUID, body: TrackedPrefixCreate, db: DB, user: CurrentUser
) -> TrackedPrefixRead:
    """Manually add a tracked prefix for an AS (``source="manual"``).
    Manual rows are never auto-pruned by the reconcile sweep."""
    from app.models.bgp_monitor import BGPTrackedPrefix  # noqa: PLC0415

    asn = await db.get(ASN, asn_id)
    if asn is None:
        raise HTTPException(status_code=404, detail="ASN not found")

    # CIDR equality is dialect-fiddly; compare in Python over this AS's
    # (bounded) tracked-prefix set.
    existing_rows = (
        (await db.execute(select(BGPTrackedPrefix).where(BGPTrackedPrefix.asn_id == asn_id)))
        .scalars()
        .all()
    )
    if any(str(r.prefix) == body.prefix for r in existing_rows):
        raise HTTPException(status_code=409, detail="prefix already tracked for this ASN")

    row = BGPTrackedPrefix(
        asn_id=asn_id,
        prefix=body.prefix,
        expected_origin_asn=int(asn.number),
        source="manual",
        enabled=body.enabled,
        allowed_origins=[int(o) for o in body.allowed_origins],
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="bgp_tracked_prefix",
        resource_id=str(row.id),
        resource_display=f"AS{asn.number} {body.prefix}",
        new_value={"prefix": body.prefix, "source": "manual"},
    )
    await db.commit()
    await db.refresh(row)
    return TrackedPrefixRead.model_validate(row)


@router.delete("/bgp/tracked-prefixes/{prefix_id:uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tracked_prefix(prefix_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    from app.models.bgp_monitor import BGPTrackedPrefix  # noqa: PLC0415

    row = await db.get(BGPTrackedPrefix, prefix_id)
    if row is None:
        raise HTTPException(status_code=404, detail="tracked prefix not found")
    display = str(row.prefix)
    await db.delete(row)
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="bgp_tracked_prefix",
        resource_id=str(prefix_id),
        resource_display=display,
    )
    await db.commit()


@router.get("/bgp/hijacks", response_model=list[HijackDetectionRead])
async def list_bgp_hijacks(
    db: DB,
    _: CurrentUser,
    asn_id: uuid.UUID | None = Query(default=None),
    detection_kind: str | None = Query(default=None),
    active_only: bool = Query(default=True),
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[HijackDetectionRead]:
    """List prefix-hijack detections, newest first."""
    from app.models.bgp_monitor import BGPHijackDetection  # noqa: PLC0415

    stmt = select(BGPHijackDetection)
    if asn_id is not None:
        stmt = stmt.where(BGPHijackDetection.asn_id == asn_id)
    if detection_kind is not None:
        stmt = stmt.where(BGPHijackDetection.detection_kind == detection_kind)
    if active_only:
        stmt = stmt.where(BGPHijackDetection.resolved_at.is_(None))
    stmt = stmt.order_by(BGPHijackDetection.last_seen_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [HijackDetectionRead.model_validate(r) for r in rows]


@router.post("/bgp/hijacks/{detection_id:uuid}/acknowledge", response_model=HijackDetectionRead)
async def acknowledge_bgp_hijack(
    detection_id: uuid.UUID, db: DB, user: CurrentUser
) -> HijackDetectionRead:
    """Acknowledge a detection — suppresses the alert (the matcher skips
    acknowledged rows) without waiting for the announcement to delist."""
    from app.models.bgp_monitor import BGPHijackDetection  # noqa: PLC0415

    row = await db.get(BGPHijackDetection, detection_id)
    if row is None:
        raise HTTPException(status_code=404, detail="detection not found")
    row.acknowledged = True
    write_audit(
        db,
        user=user,
        action="acknowledge",
        resource_type="bgp_hijack_detection",
        resource_id=str(detection_id),
        resource_display=f"{row.observed_prefix} ← AS{row.observed_origin_asn}",
    )
    await db.commit()
    await db.refresh(row)
    return HijackDetectionRead.model_validate(row)


@router.post(
    "/bgp/hijacks/{detection_id:uuid}/allowlist-origin", response_model=HijackDetectionRead
)
async def allowlist_bgp_hijack_origin(
    detection_id: uuid.UUID, db: DB, user: CurrentUser
) -> HijackDetectionRead:
    """Mark the observed origin as an EXPECTED additional origin for the
    tracked prefix (intentional multi-origin / anycast / scrubbing) —
    appends it to the tracked prefix's ``allowed_origins`` so future
    announcements from that origin don't fire, and acknowledges this
    detection."""
    from app.models.bgp_monitor import BGPHijackDetection, BGPTrackedPrefix  # noqa: PLC0415

    row = await db.get(BGPHijackDetection, detection_id)
    if row is None:
        raise HTTPException(status_code=404, detail="detection not found")

    if row.tracked_prefix_id is not None:
        tracked = await db.get(BGPTrackedPrefix, row.tracked_prefix_id)
        if tracked is not None:
            allowed = list(tracked.allowed_origins or [])
            if int(row.observed_origin_asn) not in allowed:
                allowed.append(int(row.observed_origin_asn))
                tracked.allowed_origins = allowed
    row.acknowledged = True
    write_audit(
        db,
        user=user,
        action="allowlist_origin",
        resource_type="bgp_hijack_detection",
        resource_id=str(detection_id),
        resource_display=f"{row.observed_prefix} ← AS{row.observed_origin_asn}",
        new_value={"allowlisted_origin": int(row.observed_origin_asn)},
    )
    await db.commit()
    await db.refresh(row)
    return HijackDetectionRead.model_validate(row)


class RefreshBgpResult(BaseModel):
    asn_id: uuid.UUID
    asn_number: int
    prefixes_added: int
    prefixes_evaluated: int
    detections_opened: int
    detections_resolved: int


@router.post("/{asn_id:uuid}/refresh-bgp", response_model=RefreshBgpResult)
async def refresh_asn_bgp(asn_id: uuid.UUID, db: DB, user: CurrentUser) -> RefreshBgpResult:
    """Synchronous "Check BGP now" for one AS — reconciles tracked
    prefixes then evaluates every enabled one against the live routing
    table. Same detection state machine as the scheduled poll; driven by
    an operator click. Returns 400 for private ASNs (no public routing
    presence to check)."""
    from datetime import UTC as _UTC  # noqa: PLC0415
    from datetime import datetime as _dt  # noqa: PLC0415

    from app.models.bgp_monitor import BGPTrackedPrefix  # noqa: PLC0415
    from app.services.bgp.hijack_monitor import (  # noqa: PLC0415
        evaluate_tracked_prefix,
        refresh_tracked_prefixes_for_asn,
        resolve_stale_detections,
    )

    asn = await db.get(ASN, asn_id)
    if asn is None:
        raise HTTPException(status_code=404, detail="ASN not found")
    if asn.kind == "private":
        raise HTTPException(status_code=400, detail="private ASN — no public routing presence")

    now = _dt.now(_UTC)
    added = await refresh_tracked_prefixes_for_asn(db, asn, now=now)
    await db.flush()

    rows = (
        (
            await db.execute(
                select(BGPTrackedPrefix).where(
                    BGPTrackedPrefix.asn_id == asn_id,
                    BGPTrackedPrefix.enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    evaluated = 0
    opened = 0
    for tracked in rows:
        summary = await evaluate_tracked_prefix(db, tracked, now=now)
        evaluated += 1
        opened += summary["opened"]
        tracked.next_check_at = now
    resolved = await resolve_stale_detections(db, asn_id=asn_id, now=now)

    write_audit(
        db,
        user=user,
        action="refresh_bgp",
        resource_type="asn",
        resource_id=str(asn_id),
        resource_display=f"AS{asn.number}",
        new_value={
            "prefixes_added": added,
            "prefixes_evaluated": evaluated,
            "detections_opened": opened,
            "detections_resolved": resolved,
        },
    )
    await db.commit()
    return RefreshBgpResult(
        asn_id=asn_id,
        asn_number=int(asn.number),
        prefixes_added=added,
        prefixes_evaluated=evaluated,
        detections_opened=opened,
        detections_resolved=resolved,
    )


__all__ = ["router"]
