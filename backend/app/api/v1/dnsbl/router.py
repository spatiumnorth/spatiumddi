"""DNSBL / RBL reputation monitoring CRUD + on-demand check (#528).

Manage the curated blocklist catalog (per-list enable + custom lists),
operator-pinned IPs, the blocklisted-IP overview, and fire an on-demand
per-IP reputation check.

Permissions: every endpoint gates on the ``dnsbl`` resource_type (admin
via the seeded Network Editor builtin role; read via Viewer / Auditor;
superadmin always passes). The whole router is feature-gated behind
``security.dnsbl`` at the include site (404 when off). Each mutation
writes an ``audit_log`` row before commit (non-negotiable #4).

The global sweep settings (master enable / cadence / resolvers) live on
``PlatformSettings`` and are exposed here (``GET/PUT /dnsbl/settings``) so
the whole feature is configurable from one admin surface.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import String, cast, func, or_, select

from app.api.deps import DB, CurrentUser
from app.api.v1.ownership._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.dnsbl import DNSBLList, DNSBLListing, DNSBLPinnedIP
from app.models.settings import PlatformSettings
from app.services.api_token_scopes import token_write

router = APIRouter(
    tags=["dnsbl"],
    dependencies=[Depends(require_resource_permission("dnsbl"))],
)

_SINGLETON_ID = 1


def _norm_ip(value: str) -> str:
    """Validate + normalise a bare IPv4 address (v1 is IPv4-only)."""
    bare = str(value).split("/")[0].strip()
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid IP {value!r}") from exc
    if not isinstance(addr, ipaddress.IPv4Address):
        raise HTTPException(status_code=422, detail="DNSBL monitoring is IPv4-only in v1")
    return str(addr)


# ── Schemas ─────────────────────────────────────────────────────────


class DNSBLListRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    zone_suffix: str
    category: str
    description: str
    homepage_url: str | None
    enabled: bool
    return_codes: dict[str, str]
    requires_registration: bool
    qps_note: str
    is_builtin: bool
    created_at: datetime
    modified_at: datetime


class DNSBLListCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    zone_suffix: str = Field(..., min_length=1, max_length=255)
    category: str = Field(default="combined", max_length=24)
    description: str = ""
    homepage_url: str | None = Field(default=None, max_length=255)
    enabled: bool = False
    return_codes: dict[str, str] = Field(default_factory=dict)
    requires_registration: bool = False
    qps_note: str = ""

    @field_validator("zone_suffix")
    @classmethod
    def _v_suffix(cls, v: str) -> str:
        return v.strip().strip(".").lower()


class DNSBLListUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    category: str | None = Field(default=None, max_length=24)
    description: str | None = None
    homepage_url: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    return_codes: dict[str, str] | None = None
    requires_registration: bool | None = None
    qps_note: str | None = None


class DNSBLPinnedIPRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    ip: str
    note: str
    ip_address_id: uuid.UUID | None
    created_at: datetime


class DNSBLPinnedIPCreate(BaseModel):
    ip: str
    note: str = ""


class DNSBLListingRead(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    ip: str
    list_id: uuid.UUID
    listed: bool
    source: str
    return_codes: list[str]
    txt_reason: str | None
    check_error: str | None
    first_listed_at: datetime | None
    last_checked_at: datetime | None
    resolved_at: datetime | None


class DNSBLListingListResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class DNSBLSettingsRead(BaseModel):
    dnsbl_monitoring_enabled: bool
    dnsbl_check_interval_hours: int
    dnsbl_query_resolvers: list[str] | None
    dnsbl_sweep_last_run_at: datetime | None


class DNSBLSettingsUpdate(BaseModel):
    dnsbl_monitoring_enabled: bool | None = None
    dnsbl_check_interval_hours: int | None = Field(default=None, ge=6, le=168)
    dnsbl_query_resolvers: list[str] | None = None


class DNSBLCheckRequest(BaseModel):
    ip: str


# ── Catalog (lists) ─────────────────────────────────────────────────


@router.get("/lists", response_model=list[DNSBLListRead])
async def list_lists(db: DB, _: CurrentUser) -> list[DNSBLList]:
    rows = (await db.execute(select(DNSBLList).order_by(DNSBLList.name.asc()))).scalars().all()
    return list(rows)


@router.post("/lists", response_model=DNSBLListRead, status_code=status.HTTP_201_CREATED)
async def create_list(body: DNSBLListCreate, db: DB, user: CurrentUser) -> DNSBLList:
    dup = await db.scalar(select(DNSBLList).where(DNSBLList.zone_suffix == body.zone_suffix))
    if dup is not None:
        raise HTTPException(status_code=409, detail=f"list {body.zone_suffix} already exists")
    row = DNSBLList(
        name=body.name,
        zone_suffix=body.zone_suffix,
        category=body.category,
        description=body.description,
        homepage_url=body.homepage_url,
        enabled=body.enabled,
        return_codes=body.return_codes,
        requires_registration=body.requires_registration,
        qps_note=body.qps_note,
        is_builtin=False,
    )
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dnsbl",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={"zone_suffix": row.zone_suffix, "enabled": row.enabled},
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.put("/lists/{list_id}", response_model=DNSBLListRead)
async def update_list(
    list_id: uuid.UUID, body: DNSBLListUpdate, db: DB, user: CurrentUser
) -> DNSBLList:
    row = await db.get(DNSBLList, list_id)
    if row is None:
        raise HTTPException(status_code=404, detail="list not found")
    data = body.model_dump(exclude_unset=True)
    changed: list[str] = []
    for field_name, value in data.items():
        if getattr(row, field_name) != value:
            setattr(row, field_name, value)
            changed.append(field_name)
    if changed:
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="dnsbl",
            resource_id=str(row.id),
            resource_display=row.name,
            changed_fields=changed,
        )
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/lists/{list_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_list(list_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(DNSBLList, list_id)
    if row is None:
        raise HTTPException(status_code=404, detail="list not found")
    if row.is_builtin:
        raise HTTPException(
            status_code=409,
            detail="cannot delete a built-in catalog list — disable it instead",
        )
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dnsbl",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.delete(row)
    await db.commit()


# ── Pinned IPs ──────────────────────────────────────────────────────


@router.get("/pinned", response_model=list[DNSBLPinnedIPRead])
async def list_pinned(db: DB, _: CurrentUser) -> list[dict[str, Any]]:
    rows = (
        (await db.execute(select(DNSBLPinnedIP).order_by(DNSBLPinnedIP.created_at.desc())))
        .scalars()
        .all()
    )
    return [
        {
            "id": r.id,
            "ip": str(r.ip),
            "note": r.note,
            "ip_address_id": r.ip_address_id,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.post("/pinned", response_model=DNSBLPinnedIPRead, status_code=status.HTTP_201_CREATED)
async def add_pinned(body: DNSBLPinnedIPCreate, db: DB, user: CurrentUser) -> dict[str, Any]:
    ip = _norm_ip(body.ip)
    dup = await db.scalar(select(DNSBLPinnedIP).where(DNSBLPinnedIP.ip == ip))
    if dup is not None:
        raise HTTPException(status_code=409, detail=f"{ip} is already pinned")
    row = DNSBLPinnedIP(ip=ip, note=body.note)
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dnsbl",
        resource_id=str(row.id),
        resource_display=ip,
        new_value={"ip": ip},
    )
    await db.commit()
    await db.refresh(row)
    return {
        "id": row.id,
        "ip": str(row.ip),
        "note": row.note,
        "ip_address_id": row.ip_address_id,
        "created_at": row.created_at,
    }


@router.delete("/pinned/{pin_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pinned(pin_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(DNSBLPinnedIP, pin_id)
    if row is None:
        raise HTTPException(status_code=404, detail="pin not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dnsbl",
        resource_id=str(row.id),
        resource_display=str(row.ip),
    )
    await db.delete(row)
    await db.commit()


# ── Listings (results) ──────────────────────────────────────────────


def _listing_dict(row: DNSBLListing, list_name: str | None) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "ip": str(row.ip),
        "list_id": str(row.list_id),
        "list_name": list_name,
        "listed": row.listed,
        "source": row.source,
        "return_codes": list(row.return_codes or []),
        "txt_reason": row.txt_reason,
        "check_error": row.check_error,
        "first_listed_at": row.first_listed_at.isoformat() if row.first_listed_at else None,
        "last_checked_at": row.last_checked_at.isoformat() if row.last_checked_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
    }


@router.get("/listings", response_model=DNSBLListingListResponse)
async def list_listings(
    db: DB,
    _: CurrentUser,
    listed_only: bool = Query(default=True),
    list_id: uuid.UUID | None = Query(default=None),
    source: str | None = Query(default=None),
    search: str | None = Query(default=None, description="Substring on ip / txt_reason."),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> DNSBLListingListResponse:
    stmt = select(DNSBLListing, DNSBLList.name).join(
        DNSBLList, DNSBLList.id == DNSBLListing.list_id
    )
    if listed_only:
        stmt = stmt.where(DNSBLListing.listed.is_(True))
    if list_id is not None:
        stmt = stmt.where(DNSBLListing.list_id == list_id)
    if source is not None:
        stmt = stmt.where(DNSBLListing.source == source)
    if search:
        needle = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                cast(DNSBLListing.ip, String).ilike(needle),
                DNSBLListing.txt_reason.ilike(needle),
            )
        )
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = await db.scalar(count_stmt) or 0
    stmt = (
        stmt.order_by(DNSBLListing.first_listed_at.desc().nullslast()).limit(limit).offset(offset)
    )
    rows = (await db.execute(stmt)).all()
    return DNSBLListingListResponse(
        items=[_listing_dict(listing, name) for listing, name in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


class DNSBLListingEntry(BaseModel):
    """One list's verdict on an IP."""

    list_id: uuid.UUID | None = None
    list_name: str | None = None
    zone_suffix: str | None = None
    listed: bool
    #: False when this list has never been queried for the IP — which is a
    #: different statement from "queried and not listed".
    checked: bool
    return_codes: list[str] = []
    txt_reason: str | None = None
    check_error: str | None = None
    first_listed_at: datetime | None = None
    last_checked_at: datetime | None = None
    resolved_at: datetime | None = None


class DNSBLListingsByIP(BaseModel):
    ip: str
    listed_count: int
    entries: list[DNSBLListingEntry]


class DNSBLCheckResult(BaseModel):
    """Result of an on-demand check across every enabled list."""

    ip: str
    #: How many lists were actually queried. Zero with an ``error`` set means
    #: nothing ran — not that the IP came back clean.
    checked: int = 0
    listed: int = 0
    source: str | None = None
    error: str | None = None


@router.get("/listings/by-ip/{ip}", response_model=DNSBLListingsByIP)
async def listings_by_ip(ip: str, db: DB, _: CurrentUser) -> DNSBLListingsByIP:
    """Per-IP reputation across every enabled list (the Reputation panel).

    Returns one entry per enabled list — merging any existing listing row
    with the not-yet-checked lists so the panel can show full coverage.
    """
    ip = _norm_ip(ip)
    enabled_lists = (
        (await db.execute(select(DNSBLList).where(DNSBLList.enabled.is_(True)))).scalars().all()
    )
    existing = (await db.execute(select(DNSBLListing).where(DNSBLListing.ip == ip))).scalars().all()
    by_list = {r.list_id: r for r in existing}
    entries: list[dict[str, Any]] = []
    for lst in enabled_lists:
        row = by_list.get(lst.id)
        entries.append(
            {
                "list_id": str(lst.id),
                "list_name": lst.name,
                "zone_suffix": lst.zone_suffix,
                "listed": bool(row.listed) if row else False,
                "checked": row is not None,
                "return_codes": list(row.return_codes or []) if row else [],
                "txt_reason": row.txt_reason if row else None,
                "check_error": row.check_error if row else None,
                "first_listed_at": (
                    row.first_listed_at.isoformat() if row and row.first_listed_at else None
                ),
                "last_checked_at": (
                    row.last_checked_at.isoformat() if row and row.last_checked_at else None
                ),
                # Populated here too, not just on the per-listing route: a
                # delisting date is the single most useful field on a
                # reputation panel, and declaring it on the schema while
                # never filling it in is worse than omitting it.
                "resolved_at": (row.resolved_at.isoformat() if row and row.resolved_at else None),
            }
        )
    listed_count = sum(1 for e in entries if e["listed"])
    return DNSBLListingsByIP.model_validate(
        {"ip": ip, "listed_count": listed_count, "entries": entries}
    )


@router.post("/check", response_model=DNSBLCheckResult)
@token_write(
    "Queries DNSBL zones through the configured resolvers (outbound) and writes an audit row"
)
async def check_now(body: DNSBLCheckRequest, db: DB, user: CurrentUser) -> DNSBLCheckResult:
    """On-demand reputation check of one IP across every enabled list."""
    from app.services.dnsbl.sweep import check_ip_now  # noqa: PLC0415

    ip = _norm_ip(body.ip)
    settings = await db.get(PlatformSettings, _SINGLETON_ID)
    resolvers = settings.dnsbl_query_resolvers if settings else None
    result = await check_ip_now(db, ip, resolvers=resolvers or None)
    write_audit(
        db,
        user=user,
        action="check",
        resource_type="dnsbl",
        resource_id=ip,
        resource_display=ip,
        new_value={"checked": result.get("checked"), "listed": result.get("listed")},
    )
    await db.commit()
    return DNSBLCheckResult.model_validate(result)


# ── Settings ────────────────────────────────────────────────────────


@router.get("/settings", response_model=DNSBLSettingsRead)
async def get_settings(db: DB, _: CurrentUser) -> DNSBLSettingsRead:
    ps = await db.get(PlatformSettings, _SINGLETON_ID)
    if ps is None:
        raise HTTPException(status_code=404, detail="platform settings not initialised")
    return DNSBLSettingsRead(
        dnsbl_monitoring_enabled=ps.dnsbl_monitoring_enabled,
        dnsbl_check_interval_hours=ps.dnsbl_check_interval_hours,
        dnsbl_query_resolvers=ps.dnsbl_query_resolvers,
        dnsbl_sweep_last_run_at=ps.dnsbl_sweep_last_run_at,
    )


@router.put("/settings", response_model=DNSBLSettingsRead)
async def update_settings(
    body: DNSBLSettingsUpdate, db: DB, user: CurrentUser
) -> DNSBLSettingsRead:
    ps = await db.get(PlatformSettings, _SINGLETON_ID)
    if ps is None:
        raise HTTPException(status_code=404, detail="platform settings not initialised")
    data = body.model_dump(exclude_unset=True)
    changed: list[str] = []
    for field_name, value in data.items():
        if getattr(ps, field_name) != value:
            setattr(ps, field_name, value)
            changed.append(field_name)
    if changed:
        write_audit(
            db,
            user=user,
            action="update",
            resource_type="dnsbl",
            resource_id="settings",
            resource_display="DNSBL settings",
            changed_fields=changed,
        )
    await db.commit()
    return DNSBLSettingsRead(
        dnsbl_monitoring_enabled=ps.dnsbl_monitoring_enabled,
        dnsbl_check_interval_hours=ps.dnsbl_check_interval_hours,
        dnsbl_query_resolvers=ps.dnsbl_query_resolvers,
        dnsbl_sweep_last_run_at=ps.dnsbl_sweep_last_run_at,
    )
