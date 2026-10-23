"""Diagnostics — uncaught exception viewer (issue #123).

All endpoints are gated to ``is_superadmin``. Tracebacks may carry
internal paths + sanitised-but-still-sensitive context; we don't want
delegated department admins picking that up. A dedicated
``diagnostics:read`` permission can land later if operators need
auditor-style access — for now superadmin is the right blast radius.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select

from app.api.deps import DB, SuperAdmin
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.diagnostics import InternalError
from app.services.dns_names_report import scan_name_conformance

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────


class InternalErrorResponse(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    service: str
    kind: str
    request_id: str | None
    route_or_task: str | None
    exception_class: str
    message: str
    traceback: str
    context_json: dict[str, Any]
    fingerprint: str
    occurrence_count: int
    last_seen_at: datetime
    acknowledged_by: uuid.UUID | None
    acknowledged_at: datetime | None
    suppressed_until: datetime | None

    class Config:
        from_attributes = True


class InternalErrorListItem(BaseModel):
    """Lighter shape for the list view — leaves traceback +
    context_json out so the table query stays fast on installs with
    thousands of rows. The detail endpoint carries the full payload.
    """

    id: uuid.UUID
    timestamp: datetime
    service: str
    kind: str
    route_or_task: str | None
    exception_class: str
    message: str
    fingerprint: str
    occurrence_count: int
    last_seen_at: datetime
    acknowledged_by: uuid.UUID | None
    acknowledged_at: datetime | None
    suppressed_until: datetime | None

    class Config:
        from_attributes = True


class InternalErrorStats(BaseModel):
    total: int
    unacknowledged: int
    # Unacked errors with ``occurrence_count >= 5`` in the last 24 h.
    # Drives the floating banner on the admin pages.
    noisy_unacked: int


# ── Endpoints ──────────────────────────────────────────────────────────


@router.get("/errors", response_model=list[InternalErrorListItem])
async def list_errors(
    db: DB,
    current_user: SuperAdmin,
    service: str | None = Query(None, description="api / worker / beat"),
    acknowledged: str | None = Query(
        None,
        description="yes / no / all (default: all)",
    ),
    since_hours: int | None = Query(
        None,
        ge=1,
        le=24 * 30,
        description="filter to errors with last_seen_at within the last N hours",
    ),
    exception_class: str | None = Query(
        None,
        description="exact match on the dotted class name",
    ),
    limit: int = Query(200, ge=1, le=500),
) -> list[InternalError]:
    stmt = select(InternalError).order_by(desc(InternalError.last_seen_at))
    if service:
        stmt = stmt.where(InternalError.service == service)
    if acknowledged == "yes":
        stmt = stmt.where(InternalError.acknowledged_by.isnot(None))
    elif acknowledged == "no":
        stmt = stmt.where(InternalError.acknowledged_by.is_(None))
    if since_hours is not None:
        cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
        stmt = stmt.where(InternalError.last_seen_at >= cutoff)
    if exception_class:
        stmt = stmt.where(InternalError.exception_class == exception_class)
    stmt = stmt.limit(limit)
    return list((await db.execute(stmt)).scalars().all())


@router.get("/errors/stats", response_model=InternalErrorStats)
async def error_stats(
    db: DB,
    current_user: SuperAdmin,
) -> InternalErrorStats:
    total = (await db.execute(select(func.count()).select_from(InternalError))).scalar_one()
    unack = (
        await db.execute(
            select(func.count())
            .select_from(InternalError)
            .where(InternalError.acknowledged_by.is_(None))
        )
    ).scalar_one()
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    noisy = (
        await db.execute(
            select(func.count())
            .select_from(InternalError)
            .where(
                InternalError.acknowledged_by.is_(None),
                InternalError.occurrence_count >= 5,
                InternalError.last_seen_at >= cutoff,
            )
        )
    ).scalar_one()
    return InternalErrorStats(total=total, unacknowledged=unack, noisy_unacked=noisy)


@router.get("/errors/{error_id}", response_model=InternalErrorResponse)
async def get_error(
    error_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> InternalError:
    row = await db.get(InternalError, error_id)
    if row is None:
        raise HTTPException(status_code=404, detail="error not found")
    return row


def _audit_error(
    action: str, row: InternalError, user: User, *, extra: dict[str, Any] | None = None
) -> AuditLog:
    """One audit row for a mutation of a captured error (#2301). Carries
    the fingerprint and exception class; never the traceback."""
    return AuditLog(
        action=action,
        resource_type="internal_error",
        resource_id=str(row.id),
        resource_display=f"{row.exception_class} ({row.fingerprint[:12]})",
        user_id=user.id,
        user_display_name=user.username,
        result="success",
        new_value={
            "fingerprint": row.fingerprint,
            "exception_class": row.exception_class,
            "service": row.service,
            **(extra or {}),
        },
    )


class AcknowledgeRequest(BaseModel):
    note: str | None = Field(None, max_length=500)


@router.post("/errors/{error_id}/acknowledge", response_model=InternalErrorResponse)
async def acknowledge_error(
    error_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> InternalError:
    row = await db.get(InternalError, error_id)
    if row is None:
        raise HTTPException(status_code=404, detail="error not found")
    if row.acknowledged_by is None:
        row.acknowledged_by = current_user.id
        row.acknowledged_at = datetime.now(UTC)
        db.add(_audit_error("acknowledge", row, current_user))
        await db.commit()
        await db.refresh(row)
    return row


class SuppressRequest(BaseModel):
    hours: int = Field(24, ge=1, le=24 * 30)


@router.post("/errors/{error_id}/suppress", response_model=InternalErrorResponse)
async def suppress_error(
    error_id: uuid.UUID,
    body: SuppressRequest,
    db: DB,
    current_user: SuperAdmin,
) -> InternalError:
    """Silence the matching fingerprint for ``hours``. While the
    suppression window is active the capture loop still bumps
    ``occurrence_count`` on the existing row, but no new rows are
    inserted. The "Suppress 24h" button in the admin viewer hits
    this with ``hours=24``.
    """
    row = await db.get(InternalError, error_id)
    if row is None:
        raise HTTPException(status_code=404, detail="error not found")
    row.suppressed_until = datetime.now(UTC) + timedelta(hours=body.hours)
    db.add(
        _audit_error(
            "suppress",
            row,
            current_user,
            extra={"hours": body.hours, "suppressed_until": row.suppressed_until.isoformat()},
        )
    )
    await db.commit()
    await db.refresh(row)
    return row


@router.delete("/errors/{error_id}", status_code=204)
async def delete_error(
    error_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> None:
    row = await db.get(InternalError, error_id)
    if row is None:
        raise HTTPException(status_code=404, detail="error not found")
    db.add(
        _audit_error("delete", row, current_user, extra={"occurrence_count": row.occurrence_count})
    )
    await db.delete(row)
    await db.commit()


class NameConformanceExample(BaseModel):
    """One offending value. ``context`` is present for categories where the
    value alone is ambiguous (a record owner needs its zone)."""

    id: str
    value: str
    reason: str
    context: str | None = None


class NameConformanceCategory(BaseModel):
    category: str
    #: Exact count — only ``examples`` is truncated.
    total: int
    #: True when the scan hit its own row cap, so ``total`` is a floor rather
    #: than the whole picture.
    scanned_capped: bool
    examples: list[NameConformanceExample]


class NameConformanceReport(BaseModel):
    total_nonconforming: int
    examples_per_category: int
    categories: list[NameConformanceCategory]


@router.get("/name-conformance", response_model=NameConformanceReport)
async def name_conformance(
    db: DB,
    current_user: SuperAdmin,
) -> NameConformanceReport:
    """Report existing names that the #597 DNS-name validators would reject.

    Read-only. The validators reject non-conforming names on write, but
    pre-existing rows are left untouched — this surfaces them (IPAM
    hostnames, DNS record owners, DNS zone names, DHCP static hostnames)
    so an operator can fix them deliberately. Nothing is mutated.
    """
    return NameConformanceReport.model_validate(await scan_name_conformance(db))
