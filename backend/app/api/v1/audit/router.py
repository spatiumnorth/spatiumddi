"""Audit log read endpoints (superadmin or users with `read:audit_log`)."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select

from app.api.deps import DB
from app.core.permissions import require_permission
from app.core.responses import PdfResponse
from app.models.audit import AuditLog
from app.services.audit_chain import verify_chain
from app.services.audit_report import generate_change_report_pdf

router = APIRouter(dependencies=[Depends(require_permission("read", "audit_log"))])


class AuditLogResponse(BaseModel):
    id: str
    # A real ``datetime``, not a pre-formatted string (#907). Typed as ``str``
    # it published as a bare ``type: string`` with no ``format: date-time`` —
    # so a generated client read the API's most audit-relevant timestamp as
    # text — and it went out in ``isoformat()``'s six-digit ``+00:00`` shape
    # while every other timestamp in the API is millisecond ``Z``.
    timestamp: datetime
    user_display_name: str
    auth_source: str
    action: str
    resource_type: str
    resource_id: str
    resource_display: str
    result: str
    source_ip: str | None = None

    model_config = {"from_attributes": True}

    @field_validator("id", mode="before")
    @classmethod
    def coerce_id(cls, v: object) -> str:
        return str(v)


class AuditLogPage(BaseModel):
    total: int
    items: list[AuditLogResponse]


@router.get("", response_model=AuditLogPage)
async def list_audit_log(
    db: DB,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    user_display_name: str | None = Query(default=None),
    resource_display: str | None = Query(default=None),
    result: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
) -> AuditLogPage:
    q = select(AuditLog)

    if action:
        q = q.where(AuditLog.action == action)
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if user_display_name:
        q = q.where(AuditLog.user_display_name.ilike(f"%{user_display_name}%"))
    if resource_display:
        q = q.where(AuditLog.resource_display.ilike(f"%{resource_display}%"))
    if result:
        q = q.where(AuditLog.result == result)
    if source_ip:
        q = q.where(AuditLog.source_ip.ilike(f"%{source_ip}%"))

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)
    rows = (await db.execute(q)).scalars().all()

    return AuditLogPage(total=total, items=list(rows))


# ── Compliance / change report PDF (issue #48) ──────────────────────


@router.get(
    "/export.pdf",
    # Declared media type, not just the wire header: FastAPI documents a bare
    # `-> Response` as application/json, so the (correctly sent)
    # application/pdf was undocumented and schema-conformance clients flagged
    # every response (schemathesis UndefinedContentType, 13/13 runs).
    # ``response_class`` rather than a ``responses={200: {"content": ...}}``
    # entry (#921): that entry MERGES with the inferred application/json, so
    # the route still declared a JSON body it never produces.
    response_class=PdfResponse,
    responses={200: {"description": "PDF change report"}},
)
async def export_change_report_pdf(
    db: DB,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
) -> Response:
    """Auditor-facing PDF rollup of every audit-log mutation in a date
    range, grouped by user / resource type / action, with a SHA-256
    tamper-evidence trailer. Defaults to the last 30 days. Gated by the
    router-level ``read:audit_log`` permission."""
    now = datetime.now(UTC)
    until = until or now
    # Coerce naive client-supplied datetimes to UTC so the comparison
    # against the timezone-aware ``timestamp`` column is well-defined.
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    if since is None:
        # #1201: an ``until`` within 30 days of year 1 steps the default
        # before ``datetime.min``, which raises OverflowError, a 500. "The 30
        # days before it" then means everything, so start at the earliest
        # instant a datetime holds.
        try:
            since = until - timedelta(days=30)
        except OverflowError:
            since = datetime.min.replace(tzinfo=UTC)
    elif since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    pdf_bytes = await generate_change_report_pdf(db, since=since, until=until)
    fname = f"spatiumddi-change-report-{now.strftime('%Y%m%d-%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Tamper-evidence verifier (issue #73) ────────────────────────────


class ChainBreakResponse(BaseModel):
    seq: int
    audit_id: str
    expected_hash: str
    actual_hash: str
    reason: str


class IntegrityResponse(BaseModel):
    """Result of running the chain verifier across the audit log.

    ``ok`` is the bottom line — the headline pill on the Audit page.
    ``rows_checked`` lets the operator confirm the verifier saw the
    full table (vs. a half-finished spot check). ``breaks`` is empty
    when ``ok`` is True and lists every tampered row otherwise; the
    UI surfaces a quick-jump link from each break to the
    ``audit/{seq}`` row in the table.
    """

    ok: bool
    rows_checked: int
    breaks: list[ChainBreakResponse]


@router.get("/integrity", response_model=IntegrityResponse)
async def get_audit_integrity(
    db: DB,
    max_rows: int | None = Query(
        default=None,
        ge=1,
        description=(
            "Cap the number of rows checked. Useful on huge tables where "
            "the full walk is expensive — leave unset for a complete sweep."
        ),
    ),
) -> IntegrityResponse:
    """Walk the audit_log chain and report any tamper. Slow on tables
    past ~1M rows — the nightly Celery task pre-computes the same
    answer and writes an alert event when it breaks, so the UI hit
    is mostly for ad-hoc operator confirmation."""
    result = await verify_chain(db, max_rows=max_rows)
    return IntegrityResponse(
        ok=result.ok,
        rows_checked=result.rows_checked,
        breaks=[
            ChainBreakResponse(
                seq=b.seq,
                audit_id=b.audit_id,
                expected_hash=b.expected_hash,
                actual_hash=b.actual_hash,
                reason=b.reason,
            )
            for b in result.breaks
        ],
    )
