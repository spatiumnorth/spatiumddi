"""Operator Copilot tools — diagnostics / uncaught exceptions
(issue #123).

Read-only surface over the ``internal_error`` table. The matching
REST endpoints in ``app.api.v1.diagnostics.router`` are
superadmin-only because tracebacks may carry internal paths +
sanitised-but-still-sensitive request context; these tools mirror
that gating with the same `_superadmin_gate` shape used by
``app/services/ai/tools/admin.py``.

Per CLAUDE.md non-negotiable #13, these tools are
**default-disabled** — operationally-sensitive surface that an
operator should explicitly opt into. Superadmins who want to ask
"what's been crashing?" through the chat flip them on in
Settings → AI → Tool Catalog.

No write proposals here. Acknowledge / suppress / delete are
deliberate operator decisions; the chat is the wrong UX for them
and the buttons sit right on the admin page.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.models.diagnostics import InternalError
from app.services.ai.tools.base import register_tool
from app.services.dns_names_report import scan_name_conformance


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "This tool exposes uncaught exception tracebacks + "
                "sanitised request context, so it's restricted to "
                "superadmin users. Ask your platform admin to run the "
                "query, or open Admin → Diagnostics → Errors directly."
            )
        }
    return None


def _row_to_summary(row: InternalError) -> dict[str, Any]:
    """Light shape — leaves traceback + context_json out so chat
    transcripts stay readable. Operators drill into the admin page
    for the full dump.
    """
    is_acked = row.acknowledged_by is not None
    is_suppressed = row.suppressed_until is not None and row.suppressed_until > datetime.now(UTC)
    return {
        "id": str(row.id),
        "service": row.service,
        "exception_class": row.exception_class,
        "message": row.message,
        "route_or_task": row.route_or_task,
        "occurrence_count": row.occurrence_count,
        "last_seen_at": row.last_seen_at.isoformat(),
        "first_seen_at": row.timestamp.isoformat(),
        "fingerprint": row.fingerprint,
        "state": "acked" if is_acked else "suppressed" if is_suppressed else "open",
    }


# ── find_internal_errors ──────────────────────────────────────────────


class FindInternalErrorsArgs(BaseModel):
    service: str | None = Field(
        default=None,
        description="Filter by service: api / worker / beat. Omit for all.",
    )
    acknowledged: str | None = Field(
        default=None,
        description="'yes' / 'no' — filter by ack state. Omit for all.",
    )
    since_hours: int | None = Field(
        default=None,
        ge=1,
        le=24 * 30,
        description="Only return errors seen in the last N hours.",
    )
    exception_class: str | None = Field(
        default=None,
        description="Exact match on the dotted class name (e.g. 'sqlalchemy.exc.IntegrityError').",
    )
    limit: int = Field(default=20, ge=1, le=200)


@register_tool(
    name="find_internal_errors",
    permission="superadmin",
    description=(
        "List uncaught Python exceptions captured from the API + "
        "Celery workers (superadmin only). Each row carries service, "
        "exception class, one-line message, route or task, occurrence "
        "count, last-seen timestamp, fingerprint, and state "
        "(open / acked / suppressed). Use for 'what's been crashing "
        "today?', 'show me unacked worker errors', or 'is anything "
        "still throwing IntegrityError?'. Tracebacks + request context "
        "are NOT included here — call ``get_internal_error`` for "
        "those."
    ),
    args_model=FindInternalErrorsArgs,
    category="ops",
    default_enabled=False,
)
async def find_internal_errors(
    db: AsyncSession,
    user: User,
    args: FindInternalErrorsArgs,
) -> list[dict[str, Any]]:
    gate = _superadmin_gate(user)
    if gate:
        return [gate]
    stmt = select(InternalError).order_by(desc(InternalError.last_seen_at))
    if args.service:
        stmt = stmt.where(InternalError.service == args.service)
    if args.acknowledged == "yes":
        stmt = stmt.where(InternalError.acknowledged_by.isnot(None))
    elif args.acknowledged == "no":
        stmt = stmt.where(InternalError.acknowledged_by.is_(None))
    if args.since_hours is not None:
        cutoff = datetime.now(UTC) - timedelta(hours=args.since_hours)
        stmt = stmt.where(InternalError.last_seen_at >= cutoff)
    if args.exception_class:
        stmt = stmt.where(InternalError.exception_class == args.exception_class)
    stmt = stmt.limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_row_to_summary(r) for r in rows]


# ── count_internal_errors ─────────────────────────────────────────────


class CountInternalErrorsArgs(BaseModel):
    service: str | None = Field(default=None, description="api / worker / beat.")
    acknowledged: str | None = Field(default=None, description="'yes' / 'no'.")
    since_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    exception_class: str | None = Field(default=None)


@register_tool(
    name="count_internal_errors",
    permission="superadmin",
    description=(
        "Count uncaught exceptions matching a filter (superadmin "
        "only). Returns ``{count, total_occurrences}`` — distinct "
        "fingerprints vs. cumulative occurrence count. Use for "
        "headline summaries: 'how many distinct crashes did we see "
        "this week?' / 'how noisy is the worker right now?'."
    ),
    args_model=CountInternalErrorsArgs,
    category="ops",
    default_enabled=False,
)
async def count_internal_errors(
    db: AsyncSession,
    user: User,
    args: CountInternalErrorsArgs,
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate
    stmt_count = select(
        func.count().label("c"),
        func.coalesce(func.sum(InternalError.occurrence_count), 0).label("total"),
    )
    if args.service:
        stmt_count = stmt_count.where(InternalError.service == args.service)
    if args.acknowledged == "yes":
        stmt_count = stmt_count.where(InternalError.acknowledged_by.isnot(None))
    elif args.acknowledged == "no":
        stmt_count = stmt_count.where(InternalError.acknowledged_by.is_(None))
    if args.since_hours is not None:
        cutoff = datetime.now(UTC) - timedelta(hours=args.since_hours)
        stmt_count = stmt_count.where(InternalError.last_seen_at >= cutoff)
    if args.exception_class:
        stmt_count = stmt_count.where(InternalError.exception_class == args.exception_class)
    row = (await db.execute(stmt_count)).first()
    return {
        "count": int(row.c) if row else 0,
        "total_occurrences": int(row.total) if row else 0,
    }


# ── get_internal_error ────────────────────────────────────────────────


class GetInternalErrorArgs(BaseModel):
    id: str = Field(
        ...,
        description="UUID of the internal_error row (from ``find_internal_errors``).",
    )


@register_tool(
    name="get_internal_error",
    permission="superadmin",
    description=(
        "Return the full record for a single uncaught exception "
        "(superadmin only): traceback + sanitised request/task "
        "context_json + ack state + suppression window. Use after "
        "``find_internal_errors`` to drill into a specific crash. "
        "Tracebacks may carry internal file paths; redirect off-prem "
        "providers to the admin UI rather than echoing the full dump "
        "in chat where appropriate."
    ),
    args_model=GetInternalErrorArgs,
    category="ops",
    default_enabled=False,
)
async def get_internal_error(
    db: AsyncSession,
    user: User,
    args: GetInternalErrorArgs,
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate
    try:
        row_id = uuid.UUID(args.id)
    except (ValueError, AttributeError):
        return {"error": f"'{args.id}' is not a valid UUID"}
    row = await db.get(InternalError, row_id)
    if row is None:
        return {"error": f"no internal_error with id {args.id}"}
    summary = _row_to_summary(row)
    summary["traceback"] = row.traceback
    summary["context_json"] = row.context_json
    summary["request_id"] = row.request_id
    summary["acknowledged_at"] = row.acknowledged_at.isoformat() if row.acknowledged_at else None
    summary["acknowledged_by"] = str(row.acknowledged_by) if row.acknowledged_by else None
    summary["suppressed_until"] = row.suppressed_until.isoformat() if row.suppressed_until else None
    return summary


# ── find_nonconforming_names ──────────────────────────────────────────


class FindNonconformingNamesArgs(BaseModel):
    pass


@register_tool(
    name="find_nonconforming_names",
    permission="superadmin",
    description=(
        "Report existing names that violate DNS naming rules "
        "(issue #597, superadmin only). Scans IPAM hostnames, DNS "
        "record owners, DNS zone names, and DHCP static reservation "
        "hostnames for values the write-time validators now reject — "
        "spaces, control characters, illegal punctuation, "
        "over-length labels, etc. Returns per-category counts plus "
        "up to 100 examples each (id + value + reason). Read-only; "
        "fixes are made by editing the offending rows. Use for 'which "
        "hostnames aren't valid DNS names?' / 'do we have any records "
        "that would break a zone file?'."
    ),
    args_model=FindNonconformingNamesArgs,
    category="ops",
    default_enabled=True,
)
async def find_nonconforming_names(
    db: AsyncSession,
    user: User,
    args: FindNonconformingNamesArgs,
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate:
        return gate
    return await scan_name_conformance(db)
