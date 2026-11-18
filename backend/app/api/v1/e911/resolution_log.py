"""E911 resolution trail — read surface (#3598).

* ``GET /e911/resolution-log`` — filterable, paginated list, newest first.
* ``GET /e911/resolution-log/export.csv`` — the same filters, as CSV.

Gated on its own ``e911_resolution_log`` resource type, NOT on
``e911_location``: the trail says who asked where which device is, so the PBX
account that holds ``e911_location: read`` to do lookups must not be able to
read other people's. No builtin role names it, so by default it is a
superadmin (or a wildcard ``read *`` Viewer) read. Every read, including each
page of the list, writes an ``audit_log`` row. Nothing here writes the trail.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel

from app.api.deps import DB, CurrentUser
from app.core.content_disposition import content_disposition
from app.core.permissions import require_resource_permission
from app.core.responses import CsvResponse
from app.services.e911.resolution_trail import (
    EXPORT_ROW_CAP,
    TrailFilters,
    TrailRow,
    audit_trail_read,
    list_trail,
    render_trail_csv,
)

router = APIRouter(
    tags=["e911"],
    dependencies=[Depends(require_resource_permission("e911_resolution_log"))],
)


class ResolutionLogRead(BaseModel):
    id: uuid.UUID
    #: ``lookup`` or ``counter`` (an aggregated "N lookups not individually logged" row).
    kind: Literal["lookup", "counter"]
    queried_at: datetime
    identity_kind: str
    identity_value: str
    actor_kind: str
    actor_id: uuid.UUID | None
    actor_label: str | None
    source_ip: str | None
    erl_id: uuid.UUID | None
    erl_name: str | None
    rule_matched: str | None
    confidence: str
    degraded_reason: str | None
    evidence_age_seconds: int | None
    window_start: datetime | None
    suppressed_count: int | None


class ResolutionLogList(BaseModel):
    items: list[ResolutionLogRead]
    total: int
    limit: int
    offset: int


def _read(t: TrailRow) -> ResolutionLogRead:
    r = t.row
    return ResolutionLogRead(
        id=r.id,
        kind=t.kind,  # type: ignore[arg-type]
        queried_at=r.queried_at,
        identity_kind=r.identity_kind,
        identity_value=r.identity_value,
        actor_kind=r.actor_kind,
        actor_id=r.actor_id,
        actor_label=t.actor_label,
        source_ip=str(r.source_ip) if r.source_ip is not None else None,
        erl_id=r.erl_id,
        erl_name=t.erl_name,
        rule_matched=r.rule_matched,
        confidence=r.confidence,
        degraded_reason=r.degraded_reason,
        evidence_age_seconds=r.evidence_age_seconds,
        window_start=r.window_start,
        suppressed_count=r.suppressed_count,
    )


def _filters(
    identity: str | None = Query(None, max_length=255, description="Substring of IP / MAC / port"),
    identity_kind: Literal["ip", "mac", "chassis_port"] | None = Query(None),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None, description="Exclusive upper bound"),
    actor_id: uuid.UUID | None = Query(None, description="User or API token id"),
    actor_kind: Literal["user", "api_token", "device_self"] | None = Query(None),
    confidence: Literal["observed", "degraded", "none"] | None = Query(None),
    erl_id: uuid.UUID | None = Query(None),
    kind: Literal["lookup", "counter"] | None = Query(None),
) -> TrailFilters:
    return TrailFilters(
        identity=identity or None,
        identity_kind=identity_kind,
        since=since,
        until=until,
        actor_id=actor_id,
        actor_kind=actor_kind,
        confidence=confidence,
        erl_id=erl_id,
        kind=kind,
    )


@router.get("/resolution-log", response_model=ResolutionLogList)
async def list_resolution_log(
    db: DB,
    user: CurrentUser,
    filters: TrailFilters = Depends(_filters),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> ResolutionLogList:
    rows, total = await list_trail(db, filters, limit=limit, offset=offset)
    audit_trail_read(db, user, action="read", filters=filters, returned=len(rows))
    await db.commit()
    return ResolutionLogList(
        items=[_read(t) for t in rows], total=total, limit=limit, offset=offset
    )


@router.get("/resolution-log/export.csv", response_class=CsvResponse)
async def export_resolution_log_csv(
    db: DB,
    user: CurrentUser,
    filters: TrailFilters = Depends(_filters),
) -> Response:
    """The trail as CSV, newest first, capped at :data:`EXPORT_ROW_CAP` rows."""
    rows, _total = await list_trail(db, filters, limit=EXPORT_ROW_CAP, offset=0)
    audit_trail_read(db, user, action="export", filters=filters, returned=len(rows))
    await db.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Response(
        content=render_trail_csv(rows),
        media_type="text/csv",
        headers={"Content-Disposition": content_disposition(f"e911-resolution-log-{stamp}.csv")},
    )
