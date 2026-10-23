"""Restore-verification drill endpoints (issue #702).

Mounted at ``/backup/drills`` by the parent backup router. All
gated to superadmin, matching the rest of the backup surface: a
drill result names the destination and the archive, which is the
same class of metadata the targets endpoints protect.

Drills are read-mostly — the schedule itself lives on the backup
target (``drill_enabled`` / ``drill_cron``, set through
``PATCH /backup/targets/{id}``), so the only mutation here is the
manual "run one now" kick.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select

from app.api.deps import DB, SuperAdmin
from app.core.demo_mode import forbid_in_demo_mode
from app.models.backup import BackupTarget, RestoreDrill
from app.services.backup.drill import (
    compute_drill_readiness,
    drill_mutex_is_stale,
    run_drill_for_target,
)

router = APIRouter()


class RestoreDrillResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    target_name: str | None = None
    state: str
    triggered_by: str
    filename: str | None
    archive_bytes: int | None
    manifest: dict[str, Any] | None
    scratch_db: str | None
    assertions: list[dict[str, Any]]
    error: str | None
    started_at: datetime
    finished_at: datetime | None
    duration_ms: int | None


def _to_response(row: RestoreDrill, *, target_name: str | None = None) -> RestoreDrillResponse:
    return RestoreDrillResponse(
        id=row.id,
        target_id=row.target_id,
        target_name=target_name,
        state=row.state,
        triggered_by=row.triggered_by,
        filename=row.filename,
        archive_bytes=row.archive_bytes,
        manifest=row.manifest,
        scratch_db=row.scratch_db,
        assertions=row.assertions or [],
        error=row.error,
        started_at=row.started_at,
        finished_at=row.finished_at,
        duration_ms=row.duration_ms,
    )


@router.get("", response_model=list[RestoreDrillResponse])
async def list_drills(
    db: DB,
    current_user: SuperAdmin,
    target_id: uuid.UUID | None = Query(default=None),
    state: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[RestoreDrillResponse]:
    """Recent drills, newest first, optionally scoped to one target."""
    stmt = (
        select(RestoreDrill, BackupTarget.name)
        .join(BackupTarget, BackupTarget.id == RestoreDrill.target_id)
        .order_by(desc(RestoreDrill.started_at))
        .limit(limit)
    )
    if target_id is not None:
        stmt = stmt.where(RestoreDrill.target_id == target_id)
    if state is not None:
        stmt = stmt.where(RestoreDrill.state == state)
    rows = (await db.execute(stmt)).all()
    return [_to_response(row, target_name=name) for row, name in rows]


class DrillReadinessSummary(BaseModel):
    """Per-target recovery readiness — "can I restore this, and how do I know?".

    ``verified_targets`` counts targets with a *proven* restore, not targets
    with a backup: an unverified archive is a hypothesis, and reporting the
    two as one number is how a restore fails on the day it matters.
    """

    targets: list[dict[str, Any]]
    total_targets: int
    verified_targets: int
    unverified_targets: int


@router.get("/readiness", response_model=DrillReadinessSummary)
async def get_readiness(db: DB, current_user: SuperAdmin) -> DrillReadinessSummary:
    """Per-target recovery readiness — "can I restore this, and how do
    I know?".

    Registered before ``/{drill_id}`` so the literal path isn't
    swallowed by the UUID route. Shares
    :func:`compute_drill_readiness` with the Operator Copilot tool, so
    the UI and the assistant can't disagree about whether a backup is
    proven.
    """
    rows = await compute_drill_readiness(db)
    verified = sum(1 for r in rows if r["verified"])
    return DrillReadinessSummary(
        targets=rows,
        total_targets=len(rows),
        verified_targets=verified,
        unverified_targets=len(rows) - verified,
    )


@router.get("/{drill_id}", response_model=RestoreDrillResponse)
async def get_drill(drill_id: uuid.UUID, db: DB, current_user: SuperAdmin) -> RestoreDrillResponse:
    row = await db.get(RestoreDrill, drill_id)
    if row is None:
        raise HTTPException(status_code=404, detail="restore drill not found")
    target = await db.get(BackupTarget, row.target_id)
    return _to_response(row, target_name=target.name if target else None)


@router.post("/run/{target_id}", response_model=RestoreDrillResponse)
async def run_drill_now(
    target_id: uuid.UUID, db: DB, current_user: SuperAdmin
) -> RestoreDrillResponse:
    """Run one drill against this target now.

    Synchronous — blocks until the archive is downloaded, replayed
    into a scratch database, asserted against, and the scratch
    database dropped. That can take as long as a real restore on a
    large install; the UI polls the row rather than holding the
    request open where it matters.
    """
    forbid_in_demo_mode("restore drills")

    # A drill replays into a throwaway database and never writes to
    # the live one, so it is safe alongside most operations — but a
    # rolling upgrade moves the schema underneath the assertions,
    # which would produce a confusing false verdict.
    from app.services.upgrades.safety import (  # noqa: PLC0415
        assert_no_upgrade_in_flight,
    )

    await assert_no_upgrade_in_flight(db, operation_hint="restore drill")

    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    # Same staleness escape the sweep applies. Without it, a mutex
    # stranded by an api restart or a client disconnect would 409 this
    # endpoint forever with no operator-reachable way to clear the flag
    # (``drill_last_status`` isn't writable through the target API).
    if row.drill_last_status == "in_progress" and not drill_mutex_is_stale(row, datetime.now(UTC)):
        raise HTTPException(
            status_code=409,
            detail="a drill is already running against this target",
        )

    # The runner writes the audit row itself so scheduled drills are
    # audited on the same path — see ``run_drill_for_target``.
    drill = await run_drill_for_target(
        db,
        target=row,
        triggered_by="manual",
        actor_id=current_user.id,
        actor_display=current_user.username,
    )
    await db.commit()
    await db.refresh(drill)
    return _to_response(drill, target_name=row.name)
