"""Multi-node rolling upgrades — operator surface (#296 Phases A + D).

Mounted at ``/api/v1/upgrades``.

Read-only (Phase A):

    GET   /preflight?target=<release-tag>  — run safety checks; no
                                              writes; no lease acquired.
    GET   /lease                           — current mutex state for
                                              surfacing "an upgrade is
                                              in flight" on the Fleet UI.

State-machine endpoints (Phase D):

    POST  /plan                            — preflight + node-order +
                                              persist a ``planned`` run.
    POST  /{run_id}/start                  — acquire the lease + enqueue
                                              the orchestrator task.
    POST  /{run_id}/halt                   — operator pause (resumable).
    POST  /{run_id}/resume                 — re-enqueue the task.
    POST  /{run_id}/abort                  — terminal cancel.
    GET   /{run_id}                        — single run detail.
    GET   /runs                            — most-recent-first history.

All mutations are gated on ``admin appliance``; reads on
``read appliance``. The Fleet UI's Upgrades tab calls these directly
+ polls ``GET /{run_id}`` for live per-node progress.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_permission
from app.services.appliance.slot_image_target import (
    SlotImageResolutionError,
    SlotImageTarget,
    new_refire_nonce,
    resolve_slot_image_target,
)
from app.services.upgrades import mutex, orchestrator, preflight

logger = structlog.get_logger(__name__)

router = APIRouter()


# ── Preflight + lease (Phase A — unchanged) ──────────────────────────


class PreflightCheckOut(BaseModel):
    name: str
    level: str = Field(description="ok | warn | fail")
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)


class PreflightReportOut(BaseModel):
    target_version: str
    current_version: str
    overall: str = Field(description="worst level across results")
    can_start: bool = Field(description="overall != 'fail'")
    results: list[PreflightCheckOut]


class LeaseStateOut(BaseModel):
    held: bool
    holder: str | None
    renew_time: str | None
    transitions: int
    expired: bool


@router.get(
    "/preflight",
    response_model=PreflightReportOut,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Run pre-flight safety checks for a rolling upgrade to <target>",
)
async def get_preflight(target: str) -> PreflightReportOut:
    if not target or len(target) > 64:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "target must be a 1-64 char release tag (e.g. 2026.06.01-1 or 1.0.0)",
        )
    report = await preflight.run_all(target_version=target)
    return PreflightReportOut(**report.to_dict())


@router.get(
    "/lease",
    response_model=LeaseStateOut,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Current state of the cluster-wide upgrade mutex",
)
async def get_lease_state() -> LeaseStateOut:
    state = mutex.get_state()
    return LeaseStateOut(
        held=state.held,
        holder=state.holder,
        renew_time=state.renew_time,
        transitions=state.transitions,
        expired=state.expired,
    )


# ── Phase D — orchestrator state-machine endpoints ───────────────────


class PlanRequest(BaseModel):
    """Plan a cluster-wide rolling upgrade.

    Two source modes for the slot image — exactly one of them must be
    supplied. Same shape as ``POST /appliances/{id}/upgrade`` (the per-
    box per-appliance scheduler in supervisor.py); kept in sync so
    operators see the same affordances on both surfaces:

    * **External URL** (``slot_image_url``) — caller provides the
      ``http(s)://…/raw.xz`` URL spatium-upgrade-slot apply will pull
      from on each node. Used in connected environments where every
      appliance can reach github.com (or a private mirror) directly.

    * **Uploaded image** (``slot_image_id``) — an
      ``appliance_upgrade_image`` row id from
      ``POST /api/v1/appliance/upgrade-images`` (the air-gap upload
      endpoint). The control plane composes the authenticated internal
      URL on plan-acceptance, so every per-node runner pulls bytes
      through the same control-plane → mirror path the per-box flow
      uses. Air-gap-friendly: no per-node egress.

    The version label is always required so preflight's version_path
    check can compare release versions + auto-clear logic on the appliance
    row can detect "installed matches desired" without sniffing the
    binary.
    """

    target_version: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Release tag the cluster will be upgraded to: CalVer "
            "(2026.06.01-1) before 1.0.0, SemVer (1.0.0) from it."
        ),
    )
    slot_image_url: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "External URL the host-side ``spatium-upgrade-slot apply`` "
            "will pull from on each node. Either a GitHub release asset "
            "(online) or any HTTP(S)-reachable mirror. Mutually "
            "exclusive with ``slot_image_id``."
        ),
    )
    slot_image_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "ID of an uploaded upgrade image (``appliance_upgrade_image`` "
            "row from ``POST /api/v1/appliance/upgrade-images``). The "
            "control plane composes the authenticated download URL on "
            "plan + every node pulls bytes through it. Air-gap-friendly. "
            "Mutually exclusive with ``slot_image_url``."
        ),
    )
    cnpg_cluster_name: str = Field(
        default="",
        max_length=128,
        description=(
            "Name of the CNPG Cluster CR. Empty disables CNPG-related "
            "steps for non-CNPG deploys; on the appliance shape this is "
            "the chart's ``<release>-postgresql`` resource."
        ),
    )
    cnpg_namespace: str | None = Field(
        default=None,
        max_length=63,
        description="CNPG Cluster's namespace; defaults to the api pod's.",
    )

    @field_validator("slot_image_url")
    @classmethod
    def _validate_slot_image_url(cls, v: str | None) -> str | None:
        # Review polish — catch operator typos at plan time rather than
        # surfacing a confusing "unsupported scheme" error 30 min into
        # the rolling upgrade when the host runner finally tries to
        # GET the URL. Only http(s) is accepted; file:// + s3:// are
        # deliberately not supported by spatium-upgrade-slot apply.
        if v is None:
            return v
        from urllib.parse import urlparse  # noqa: PLC0415

        try:
            parsed = urlparse(v)
        except ValueError as exc:
            raise ValueError(f"slot_image_url is not a parseable URL: {exc}") from exc
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"slot_image_url scheme must be http or https, got {parsed.scheme!r}")
        if not parsed.netloc:
            raise ValueError("slot_image_url must include a host")
        return v

    @model_validator(mode="after")
    def _exactly_one_source(self) -> PlanRequest:
        # Same "exactly one of two" pattern as the per-box ``schedule_
        # appliance_upgrade`` (ApplianceUpgradeRequest in supervisor.py).
        # Pydantic-level enforcement so the orchestrator never has to
        # decide between conflicting / missing inputs at plan time.
        has_url = self.slot_image_url is not None and self.slot_image_url.strip() != ""
        has_id = self.slot_image_id is not None
        if has_url == has_id:
            raise ValueError(
                "Pass exactly one of ``slot_image_url`` or ``slot_image_id`` — "
                "got both, or neither. URL is for online environments that "
                "fetch directly; ID is for air-gap fleets that upload "
                "through ``POST /api/v1/appliance/upgrade-images`` first."
            )
        return self


class PreflightRowOut(BaseModel):
    name: str
    level: str
    message: str


class PlanResponse(BaseModel):
    run_id: uuid.UUID
    target_version: str
    node_order: list[str]
    preflight_overall: str
    preflight: list[PreflightRowOut]


class UpgradeRunOut(BaseModel):
    id: uuid.UUID
    kind: str
    state: str
    target_version: str
    source_versions: dict[str, Any] = Field(default_factory=dict)
    plan: dict[str, Any] = Field(default_factory=dict)
    progress: dict[str, Any] = Field(default_factory=dict)
    lease_holder: str | None = None
    lease_acquired_at: Any = None  # datetime serialised by FastAPI
    last_error: str | None = None
    started_by_user_id: uuid.UUID | None = None
    started_at: Any = None
    finished_at: Any = None


def _row_to_schema(run: Any) -> UpgradeRunOut:
    return UpgradeRunOut(
        id=run.id,
        kind=run.kind,
        state=run.state,
        target_version=run.target_version,
        source_versions=run.source_versions or {},
        plan=run.plan or {},
        progress=run.progress or {},
        lease_holder=run.lease_holder,
        lease_acquired_at=run.lease_acquired_at,
        last_error=run.last_error,
        started_by_user_id=run.started_by_user_id,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


@router.post(
    "/plan",
    response_model=PlanResponse,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Plan a rolling upgrade — preflight + node enumeration",
)
async def post_plan(
    body: PlanRequest,
    request: Request,
    current_user: CurrentUser,
    db: DB,
) -> PlanResponse:
    """Run preflight + capture the upgrade plan as a ``planned`` row.

    Does NOT acquire the upgrade lease yet; ``POST /{run_id}/start``
    does that. Refuses if another non-terminal run already exists or
    if preflight returns ``overall='fail'``.

    The ``slot_image_id`` (air-gap) branch resolves to the same
    token-authenticated mirror URL the per-box ``schedule_appliance_
    upgrade`` produces, so the orchestrator only ever sees a URL string
    + every per-node runner pulls bytes through the same control-plane
    → mirror path. Operators on connected installs keep using
    ``slot_image_url`` directly.
    """
    target = await _resolve_slot_image_target(db, request, body)
    try:
        plan = await orchestrator.plan_upgrade(
            db,
            target_version=body.target_version,
            slot_image=target,
            cnpg_cluster_name=body.cnpg_cluster_name,
            cnpg_namespace=body.cnpg_namespace,
            started_by_user_id=current_user.id,
            audit_actor_display=current_user.display_name,
            audit_actor_source=current_user.auth_source,
        )
    except orchestrator.OrchestratorError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return PlanResponse(
        run_id=plan.run_id,
        target_version=plan.target_version,
        node_order=plan.node_order,
        preflight_overall=plan.preflight_overall,
        preflight=[
            PreflightRowOut(name=r["name"], level=r["level"], message=r["message"])
            for r in plan.preflight_results
        ],
    )


async def _resolve_slot_image_target(
    db: DB,
    request: Request,
    body: PlanRequest,
) -> SlotImageTarget:
    """Resolve what every per-node runner in this run will fetch + verify.

    Delegates to the same resolver the per-box ``schedule_appliance_
    upgrade`` uses, so the two surfaces cannot diverge on URL shape, token
    scheme, or the integrity/transport hints that ride alongside — the
    divergence that left this path re-creating #386 (see #787).
    """
    try:
        target = await resolve_slot_image_target(
            db,
            base_url=str(request.base_url),
            slot_image_id=body.slot_image_id,
            slot_image_url=body.slot_image_url,
        )
        # One nonce for the whole run, persisted in the plan, so a resume
        # re-stamps the identical URL and the fire-once marker still holds.
        return replace(target, nonce=new_refire_nonce())
    except SlotImageResolutionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


@router.post(
    "/{run_id}/start",
    response_model=UpgradeRunOut,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Start (or re-enqueue) a planned upgrade run",
)
async def post_start(run_id: uuid.UUID, current_user: CurrentUser, db: DB) -> UpgradeRunOut:
    """Enqueue the orchestrator celery task.

    The api endpoint only enqueues — it does NOT drive the run itself
    (a 30+ min request would tie up the worker pool). The celery task
    acquires the lease, drives the per-node loop, and updates the row
    on each transition. The Fleet UI polls ``GET /{run_id}`` for
    progress.
    """
    try:
        run = await orchestrator.get_run(db, run_id)
    except orchestrator.OrchestratorError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    if run.state not in ("planned", "running"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cannot start a run in state {run.state!r}; use /resume for halted runs",
        )

    # Inline import — keeps the celery dep off the api boot path for
    # docker-compose deploys that don't run a worker.
    from app.tasks.upgrade_orchestrator import drive_upgrade_run  # noqa: PLC0415

    drive_upgrade_run.delay(str(run.id))
    logger.info(
        "upgrade_run_enqueued",
        run_id=str(run.id),
        actor=current_user.username,
    )
    await db.refresh(run)
    return _row_to_schema(run)


@router.post(
    "/{run_id}/halt",
    response_model=UpgradeRunOut,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Pause a running upgrade",
)
async def post_halt(run_id: uuid.UUID, current_user: CurrentUser, db: DB) -> UpgradeRunOut:
    try:
        run = await orchestrator.halt_upgrade(
            db,
            run_id,
            actor_user_id=current_user.id,
            actor_display=current_user.display_name,
            actor_source=current_user.auth_source,
        )
    except orchestrator.OrchestratorError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _row_to_schema(run)


@router.post(
    "/{run_id}/resume",
    response_model=UpgradeRunOut,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Resume a halted upgrade",
)
async def post_resume(run_id: uuid.UUID, current_user: CurrentUser, db: DB) -> UpgradeRunOut:
    try:
        run = await orchestrator.resume_upgrade(
            db,
            run_id,
            actor_user_id=current_user.id,
            actor_display=current_user.display_name,
            actor_source=current_user.auth_source,
        )
    except orchestrator.OrchestratorError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    # Re-enqueue the orchestrator celery task to pick up from progress.
    from app.tasks.upgrade_orchestrator import drive_upgrade_run  # noqa: PLC0415

    drive_upgrade_run.delay(str(run.id))
    return _row_to_schema(run)


@router.post(
    "/{run_id}/abort",
    response_model=UpgradeRunOut,
    dependencies=[Depends(require_permission("admin", "appliance"))],
    summary="Abort an upgrade (terminal — no resume)",
)
async def post_abort(run_id: uuid.UUID, current_user: CurrentUser, db: DB) -> UpgradeRunOut:
    try:
        run = await orchestrator.abort_upgrade(
            db,
            run_id,
            actor_user_id=current_user.id,
            actor_display=current_user.display_name,
            actor_source=current_user.auth_source,
        )
    except orchestrator.OrchestratorError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _row_to_schema(run)


@router.get(
    "/runs",
    response_model=list[UpgradeRunOut],
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="List recent upgrade runs (most-recent first)",
)
async def get_runs(db: DB, limit: int = 25) -> list[UpgradeRunOut]:
    if limit < 1 or limit > 200:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "limit must be 1-200")
    runs = await orchestrator.list_recent_runs(db, limit=limit)
    return [_row_to_schema(r) for r in runs]


@router.get(
    "/{run_id}",
    response_model=UpgradeRunOut,
    dependencies=[Depends(require_permission("read", "appliance"))],
    summary="Get a single upgrade run by id",
)
async def get_run(run_id: uuid.UUID, db: DB) -> UpgradeRunOut:
    try:
        run = await orchestrator.get_run(db, run_id)
    except orchestrator.OrchestratorError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _row_to_schema(run)
