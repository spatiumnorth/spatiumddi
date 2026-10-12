"""Factory-reset endpoints (issue #116).

* ``GET  /system/factory-reset/sections`` — catalog of available
  sections + per-section confirm phrase.
* ``POST /system/factory-reset/preview`` — dry-run, returns row
  counts that would be deleted by the supplied section keys.
* ``POST /system/factory-reset/execute`` — destructive. Validates
  every guardrail server-side: superadmin gate, password
  re-verification, per-section confirm-phrase, mutex against
  in-flight backups + concurrent resets, 6-hour cooldown.

The execute endpoint surfaces a ``backup_warning`` flag in the
preview response when no enabled backup target exists. Operators
must opt past the warning by setting ``acknowledge_no_backup=true``
in the execute body — the issue asks for "warn-only with override".
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.config import settings
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import is_effective_superadmin
from app.models.backup import BackupTarget
from app.services.factory_reset import (
    FACTORY_SECTIONS,
    FACTORY_SECTIONS_BY_KEY,
    FactoryResetError,
    FactoryResetMutexError,
    apply_factory_reset,
    preview_factory_reset,
)
from app.services.factory_reset.runner import (
    FactoryResetCooldownError,
    verify_user_password,
)

router = APIRouter()
logger = structlog.get_logger(__name__)


def _require_superadmin(current_user: CurrentUser) -> None:
    if not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Factory reset is restricted to superadmin",
        )


# ── Schemas ──────────────────────────────────────────────────────────


class SectionCatalogEntry(BaseModel):
    key: str
    label: str
    description: str
    phrase: str
    kind: str
    table_count: int


class PreviewRequest(BaseModel):
    section_keys: list[str] = Field(..., min_length=1)


class SectionPreviewResponse(BaseModel):
    section_key: str
    label: str
    kind: str
    affected_rows: int
    table_counts: dict[str, int]
    notes: list[str]


class PreviewResponse(BaseModel):
    sections: list[SectionPreviewResponse]
    deleted_rows_total: int
    backup_warning: bool
    backup_warning_detail: str | None
    cooldown_blocking: bool
    cooldown_detail: str | None


class ExecuteRequest(BaseModel):
    section_keys: list[str] = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    confirm_phrases: dict[str, str] = Field(default_factory=dict)
    acknowledge_no_backup: bool = False


class ExecuteResponse(BaseModel):
    success: bool
    sections: list[str]
    deleted_rows_total: int
    audit_anchor_id: str | None
    duration_ms: int


# ── Endpoints ────────────────────────────────────────────────────────


class FactorySectionCatalog(BaseModel):
    """Catalog the factory-reset page reflects on to render itself."""

    sections: list[SectionCatalogEntry]


@router.get("/sections", response_model=FactorySectionCatalog)
async def list_sections(current_user: CurrentUser) -> FactorySectionCatalog:
    """Section catalog the UI reflects on to render the page."""
    _require_superadmin(current_user)
    return FactorySectionCatalog(
        sections=[
            SectionCatalogEntry(
                key=s.key,
                label=s.label,
                description=s.description,
                phrase=s.phrase,
                kind=s.kind,
                table_count=len(s.tables),
            )
            for s in FACTORY_SECTIONS
        ],
    )


@router.post("/preview", response_model=PreviewResponse)
async def preview(body: PreviewRequest, db: DB, current_user: CurrentUser) -> PreviewResponse:
    """Read-only dry-run. Returns the row counts that would be
    deleted plus diagnostic flags (backup warning, cooldown).
    """
    _require_superadmin(current_user)
    for k in body.section_keys:
        if k not in FACTORY_SECTIONS_BY_KEY:
            raise HTTPException(status_code=422, detail=f"unknown section key: {k!r}")
    try:
        previews = await preview_factory_reset(
            db, section_keys=body.section_keys, calling_user_id=current_user.id
        )
    except FactoryResetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Backup-warning surface — does the install have at least one
    # enabled backup target the operator could fall back on?
    targets_q = await db.execute(select(BackupTarget.name).where(BackupTarget.enabled.is_(True)))
    enabled_targets = list(targets_q.scalars().all())
    if enabled_targets:
        backup_warning = False
        backup_detail = None
    else:
        backup_warning = True
        backup_detail = (
            "No enabled backup target is configured. The factory reset is "
            "destructive and there's no built-in undo. Configure a backup "
            "destination under Administration → Backup → Destinations, run a "
            "backup, and only then "
            "proceed — or acknowledge the risk by setting "
            "acknowledge_no_backup=true on the execute call."
        )

    # Cooldown-blocking surface — show in the preview so the UI can
    # disable the confirm button BEFORE the operator types phrases.
    cooldown_blocking = False
    cooldown_detail: str | None = None
    try:
        from app.services.factory_reset.runner import (  # noqa: PLC0415
            _ensure_cooldown_clear,
        )

        await _ensure_cooldown_clear(db)
    except FactoryResetCooldownError as exc:
        cooldown_blocking = True
        cooldown_detail = str(exc)

    deleted_total = sum(p.affected_rows for p in previews)
    return PreviewResponse(
        sections=[
            SectionPreviewResponse(
                section_key=p.section_key,
                label=p.label,
                kind=p.kind,
                affected_rows=p.affected_rows,
                table_counts=p.table_counts,
                notes=p.notes,
            )
            for p in previews
        ],
        deleted_rows_total=deleted_total,
        backup_warning=backup_warning,
        backup_warning_detail=backup_detail,
        cooldown_blocking=cooldown_blocking,
        cooldown_detail=cooldown_detail,
    )


@router.post("/execute", response_model=ExecuteResponse)
async def execute(body: ExecuteRequest, db: DB, current_user: CurrentUser) -> ExecuteResponse:
    """Run the destructive factory reset. Validates every guardrail
    server-side before any TRUNCATE runs.
    """
    forbid_in_demo_mode("Factory reset is disabled")
    _require_superadmin(current_user)
    # #296 Phase H — refuse if a rolling upgrade is in flight. A
    # mid-upgrade factory reset would leave the orchestrator's
    # SystemUpgradeRun row pointing at a wiped cluster. The Lease
    # would also persist in etcd (factory reset is namespace-scoped
    # to Postgres tables; it doesn't touch the coordination.k8s.io
    # Lease) and block subsequent legitimate upgrades until
    # manually cleaned up.
    from app.services.upgrades.safety import (  # noqa: PLC0415
        assert_no_upgrade_in_flight,
    )

    await assert_no_upgrade_in_flight(db, operation_hint="factory reset")

    # 1. Validate section keys.
    for k in body.section_keys:
        if k not in FACTORY_SECTIONS_BY_KEY:
            raise HTTPException(status_code=422, detail=f"unknown section key: {k!r}")

    # 2. Validate per-section confirm phrases. ``everything`` is a
    #    pseudo-section that needs ITS OWN phrase — the per-leaf
    #    sections inside don't need separate phrases on top.
    for k in body.section_keys:
        section = FACTORY_SECTIONS_BY_KEY[k]
        supplied = body.confirm_phrases.get(k, "")
        if supplied != section.phrase:
            raise HTTPException(
                status_code=422,
                detail=(f"confirm_phrase for section {k!r} must be exactly " f"{section.phrase!r}"),
            )

    # 3. Re-verify the calling user's password. Bearer-token check
    #    isn't enough — operator has to prove fresh knowledge of
    #    the password.
    if not verify_user_password(current_user, body.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="password does not match this user's account",
        )

    # 4. Backup-warning gate. If no enabled backup target exists +
    #    the operator hasn't explicitly acknowledged, refuse with
    #    a 412 (Precondition Failed) carrying the override hint.
    targets_q = await db.execute(select(BackupTarget.name).where(BackupTarget.enabled.is_(True)))
    enabled_targets = list(targets_q.scalars().all())
    if not enabled_targets and not body.acknowledge_no_backup:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=(
                "No enabled backup target is configured. Either configure "
                "and run a backup first, or set acknowledge_no_backup=true "
                "on this request to override."
            ),
        )

    # 5. Mutex + cooldown + actually-do-it. The runner re-checks
    #    these inside its own pre-flight; the preview path also
    #    surfaces them so the UI can disable the button up front.
    try:
        outcome = await apply_factory_reset(
            db,
            section_keys=body.section_keys,
            calling_user_id=current_user.id,
            calling_user_display=current_user.username,
            db_url=str(settings.database_url),
        )
    except FactoryResetMutexError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except FactoryResetCooldownError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except FactoryResetError as exc:
        logger.error("factory_reset_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # 6. The audit row inside the runner already carries actor +
    #    sections + per-section counts. Standard event-outbox
    #    pickup fan-outs the ``system.factory_reset`` typed event
    #    via the SQLAlchemy commit hook.
    return ExecuteResponse(
        success=True,
        sections=outcome.sections,
        deleted_rows_total=outcome.deleted_rows_total,
        audit_anchor_id=outcome.audit_anchor_id,
        duration_ms=outcome.duration_ms,
    )


__all__ = ["router"]
