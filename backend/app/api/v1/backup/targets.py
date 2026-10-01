"""Backup-target CRUD + run-now + test endpoints (issue #117).

All gated to superadmin. Audit-logged on every mutation. Mounted
at ``/backup/targets`` by the parent backup router.

The router accepts any kind registered in the
:mod:`app.services.backup.targets` driver registry — the API
layer doesn't have to learn each new kind. Tier 1 (Phase 1):
``local_volume`` / ``s3`` / ``scp`` / ``azure_blob``.
Tier 2 (Phase 2): ``smb`` / ``ftp`` / ``gcs``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from email.utils import format_datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import attributes

from app.api.deps import DB, CurrentUser
from app.core.content_disposition import content_disposition
from app.core.crypto import encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.http_etag import etag_matches, format_etag
from app.core.permissions import is_effective_superadmin
from app.core.responses import ZipResponse
from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup.runner import run_backup_for_target
from app.services.backup.schedule import (
    InvalidCronExpression,
    compute_next_run,
    validate_cron,
)
from app.services.backup.targets import (
    ARCHIVE_NAME_RE,
    BackupDestinationError,
    DestinationConfigError,
    InvalidArchiveNameError,
    SecretFieldError,
    UnsupportedOperationError,
    decrypt_config_secrets,
    encrypt_config_secrets,
    get_destination,
    list_destination_kinds,
    merge_config_for_update,
    redact_config_secrets,
    safe_filename,
)

router = APIRouter()
logger = structlog.get_logger(__name__)


# Pulled from the driver registry rather than hardcoded so new
# destination drivers are accepted by the API the moment they're
# registered in ``app.services.backup.targets.__init__``.
def _valid_kinds() -> set[str]:
    from app.services.backup.targets.base import DESTINATIONS  # noqa: PLC0415

    return set(DESTINATIONS)


def _resolve_write_only(driver, requested: bool) -> bool:
    """A kind with no listing and no delete is write-only whatever the
    operator asked for (#989 item 2).

    Forcing it is not paternalism: with ``write_only=False`` the row
    would accept a retention policy that can never run, and the nightly
    prune would report success while deleting nothing. Better to make
    the row state true than to let two settings disagree.
    """
    return True if driver.inherently_write_only else requested


def _assert_retention_is_reachable(driver, *, write_only: bool, keep_n, keep_days) -> None:
    """Refuse a retention policy that could never be applied.

    A write-only target skips the prune by design, so accepting
    ``retention_keep_last_n`` alongside it would leave the operator with
    a number on screen that does nothing — the failure mode this whole
    item exists to remove, reintroduced one field over.
    """
    if not write_only:
        return
    if keep_n is None and keep_days is None:
        return
    reason = (
        "this destination kind cannot delete, so retention is the receiver's own policy"
        if driver.inherently_write_only
        else "a write-only target never prunes — retention is the destination's own policy"
    )
    raise HTTPException(
        status_code=422,
        detail=(
            f"retention cannot be set on a write-only target: {reason}. "
            "Clear retention_keep_last_n / retention_keep_days, or turn write_only off."
        ),
    )


def _require_superadmin(current_user: CurrentUser) -> None:
    if not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Backup targets are restricted to superadmin",
        )


def _archive_name(filename: str) -> str:
    """Refuse a caller-supplied archive name that is not one of ours (#1243).

    Two checks, and both are needed. ``safe_filename`` refuses anything
    that is not one plain path component — ``..`` above all, which on a
    WebDAV target used to become the parent collection's URL and turn an
    archive delete into a recursive ``DELETE`` one level up. The name
    pattern then restricts download / restore / delete to what the listing
    shows: every driver filters its listing with ``ARCHIVE_NAME_RE``, so a
    name outside it is one this API never offered, and refusing it keeps a
    destination shared with unrelated files out of reach of these routes.

    422 because the name is the caller's mistake; the drivers still run
    ``safe_filename`` themselves, so a caller that bypasses this helper
    fails closed rather than reaching storage.
    """
    try:
        safe_filename(filename)
    except InvalidArchiveNameError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not ARCHIVE_NAME_RE.match(filename):
        raise HTTPException(
            status_code=422,
            detail=(
                f"{filename!r} is not a SpatiumDDI backup archive name "
                "(spatiumddi-backup-*.zip or pre-restore-*.zip)"
            ),
        )
    return filename


# ── Schemas ────────────────────────────────────────────────────────────


class BackupTargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field("", max_length=500)
    kind: str = Field(..., min_length=1, max_length=40)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    passphrase: str = Field(..., min_length=8, max_length=512)
    passphrase_hint: str = Field("", max_length=200)
    schedule_cron: str | None = Field(default=None, max_length=120)
    retention_keep_last_n: int | None = Field(default=None, ge=0, le=10_000)
    retention_keep_days: int | None = Field(default=None, ge=0, le=10_000)
    write_only: bool = False

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        valid = _valid_kinds()
        if v not in valid:
            raise ValueError(f"kind must be one of {sorted(valid)}")
        return v


class BackupTargetUpdate(BaseModel):
    """Partial update — only the explicitly-supplied fields are
    overwritten. Passphrase has its own dedicated rotation
    semantics: pass a non-None value to rotate, omit to leave
    untouched. Empty-string passphrase is rejected at the
    validator below.
    """

    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    passphrase: str | None = Field(default=None, min_length=8, max_length=512)
    passphrase_hint: str | None = None
    schedule_cron: str | None = None
    retention_keep_last_n: int | None = Field(default=None, ge=0, le=10_000)
    retention_keep_days: int | None = Field(default=None, ge=0, le=10_000)
    write_only: bool | None = None
    drill_enabled: bool | None = None
    drill_cron: str | None = None


class BackupTargetResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    kind: str
    enabled: bool
    config: dict[str, Any]
    passphrase_set: bool  # never expose the encrypted bytes
    passphrase_hint: str
    schedule_cron: str | None
    retention_keep_last_n: int | None
    retention_keep_days: int | None
    write_only: bool
    last_run_status: str
    last_run_at: datetime | None
    last_run_filename: str | None
    last_run_bytes: int | None
    last_run_duration_ms: int | None
    last_run_error: str | None
    next_run_at: datetime | None
    drill_enabled: bool
    drill_cron: str | None
    drill_next_run_at: datetime | None
    drill_last_status: str
    drill_last_at: datetime | None
    created_at: datetime
    modified_at: datetime


def _to_response(t: BackupTarget) -> BackupTargetResponse:
    # Redact any secret fields per the driver's ``config_fields``
    # spec — operators see ``"<set>"`` rather than the encrypted
    # ciphertext (or, worse, the cleartext if a future bug bypasses
    # encryption). The driver registry knows what's secret per kind.
    try:
        driver = get_destination(t.kind)
        safe_config = redact_config_secrets(driver, t.config)
    except DestinationConfigError:
        # Unknown kind (left over from a kind we removed?). Fall
        # back to the raw config; the kind is dead anyway.
        safe_config = t.config
    return BackupTargetResponse(
        id=t.id,
        name=t.name,
        description=t.description,
        kind=t.kind,
        enabled=t.enabled,
        config=safe_config,
        passphrase_set=bool(t.passphrase_encrypted),
        passphrase_hint=t.passphrase_hint,
        schedule_cron=t.schedule_cron,
        retention_keep_last_n=t.retention_keep_last_n,
        retention_keep_days=t.retention_keep_days,
        write_only=t.write_only,
        last_run_status=t.last_run_status,
        last_run_at=t.last_run_at,
        last_run_filename=t.last_run_filename,
        last_run_bytes=t.last_run_bytes,
        last_run_duration_ms=t.last_run_duration_ms,
        last_run_error=t.last_run_error,
        next_run_at=t.next_run_at,
        drill_enabled=t.drill_enabled,
        drill_cron=t.drill_cron,
        drill_next_run_at=t.drill_next_run_at,
        drill_last_status=t.drill_last_status,
        drill_last_at=t.drill_last_at,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


# ── Endpoints ──────────────────────────────────────────────────────────


class BackupTargetKinds(BaseModel):
    """The destination kinds this build supports (s3 / sftp / …).

    Each entry carries ``inherently_write_only`` so the form can render
    the write-only switch as forced-on for a kind that has no listing
    and no delete at all (#989 item 2), rather than letting the operator
    set a retention policy that could never run.
    """

    kinds: list[dict[str, Any]]


@router.get("/kinds", response_model=BackupTargetKinds)
async def list_kinds(current_user: CurrentUser) -> BackupTargetKinds:
    """Catalog of available destination kinds + their config-field
    descriptors. The frontend reflects on these to render the
    per-kind config form.
    """
    _require_superadmin(current_user)
    return BackupTargetKinds(kinds=list_destination_kinds())


@router.get("", response_model=list[BackupTargetResponse])
async def list_targets(db: DB, current_user: CurrentUser) -> list[BackupTargetResponse]:
    _require_superadmin(current_user)
    rows = (await db.execute(select(BackupTarget).order_by(BackupTarget.name))).scalars().all()
    return [_to_response(r) for r in rows]


@router.get("/{target_id}", response_model=BackupTargetResponse)
async def get_target(
    target_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> BackupTargetResponse:
    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    return _to_response(row)


@router.post("", response_model=BackupTargetResponse, status_code=201)
async def create_target(
    body: BackupTargetCreate, db: DB, current_user: CurrentUser
) -> BackupTargetResponse:
    forbid_in_demo_mode("Backup target creation is disabled")
    _require_superadmin(current_user)
    if body.retention_keep_last_n is not None and body.retention_keep_days is not None:
        raise HTTPException(
            status_code=422,
            detail=(
                "retention_keep_last_n and retention_keep_days are mutually "
                "exclusive — set exactly one (or neither for no auto-prune)"
            ),
        )

    driver = get_destination(body.kind)
    try:
        driver.validate_config(body.config)
        # Second pass, allowed to resolve DNS (the https_put SSRF guard).
        # Only at create / update / test — never on the scheduled-run
        # path, which must not depend on a resolver.
        await driver.validate_config_network(body.config)
    except DestinationConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    write_only = _resolve_write_only(driver, body.write_only)
    _assert_retention_is_reachable(
        driver,
        write_only=write_only,
        keep_n=body.retention_keep_last_n,
        keep_days=body.retention_keep_days,
    )

    # #989 item 3 — a removable-disk destination is node-local, so
    # derive which node from the fleet rather than asking the operator
    # to type a Kubernetes node name into a generic text box. No-op for
    # every other path and every other kind.
    from app.services.appliance.removable import stamp_node_name  # noqa: PLC0415

    body.config = await stamp_node_name(db, body.config)

    # Encrypt any ``secret=True`` fields before they hit the
    # JSONB column. Driver got plaintext for validation; storage
    # gets ciphertext.
    stored_config = encrypt_config_secrets(driver, body.config)

    next_run = None
    if body.schedule_cron is not None:
        try:
            validate_cron(body.schedule_cron)
            next_run = compute_next_run(body.schedule_cron)
        except InvalidCronExpression as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = BackupTarget(
        name=body.name,
        description=body.description,
        kind=body.kind,
        enabled=body.enabled,
        config=stored_config,
        passphrase_encrypted=encrypt_str(body.passphrase),
        passphrase_hint=body.passphrase_hint,
        schedule_cron=body.schedule_cron,
        retention_keep_last_n=body.retention_keep_last_n,
        retention_keep_days=body.retention_keep_days,
        write_only=write_only,
        next_run_at=next_run,
    )
    db.add(row)
    db.add(
        AuditLog(
            action="create",
            resource_type="backup_target",
            resource_id=str(row.id),
            resource_display=body.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={
                "kind": body.kind,
                "enabled": body.enabled,
                "schedule_cron": body.schedule_cron,
                "write_only": write_only,
            },
        )
    )
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.patch("/{target_id}", response_model=BackupTargetResponse)
async def update_target(
    target_id: uuid.UUID,
    body: BackupTargetUpdate,
    db: DB,
    current_user: CurrentUser,
) -> BackupTargetResponse:
    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")

    payload = body.model_dump(exclude_unset=True)

    new_keep_n = payload.get("retention_keep_last_n", row.retention_keep_last_n)
    new_keep_days = payload.get("retention_keep_days", row.retention_keep_days)
    if new_keep_n is not None and new_keep_days is not None:
        raise HTTPException(
            status_code=422,
            detail=(
                "retention_keep_last_n and retention_keep_days are mutually "
                "exclusive — set exactly one (or neither for no auto-prune)"
            ),
        )

    driver = get_destination(row.kind)
    # ``exclude_unset`` keeps a key the client explicitly set to null, and
    # ``write_only`` is ``bool | None`` in the update model — so a literal
    # ``{"write_only": null}`` (which the published OpenAPI declares legal,
    # so a generated client will send it) would otherwise reach a NOT NULL
    # column and answer 500, not 422, because the #922 integrity handler
    # deliberately re-raises a NOT NULL violation. An explicit null means
    # "leave it alone", which is what every nullable field on this handler
    # already does. Same class as #700.
    requested_write_only = payload.get("write_only")
    if requested_write_only is None:
        requested_write_only = row.write_only
    new_write_only = _resolve_write_only(driver, requested_write_only)
    _assert_retention_is_reachable(
        driver, write_only=new_write_only, keep_n=new_keep_n, keep_days=new_keep_days
    )
    row.write_only = new_write_only

    if "config" in payload:
        # PATCH semantics for secret fields: an operator who only
        # changes the bucket name shouldn't have to retype the
        # secret access key. ``merge_config_for_update`` keeps the
        # existing encrypted value when the incoming payload omits
        # the secret (or sends the redaction sentinel). Validation
        # runs on the merged dict so shape checks see all fields.
        merged = merge_config_for_update(driver, incoming=payload["config"], existing=row.config)
        # #989 item 3 — same derivation as create. No-op unless the path
        # moved under the removable root and no node was set by hand.
        from app.services.appliance.removable import stamp_node_name  # noqa: PLC0415

        merged = await stamp_node_name(db, merged)
        try:
            driver.validate_config(merged)
            await driver.validate_config_network(merged)
        except DestinationConfigError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        # Re-encrypt — fields carried over are already wrapped
        # (the helper detects the prefix and skips them); newly
        # supplied secrets get wrapped fresh.
        row.config = encrypt_config_secrets(driver, merged)
        attributes.flag_modified(row, "config")

    if "schedule_cron" in payload:
        if payload["schedule_cron"] is None or payload["schedule_cron"] == "":
            row.schedule_cron = None
            row.next_run_at = None
        else:
            try:
                validate_cron(payload["schedule_cron"])
                row.next_run_at = compute_next_run(payload["schedule_cron"])
            except InvalidCronExpression as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            row.schedule_cron = payload["schedule_cron"]

    if "drill_cron" in payload:
        if payload["drill_cron"] is None or payload["drill_cron"] == "":
            row.drill_cron = None
            row.drill_next_run_at = None
        else:
            try:
                validate_cron(payload["drill_cron"])
                row.drill_next_run_at = compute_next_run(payload["drill_cron"])
            except InvalidCronExpression as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            row.drill_cron = payload["drill_cron"]

    if payload.get("drill_enabled") and not (payload.get("drill_cron") or row.drill_cron):
        raise HTTPException(
            status_code=422,
            detail="drill_enabled requires drill_cron — set a drill schedule first",
        )

    if "passphrase" in payload and payload["passphrase"] is not None:
        row.passphrase_encrypted = encrypt_str(payload["passphrase"])

    for key in (
        "name",
        "description",
        "enabled",
        "passphrase_hint",
        "retention_keep_last_n",
        "retention_keep_days",
        "drill_enabled",
    ):
        if key in payload:
            setattr(row, key, payload[key])

    db.add(
        AuditLog(
            action="update",
            resource_type="backup_target",
            resource_id=str(row.id),
            resource_display=row.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={k: v for k, v in payload.items() if k != "passphrase"},
        )
    )
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    db.add(
        AuditLog(
            action="delete",
            resource_type="backup_target",
            resource_id=str(row.id),
            resource_display=row.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
        )
    )
    await db.delete(row)
    await db.commit()


# ── Run-now / test / archive listing ───────────────────────────────────


class RunNowResponse(BaseModel):
    success: bool
    filename: str | None
    bytes: int | None
    duration_ms: int | None
    deleted: int
    error: str | None


@router.post("/{target_id}/run-now", response_model=RunNowResponse)
async def run_target_now(target_id: uuid.UUID, db: DB, current_user: CurrentUser) -> RunNowResponse:
    """Kick a one-off backup against this target. Synchronous —
    blocks until ``pg_dump`` + driver write + retention prune
    finish. The schedule sweep uses the same code path.
    """
    _require_superadmin(current_user)
    # #296 Phase H — refuse if a rolling upgrade is in flight (same
    # rationale as create-and-download: mid-upgrade snapshots are
    # internally inconsistent + surprise the operator on restore).
    from app.services.upgrades.safety import (  # noqa: PLC0415
        assert_no_upgrade_in_flight,
    )

    await assert_no_upgrade_in_flight(db, operation_hint="manual backup run")
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    if not row.enabled:
        raise HTTPException(status_code=409, detail="target is disabled — enable it first")
    result = await run_backup_for_target(
        db,
        target=row,
        triggered_by="manual",
        actor_id=current_user.id,
        actor_display=current_user.username,
    )
    return RunNowResponse(**result)


@router.post("/{target_id}/test")
async def test_target(target_id: uuid.UUID, db: DB, current_user: CurrentUser) -> dict[str, Any]:
    """Connectivity probe — write a tiny file at the destination, verify
    it, and remove it. Doesn't touch the DB or build a real archive.

    **The probe object is not always removed, and the result says so.**
    A write-only S3 key has no ``DeleteObject`` grant and ``https_put``
    has no delete verb at all; in both cases the probe still passes and
    reports ``probe_retained: true``, naming the object left behind —
    failing there is what trains operators to widen a deliberately narrow
    credential. On a single-object (presigned) ``https_put`` URL the
    probe is refused outright rather than run, because writing it would
    overwrite the stored archive.
    """
    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    driver = get_destination(row.kind)
    try:
        plain_config = decrypt_config_secrets(driver, row.config)
        outcome = await driver.test_connection(config=plain_config)
    except SecretFieldError as exc:
        outcome = {"ok": False, "error": str(exc)}
    except BackupDestinationError as exc:
        outcome = {"ok": False, "error": str(exc)}
    return outcome


class ArchiveListingResponse(BaseModel):
    filename: str
    size_bytes: int
    created_at: datetime


@router.get("/{target_id}/archives", response_model=list[ArchiveListingResponse])
async def list_target_archives(
    target_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> list[ArchiveListingResponse]:
    """List archives stored at this target, newest-first."""
    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    driver = get_destination(row.kind)
    try:
        plain_config = decrypt_config_secrets(driver, row.config)
        archives = await driver.list_archives(config=plain_config)
    except SecretFieldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except UnsupportedOperationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BackupDestinationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return [
        ArchiveListingResponse(
            filename=a.filename,
            size_bytes=a.size_bytes,
            created_at=a.created_at,
        )
        for a in archives
    ]


@router.get(
    "/{target_id}/archives/latest/download",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=ZipResponse,
    responses={200: {"description": "Backup archive"}},
)
async def download_latest_target_archive(
    target_id: uuid.UUID,
    db: DB,
    current_user: CurrentUser,
    request: Request,
):
    """One-shot 'give me the newest archive at this target'
    download (issue #117 Phase 3). Resolves to the same code path
    as the explicit-filename download below — we just look up the
    newest entry from ``driver.list_archives`` first. Returns 404
    when the target has no archives yet.

    This is the pull-mode entry point (#989 item 4): an external backup
    tool (Veeam, Bacula, a cron ``curl``) fetches from here with an API
    token restricted via ``allowed_paths`` to this one route.

    It is conditional. Archive filenames are timestamped and the bytes
    under a given name never change, so the filename *is* a strong
    validator — ``ETag`` plus ``If-None-Match`` turns a poller's second
    run into a 304 instead of a re-download of a multi-GB archive. The
    ETag is computed from the listing, so an unchanged archive costs one
    list call and no transfer at all.
    """
    from fastapi.responses import StreamingResponse  # noqa: PLC0415

    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    if row.write_only:
        raise HTTPException(
            status_code=409,
            detail=(
                "this target is write-only, so SpatiumDDI cannot read archives back "
                "from it — pull mode needs a destination it can list and download. "
                "Point the puller at a readable target (a local_volume staging "
                "target is the usual answer), or fetch from the destination directly."
            ),
        )
    driver = get_destination(row.kind)
    try:
        plain_config = decrypt_config_secrets(driver, row.config)
        archives = await driver.list_archives(config=plain_config)
    except SecretFieldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BackupDestinationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not archives:
        raise HTTPException(status_code=404, detail=f"no archives at target {row.name!r}")
    # ``list_archives`` already returns newest-first by contract.
    newest = archives[0]
    # ``format_etag`` / ``etag_matches`` from app.core.http_etag rather
    # than a local pair: that module already handles ``*``, comma lists,
    # the ``W/`` prefix and the legacy unquoted spelling, and it mints a
    # WEAK tag — #862's lesson, that nginx's gzip filter strips a strong
    # validator, so a hand-rolled strong ETag silently stops conditioning
    # anything the moment a client sends ``Accept-Encoding: gzip``.
    etag = format_etag(newest.filename)
    if etag_matches(request.headers.get("if-none-match"), newest.filename):
        # 304 must carry the validators and no body (RFC 9110 §15.4.5).
        return Response(
            status_code=304,
            headers={
                "ETag": etag,
                "Last-Modified": format_datetime(newest.created_at, usegmt=True),
                "Cache-Control": "private, no-cache",
            },
        )
    try:
        archive_bytes = await driver.download(config=plain_config, filename=newest.filename)
    except BackupDestinationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    def _iter():
        yield archive_bytes

    return StreamingResponse(
        _iter(),
        media_type="application/zip",
        headers={
            "Content-Disposition": content_disposition(newest.filename),
            "Content-Length": str(len(archive_bytes)),
            "ETag": etag,
            "Last-Modified": format_datetime(newest.created_at, usegmt=True),
            # Only secrets.enc inside the archive is encrypted; the
            # database dump is not. No shared cache should hold it.
            "Cache-Control": "private, no-cache",
        },
    )


@router.get(
    "/{target_id}/archives/{filename}/download",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=ZipResponse,
    responses={200: {"description": "Backup archive"}},
)
async def download_target_archive(
    target_id: uuid.UUID,
    filename: str,
    db: DB,
    current_user: CurrentUser,
    request: Request,
):
    """Stream a stored archive back to the operator's browser as a
    zip download. Works the same way for every destination kind —
    the driver's ``download(filename)`` method does the heavy
    lifting; we wrap the bytes in a ``StreamingResponse`` with
    ``Content-Disposition: attachment``. For large archives this
    fetches into memory before streaming; the existing 2 GB hard
    cap on the api process catches anything pathological.
    """
    from fastapi.responses import StreamingResponse  # noqa: PLC0415

    _require_superadmin(current_user)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    driver = get_destination(row.kind)
    safe_name = _archive_name(filename)
    etag = format_etag(safe_name)
    # **The conditional check has to come AFTER the archive is resolved.**
    #
    # The ETag here is derived from the client's own path parameter, so a
    # 304 returned before the lookup asserts "unchanged and present" about
    # something nobody has looked for. A pull-mode poller that cached an
    # archive which retention has since removed would then be told 304
    # forever and never notice its copy is the only one left; and
    # ``If-None-Match: *`` would answer 304 for a name that never existed,
    # which RFC 9110 §13.2.1 forbids — a precondition is only evaluated
    # when the unconditional response would be 2xx. The sibling ``latest``
    # route gets this right by construction, because its validator comes
    # out of a real listing.
    try:
        plain_config = decrypt_config_secrets(driver, row.config)
        archive_bytes = await driver.download(config=plain_config, filename=safe_name)
    except SecretFieldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except UnsupportedOperationError as exc:
        # A write-only kind cannot read an archive back. 409 rather than
        # the generic 502 below, so the reason is legible instead of
        # looking like the destination is down.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BackupDestinationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # The archive exists and is readable — only now is a precondition
    # meaningful.
    if etag_matches(request.headers.get("if-none-match"), safe_name):
        return Response(
            status_code=304,
            headers={"ETag": etag, "Cache-Control": "private, no-cache"},
        )

    def _iter():
        yield archive_bytes

    return StreamingResponse(
        _iter(),
        media_type="application/zip",
        headers={
            "Content-Disposition": content_disposition(safe_name),
            "Content-Length": str(len(archive_bytes)),
            "ETag": etag,
            "Cache-Control": "private, no-cache",
        },
    )


class RestoreFromArchiveBody(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    passphrase: str = Field(..., min_length=8, max_length=512)
    confirmation_phrase: str
    #: Optional list of section keys (from ``GET /backup/sections``)
    #: for selective restore. Empty / None → full hard-overwrite
    #: restore (Phase 1 behaviour).
    sections: list[str] | None = None
    #: Override the refusal to restore an archive whose schema head this
    #: build doesn't know. Exists for the A/B-rollback case, where the
    #: operator rolled back *because* the newer build broke and would
    #: otherwise be told to upgrade into it (#781). Audited; the response
    #: warns that the schema-head readiness gate may then fail.
    allow_newer_schema: bool = False


@router.post("/{target_id}/archives/restore")
async def restore_from_archive(
    target_id: uuid.UUID,
    body: RestoreFromArchiveBody,
    db: DB,
    current_user: CurrentUser,
) -> dict[str, Any]:
    """Pull ``filename`` from the destination, decrypt + replay
    via the same code path as ``POST /backup/restore`` (Phase 1a).
    Operator types the passphrase even though the target stores
    one — symmetric with the upload-based restore + proves the
    operator knows the key, so a stolen session token can't roll
    back the install on a hunch.
    """
    _require_superadmin(current_user)
    _archive_name(body.filename)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    driver = get_destination(row.kind)
    try:
        plain_config = decrypt_config_secrets(driver, row.config)
        archive_bytes = await driver.download(config=plain_config, filename=body.filename)
    except SecretFieldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BackupDestinationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not archive_bytes:
        raise HTTPException(
            status_code=502,
            detail=f"archive {body.filename!r} fetched empty from destination",
        )

    # Reuse the Phase 1a restore path so the safety dump +
    # passphrase verify + psql replay + post-replay audit row all
    # behave the same as the upload-based restore.
    from app.config import settings  # noqa: PLC0415
    from app.services.backup import (  # noqa: PLC0415
        BackupArchiveError,
        BackupCryptoError,
        BackupRestoreError,
        apply_backup_restore,
    )

    try:
        outcome = await apply_backup_restore(
            db,
            archive_bytes=archive_bytes,
            passphrase=body.passphrase,
            confirmation_phrase=body.confirmation_phrase,
            db_url=str(settings.database_url),
            sections=body.sections or None,
            allow_newer_schema=body.allow_newer_schema,
        )
    except (BackupArchiveError, BackupCryptoError, BackupRestoreError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Post-replay audit on a fresh session — the current ``db``
    # session was closed inside ``apply_backup_restore`` (engine
    # disposed). Same shape the Phase 1a upload-restore endpoint
    # uses.
    from app.db import AsyncSessionLocal  # noqa: PLC0415

    async with AsyncSessionLocal() as fresh:
        fresh.add(
            AuditLog(
                action="backup_restored",
                resource_type="backup_target",
                resource_id=str(row.id),
                resource_display=row.name,
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                new_value={
                    "source": "destination",
                    "target_kind": row.kind,
                    "filename": body.filename,
                    "manifest": outcome.manifest,
                    "duration_ms": outcome.duration_ms,
                    "selective": outcome.selective,
                    "restored_sections": outcome.restored_sections,
                    "pre_restore_safety_path": outcome.pre_restore_path,
                    "migration": (
                        {
                            "state": outcome.migration.state,
                            "source_head": outcome.migration.source_head,
                            "local_head": outcome.migration.local_head,
                            "migrations_applied": outcome.migration.migrations_applied,
                            "error": outcome.migration.error,
                        }
                        if outcome.migration is not None
                        else None
                    ),
                    "rewrap": (
                        {
                            "same_install": outcome.rewrap.same_install,
                            "rewrapped_rows": outcome.rewrap.rewrapped_rows,
                            "rewrapped_jsonb_fields": (outcome.rewrap.rewrapped_jsonb_fields),
                            "skipped_idempotent_rows": (outcome.rewrap.skipped_idempotent_rows),
                            "failed_rows": outcome.rewrap.failed_rows,
                            "columns_visited": outcome.rewrap.columns_visited,
                            "aborted": outcome.rewrap.aborted,
                            "failures": outcome.rewrap.failures,
                        }
                        if outcome.rewrap is not None
                        else None
                    ),
                    # Both change what the operator got versus what they
                    # asked for, so the trail has to carry them — and this
                    # endpoint has to match POST /backup/restore or a
                    # destination-based restore is the less auditable of
                    # two paths doing the same thing (#781).
                    "cascade_widened_tables": outcome.cascade_widened_tables,
                    "allow_newer_schema": body.allow_newer_schema,
                    "warnings": outcome.warnings,
                },
            )
        )
        await fresh.commit()

    return {
        "success": True,
        "filename": body.filename,
        "duration_ms": outcome.duration_ms,
        "manifest": outcome.manifest,
        "pre_restore_safety_path": outcome.pre_restore_path,
        "selective": outcome.selective,
        "restored_sections": outcome.restored_sections,
        "cascade_widened_tables": outcome.cascade_widened_tables,
        "migration": (
            {
                "state": outcome.migration.state,
                "source_head": outcome.migration.source_head,
                "local_head": outcome.migration.local_head,
                "migrations_applied": outcome.migration.migrations_applied,
                "error": outcome.migration.error,
            }
            if outcome.migration is not None
            else None
        ),
        "rewrap": (
            {
                "same_install": outcome.rewrap.same_install,
                "rewrapped_rows": outcome.rewrap.rewrapped_rows,
                "rewrapped_jsonb_fields": outcome.rewrap.rewrapped_jsonb_fields,
                "skipped_idempotent_rows": outcome.rewrap.skipped_idempotent_rows,
                "failed_rows": outcome.rewrap.failed_rows,
                "columns_visited": outcome.rewrap.columns_visited,
                "aborted": outcome.rewrap.aborted,
                "failures": outcome.rewrap.failures,
            }
            if outcome.rewrap is not None
            else None
        ),
        # This response omitted ``warnings`` entirely, so a
        # destination-based restore never surfaced the DNSSEC
        # registrar-republish advisory. Pre-existing, but it matters more
        # now: the cascade-widening, half-migrated-rewrap and
        # schema-override notices all ride this channel (#781).
        "warnings": outcome.warnings,
    }


@router.delete("/{target_id}/archives/{filename}", status_code=204)
async def delete_target_archive(
    target_id: uuid.UUID,
    filename: str,
    db: DB,
    current_user: CurrentUser,
) -> None:
    """Manually drop one archive at this target."""
    _require_superadmin(current_user)
    _archive_name(filename)
    row = await db.get(BackupTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="backup target not found")
    if row.write_only:
        # The point of a write-only target is that nothing SpatiumDDI
        # holds can remove an archive — including this route. Refusing
        # here rather than letting the driver's 403 surface as a 502
        # keeps the reason legible.
        raise HTTPException(
            status_code=409,
            detail=(
                "this target is write-only: archives cannot be deleted through "
                "SpatiumDDI. Retention is the destination's own policy — a bucket "
                "lifecycle rule, an Object Lock retention period, or the receiver's "
                "cleanup task. Remove it at the destination if you really need to."
            ),
        )
    driver = get_destination(row.kind)
    try:
        plain_config = decrypt_config_secrets(driver, row.config)
        await driver.delete(config=plain_config, filename=filename)
    except SecretFieldError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BackupDestinationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.add(
        AuditLog(
            action="backup_archive_deleted",
            resource_type="backup_target",
            resource_id=str(row.id),
            resource_display=row.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={"filename": filename},
        )
    )
    await db.commit()
