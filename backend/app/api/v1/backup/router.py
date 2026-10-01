"""Backup + restore endpoints (issue #117 Phase 1a).

Two endpoints today, both superadmin-only:

* ``POST /backup/create-and-download`` — synchronous: build the
  archive in memory, stream it back via ``Content-Disposition:
  attachment``. Same shape as the conformity PDF export.
* ``POST /backup/restore`` — multipart upload (zip file +
  passphrase + confirmation phrase). Validates the archive, takes
  a pre-restore safety dump, replays the SQL via
  ``psql --single-transaction``, returns a JSON outcome summary.

Phase 1b will add backup-target rows + scheduled remote
destinations (S3 / SCP / Azure / etc.) under the same router
prefix.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import (
    APIRouter,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.deps import DB, CurrentUser
from app.config import settings
from app.core.content_disposition import content_disposition
from app.core.permissions import is_effective_superadmin
from app.core.responses import ZipResponse
from app.models.audit import AuditLog
from app.services.backup import (
    BackupArchiveError,
    BackupCryptoError,
    BackupRestoreError,
    apply_backup_restore,
    build_backup_archive,
)
from app.services.backup.sections import SECTIONS

router = APIRouter()
logger = structlog.get_logger(__name__)

# Hard ceiling on uploaded backup archives. SpatiumDDI installs are
# single-digit-GB at most (see Phase 1a scope notes); anything past
# 2 GB is almost certainly an accident or a malicious payload.
_MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024


def _require_superadmin(current_user: CurrentUser) -> None:
    if not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Backup + restore is restricted to superadmin",
        )


# ── /backup/create-and-download ──────────────────────────────────────


class BackupSection(BaseModel):
    """One selectable slice of the backup, as offered to the operator."""

    key: str
    label: str
    description: str
    table_count: int
    #: Volatile sections (caches, transient metrics) restore cleanly but are
    #: rarely worth including — flagged so the UI can default them off.
    volatile: bool
    #: False for sections that must always be included; the UI renders those
    #: as fixed rather than as an unticked checkbox.
    selectable: bool


class BackupSectionCatalog(BaseModel):
    sections: list[BackupSection]


@router.get("/sections", response_model=BackupSectionCatalog)
async def list_backup_sections(current_user: CurrentUser) -> BackupSectionCatalog:
    """Catalog of backup sections (issue #117 Phase 2a). Drives
    the upcoming selective-backup + selective-restore checkboxes —
    operators tick which sections to include / apply.
    """
    if not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Backup is restricted to superadmin",
        )
    return BackupSectionCatalog(
        sections=[
            BackupSection(
                key=s.key,
                label=s.label,
                description=s.description,
                table_count=len(s.tables),
                volatile=s.volatile,
                selectable=s.selectable,
            )
            for s in SECTIONS
        ]
    )


@router.post(
    "/create-and-download",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=ZipResponse,
    responses={200: {"description": "Backup archive"}},
)
async def create_and_download_backup(
    db: DB,
    current_user: CurrentUser,
    passphrase: str = Form(..., min_length=8, max_length=512),
    passphrase_hint: str = Form(default="", max_length=200),
    exclude_secrets: bool = Form(default=False),
) -> StreamingResponse:
    """Build a backup archive synchronously and stream it as a
    zip download. Operator passphrase is required (min 8 chars) so
    the secret-bearing payload inside ``secrets.enc`` is never
    written in clear.

    ``exclude_secrets`` (Phase 3 diagnostic mode): NULL every
    Fernet-encrypted column inside a transaction whose snapshot
    drives pg_dump, then roll back. The dumped archive contains
    no decryptable credentials — operators can share it with
    support / consultants without leaking integration creds /
    auth-provider secrets / TSIG keys / etc. Restoring such an
    archive yields an install with empty credential fields; the
    operator re-enters them by hand.
    """
    _require_superadmin(current_user)
    # #296 Phase H — refuse if a rolling upgrade is in flight. The
    # backup snapshot captures schema + data state; running one mid-
    # upgrade would capture a half-upgraded cluster that would surprise
    # the operator on restore.
    from app.services.upgrades.safety import (  # noqa: PLC0415
        assert_no_upgrade_in_flight,
    )

    await assert_no_upgrade_in_flight(db, operation_hint="backup creation")
    try:
        archive_bytes, filename = await build_backup_archive(
            db,
            passphrase=passphrase,
            passphrase_hint=passphrase_hint,
            exclude_secrets=exclude_secrets,
        )
    except BackupArchiveError as exc:
        logger.warning("backup_create_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"backup failed: {exc}") from exc

    db.add(
        AuditLog(
            action="backup_created",
            resource_type="platform",
            resource_id="backup",
            resource_display=filename,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={
                "filename": filename,
                "bytes": len(archive_bytes),
                "passphrase_hint": passphrase_hint or None,
                "secrets_excluded": exclude_secrets,
            },
        )
    )
    await db.commit()

    def _iter() -> Any:
        # Single-shot iterator — the archive lives in memory at
        # this point, we just hand it off in one chunk so the
        # browser sees Content-Length and can show a real
        # progress bar. Streaming a generator one-byte-at-a-time
        # would defeat that.
        yield archive_bytes

    return StreamingResponse(
        _iter(),
        media_type="application/zip",
        headers={
            "Content-Disposition": content_disposition(filename),
            "Content-Length": str(len(archive_bytes)),
        },
    )


# ── /backup/restore ──────────────────────────────────────────────────


class RewrapOutcomeResponse(BaseModel):
    """Per-restore counters for the cross-install secret rewrap
    pass (issue #117 Phase 2). ``same_install=True`` means the
    archive came from this install — the rewrap was skipped and
    every other counter is zero.
    """

    same_install: bool
    rewrapped_rows: int
    rewrapped_jsonb_fields: int
    skipped_idempotent_rows: int
    failed_rows: int
    columns_visited: int
    # True when the walk stopped early — the counters above then
    # describe a HALF-migrated credential store, not a clean pass
    # (#781). Read this before reading the counters.
    aborted: bool = False
    failures: list[dict[str, Any]] = []


class MigrationOutcomeResponse(BaseModel):
    """Result of the alembic upgrade-on-restore pass (issue #117
    Phase 2). ``state`` is one of:

    * ``up_to_date`` — source + destination on the same head
    * ``upgraded`` — source was on an older head; ``alembic
      upgrade head`` ran and applied ``migrations_applied``
    * ``incompatible_newer`` — source head isn't an ancestor of
      this install's head; the operator must upgrade SpatiumDDI
      before relying on this restored install
    * ``unknown`` — manifest didn't carry a schema_version or
      the local install has multiple alembic heads
    * ``failed`` — alembic upgrade subprocess failed; ``error``
      carries the message
    """

    state: str
    source_head: str | None
    local_head: str | None
    migrations_applied: list[str]
    error: str | None = None


class RestoreOutcomeResponse(BaseModel):
    success: bool
    pre_restore_safety_path: str | None
    duration_ms: int
    manifest: dict[str, Any]
    secrets_payload_keys: list[str]
    note: str
    selective: bool = False
    restored_sections: list[str] | None = None
    # Tables restored because TRUNCATE ... CASCADE would otherwise have
    # emptied them, not because their section was selected (#781).
    cascade_widened_tables: list[str] = []
    migration: MigrationOutcomeResponse | None = None
    rewrap: RewrapOutcomeResponse | None = None
    # Operator-actionable post-restore advisories (issue #127
    # Phase 4d). Currently surfaces the PowerDNS DNSSEC re-sign
    # caveat — the destination agent regenerates LMDB keys on
    # first sync and produces new DS records.
    warnings: list[str] = []


@router.post("/restore", response_model=RestoreOutcomeResponse)
async def restore_backup(
    db: DB,
    current_user: CurrentUser,
    archive: UploadFile = File(...),
    passphrase: str = Form(..., min_length=8, max_length=512),
    confirmation_phrase: str = Form(...),
    sections: str = Form(default=""),
    allow_newer_schema: bool = Form(default=False),
) -> RestoreOutcomeResponse:
    """Apply a backup archive — hard overwrite OR selective per
    sections. The operator must type the literal phrase
    ``RESTORE-FROM-BACKUP`` so accidental drag-and-drops don't
    nuke the install. A pre-restore safety dump is taken before
    any destructive change so botched restores have a recovery
    path on the local filesystem.

    When ``sections`` is empty (Phase 1 default) the call is a
    full restore. Pass a comma-separated list of section keys
    (from ``GET /backup/sections``) for a selective restore;
    those sections' tables are TRUNCATEd CASCADE and re-loaded
    from the archive.

    A selective restore necessarily reaches past the sections you
    pick: ``TRUNCATE … CASCADE`` empties every table holding a foreign
    key into a selected one, so those are restored from the archive
    too rather than left empty (#781). ``cascade_widened_tables`` on
    the response lists exactly which, and a warning repeats it.

    ``allow_newer_schema`` overrides the refusal to restore an archive
    whose schema head this build does not know. It exists for the
    A/B-rollback case — an operator who rolled back *because* the new
    build broke would otherwise be told to upgrade into it. The
    override is audited, and the response warns that the api's
    schema-head readiness gate may now fail.
    """
    _require_superadmin(current_user)
    # #296 Phase H — restoring a backup mid-upgrade would rip the
    # schema + data state out from under the orchestrator. Refuse.
    from app.services.upgrades.safety import (  # noqa: PLC0415
        assert_no_upgrade_in_flight,
    )

    await assert_no_upgrade_in_flight(db, operation_hint="backup restore")

    archive_bytes = await archive.read()
    if not archive_bytes:
        raise HTTPException(status_code=422, detail="archive is empty")
    if len(archive_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"archive exceeds {_MAX_UPLOAD_BYTES} bytes",
        )

    sections_list = [s.strip() for s in sections.split(",") if s.strip()] or None
    try:
        outcome = await apply_backup_restore(
            db,
            archive_bytes=archive_bytes,
            passphrase=passphrase,
            confirmation_phrase=confirmation_phrase,
            db_url=str(settings.database_url),
            sections=sections_list,
            allow_newer_schema=allow_newer_schema,
        )
    except (BackupArchiveError, BackupCryptoError, BackupRestoreError) as exc:
        # Same shape for archive / crypto / restore errors — the
        # message is enough for the operator to know whether to
        # re-export, retype the passphrase, or upgrade the
        # destination install. Surfacing class names would just
        # confuse non-engineers without adding info.
        logger.warning(
            "backup_restore_failed",
            error=str(exc),
            error_class=type(exc).__name__,
            archive_bytes=len(archive_bytes),
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # The restore replayed the archive's SQL, which means the
    # ``audit_log`` table is now whatever was in the archive — our
    # own commit below survives because it's a NEW row inserted
    # post-replay. We deliberately log the restore *after* the
    # destructive step so the trail of evidence sits in the freshly
    # restored database, not in the wiped one.
    #
    # Re-open the session via a fresh insertion. The current ``db``
    # session was closed inside ``apply_backup_restore``; reach for
    # AsyncSessionLocal here instead.
    from app.db import AsyncSessionLocal  # noqa: PLC0415

    async with AsyncSessionLocal() as fresh:
        fresh.add(
            AuditLog(
                action="backup_restored",
                resource_type="platform",
                resource_id="backup",
                resource_display=str(outcome.manifest.get("hostname", "unknown-source")),
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                new_value={
                    "manifest": outcome.manifest,
                    "pre_restore_safety_path": outcome.pre_restore_path,
                    "duration_ms": outcome.duration_ms,
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
                    "selective": outcome.selective,
                    "restored_sections": outcome.restored_sections,
                    "cascade_widened_tables": outcome.cascade_widened_tables,
                    # Both of these change what the operator got versus
                    # what they asked for, so the trail has to carry them
                    # (#781): the override bypassed a safety refusal, and
                    # the widening restored tables outside the selection.
                    "allow_newer_schema": allow_newer_schema,
                    "warnings": outcome.warnings,
                },
            )
        )
        await fresh.commit()

    migration = outcome.migration
    migration_resp: MigrationOutcomeResponse | None = None
    if migration is not None:
        migration_resp = MigrationOutcomeResponse(
            state=migration.state,
            source_head=migration.source_head,
            local_head=migration.local_head,
            migrations_applied=migration.migrations_applied,
            error=migration.error,
        )

    rewrap = outcome.rewrap
    rewrap_resp: RewrapOutcomeResponse | None = None
    if rewrap is not None:
        rewrap_resp = RewrapOutcomeResponse(
            same_install=rewrap.same_install,
            rewrapped_rows=rewrap.rewrapped_rows,
            rewrapped_jsonb_fields=rewrap.rewrapped_jsonb_fields,
            skipped_idempotent_rows=rewrap.skipped_idempotent_rows,
            failed_rows=rewrap.failed_rows,
            columns_visited=rewrap.columns_visited,
            aborted=rewrap.aborted,
            failures=rewrap.failures,
        )

    if rewrap is None or rewrap.same_install:
        note = (
            "Restore complete. Source archive came from this install — " "no key rewrap was needed."
        )
    elif rewrap.failed_rows == 0:
        rewrapped_total = rewrap.rewrapped_rows + rewrap.rewrapped_jsonb_fields
        note = (
            f"Restore complete. Cross-install rewrap re-encrypted "
            f"{rewrapped_total} secret value{'s' if rewrapped_total != 1 else ''} "
            f"with this install's SECRET_KEY. All credentials should be "
            f"usable without manual key copy."
        )
    else:
        rewrapped_total = rewrap.rewrapped_rows + rewrap.rewrapped_jsonb_fields
        note = (
            f"Restore complete. Cross-install rewrap re-encrypted "
            f"{rewrapped_total} secret value{'s' if rewrapped_total != 1 else ''}, "
            f"but {rewrap.failed_rows} row{'s' if rewrap.failed_rows != 1 else ''} "
            f"could not be decrypted with either the source or "
            f"destination key. Those credentials must be re-entered "
            f"manually — see the failures list below."
        )

    # Migration commentary is appended after the rewrap copy so
    # operators see both stages in order on the success screen.
    if migration is not None and migration.state == "upgraded":
        n = len(migration.migrations_applied)
        note += (
            f" Schema upgraded from {migration.source_head!r} to "
            f"{migration.local_head!r} ({n} migration{'s' if n != 1 else ''} "
            f"applied)."
        )
    elif migration is not None and migration.state == "auto_recovered":
        n = len(migration.migrations_applied)
        note += (
            f" Schema-version drift detected ({migration.source_head!r} → "
            f"{migration.local_head!r}) and auto-recovered via "
            f"`alembic stamp head`: the upgrade stopped on an object that "
            f"already exists, and every table and column the local head "
            f"declares was found in the restored schema"
            + (
                f" ({n} migration{'s' if n != 1 else ''} committed before the stop)."
                if n
                else ", so no migrations actually needed to run."
            )
        )
    elif migration is not None and migration.state == "incompatible_newer":
        note += (
            f" WARNING: archive is from a newer release of SpatiumDDI "
            f"(schema head {migration.source_head!r} is not in this "
            f"install's chain). Upgrade SpatiumDDI on this destination, "
            f"then re-run the restore."
        )
    elif migration is not None and migration.state == "failed":
        note += (
            f" WARNING: alembic upgrade failed after the data load — "
            f"run `alembic upgrade head` manually before relying on this "
            f"install. Reason: {migration.error}"
        )
    elif migration is not None and migration.state == "unknown":
        note += f" Schema-version skew check skipped: {migration.error or 'unknown reason'}."

    if outcome.pre_restore_path is None:
        note += (
            " WARNING: pre-restore safety dump was NOT written "
            "(no writable /var/lib/spatiumddi/backups path). If you "
            "need to roll back, the only path is restoring from a "
            "prior backup."
        )

    return RestoreOutcomeResponse(
        success=True,
        pre_restore_safety_path=outcome.pre_restore_path,
        duration_ms=outcome.duration_ms,
        manifest=outcome.manifest,
        secrets_payload_keys=outcome.secrets_payload_keys,
        note=note,
        selective=outcome.selective,
        restored_sections=outcome.restored_sections,
        cascade_widened_tables=outcome.cascade_widened_tables,
        migration=migration_resp,
        rewrap=rewrap_resp,
        warnings=outcome.warnings,
    )


# ── /backup/manifest-preview ─────────────────────────────────────────


@router.post("/manifest-preview")
async def preview_archive_manifest(
    current_user: CurrentUser,
    archive: UploadFile = File(...),
) -> dict[str, Any]:
    """Pull just ``manifest.json`` from an uploaded archive without
    applying anything. Lets the restore UI show the operator
    "you're about to restore from <hostname> @ <created_at>" before
    they commit to the typed-confirmation step.
    """
    _require_superadmin(current_user)
    archive_bytes = await archive.read()
    if not archive_bytes:
        raise HTTPException(status_code=422, detail="archive is empty")
    if len(archive_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"archive exceeds {_MAX_UPLOAD_BYTES} bytes",
        )
    from app.services.backup.archive import (  # noqa: PLC0415
        read_backup_manifest,
    )

    try:
        manifest = read_backup_manifest(archive_bytes)
    except BackupArchiveError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "manifest": manifest,
        "archive_bytes": len(archive_bytes),
        "format_recognised": manifest.get("format") == "spatiumddi-backup",
    }
