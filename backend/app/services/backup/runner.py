"""Run a backup against one configured target (issue #117 Phase 1b).

Threads :func:`build_backup_archive` (Phase 1a) into the
destination drivers + the per-target retention sweep + the
``last_run_*`` state-machine on ``backup_target``. Used by both
the on-demand "Run Now" button and the beat-driven schedule
sweep.

State machine on the row:

* Pre-run → ``last_run_status = "in_progress"``, all other
  ``last_run_*`` cleared. Stamp committed before the destination
  write so a stuck driver can't leave the row in ambiguous state.
* On success → ``last_run_status = "success"``, filename / bytes
  / duration_ms populated, ``last_run_error = NULL``,
  ``next_run_at`` recomputed from the cron string.
* On failure → ``last_run_status = "failed"``, error captured,
  ``next_run_at`` still recomputed so the next tick retries
  rather than getting wedged.

Audit-log row written for both outcomes — same shape as the
on-demand backup endpoint emits.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup.archive import (
    BackupArchiveError,
    build_backup_archive,
)
from app.services.backup.schedule import compute_next_run
from app.services.backup.targets import (
    PRE_RESTORE_KEEP_LAST_N,
    BackupDestinationError,
    RetentionLockedError,
    SecretFieldError,
    decrypt_config_secrets,
    get_destination,
    is_pre_restore_archive,
)

logger = structlog.get_logger(__name__)


def _decrypt_passphrase(target: BackupTarget) -> str:
    """Pull the operator's per-target passphrase out of the
    Fernet-encrypted column. Surfaces a clean
    :class:`BackupArchiveError` if the column is somehow corrupt
    so the runner's ``except (BackupArchiveError, ...)`` catch
    grounds the failure message in something operator-readable.
    """
    try:
        return decrypt_str(target.passphrase_encrypted)
    except ValueError as exc:
        raise BackupArchiveError(
            "could not decrypt the target's stored passphrase — "
            "re-save the target with a fresh passphrase"
        ) from exc


async def _retention_sweep(
    db: AsyncSession,
    *,
    target: BackupTarget,
    config: dict[str, Any],
) -> int:
    """Drop archives outside the target's retention window. One of
    ``retention_keep_last_n`` / ``retention_keep_days`` may be set
    (mutually exclusive at the validator layer); both NULL means
    "no automatic pruning". Returns the number of archives
    deleted.
    """
    if target.write_only:
        # Write-only destination (#989): retention belongs to the
        # destination, not to us. Pruning here would need a delete
        # credential — which is the exact thing this flag exists to make
        # unnecessary — and on an Object-Lock bucket every attempt would
        # be refused anyway, logging a warning per file per night about
        # the feature working correctly.
        return 0
    if target.retention_keep_last_n is None and target.retention_keep_days is None:
        return 0
    driver = get_destination(target.kind)
    archives = await driver.list_archives(config=config)
    # Split the listing BEFORE any retention arithmetic (#1574). The
    # recommended local-volume path is also where restore writes its
    # ``pre-restore-*.zip`` safety dumps, and the name pattern matches
    # both. Counted together, every restore pushed one real backup out
    # of a keep-last-N window early, and a keep-days policy deleted
    # the rollback copy on the backups' schedule. Safety dumps are
    # listed (an operator may still want one) but pruned under their
    # own keep-last-N, below.
    backups = [a for a in archives if not is_pre_restore_archive(a.filename)]
    safety_dumps = [a for a in archives if is_pre_restore_archive(a.filename)]
    # Archives an Object Lock refused. Counted and reported rather than
    # only logged at DEBUG: a target with a 30-day lock and a keep-7
    # policy prunes NOTHING every night while the run reports success and
    # the UI keeps showing "keep last 7" — the same silent no-op the
    # write-only retention guard exists to prevent, one field over.
    locked: list[str] = []

    async def _prune(filename: str) -> bool:
        """Delete one archive, distinguishing "refused because it is
        under a retention lock" from a real failure.

        A locked object is the feature working: an S3 bucket in
        compliance mode refuses the delete until the retain-until date,
        and logging that at WARNING once per file per night turns a
        correctly-configured install into a nightly warning storm. So it
        is skipped quietly at DEBUG, and only unexpected failures warn.
        """
        try:
            await driver.delete(config=config, filename=filename)
        except RetentionLockedError:
            # Ordered before the base class rather than re-tested with an
            # isinstance helper — Python's own dispatch does this, and the
            # helper was one boolean spread over four files.
            locked.append(filename)
            logger.debug(
                "backup_retention_object_locked",
                target_id=str(target.id),
                filename=filename,
            )
            return False
        except BackupDestinationError as exc:
            logger.warning(
                "backup_retention_delete_failed",
                target_id=str(target.id),
                filename=filename,
                error=str(exc),
            )
            return False
        return True

    deleted = 0
    if target.retention_keep_last_n is not None:
        keep_n = max(target.retention_keep_last_n, 0)
        for stale in backups[keep_n:]:
            deleted += 1 if await _prune(stale.filename) else 0
    elif target.retention_keep_days is not None:
        cutoff = datetime.now(UTC).timestamp() - target.retention_keep_days * 86400
        for archive in backups:
            if archive.created_at.timestamp() < cutoff:
                deleted += 1 if await _prune(archive.filename) else 0
    # Safety dumps: their own keep-last-N, independent of which (if
    # any) retention policy the backups use (#1574). Without this the
    # rollback copies accumulated forever; with the backups' policy
    # they vanished on a schedule nobody chose for them.
    for stale_dump in safety_dumps[PRE_RESTORE_KEEP_LAST_N:]:
        deleted += 1 if await _prune(stale_dump.filename) else 0
    if locked:
        logger.info(
            "backup_retention_blocked_by_object_lock",
            target_id=str(target.id),
            locked=len(locked),
            hint=(
                "retention is configured on this target but the destination's "
                "Object Lock refused every delete — the archives will not be "
                "pruned until their retention period expires"
            ),
        )
    return deleted


async def run_backup_for_target(
    db: AsyncSession,
    *,
    target: BackupTarget,
    triggered_by: str,
    actor_id: Any | None = None,
    actor_display: str = "system",
) -> dict[str, Any]:
    """Build + write + prune for one target. Caller passes the
    fully-loaded ``target`` row + a label for ``triggered_by``
    (``"manual"`` / ``"schedule"``) which lands in the audit row.

    Returns a result dict the caller can render straight to the
    UI: ``{success, filename, bytes, duration_ms, error, deleted}``.
    """
    started = datetime.now(UTC)
    target.last_run_status = "in_progress"
    target.last_run_at = started
    target.last_run_filename = None
    target.last_run_bytes = None
    target.last_run_duration_ms = None
    target.last_run_error = None
    await db.commit()
    await db.refresh(target)

    result: dict[str, Any] = {
        "success": False,
        "filename": None,
        "bytes": None,
        "duration_ms": None,
        "error": None,
        "deleted": 0,
    }

    try:
        passphrase = _decrypt_passphrase(target)
        driver = get_destination(target.kind)
        # Decrypt the per-driver secret fields (S3 access keys,
        # future SCP private keys, Azure account keys) once at the
        # top so every downstream call sees plaintext.
        plain_config = decrypt_config_secrets(driver, target.config)
        driver.validate_config(plain_config)

        archive_bytes, filename = await build_backup_archive(
            db,
            passphrase=passphrase,
            passphrase_hint=target.passphrase_hint or None,
        )
        await driver.write(config=plain_config, filename=filename, archive_bytes=archive_bytes)
        deleted = await _retention_sweep(db, target=target, config=plain_config)

        finished = datetime.now(UTC)
        duration_ms = int((finished - started).total_seconds() * 1000)
        target.last_run_status = "success"
        target.last_run_filename = filename
        target.last_run_bytes = len(archive_bytes)
        target.last_run_duration_ms = duration_ms
        if target.schedule_cron:
            target.next_run_at = compute_next_run(target.schedule_cron, after=finished)
        result.update(
            {
                "success": True,
                "filename": filename,
                "bytes": len(archive_bytes),
                "duration_ms": duration_ms,
                "deleted": deleted,
            }
        )
        action = "backup_target_run_success"
        result_state = "success"
    except (BackupArchiveError, BackupDestinationError, SecretFieldError) as exc:
        finished = datetime.now(UTC)
        duration_ms = int((finished - started).total_seconds() * 1000)
        target.last_run_status = "failed"
        target.last_run_duration_ms = duration_ms
        target.last_run_error = str(exc)[:5000]
        if target.schedule_cron:
            target.next_run_at = compute_next_run(target.schedule_cron, after=finished)
        result.update({"error": str(exc), "duration_ms": duration_ms})
        action = "backup_target_run_failed"
        result_state = "failed"
        logger.warning(
            "backup_target_run_failed",
            target_id=str(target.id),
            kind=target.kind,
            error=str(exc),
        )

    db.add(
        AuditLog(
            action=action,
            resource_type="backup_target",
            resource_id=str(target.id),
            resource_display=target.name,
            user_id=actor_id,
            user_display_name=actor_display,
            result=result_state,
            new_value={
                "triggered_by": triggered_by,
                "kind": target.kind,
                **{k: v for k, v in result.items() if k != "error" or v is not None},
            },
            error_detail=result.get("error"),
        )
    )
    await db.commit()
    await db.refresh(target)
    return result
