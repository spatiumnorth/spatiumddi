"""Run a backup against one configured target (issue #117 Phase 1b).

Threads :func:`build_backup_archive` (Phase 1a) into the
destination drivers + the per-target retention sweep + the
``last_run_*`` state-machine on ``backup_target``. Used by both
the on-demand "Run Now" button and the beat-driven schedule
sweep.

State machine on the row:

* Pre-run → ``last_run_status = "in_progress"``, all other
  ``last_run_*`` cleared — via ONE atomic conditional UPDATE
  (:func:`claim_backup_run`, #1571), so two callers cannot both
  claim the same target. Stamp committed before the destination
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
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup.archive import (
    BackupArchiveError,
    build_backup_archive,
)
from app.services.backup.health import RUN_PRESUMED_DEAD_AFTER
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


class BackupRunBusyError(Exception):
    """Another run already holds this target's ``in_progress`` claim.

    Raised by :func:`run_backup_for_target` when its atomic claim
    loses the race (#1571). Callers translate it: Run Now answers
    409, the schedule sweep counts a skip. Distinct from a run
    *failure* — nothing was attempted, so nothing is stamped and no
    audit row is written.
    """


async def claim_backup_run(
    db: AsyncSession,
    *,
    target: BackupTarget,
    started: datetime,
) -> bool:
    """Atomically claim ``target`` for a run: one conditional UPDATE
    that stamps ``in_progress`` only when the row is not already
    claimed (#1571).

    The old shape — read the status, decide, stamp, commit — let two
    callers (Run Now double-clicked, Run Now racing the sweep) both
    read "not running" and both run, interleaving writes to the same
    destination filename. Here the WHERE is evaluated against the
    committed row under its lock: concurrent claimers serialise, and
    exactly one gets the row back. Mirrors the WOL scheduler's claim
    (#533). Both exits leave a persistent ``target`` refreshed:
    the success path after its commit, the lost-race path after
    its rollback (which would otherwise leave every attribute
    expired, so the next read trips a lazy refresh outside a
    greenlet).
    """
    claimed_id = (
        await db.execute(
            update(BackupTarget)
            .where(
                BackupTarget.id == target.id,
                BackupTarget.last_run_status != "in_progress",
            )
            .values(
                last_run_status="in_progress",
                last_run_at=started,
                last_run_filename=None,
                last_run_bytes=None,
                last_run_duration_ms=None,
                last_run_error=None,
            )
            .returning(BackupTarget.id)
        )
    ).scalar_one_or_none()
    if claimed_id is None:
        await db.rollback()
        # The rollback expires ``target``'s attributes; refresh so
        # callers can read the committed state (the winner's
        # ``in_progress`` stamp) without tripping a lazy load —
        # the success path below refreshes for the same reason.
        # Only when the instance is persistent: a never-committed
        # target is transient again after the rollback and has no
        # committed state to read back (refresh would raise).
        if sa_inspect(target).persistent:
            await db.refresh(target)
        return False
    await db.commit()
    await db.refresh(target)
    return True


def backup_run_is_stale(target: BackupTarget, now: datetime) -> bool:
    """True when an ``in_progress`` claim was stranded by a dead
    process rather than being genuinely held (#1515).

    The runner stamps ``in_progress`` and commits BEFORE doing any
    work, so a process that dies mid-run (OOM kill, pod restart, a
    native-library crash) never reaches a terminal branch — and the
    sweep used to skip the row forever, silently stopping that
    target's schedule. The age test reuses the health module's
    presumption threshold (:data:`RUN_PRESUMED_DEAD_AFTER`, 2 h —
    far above a legitimate run: pg_dump is capped at 30 min and the
    destination write has its own timeouts), so the alerting code
    and the recovery code agree on when a run is dead. A NULL
    ``last_run_at`` on an ``in_progress`` row was never stamped
    properly at all, which is also stale.
    """
    if target.last_run_status != "in_progress":
        return False
    if target.last_run_at is None:
        return True
    return now - target.last_run_at >= RUN_PRESUMED_DEAD_AFTER


async def reap_stale_backup_run(
    db: AsyncSession,
    *,
    target: BackupTarget,
    actor_display: str = "system (stale-run reaper)",
) -> bool:
    """Stamp a stranded ``in_progress`` run ``failed`` so the target
    can run again (#1515). Returns True when it reaped.

    Writes the same terminal state + audit shape the runner's own
    failure branch writes, recomputes ``next_run_at`` so the
    schedule resumes, and commits — after which the caller proceeds
    with the due run in the same tick.
    """
    now = datetime.now(UTC)
    if not backup_run_is_stale(target, now):
        return False
    started_at = target.last_run_at
    error = (
        f"run marked in progress since {started_at.isoformat() if started_at else 'an unknown time'} "
        "never finished — the process running it most likely died (OOM kill, "
        "pod restart, deploy). Stamped failed by the staleness reaper so the "
        "schedule can resume."
    )
    target.last_run_status = "failed"
    target.last_run_error = error[:5000]
    if target.schedule_cron:
        try:
            target.next_run_at = compute_next_run(target.schedule_cron, after=now)
        except Exception as exc:  # noqa: BLE001 — a bad cron must not wedge the reaper
            logger.warning(
                "backup_stale_reap_next_run_failed",
                target_id=str(target.id),
                cron=target.schedule_cron,
                error=str(exc),
            )
            target.next_run_at = None
    db.add(
        AuditLog(
            action="backup_target_run_failed",
            resource_type="backup_target",
            resource_id=str(target.id),
            resource_display=target.name,
            user_id=None,
            user_display_name=actor_display,
            result="failure",
            new_value={"triggered_by": "stale_reaper", "kind": target.kind},
            error_detail=error,
        )
    )
    await db.commit()
    await db.refresh(target)
    logger.warning(
        "backup_stale_run_reaped",
        target_id=str(target.id),
        in_progress_since=started_at.isoformat() if started_at else None,
    )
    return True


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
    "no automatic pruning" of BACKUPS — pre-restore safety dumps
    are still pruned to their own keep-last-N either way (#1574),
    so this sweep lists the destination even when no backup
    retention is configured. Returns the number of archives
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
    # No early return when both backup-retention fields are NULL:
    # the listing is still needed to prune safety dumps under their
    # own allowance below (#1574). The backup branches no-op on
    # their own when their field is unset.
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
        except Exception as exc:  # noqa: BLE001
            # A driver bug must not escape the retention sweep either
            # (#1515): this runs AFTER the archive was written, so an
            # escape here would strand the run's terminal stamp.
            logger.warning(
                "backup_retention_delete_failed",
                target_id=str(target.id),
                filename=filename,
                error=f"unexpected: {exc}",
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

    The run is claimed atomically first (:func:`claim_backup_run`);
    a target already ``in_progress`` raises
    :class:`BackupRunBusyError` rather than running twice (#1571).
    """
    started = datetime.now(UTC)
    if not await claim_backup_run(db, target=target, started=started):
        raise BackupRunBusyError(f"backup target {target.name!r} already has a run in progress")

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
    except Exception as exc:  # noqa: BLE001
        # The catch-all IS the fix (#1515). The typed catch above
        # covers the errors drivers are SUPPOSED to raise; anything
        # else — a driver bug, a bare OSError that escaped
        # translation, a library exception — used to propagate past
        # the terminal stamp entirely, leaving the row ``in_progress``
        # (which the sweep then skipped forever) and giving the API
        # caller a bare 500. Stamp it failed, recompute next_run_at,
        # write the audit row below; the run is recorded, the
        # schedule survives, and the failure is visible in the UI
        # instead of only in a traceback.
        finished = datetime.now(UTC)
        duration_ms = int((finished - started).total_seconds() * 1000)
        target.last_run_status = "failed"
        target.last_run_duration_ms = duration_ms
        target.last_run_error = f"unexpected error: {exc}"[:5000]
        if target.schedule_cron:
            target.next_run_at = compute_next_run(target.schedule_cron, after=finished)
        result.update({"error": f"unexpected error: {exc}", "duration_ms": duration_ms})
        action = "backup_target_run_failed"
        result_state = "failed"
        logger.exception(
            "backup_target_run_unexpected_error",
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
