"""A failed backup run's audit row does not carry the destination (#1617).

The ``backup_target_run_failed`` row is forwarded as-is (syslog / webhook /
SMTP forward targets, the ``system.backup_failed`` event), and a driver's
error text routinely names the destination: NFS server and export, S3
bucket, SCP host and path. The row now carries a fixed ``failure_category``
instead; the full text stays on the target and in ``error_detail``.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services import audit_forward, event_publisher
from app.services.backup import runner as runner_mod
from app.services.backup.archive import BackupArchiveError
from app.services.backup.targets import (
    BackupDestinationError,
    DestinationConfigError,
    RetentionLockedError,
    SecretFieldError,
)

_DESTINATION = "nas.example.test:/volume1/backups"


def _failing_driver(exc: BaseException):
    class _Driver:
        def validate_config(self, config) -> None:
            return None

        async def write(self, *, config, filename, archive_bytes) -> None:
            raise exc

    return _Driver()


async def _run_failing(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> tuple[BackupTarget, dict, AuditLog]:
    async def _build(db, **kw):
        return b"zip", "spatiumddi-backup-h-20261004-020000-ab12cd.zip"

    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: _failing_driver(exc))
    monkeypatch.setattr(runner_mod, "decrypt_config_secrets", lambda driver, cfg: cfg)
    monkeypatch.setattr(runner_mod, "build_backup_archive", _build)

    target = BackupTarget(
        name="nas",
        kind="nfs",
        config={},
        last_run_status="never",
        schedule_cron="0 2 * * *",
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
    )
    db_session.add(target)
    await db_session.flush()

    result = await runner_mod.run_backup_for_target(
        db_session, target=target, triggered_by="schedule"
    )
    row = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == str(target.id),
                    AuditLog.action == "backup_target_run_failed",
                )
            )
        )
        .scalars()
        .one()
    )
    return target, result, row


async def test_a_destination_error_is_kept_out_of_the_forwarded_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    exc = BackupDestinationError(
        f"mount.nfs: access denied by server while mounting {_DESTINATION}"
    )
    target, result, row = await _run_failing(db_session, monkeypatch, exc)

    assert "error" not in row.new_value
    assert row.new_value["failure_category"] == "permission_denied"
    assert _DESTINATION not in json.dumps(row.new_value)
    # Neither forwarded shape carries it.
    assert _DESTINATION not in json.dumps(audit_forward._serialize(row))  # noqa: SLF001
    assert _DESTINATION not in json.dumps(
        event_publisher._serialize_audit(row, "system.backup_failed")  # noqa: SLF001
    )
    # The full text stays where only a superadmin reads it.
    assert _DESTINATION in (target.last_run_error or "")
    assert _DESTINATION in (row.error_detail or "")
    assert _DESTINATION in (result["error"] or "")


async def test_an_unexpected_error_is_kept_out_of_the_forwarded_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    exc = RuntimeError("upload to s3://backups-bucket/prod failed")
    target, _, row = await _run_failing(db_session, monkeypatch, exc)

    assert "error" not in row.new_value
    assert row.new_value["failure_category"] == "unexpected"
    assert "backups-bucket" not in json.dumps(audit_forward._serialize(row))  # noqa: SLF001
    assert "backups-bucket" in (target.last_run_error or "")


async def test_the_stale_reaper_row_carries_a_category(db_session: AsyncSession) -> None:
    from datetime import UTC, datetime, timedelta

    target = BackupTarget(
        name="stranded",
        kind="local_volume",
        config={},
        passphrase_encrypted=b"x",
        last_run_status="in_progress",
        last_run_at=datetime.now(UTC) - timedelta(hours=5),
    )
    db_session.add(target)
    await db_session.flush()

    assert await runner_mod.reap_stale_backup_run(db_session, target=target) is True
    row = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == str(target.id))))
        .scalars()
        .one()
    )
    assert row.new_value["failure_category"] == "run_died"


@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (BackupDestinationError(f"{_DESTINATION}: Connection refused"), "unreachable"),
        (BackupDestinationError("No route to host"), "unreachable"),
        (BackupDestinationError("ssh: connect to host h port 22: Connection timed out"), "timeout"),
        (BackupDestinationError("AccessDenied: Access Denied"), "permission_denied"),
        (BackupDestinationError("NT_STATUS_LOGON_FAILURE"), "auth_failed"),
        (BackupDestinationError("No space left on device"), "no_space"),
        (BackupDestinationError("NoSuchBucket: The specified bucket does not exist"), "not_found"),
        (BackupDestinationError("something else entirely"), "destination_error"),
        (DestinationConfigError("missing 'export'"), "config_invalid"),
        (RetentionLockedError("object locked"), "retention_locked"),
        (SecretFieldError("cannot decrypt"), "secret_unreadable"),
        (BackupArchiveError("pg_dump failed"), "archive_error"),
        (RuntimeError("boom"), "unexpected"),
    ],
)
def test_failure_category(exc: BaseException, category: str) -> None:
    assert runner_mod.backup_failure_category(exc) == category
