"""A backup run whose session a restore ended still records its end (#2353).

A restore runs ``pg_terminate_backend`` on every other session, the
running backup's included. The run used to be unable to stamp its own
terminal state, leaving the target ``in_progress`` (Run now 409) until
the 2 h presumed-dead reap.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.crypto import encrypt_str
from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup import runner as runner_mod
from app.services.backup.targets import BackupDestinationError


def _driver(db_session: AsyncSession, *, fail: bool):
    class _Driver:
        def validate_config(self, config) -> None:
            return None

        async def write(self, *, config, filename, archive_bytes) -> None:
            # What the restore does: end the run's own session.
            async with db_session.bind.connect() as other:  # type: ignore[union-attr]
                await other.execute(text("SELECT pg_terminate_backend(:p)"), {"p": self.pid})
                await other.commit()
            if fail:
                raise BackupDestinationError("destination timed out")

        pid = 0

    return _Driver()


async def _run(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, *, fail: bool):
    async def _build(db, **kw):
        # The archive build reads through the run's session, so it holds
        # an open transaction (and a connection) while the destination
        # write is in flight; that is the connection a restore ends.
        driver.pid = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        return b"zip", "spatiumddi-backup-h-20261004-020000-ab12cd.zip"

    target = BackupTarget(
        name="hung",
        kind="webdav",
        config={},
        last_run_status="never",
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
    )
    db_session.add(target)
    await db_session.commit()
    target_id = target.id
    driver = _driver(db_session, fail=fail)

    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: driver)
    monkeypatch.setattr(runner_mod, "decrypt_config_secrets", lambda d, c: c)
    monkeypatch.setattr(runner_mod, "build_backup_archive", _build)
    import app.db as app_db

    monkeypatch.setattr(
        app_db, "AsyncSessionLocal", async_sessionmaker(db_session.bind, expire_on_commit=False)
    )
    # The claim has to land before the write terminates the session.
    result = await runner_mod.run_backup_for_target(
        db_session, target=target, triggered_by="manual"
    )
    return target_id, result


async def test_failed_run_on_a_terminated_session_is_stamped_failed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_id, result = await _run(db_session, monkeypatch, fail=True)
    assert result["success"] is False

    fresh = async_sessionmaker(db_session.bind, expire_on_commit=False)
    async with fresh() as s:
        row = await s.get(BackupTarget, target_id)
        assert row is not None
        assert row.last_run_status == "failed"
        assert "timed out" in (row.last_run_error or "")
        audit = (
            (
                await s.execute(
                    select(AuditLog).where(
                        AuditLog.resource_id == str(target_id),
                        AuditLog.action == "backup_target_run_failed",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(audit) == 1

        # Run now is no longer blocked by a phantom in-progress claim.
        assert await runner_mod.claim_backup_run(s, target=row, started=datetime.now(UTC))


async def test_successful_write_on_a_terminated_session_is_stamped_success(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_id, result = await _run(db_session, monkeypatch, fail=False)
    assert result["success"] is True
    fresh = async_sessionmaker(db_session.bind, expire_on_commit=False)
    async with fresh() as s:
        row = await s.get(BackupTarget, target_id)
        assert row is not None
        assert row.last_run_status == "success"
        assert row.last_run_filename is not None


async def test_a_newer_claim_is_not_overwritten(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import update

    async def _build(db, **kw):
        driver.pid = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        return b"zip", "x.zip"

    target = BackupTarget(
        name="hung2",
        kind="webdav",
        config={},
        last_run_status="never",
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
    )
    db_session.add(target)
    await db_session.commit()
    tid = target.id
    driver = _driver(db_session, fail=True)
    newer = datetime.now(UTC) + timedelta(minutes=5)

    orig_write = driver.write

    async def write(**kw):
        async with async_sessionmaker(db_session.bind)() as s:
            await s.execute(
                update(BackupTarget).where(BackupTarget.id == tid).values(last_run_at=newer)
            )
            await s.commit()
        await orig_write(**kw)

    driver.write = write  # type: ignore[method-assign]
    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: driver)
    monkeypatch.setattr(runner_mod, "decrypt_config_secrets", lambda d, c: c)
    monkeypatch.setattr(runner_mod, "build_backup_archive", _build)
    import app.db as app_db

    monkeypatch.setattr(
        app_db, "AsyncSessionLocal", async_sessionmaker(db_session.bind, expire_on_commit=False)
    )
    await runner_mod.run_backup_for_target(db_session, target=target, triggered_by="manual")
    async with async_sessionmaker(db_session.bind)() as s:
        row = await s.get(BackupTarget, tid)
        assert row.last_run_status == "in_progress"  # someone else's claim, untouched
