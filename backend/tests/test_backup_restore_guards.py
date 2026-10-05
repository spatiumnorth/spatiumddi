"""Backup / restore guard regressions: #1575, #1574, #1571, #1515.

* #1575 — a selective restore that will be refused (plain-format
  archive, unknown section keys) is refused BEFORE the pre-restore
  safety dump is taken and before the connection pool is disposed:
  both facts are knowable from the parsed archive alone.
* #1574 — pre-restore safety dumps are not real backups: they must
  not consume the target's retention slots, must not be served as
  the "latest" archive, and get their own small keep-last-N.
* #1571 — restore takes a Postgres advisory lock, Run Now / the
  sweep claim a target atomically, and archive + safety-dump names
  carry a random suffix so two runs in the same second cannot
  overwrite each other.
* #1515 — a backup run whose process dies, or whose driver raises
  something unexpected, must not leave the target ``in_progress``
  forever: the runner stamps ``failed`` for ANY exception, the
  sweep reaps a stale ``in_progress`` row instead of skipping it
  forever, and drivers translate ``OSError`` / ``httpx.InvalidURL``
  at their boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.backup import restore
from app.services.backup import runner as runner_mod
from app.services.backup.restore import BackupRestoreError
from app.services.backup.targets.base import (
    PRE_RESTORE_KEEP_LAST_N,
    ArchiveListing,
    is_pre_restore_archive,
)

# ══════════════════════════════════════════════════════════════════════
# #1575 — selective restore validates before the safety dump
# ══════════════════════════════════════════════════════════════════════


def _patch_restore_prereqs(monkeypatch: pytest.MonkeyPatch, *, dump_format: str) -> dict:
    """Stub everything ``apply_backup_restore`` does before Phase 3,
    and make the safety dump a tripwire: if validation regresses back
    behind it, these tests fail on the tripwire, not on a side effect."""
    state = {"safety_dump_calls": 0}

    def _extract(_archive_bytes: bytes):
        return ({"format_version": 2, "schema_version": None}, b"dump", dump_format, b"enc")

    async def _safety_dump(_db):  # pragma: no cover — the tripwire itself
        state["safety_dump_calls"] += 1
        raise AssertionError("safety dump taken before selective-restore validation")

    monkeypatch.setattr(restore, "extract_archive_members", _extract)
    monkeypatch.setattr(restore, "decrypt_secrets", lambda enc, passphrase: {})
    monkeypatch.setattr(restore, "schema_direction_error", lambda head: None)
    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _safety_dump)
    return state


async def test_selective_restore_of_plain_archive_refused_before_safety_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _patch_restore_prereqs(monkeypatch, dump_format="plain")

    with pytest.raises(BackupRestoreError, match="custom format"):
        await restore.apply_backup_restore(
            None,
            archive_bytes=b"zip",
            passphrase="hunter2hunter2",
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
            sections=["dns"],
        )
    assert state["safety_dump_calls"] == 0


async def test_selective_restore_with_unknown_section_refused_before_safety_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _patch_restore_prereqs(monkeypatch, dump_format="custom")

    with pytest.raises(BackupRestoreError, match="unknown section keys"):
        await restore.apply_backup_restore(
            None,
            archive_bytes=b"zip",
            passphrase="hunter2hunter2",
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
            sections=["no_such_section"],
        )
    assert state["safety_dump_calls"] == 0


# ══════════════════════════════════════════════════════════════════════
# #1574 — safety dumps are not backups for retention or "latest"
# ══════════════════════════════════════════════════════════════════════


class _ListingDriver:
    """Newest-first listing + recorded deletes, like the write-only
    suite's counting driver."""

    def __init__(self, filenames: list[str]) -> None:
        self._filenames = filenames
        self.deleted: list[str] = []

    async def list_archives(self, *, config):
        now = datetime.now(UTC)
        return [
            ArchiveListing(filename=n, size_bytes=1, created_at=now - timedelta(days=i))
            for i, n in enumerate(self._filenames)
        ]

    async def delete(self, *, config, filename):
        self.deleted.append(filename)


def _retention_target(**kw):
    from app.models.backup import BackupTarget

    defaults = dict(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    return BackupTarget(**{**defaults, **kw})


def test_is_pre_restore_archive_matches_only_safety_dumps() -> None:
    assert is_pre_restore_archive("pre-restore-20261004-120000.zip")
    assert not is_pre_restore_archive("spatiumddi-backup-host-20261004-120000.zip")
    assert not is_pre_restore_archive("a.zip")


async def test_safety_dumps_do_not_consume_keep_last_n_slots(monkeypatch) -> None:
    # Newest first: a fresh safety dump, then three real backups.
    # keep-last-2 must keep the two newest BACKUPS; before the split
    # the safety dump took one slot and b2 was pruned early.
    driver = _ListingDriver(
        [
            "pre-restore-20261004-120000.zip",
            "spatiumddi-backup-h-20261004-020000.zip",
            "spatiumddi-backup-h-20261003-020000.zip",
            "spatiumddi-backup-h-20261002-020000.zip",
        ]
    )
    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: driver)
    target = _retention_target(write_only=False, retention_keep_last_n=2)
    deleted = await runner_mod._retention_sweep(None, target=target, config={})
    assert driver.deleted == ["spatiumddi-backup-h-20261002-020000.zip"]
    assert deleted == 1


async def test_safety_dumps_pruned_under_their_own_allowance(monkeypatch) -> None:
    names = [f"pre-restore-2026100{i}-020000.zip" for i in range(1, 7)]
    driver = _ListingDriver(names)  # listing order is newest-first as given
    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: driver)
    target = _retention_target(write_only=False)  # no backup retention at all
    await runner_mod._retention_sweep(None, target=target, config={})
    assert driver.deleted == names[PRE_RESTORE_KEEP_LAST_N:]


async def test_keep_days_does_not_delete_fresh_safety_dumps(monkeypatch) -> None:
    # A 40-day-old backup goes under keep-days=30; a safety dump of
    # the same age is governed by its own allowance, not the days.
    old = datetime.now(UTC) - timedelta(days=40)
    driver = _ListingDriver(
        ["pre-restore-20260825-020000.zip", "spatiumddi-backup-h-20260825-020000.zip"]
    )

    async def _list(*, config):
        return [
            ArchiveListing(
                filename="pre-restore-20260825-020000.zip", size_bytes=1, created_at=old
            ),
            ArchiveListing(
                filename="spatiumddi-backup-h-20260825-020000.zip", size_bytes=1, created_at=old
            ),
        ]

    driver.list_archives = _list  # type: ignore[method-assign]
    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: driver)
    target = _retention_target(write_only=False, retention_keep_days=30)
    await runner_mod._retention_sweep(None, target=target, config={})
    assert driver.deleted == ["spatiumddi-backup-h-20260825-020000.zip"]


def test_latest_download_skips_safety_dumps() -> None:
    """Source-level pin, matching the write-only suite's style: the
    latest endpoint must filter before it picks ``[0]``."""
    import inspect

    from app.api.v1.backup import targets as api_targets

    src = inspect.getsource(api_targets.download_latest_target_archive)
    assert "is_pre_restore_archive" in src
    assert src.index("is_pre_restore_archive") < src.index("newest = real_archives[0]")


# ══════════════════════════════════════════════════════════════════════
# #1571 — concurrency guards + collision-proof names
# ══════════════════════════════════════════════════════════════════════


async def test_claim_stamps_in_progress_once(db_session: AsyncSession) -> None:
    target = _retention_target(last_run_status="success")
    db_session.add(target)
    await db_session.flush()

    started = datetime.now(UTC)
    assert await runner_mod.claim_backup_run(db_session, target=target, started=started) is True
    assert target.last_run_status == "in_progress"
    assert target.last_run_at is not None

    # A second claim — Run Now racing the sweep — loses atomically.
    assert await runner_mod.claim_backup_run(db_session, target=target, started=started) is False
    assert target.last_run_status == "in_progress"


async def test_runner_refuses_a_target_already_in_progress(db_session: AsyncSession) -> None:
    target = _retention_target(last_run_status="in_progress", last_run_at=datetime.now(UTC))
    db_session.add(target)
    await db_session.flush()

    with pytest.raises(runner_mod.BackupRunBusyError):
        await runner_mod.run_backup_for_target(db_session, target=target, triggered_by="manual")


class _LockResult:
    def __init__(self, value: bool) -> None:
        self._value = value

    def scalar_one(self) -> bool:
        return self._value


class _LockSession:
    """Minimal session stub recording the advisory-lock SQL."""

    def __init__(self, acquired: bool) -> None:
        self._acquired = acquired
        self.statements: list[str] = []

    async def execute(self, stmt, params=None):  # type: ignore[no-untyped-def]
        self.statements.append(str(stmt))
        return _LockResult(self._acquired)

    async def commit(self) -> None:
        return None


async def test_restore_refuses_when_the_advisory_lock_is_held(monkeypatch) -> None:
    async def _inner_must_not_run(db, **kwargs):  # pragma: no cover — tripwire
        raise AssertionError("restore body ran without the advisory lock")

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner_must_not_run)
    session = _LockSession(acquired=False)
    with pytest.raises(BackupRestoreError, match="already in progress"):
        await restore.apply_backup_restore(
            session,
            archive_bytes=b"zip",
            passphrase="hunter2hunter2",
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
        )
    assert any("pg_try_advisory_lock" in s for s in session.statements)


async def test_restore_releases_the_advisory_lock(monkeypatch) -> None:
    sentinel = object()

    async def _inner(db, **kwargs):
        return sentinel

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner)
    session = _LockSession(acquired=True)
    out = await restore.apply_backup_restore(
        session,
        archive_bytes=b"zip",
        passphrase="hunter2hunter2",
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url="postgresql+asyncpg://u:p@h:5432/db",
    )
    assert out is sentinel
    assert any("pg_advisory_unlock" in s for s in session.statements)


async def test_two_safety_dumps_in_one_second_do_not_collide(tmp_path, monkeypatch) -> None:
    """Same-second restores used to share one filename, the second
    overwriting the first's rollback copy via an overwriting write."""

    async def _fake_build(db, *, passphrase, passphrase_hint):
        return b"zipbytes", "x.zip"

    monkeypatch.setattr(restore, "PRE_RESTORE_DIR", tmp_path)
    monkeypatch.setattr(restore, "build_backup_archive", _fake_build)
    first = await restore._write_pre_restore_safety_dump(None)
    second = await restore._write_pre_restore_safety_dump(None)
    assert first is not None and second is not None
    assert first != second
    from pathlib import Path

    assert Path(first).is_file() and Path(second).is_file()


def test_archive_filename_carries_a_random_suffix() -> None:
    import inspect

    from app.services.backup import archive as archive_mod

    src = inspect.getsource(archive_mod.build_backup_archive)
    assert "token_hex" in src
    assert 'f"spatiumddi-backup-{safe_host}-{timestamp}-' in src
