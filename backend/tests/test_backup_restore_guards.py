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

import os
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.services.backup import restore
from app.services.backup import runner as runner_mod
from app.services.backup.restore import BackupRestoreError
from app.services.backup.targets import BackupDestinationError, DestinationConfigError
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


async def test_unlistable_destination_without_retention_does_not_fail_the_run(
    monkeypatch,
) -> None:
    # With no backup retention the listing only serves the safety-dump
    # allowance. A credential that may write but not list must not turn
    # the backup that was just written into a failed run.
    class _Unlistable(_ListingDriver):
        async def list_archives(self, *, config):
            raise BackupDestinationError("ListBucket denied")

    driver = _Unlistable([])
    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: driver)
    target = _retention_target(write_only=False)
    assert await runner_mod._retention_sweep(None, target=target, config={}) == 0

    # With backup retention configured, a failed listing still surfaces.
    target = _retention_target(write_only=False, retention_keep_last_n=3)
    with pytest.raises(BackupDestinationError):
        await runner_mod._retention_sweep(None, target=target, config={})


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


# The restore lock is taken on a connection of its own to ``db_url``, not
# through the request session (#1648), so these run against the test
# database. test_restore_lock_one_connection.py covers the pool, a running
# restore's phases and cancellation.
_DB_URL = os.environ["DATABASE_URL"]


async def _restore_lock_connection() -> asyncpg.Connection:
    return await asyncpg.connect(_DB_URL.replace("+asyncpg", ""))


async def test_restore_refuses_when_the_advisory_lock_is_held(
    monkeypatch, db_session: AsyncSession
) -> None:
    async def _inner_must_not_run(db, **kwargs):  # pragma: no cover — tripwire
        raise AssertionError("restore body ran without the advisory lock")

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner_must_not_run)
    holder = await _restore_lock_connection()  # another restore, mid-flight
    try:
        assert await holder.fetchval("SELECT pg_try_advisory_lock($1)", restore._RESTORE_LOCK_KEY)
        with pytest.raises(BackupRestoreError, match="already in progress"):
            await restore.apply_backup_restore(
                db_session,
                archive_bytes=b"zip",
                passphrase="hunter2hunter2",
                confirmation_phrase=restore.CONFIRM_PHRASE,
                db_url=_DB_URL,
            )
    finally:
        await holder.close()


async def test_restore_releases_the_advisory_lock(monkeypatch, db_session: AsyncSession) -> None:
    sentinel = object()

    async def _inner(db, **kwargs):
        return sentinel

    monkeypatch.setattr(restore, "_apply_backup_restore_inner", _inner)
    out = await restore.apply_backup_restore(
        db_session,
        archive_bytes=b"zip",
        passphrase="hunter2hunter2",
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url=_DB_URL,
    )
    assert out is sentinel
    # Free again: the next restore's connection takes it.
    other = await _restore_lock_connection()
    try:
        assert await other.fetchval("SELECT pg_try_advisory_lock($1)", restore._RESTORE_LOCK_KEY)
    finally:
        await other.close()


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


# ══════════════════════════════════════════════════════════════════════
# #1515 — dead / unexpected runs must not strand a target in_progress
# ══════════════════════════════════════════════════════════════════════


def test_backup_run_is_stale_only_for_old_in_progress() -> None:
    now = datetime.now(UTC)
    fresh = _retention_target(last_run_status="in_progress", last_run_at=now)
    old = _retention_target(last_run_status="in_progress", last_run_at=now - timedelta(hours=3))
    unstamped = _retention_target(last_run_status="in_progress", last_run_at=None)
    done = _retention_target(last_run_status="success", last_run_at=now - timedelta(days=9))
    assert runner_mod.backup_run_is_stale(fresh, now) is False
    assert runner_mod.backup_run_is_stale(old, now) is True
    assert runner_mod.backup_run_is_stale(unstamped, now) is True
    assert runner_mod.backup_run_is_stale(done, now) is False


async def test_reap_stamps_failed_audits_and_reschedules(db_session: AsyncSession) -> None:
    from sqlalchemy import select

    from app.models.audit import AuditLog

    target = _retention_target(
        name="stranded",
        last_run_status="in_progress",
        last_run_at=datetime.now(UTC) - timedelta(hours=5),
        schedule_cron="0 2 * * *",
        next_run_at=datetime.now(UTC) - timedelta(hours=3),
    )
    db_session.add(target)
    await db_session.flush()

    assert await runner_mod.reap_stale_backup_run(db_session, target=target) is True
    assert target.last_run_status == "failed"
    assert "most likely died" in (target.last_run_error or "")
    assert target.next_run_at is not None and target.next_run_at > datetime.now(UTC)
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == str(target.id))))
        .scalars()
        .all()
    )
    assert [r.action for r in rows] == ["backup_target_run_failed"]
    assert rows[0].new_value["triggered_by"] == "stale_reaper"

    # Idempotent: a reaped (failed) row is not reaped again.
    assert await runner_mod.reap_stale_backup_run(db_session, target=target) is False


async def test_reap_leaves_a_live_run_alone(db_session: AsyncSession) -> None:
    target = _retention_target(last_run_status="in_progress", last_run_at=datetime.now(UTC))
    db_session.add(target)
    await db_session.flush()
    assert await runner_mod.reap_stale_backup_run(db_session, target=target) is False
    assert target.last_run_status == "in_progress"


async def test_runner_catch_all_stamps_failed_for_unexpected_errors(
    db_session: AsyncSession, monkeypatch
) -> None:
    """A driver raising something the typed catch does not know —
    here a bare RuntimeError standing in for an untranslated driver
    exception — must still land the terminal stamp + audit row."""

    class _ExplodingDriver:
        def validate_config(self, config) -> None:
            return None

        async def write(self, *, config, filename, archive_bytes) -> None:
            raise RuntimeError("driver exploded in a new and exciting way")

    async def _build(db, **kw):
        return b"zip", "spatiumddi-backup-h-20261004-020000-ab12cd.zip"

    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: _ExplodingDriver())
    monkeypatch.setattr(runner_mod, "decrypt_config_secrets", lambda driver, cfg: cfg)
    monkeypatch.setattr(runner_mod, "build_backup_archive", _build)

    target = _retention_target(
        name="explody",
        last_run_status="never",
        schedule_cron="0 2 * * *",
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
    )
    db_session.add(target)
    await db_session.flush()

    result = await runner_mod.run_backup_for_target(
        db_session, target=target, triggered_by="schedule"
    )
    assert result["success"] is False
    assert "unexpected error" in (result["error"] or "")
    assert target.last_run_status == "failed"
    assert target.next_run_at is not None


async def test_local_volume_delete_translates_oserror(tmp_path) -> None:
    from app.services.backup.targets.local_volume import LocalVolumeDestination

    root = tmp_path / "backups"
    root.mkdir()
    # A directory wearing an archive's name: unlink() on it raises
    # IsADirectoryError, an OSError the old code re-raised bare.
    (root / "spatiumddi-backup-h-20261004-020000.zip").mkdir()
    driver = LocalVolumeDestination()
    with pytest.raises(BackupDestinationError):
        await driver.delete(
            config={"path": str(root)}, filename="spatiumddi-backup-h-20261004-020000.zip"
        )


async def test_local_volume_list_translates_oserror(tmp_path) -> None:
    from app.services.backup.targets.local_volume import LocalVolumeDestination

    not_a_dir = tmp_path / "a-file"
    not_a_dir.write_bytes(b"x")
    driver = LocalVolumeDestination()
    with pytest.raises(BackupDestinationError):
        await driver.list_archives(config={"path": str(not_a_dir)})


async def test_webdav_invalid_url_is_a_destination_error() -> None:
    from app.services.backup.targets.webdav import WebDAVDestination

    driver = WebDAVDestination()
    config = {"url": "http://invalid host.example/backups", "username": "u", "password": "p"}
    with pytest.raises(BackupDestinationError):
        await driver.write(config=config, filename="a.zip", archive_bytes=b"zip")


def test_webdav_validate_config_rejects_hostless_url() -> None:
    from app.services.backup.targets.webdav import WebDAVDestination

    with pytest.raises(DestinationConfigError):
        WebDAVDestination().validate_config(
            {"url": "https:///backups", "username": "u", "password": "p"}
        )


def test_scp_sets_an_sftp_channel_timeout() -> None:
    import inspect

    from app.services.backup.targets import scp as scp_mod

    assert "channel.settimeout" in inspect.getsource(scp_mod._open_sftp)
    assert inspect.getsource(scp_mod.ScpDestination).count("_open_sftp(client)") == 5
