"""The pre-restore safety dump must not be readable by other users.

Its secrets envelope uses a documented constant passphrase, so file
permissions are the only protection for the SECRET_KEY inside it.
"""

from __future__ import annotations

import os
import stat

import pytest

from app.services.backup import restore


async def _fake_build(db, *, passphrase, passphrase_hint):
    return b"zipbytes", "x.zip"


def _mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


@pytest.mark.asyncio
async def test_safety_dump_dir_and_file_are_private(tmp_path, monkeypatch):
    target = tmp_path / "backups"
    monkeypatch.setattr(restore, "PRE_RESTORE_DIR", target)
    monkeypatch.setattr(restore, "build_backup_archive", _fake_build)
    old = os.umask(0o022)
    try:
        out = await restore._write_pre_restore_safety_dump(None)
    finally:
        os.umask(old)
    assert out is not None
    assert _mode(target) == 0o700
    assert _mode(out) == 0o600


@pytest.mark.asyncio
async def test_safety_dump_tightens_preexisting_loose_dir(tmp_path, monkeypatch):
    target = tmp_path / "backups"
    target.mkdir()
    os.chmod(target, 0o755)
    monkeypatch.setattr(restore, "PRE_RESTORE_DIR", target)
    monkeypatch.setattr(restore, "build_backup_archive", _fake_build)
    old = os.umask(0o022)
    try:
        out = await restore._write_pre_restore_safety_dump(None)
    finally:
        os.umask(old)
    assert out is not None
    assert _mode(target) == 0o700
    assert _mode(out) == 0o600


@pytest.mark.asyncio
async def test_safety_dump_still_written_when_dir_chmod_is_refused(tmp_path, monkeypatch):
    """A directory this process can't chmod (not its owner) must not cost
    the rollback copy: the dump is still written, and still 0600."""
    target = tmp_path / "backups"
    target.mkdir()
    monkeypatch.setattr(restore, "PRE_RESTORE_DIR", target)
    monkeypatch.setattr(restore, "build_backup_archive", _fake_build)
    real_chmod = os.chmod

    def refuse_dir_chmod(path, mode, *a, **kw):
        if os.fspath(path) == os.fspath(target):
            raise PermissionError(1, "Operation not permitted")
        return real_chmod(path, mode, *a, **kw)

    monkeypatch.setattr(restore.os, "chmod", refuse_dir_chmod)
    old = os.umask(0o022)
    try:
        out = await restore._write_pre_restore_safety_dump(None)
    finally:
        os.umask(old)
    assert out is not None
    assert _mode(out) == 0o600


# ── local keep-last-N ───────────────────────────────────────────────────


def _seed_dumps(directory, count: int) -> list:
    directory.mkdir(mode=0o700, exist_ok=True)
    paths = []
    for i in range(count):
        p = directory / f"pre-restore-2026010{i}-000000-aaaaa{i}.zip"
        p.write_bytes(b"old")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
        paths.append(p)
    return paths


@pytest.mark.asyncio
async def test_safety_dumps_are_pruned_to_the_keep_count(tmp_path, monkeypatch):
    """Each dump carries the SECRET_KEY under a public passphrase, so old
    copies are deleted once a new one is written, keeping the newest few."""
    target = tmp_path / "backups"
    seeded = _seed_dumps(target, 6)
    unrelated = target / "spatiumddi-backup-20260101-000000.zip"
    unrelated.write_bytes(b"real backup")
    monkeypatch.setattr(restore, "PRE_RESTORE_DIR", target)
    monkeypatch.setattr(restore, "build_backup_archive", _fake_build)

    out = await restore._write_pre_restore_safety_dump(None)

    assert out is not None
    remaining = sorted(p.name for p in target.glob("pre-restore-*.zip"))
    keep_n = restore.PRE_RESTORE_KEEP_LAST_N
    assert len(remaining) == keep_n
    assert os.path.basename(out) in remaining
    # The newest of the older dumps survive, the oldest go.
    expected_old = sorted(p.name for p in seeded[-(keep_n - 1) :])
    assert set(expected_old) <= set(remaining)
    # A real backup archive in the same directory is never touched.
    assert unrelated.exists()


def test_safety_dump_prune_keeps_the_new_dump_whatever_its_mtime(tmp_path, monkeypatch):
    """The dump just written survives even if a clock step left it with
    the oldest mtime in the directory."""
    target = tmp_path / "backups"
    _seed_dumps(target, 5)
    new = target / "pre-restore-20260201-000000-bbbbbb.zip"
    new.write_bytes(b"new")
    os.utime(new, (1, 1))
    monkeypatch.setattr(restore, "PRE_RESTORE_DIR", target)

    restore._prune_pre_restore_safety_dumps(keep=new)

    assert new.exists()
    assert len(list(target.glob("pre-restore-*.zip"))) == restore.PRE_RESTORE_KEEP_LAST_N
