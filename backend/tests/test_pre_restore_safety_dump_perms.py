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
