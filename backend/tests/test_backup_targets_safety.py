"""Backup-target safety fixes (#1570 first; sibling sections follow).

Failed writes used to leave the staged ``<archive>.tmp`` behind on the
FTP, SCP, SMB and local-volume drivers. Listing and retention only
match ``*.zip``, so those orphans were invisible and were never pruned
— every failed run on a destination that was out of space made the
next failure more likely (#1570). The NFS driver already cleaned its
``.part`` up; these tests pin the same behaviour for the other four.

"""

from __future__ import annotations

import io
import os
import sys
import types
from pathlib import Path

import pytest

from app.services.backup.targets.base import BackupDestinationError
from app.services.backup.targets.ftp import FtpDestination
from app.services.backup.targets.local_volume import LocalVolumeDestination
from app.services.backup.targets.scp import ScpDestination
from app.services.backup.targets.smb import SmbDestination

_NAME = "spatiumddi-backup-20261004-120000.zip"


# ── #1570: a failed write removes its staged .tmp ────────────────────


@pytest.mark.asyncio
async def test_local_volume_failed_write_leaves_no_tmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _boom(_src: object, _dst: object) -> None:
        raise OSError("No space left on device")

    monkeypatch.setattr(os, "replace", _boom)
    driver = LocalVolumeDestination()
    with pytest.raises(BackupDestinationError):
        await driver.write(
            config={"path": str(tmp_path / "backups")},
            filename=_NAME,
            archive_bytes=b"partial",
        )
    root = tmp_path / "backups"
    assert list(root.iterdir()) == []


class _FakeFtpClient:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def storbinary(self, _cmd: str, _fh: io.BytesIO) -> None:
        raise OSError("connection dropped")

    def delete(self, path: str) -> None:
        self.deleted.append(path)

    def rename(self, _src: str, _dst: str) -> None:  # pragma: no cover
        raise AssertionError("rename must not run after a failed STOR")

    def quit(self) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_ftp_failed_write_deletes_the_staged_tmp(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeFtpClient()
    monkeypatch.setattr(FtpDestination, "_connect", lambda self, config: fake)
    config = {
        "host": "192.0.2.1",
        "username": "u",
        "password": "p",
        "remote_path": "/backups",
    }
    with pytest.raises(BackupDestinationError):
        await FtpDestination().write(config=config, filename=_NAME, archive_bytes=b"x")
    assert fake.deleted == [f"/backups/{_NAME}.tmp"]


class _FakeSftpFile:
    def __enter__(self) -> _FakeSftpFile:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def write(self, _data: bytes) -> None:
        raise OSError("No space left on device")


class _FakeSftp:
    def __init__(self) -> None:
        self.removed: list[str] = []

    def file(self, _path: str, _mode: str) -> _FakeSftpFile:
        return _FakeSftpFile()

    def remove(self, path: str) -> None:
        self.removed.append(path)

    def rename(self, _src: str, _dst: str) -> None:  # pragma: no cover
        raise AssertionError("rename must not run after a failed write")

    def close(self) -> None:
        pass


class _FakeSshClient:
    def __init__(self, sftp: _FakeSftp) -> None:
        self._sftp = sftp

    def open_sftp(self) -> _FakeSftp:
        return self._sftp

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_scp_failed_write_removes_the_staged_tmp(monkeypatch: pytest.MonkeyPatch):
    sftp = _FakeSftp()
    client = _FakeSshClient(sftp)
    monkeypatch.setattr(ScpDestination, "_connect", lambda self, config: client)
    config = {
        "host": "192.0.2.1",
        "username": "u",
        "password": "p",
        "remote_path": "/backups",
    }
    with pytest.raises(BackupDestinationError):
        await ScpDestination().write(config=config, filename=_NAME, archive_bytes=b"x")
    assert sftp.removed == [f"/backups/{_NAME}.tmp"]


@pytest.mark.asyncio
async def test_smb_failed_write_removes_the_staged_tmp(monkeypatch: pytest.MonkeyPatch):
    removed: list[str] = []

    class _FakeFile:
        def __enter__(self) -> _FakeFile:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def write(self, _data: bytes) -> None:
            raise OSError("disk full")

    fake = types.ModuleType("smbclient")
    fake.register_session = lambda *_a, **_k: None  # type: ignore[attr-defined]
    fake.open_file = lambda *_a, **_k: _FakeFile()  # type: ignore[attr-defined]
    fake.remove = removed.append  # type: ignore[attr-defined]
    fake.rename = lambda *_a, **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "smbclient", fake)

    config = {"server": "192.0.2.1", "share": "backups", "username": "u", "password": "p"}
    with pytest.raises(BackupDestinationError):
        await SmbDestination().write(config=config, filename=_NAME, archive_bytes=b"x")
    assert len(removed) == 1
    assert removed[0].endswith(_NAME + ".tmp")


# ── #1573: local-volume download refuses symlinks ────────────────────


@pytest.mark.asyncio
async def test_local_volume_download_refuses_a_symlink(tmp_path: Path):
    root = tmp_path / "backups"
    root.mkdir()
    outside = tmp_path / "outside.zip"
    outside.write_bytes(b"not an archive")
    (root / _NAME).symlink_to(outside)

    driver = LocalVolumeDestination()
    # The listing already refuses to offer the link…
    assert await driver.list_archives(config={"path": str(root)}) == []
    # …and the by-name download must refuse it too, not follow it out
    # of the configured root.
    with pytest.raises(BackupDestinationError):
        await driver.download(config={"path": str(root)}, filename=_NAME)


@pytest.mark.asyncio
async def test_local_volume_download_reads_a_regular_file(tmp_path: Path):
    root = tmp_path / "backups"
    root.mkdir()
    (root / _NAME).write_bytes(b"PK-bytes")
    driver = LocalVolumeDestination()
    assert await driver.download(config={"path": str(root)}, filename=_NAME) == b"PK-bytes"
