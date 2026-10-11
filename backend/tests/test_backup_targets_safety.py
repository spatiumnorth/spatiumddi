"""Backup-target safety fixes (#1568, #1569, #1570, #1572, #1573).

Failed writes used to leave the staged ``<archive>.tmp`` behind on the
FTP, SCP, SMB and local-volume drivers. Listing and retention only
match ``*.zip``, so those orphans were invisible and were never pruned
— every failed run on a destination that was out of space made the
next failure more likely (#1570). The NFS driver already cleaned its
``.part`` up; these tests pin the same behaviour for the other four.

The remaining sections pin, per issue:

* #1573 — the local-volume ``download`` refuses a symlink, matching
  what its listing already does, instead of following it out of the
  configured root;
* #1572 — the restore helpers pass the allowlisted
  ``_pg_subprocess_env`` to psql / pg_restore, not the full api
  environment;
* #1569 — the SCP driver's checked host-key modes can no longer be
  configured with an empty host-key store (``strict`` rejected every
  server, because no keys were ever loaded);
* #1568 — restore refuses an archive whose database member declares
  an uncompressed size past the cap before reading it, and the
  secrets envelope refuses out-of-band PBKDF2 iteration counts and
  wraps KDF / AES ``ValueError``\\ s as ``BackupCryptoError``.
"""

from __future__ import annotations

import io
import json
import os
import sys
import types
import zipfile
from pathlib import Path
from typing import Any

import pytest

from app.services.backup import archive as archive_mod
from app.services.backup.crypto import BackupCryptoError, decrypt_secrets, encrypt_secrets
from app.services.backup.targets.base import BackupDestinationError, DestinationConfigError
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

    def get_channel(self) -> None:
        # Main's _open_sftp (#1515) asks the SFTP client for its
        # channel to set a timeout; this fake has none to set one on.
        return None

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


# ── #1572: restore helpers use the allowlisted subprocess env ────────


class _FakeProc:
    returncode = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"", b""

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return 0


@pytest.fixture
def captured_envs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    """Record the ``env`` kwarg of every subprocess the restore
    helpers spawn, with a sentinel secret planted in the parent env."""
    import asyncio

    envs: list[dict[str, str]] = []

    async def _fake_exec(*_args: object, **kwargs: object) -> _FakeProc:
        envs.append(dict(kwargs["env"]))  # type: ignore[arg-type]
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setenv("SPATIUM_TEST_SECRET_SENTINEL", "must-not-leak")
    return envs


_DB_URL = "postgresql+asyncpg://spatium:pw@db.internal:5433/spatiumddi"


@pytest.mark.asyncio
async def test_restore_helpers_spawn_pg_tools_with_the_allowlisted_env(
    captured_envs: list[dict[str, str]],
):
    from app.services.backup import restore as restore_mod

    pg_env = {"PGHOST": "db.internal", "PGPASSWORD": "pw"}
    await restore_mod._terminate_other_db_connections(pg_env)
    await restore_mod._collect_post_restore_warnings(_DB_URL)

    # terminate, DNSSEC scan. The selective restore's pg_restore and psql
    # now run as one streamed replay (#1693), which this stub cannot drive;
    # test_selective_restore_app_role_1693.py pins their env on real ones.
    assert len(captured_envs) == 2
    for env in captured_envs:
        assert "SPATIUM_TEST_SECRET_SENTINEL" not in env
        assert env["PGHOST"] == "db.internal"


# ── #1569: SCP strict host-key mode needs actual host keys ───────────

_SCP_BASE = {
    "host": "192.0.2.1",
    "username": "u",
    "password": "p",
    "remote_path": "/backups",
}
_KNOWN_HOSTS = "192.0.2.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterialForTestsOnly1234"


def test_scp_default_host_key_mode_requires_known_hosts():
    # The default used to be "strict" with an empty host-key store,
    # which rejects every server. The default is now "known_hosts",
    # and a config with no host keys at all is refused up front.
    with pytest.raises(DestinationConfigError, match="known_hosts"):
        ScpDestination().validate_config(dict(_SCP_BASE))


def test_scp_strict_without_known_hosts_is_refused():
    with pytest.raises(DestinationConfigError, match="known_hosts"):
        ScpDestination().validate_config({**_SCP_BASE, "host_key_check": "strict"})


def test_scp_known_hosts_mode_still_requires_the_content():
    with pytest.raises(DestinationConfigError, match="known_hosts"):
        ScpDestination().validate_config({**_SCP_BASE, "host_key_check": "known_hosts"})


@pytest.mark.parametrize("mode", ["strict", "known_hosts"])
def test_scp_checked_modes_accept_supplied_known_hosts(mode: str):
    ScpDestination().validate_config(
        {**_SCP_BASE, "host_key_check": mode, "known_hosts": _KNOWN_HOSTS}
    )


def test_scp_insecure_skip_needs_no_known_hosts():
    ScpDestination().validate_config({**_SCP_BASE, "host_key_check": "insecure_skip"})


# ── #1568: archive size cap + envelope hardening ─────────────────────


def _archive_bytes(dump: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "manifest.json",
            json.dumps({"format": "spatiumddi-backup", "dump_format": "custom"}),
        )
        zf.writestr("database.dump", dump)
        zf.writestr("secrets.enc", encrypt_secrets({"k": "v"}, passphrase="passphrase-1"))
    return buf.getvalue()


def test_extract_refuses_a_dump_member_past_the_size_cap(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(archive_mod, "_MAX_DUMP_MEMBER_BYTES", 4)
    with pytest.raises(archive_mod.BackupArchiveError, match="exceeds"):
        archive_mod.extract_archive_members(_archive_bytes(b"12345"))


def test_extract_accepts_a_dump_member_under_the_size_cap():
    manifest, db_bytes, dump_format, _secrets = archive_mod.extract_archive_members(
        _archive_bytes(b"dump")
    )
    assert manifest["dump_format"] == "custom"
    assert db_bytes == b"dump"
    assert dump_format == "custom"


def _envelope_with(**overrides: Any) -> bytes:
    env = json.loads(encrypt_secrets({"k": "v"}, passphrase="passphrase-1"))
    env.update(overrides)
    return json.dumps(env).encode()


@pytest.mark.parametrize("iterations", [0, 1, 99_999, 10_000_001, 10**12])
def test_decrypt_refuses_out_of_band_iteration_counts(iterations: int):
    # The count comes from the (untrusted) envelope; deriving at a
    # declared 10**12 would pin the api CPU, and a count under the
    # floor is not an envelope this build wrote.
    with pytest.raises(BackupCryptoError, match="iterations"):
        decrypt_secrets(_envelope_with(iterations=iterations), passphrase="passphrase-1")


def test_decrypt_accepts_the_envelope_iteration_count():
    payload = decrypt_secrets(_envelope_with(), passphrase="passphrase-1")
    assert payload == {"k": "v"}


def test_decrypt_wraps_a_malformed_nonce_as_crypto_error():
    # A 1-byte nonce makes AESGCM raise ValueError, which used to
    # escape decrypt_secrets and surface as a 500 on restore.
    with pytest.raises(BackupCryptoError):
        decrypt_secrets(_envelope_with(nonce="00"), passphrase="passphrase-1")


def test_decrypt_wraps_a_malformed_salt_as_crypto_error():
    with pytest.raises(BackupCryptoError):
        decrypt_secrets(_envelope_with(salt="not-hex"), passphrase="passphrase-1")
