"""Archive downloads from a backup destination stop at the size cap.

Every driver's ``download`` takes ``max_bytes`` and raises
``ArchiveTooLargeError`` instead of reading an oversized archive into
memory whole: from a size it can learn before reading where the
destination offers one (a stat, ``ContentLength``, a blob's size), and
otherwise as the running total passes the cap. The by-name download and
restore-from-destination routes also check the size the destination's
listing declares before the download starts, and answer 413.

Normal downloads, restores and drills are pinned alongside, so the cap
cannot quietly break the path it guards.
"""

from __future__ import annotations

import contextlib
import ctypes
import sys
import types
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.backup import targets as targets_route
from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup.archive import MAX_ARCHIVE_BYTES
from app.services.backup.targets import base as base_mod
from app.services.backup.targets import gcs as gcs_mod
from app.services.backup.targets import nfs as nfs_mod
from app.services.backup.targets import s3 as s3_mod
from app.services.backup.targets.azure_blob import AzureBlobDestination
from app.services.backup.targets.base import ArchiveTooLargeError
from app.services.backup.targets.ftp import FtpDestination
from app.services.backup.targets.gcs import GcsDestination
from app.services.backup.targets.https_put import HttpsPutDestination
from app.services.backup.targets.libnfs_client import NfsConnection
from app.services.backup.targets.local_volume import LocalVolumeDestination
from app.services.backup.targets.nfs import NfsDestination
from app.services.backup.targets.s3 import S3Destination
from app.services.backup.targets.scp import ScpDestination
from app.services.backup.targets.smb import SmbDestination
from app.services.backup.targets.webdav import WebDAVDestination

NAME = "spatiumddi-backup-20261023-120000.zip"
CAP = 10
CHUNK = 4


class _Endless:
    """A file-like object that never reaches EOF, counting what it served."""

    def __init__(self) -> None:
        self.served = 0

    def read(self, n: int = -1) -> bytes:
        size = CHUNK if n is None or n < 0 else min(n, CHUNK)
        self.served += size
        return b"x" * size


class _Finite:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = len(self._data) - self._pos
        out = self._data[self._pos : self._pos + n]
        self._pos += len(out)
        return out


@pytest.fixture(autouse=True)
def _small_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_mod, "DOWNLOAD_CHUNK_BYTES", CHUNK)


# ── local volume ──────────────────────────────────────────────────────


async def test_local_volume_refuses_from_the_stat_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / NAME).write_bytes(b"x" * (CAP + 1))

    def _no_open(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("an archive past the cap must not be opened")

    monkeypatch.setattr(Path, "open", _no_open)
    monkeypatch.setattr(Path, "read_bytes", _no_open)
    with pytest.raises(ArchiveTooLargeError) as exc:
        await LocalVolumeDestination().download(
            config={"path": str(tmp_path)}, filename=NAME, max_bytes=CAP
        )
    assert exc.value.size_bytes == CAP + 1


async def test_local_volume_reads_an_archive_within_the_cap(tmp_path: Path) -> None:
    (tmp_path / NAME).write_bytes(b"PK" + b"y" * (CAP - 2))
    data = await LocalVolumeDestination().download(
        config={"path": str(tmp_path)}, filename=NAME, max_bytes=CAP
    )
    assert data == b"PK" + b"y" * (CAP - 2)


# ── s3 ────────────────────────────────────────────────────────────────


class _S3Body:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.closed = False

    def read(self, n: int = -1) -> bytes:
        return self.inner.read(n)

    def close(self) -> None:
        self.closed = True


def _s3(monkeypatch: pytest.MonkeyPatch, body: _S3Body, length: int | None) -> None:
    resp: dict[str, Any] = {"Body": body}
    if length is not None:
        resp["ContentLength"] = length
    client = types.SimpleNamespace(get_object=lambda **_k: resp)
    monkeypatch.setattr(s3_mod, "_client", lambda _c: client)


async def test_s3_refuses_from_content_length_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _Endless()
    body = _S3Body(stream)
    _s3(monkeypatch, body, length=CAP + 1)
    with pytest.raises(ArchiveTooLargeError):
        await S3Destination().download(config={"bucket": "b"}, filename=NAME, max_bytes=CAP)
    assert stream.served == 0
    assert body.closed


async def test_s3_stops_reading_past_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _Endless()
    _s3(monkeypatch, _S3Body(stream), length=None)
    with pytest.raises(ArchiveTooLargeError):
        await S3Destination().download(config={"bucket": "b"}, filename=NAME, max_bytes=CAP)
    assert stream.served <= CAP + CHUNK


async def test_s3_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _s3(monkeypatch, _S3Body(_Finite(b"z" * CAP)), length=CAP)
    data = await S3Destination().download(config={"bucket": "b"}, filename=NAME, max_bytes=CAP)
    assert data == b"z" * CAP


# ── azure blob ────────────────────────────────────────────────────────


class _AzureStream:
    def __init__(self, size: int | None, chunks: int) -> None:
        self.size = size
        self._chunks = chunks
        self.served = 0

    def chunks(self):
        for _ in range(self._chunks):
            self.served += CHUNK
            yield b"a" * CHUNK


def _azure(monkeypatch: pytest.MonkeyPatch, stream: _AzureStream) -> None:
    # ``download`` imports the SDK's exception types lazily; CI can carry only
    # a namespace stub of ``azure`` (no ``azure-core``), so skip rather than fail.
    exceptions = pytest.importorskip("azure.core.exceptions")
    if not hasattr(exceptions, "AzureError"):
        pytest.skip("azure-core is not installed")
    blob = types.SimpleNamespace(download_blob=lambda: stream)
    container = types.SimpleNamespace(get_blob_client=lambda _n: blob)
    monkeypatch.setattr(AzureBlobDestination, "_container_client", lambda self, _c: container)


async def test_azure_refuses_from_the_blob_size(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _AzureStream(size=CAP + 1, chunks=1000)
    _azure(monkeypatch, stream)
    with pytest.raises(ArchiveTooLargeError):
        await AzureBlobDestination().download(
            config={"container": "c"}, filename=NAME, max_bytes=CAP
        )
    assert stream.served == 0


async def test_azure_stops_reading_past_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _AzureStream(size=None, chunks=1000)
    _azure(monkeypatch, stream)
    with pytest.raises(ArchiveTooLargeError):
        await AzureBlobDestination().download(
            config={"container": "c"}, filename=NAME, max_bytes=CAP
        )
    assert stream.served <= CAP + CHUNK


async def test_azure_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _azure(monkeypatch, _AzureStream(size=2 * CHUNK, chunks=2))
    data = await AzureBlobDestination().download(
        config={"container": "c"}, filename=NAME, max_bytes=CAP
    )
    assert data == b"a" * (2 * CHUNK)


# ── gcs ───────────────────────────────────────────────────────────────


def _gcs(monkeypatch: pytest.MonkeyPatch, size: int) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def _download(**kwargs: Any) -> bytes:
        calls.append(kwargs)
        end = kwargs.get("end")
        n = size if end is None else min(size, end + 1)
        return b"g" * n

    blob = types.SimpleNamespace(download_as_bytes=_download)
    bucket = types.SimpleNamespace(blob=lambda _n: blob)
    client = types.SimpleNamespace(bucket=lambda _b: bucket)
    monkeypatch.setattr(gcs_mod, "_client", lambda _c: client)
    return calls


async def test_gcs_requests_at_most_one_byte_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _gcs(monkeypatch, size=10_000)
    with pytest.raises(ArchiveTooLargeError):
        await GcsDestination().download(config={"bucket": "b"}, filename=NAME, max_bytes=CAP)
    assert calls == [{"start": 0, "end": CAP}]


async def test_gcs_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _gcs(monkeypatch, size=CAP)
    data = await GcsDestination().download(config={"bucket": "b"}, filename=NAME, max_bytes=CAP)
    assert data == b"g" * CAP


# ── ftp ───────────────────────────────────────────────────────────────


class _FtpClient:
    def __init__(self, chunks: int) -> None:
        self._chunks = chunks
        self.served = 0

    def retrbinary(self, _cmd: str, callback) -> None:
        for _ in range(self._chunks):
            self.served += CHUNK
            callback(b"f" * CHUNK)


def _ftp_config() -> dict[str, Any]:
    return {"host": "192.0.2.1", "username": "u", "password": "p", "remote_path": "/b"}


async def test_ftp_aborts_the_transfer_past_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FtpClient(chunks=1000)
    monkeypatch.setattr(FtpDestination, "_connect", lambda self, _c: client)
    monkeypatch.setattr(FtpDestination, "_close", lambda self, _c: None)
    with pytest.raises(ArchiveTooLargeError):
        await FtpDestination().download(config=_ftp_config(), filename=NAME, max_bytes=CAP)
    assert client.served <= CAP + CHUNK


async def test_ftp_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(FtpDestination, "_connect", lambda self, _c: _FtpClient(chunks=2))
    monkeypatch.setattr(FtpDestination, "_close", lambda self, _c: None)
    data = await FtpDestination().download(config=_ftp_config(), filename=NAME, max_bytes=CAP)
    assert data == b"f" * (2 * CHUNK)


# ── scp ───────────────────────────────────────────────────────────────


class _SftpFile:
    def __init__(self, inner: Any, size: int) -> None:
        self.inner = inner
        self._size = size

    def __enter__(self) -> _SftpFile:
        return self

    def __exit__(self, *_e: object) -> None:
        return None

    def stat(self) -> Any:
        return types.SimpleNamespace(st_size=self._size)

    def read(self, n: int = -1) -> bytes:
        return self.inner.read(n)


def _scp(monkeypatch: pytest.MonkeyPatch, fh: _SftpFile) -> None:
    sftp = types.SimpleNamespace(
        get_channel=lambda: None, file=lambda _p, _m: fh, close=lambda: None
    )
    client = types.SimpleNamespace(open_sftp=lambda: sftp, close=lambda: None)
    monkeypatch.setattr(ScpDestination, "_connect", lambda self, _c: client)


async def test_scp_refuses_from_the_stat_before_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _Endless()
    _scp(monkeypatch, _SftpFile(stream, size=CAP + 1))
    with pytest.raises(ArchiveTooLargeError):
        await ScpDestination().download(config=_ftp_config(), filename=NAME, max_bytes=CAP)
    assert stream.served == 0


async def test_scp_stops_reading_when_the_stat_understates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _Endless()
    _scp(monkeypatch, _SftpFile(stream, size=1))
    with pytest.raises(ArchiveTooLargeError):
        await ScpDestination().download(config=_ftp_config(), filename=NAME, max_bytes=CAP)
    assert stream.served <= CAP + CHUNK


async def test_scp_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _scp(monkeypatch, _SftpFile(_Finite(b"s" * CAP), size=CAP))
    data = await ScpDestination().download(config=_ftp_config(), filename=NAME, max_bytes=CAP)
    assert data == b"s" * CAP


# ── smb ───────────────────────────────────────────────────────────────


def _smb(monkeypatch: pytest.MonkeyPatch, inner: Any) -> None:
    class _File:
        def __enter__(self) -> Any:
            return inner

        def __exit__(self, *_e: object) -> None:
            return None

    fake = types.ModuleType("smbclient")
    fake.register_session = lambda *_a, **_k: None  # type: ignore[attr-defined]
    fake.open_file = lambda *_a, **_k: _File()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "smbclient", fake)


_SMB_CONFIG = {"server": "192.0.2.1", "share": "backups", "username": "u", "password": "p"}


async def test_smb_stops_reading_past_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _Endless()
    _smb(monkeypatch, stream)
    with pytest.raises(ArchiveTooLargeError):
        await SmbDestination().download(config=_SMB_CONFIG, filename=NAME, max_bytes=CAP)
    assert stream.served <= CAP + CHUNK


async def test_smb_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _smb(monkeypatch, _Finite(b"m" * CAP))
    data = await SmbDestination().download(config=_SMB_CONFIG, filename=NAME, max_bytes=CAP)
    assert data == b"m" * CAP


# ── webdav ────────────────────────────────────────────────────────────


def _webdav(monkeypatch: pytest.MonkeyPatch, body: bytes, *, declared: bool) -> None:
    async def _chunks():
        for i in range(0, len(body), CHUNK):
            yield body[i : i + CHUNK]

    def _handler(_req: httpx.Request) -> httpx.Response:
        if declared:
            return httpx.Response(200, content=body)
        # A streamed body carries no Content-Length.
        return httpx.Response(200, content=_chunks())

    def _client(self: Any, _c: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(_handler))

    monkeypatch.setattr(WebDAVDestination, "_client", _client)


_DAV_CONFIG = {"url": "https://dav.example.test/backups/", "username": "u", "password": "p"}


@pytest.mark.parametrize("declared", [True, False])
async def test_webdav_refuses_past_the_cap(monkeypatch: pytest.MonkeyPatch, declared: bool) -> None:
    _webdav(monkeypatch, b"w" * (CAP * 3), declared=declared)
    with pytest.raises(ArchiveTooLargeError):
        await WebDAVDestination().download(config=_DAV_CONFIG, filename=NAME, max_bytes=CAP)


async def test_webdav_reads_an_archive_within_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _webdav(monkeypatch, b"w" * CAP, declared=True)
    data = await WebDAVDestination().download(config=_DAV_CONFIG, filename=NAME, max_bytes=CAP)
    assert data == b"w" * CAP


# ── nfs ───────────────────────────────────────────────────────────────


class _ReadLib:
    """Stands in for libnfs: a file of ``size`` bytes (None = endless)."""

    def __init__(self, size: int | None) -> None:
        self.size = size
        self.served = 0

    def nfs_open(self, ctx, path, flags, handle):
        return 0

    def nfs_pread(self, ctx, fh, offset, count, buf):
        n = count if self.size is None else max(0, min(count, self.size - offset))
        ctypes.memset(buf, ord("n"), n)
        self.served += n
        return n

    def nfs_close(self, ctx, fh):
        return 0

    def nfs_get_error(self, ctx):
        return b""


def test_libnfs_read_stops_past_the_cap() -> None:
    lib = _ReadLib(size=None)
    conn = NfsConnection(lib, ctypes.c_void_p(1), describe="nas:/e")  # type: ignore[arg-type]
    with pytest.raises(ArchiveTooLargeError):
        conn.read("/e/" + NAME, max_bytes=CAP)


def test_libnfs_read_within_the_cap() -> None:
    lib = _ReadLib(size=CAP)
    conn = NfsConnection(lib, ctypes.c_void_p(1), describe="nas:/e")  # type: ignore[arg-type]
    assert conn.read("/e/" + NAME, max_bytes=CAP) == b"n" * CAP


async def test_nfs_download_passes_the_cap_to_the_read(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int | None] = []

    class _Conn:
        def read(self, _path: str, *, max_bytes: int | None = None) -> bytes:
            seen.append(max_bytes)
            return b"ok"

    @contextlib.contextmanager
    def _open(_c: Any):
        yield _Conn()

    monkeypatch.setattr(nfs_mod, "_open", _open)
    monkeypatch.setattr(nfs_mod, "_remote_path", lambda _c, f: "/e/" + f)
    data = await NfsDestination().download(config={}, filename=NAME, max_bytes=CAP)
    assert data == b"ok"
    assert seen == [CAP]


# ── https_put ─────────────────────────────────────────────────────────


async def test_https_put_error_body_has_the_url_credential_scrubbed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_url = "https://receiver.example.test/upload?X-Amz-Signature=deadbeefsecret"

    async def _send(self: Any, **_k: Any) -> httpx.Response:
        return httpx.Response(403, text=f"denied for {secret_url}/{NAME}")

    monkeypatch.setattr(HttpsPutDestination, "_send", _send)
    from app.services.backup.targets import https_put as https_put_mod

    monkeypatch.setattr(https_put_mod, "_target_url", lambda _c, f: f"{secret_url}/{f}")
    monkeypatch.setattr(https_put_mod, "_method", lambda _c: "PUT")
    with pytest.raises(base_mod.BackupDestinationError) as exc:
        await HttpsPutDestination().write(config={}, filename=NAME, archive_bytes=b"x")
    assert "deadbeefsecret" not in str(exc.value)
    assert "403" in str(exc.value)


# ── routes ────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"cap-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="cap",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _target(db: AsyncSession, path: Path) -> BackupTarget:
    row = BackupTarget(
        name=f"lv-{uuid.uuid4().hex[:6]}",
        description="",
        kind="local_volume",
        enabled=True,
        config={"path": str(path)},
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
    )
    db.add(row)
    await db.flush()
    return row


@pytest.fixture
def plain_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets_route, "decrypt_config_secrets", lambda _d, c: c)


@pytest.fixture
def download_spy(monkeypatch: pytest.MonkeyPatch) -> list[int | None]:
    """Records the ``max_bytes`` each local-volume download was given."""
    seen: list[int | None] = []
    real = LocalVolumeDestination.download

    async def _spy(self: Any, *, config: Any, filename: str, max_bytes: Any = None) -> bytes:
        seen.append(max_bytes)
        return await real(self, config=config, filename=filename, max_bytes=max_bytes)

    monkeypatch.setattr(LocalVolumeDestination, "download", _spy)
    return seen


@pytest.mark.usefixtures("plain_config")
async def test_download_by_name_returns_the_archive(
    client: AsyncClient, db_session: AsyncSession, tmp_path: Path, download_spy: list
) -> None:
    hdr = await _superadmin(db_session)
    target = await _target(db_session, tmp_path)
    (tmp_path / NAME).write_bytes(b"PK-archive")
    res = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{NAME}/download", headers=hdr
    )
    assert res.status_code == 200, res.text
    assert res.content == b"PK-archive"
    assert download_spy == [MAX_ARCHIVE_BYTES]


@pytest.mark.usefixtures("plain_config")
async def test_download_by_name_past_the_cap_is_refused_before_reading(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    download_spy: list,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(targets_route, "MAX_ARCHIVE_BYTES", CAP)
    hdr = await _superadmin(db_session)
    target = await _target(db_session, tmp_path)
    (tmp_path / NAME).write_bytes(b"x" * (CAP + 1))
    res = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{NAME}/download", headers=hdr
    )
    assert res.status_code == 413, res.text
    assert download_spy == [], "the listing's declared size refuses it before the download"


@pytest.mark.usefixtures("plain_config")
async def test_download_by_name_past_the_cap_without_a_listing_entry_is_413(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name the listing does not carry still stops at the driver's cap."""
    monkeypatch.setattr(targets_route, "MAX_ARCHIVE_BYTES", CAP)

    async def _empty(self: Any, *, config: Any) -> list:
        return []

    monkeypatch.setattr(LocalVolumeDestination, "list_archives", _empty)
    hdr = await _superadmin(db_session)
    target = await _target(db_session, tmp_path)
    (tmp_path / NAME).write_bytes(b"x" * (CAP + 1))
    res = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{NAME}/download", headers=hdr
    )
    assert res.status_code == 413, res.text


@pytest.mark.usefixtures("plain_config")
async def test_latest_download_passes_the_cap(
    client: AsyncClient, db_session: AsyncSession, tmp_path: Path, download_spy: list
) -> None:
    hdr = await _superadmin(db_session)
    target = await _target(db_session, tmp_path)
    (tmp_path / NAME).write_bytes(b"PK-latest")
    res = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/latest/download", headers=hdr
    )
    assert res.status_code == 200, res.text
    assert res.content == b"PK-latest"
    assert download_spy == [MAX_ARCHIVE_BYTES]


def _restore_body() -> dict[str, Any]:
    return {
        "filename": NAME,
        "passphrase": "hunter2hunter2",
        "confirmation_phrase": "RESTORE-FROM-BACKUP",
    }


@pytest.mark.usefixtures("plain_config")
async def test_restore_from_target_past_the_cap_is_refused_before_reading(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    download_spy: list,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(targets_route, "MAX_ARCHIVE_BYTES", CAP)
    hdr = await _superadmin(db_session)
    target = await _target(db_session, tmp_path)
    (tmp_path / NAME).write_bytes(b"x" * (CAP + 1))
    res = await client.post(
        f"/api/v1/backup/targets/{target.id}/archives/restore", json=_restore_body(), headers=hdr
    )
    assert res.status_code == 413, res.text
    assert download_spy == []


@pytest.mark.usefixtures("plain_config")
async def test_restore_from_target_hands_the_archive_to_the_restore(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    download_spy: list,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The normal path: the archive bytes reach the restore unchanged."""
    import app.services.backup as backup_pkg

    received: list[bytes] = []

    async def _fake_restore(_db: Any, *, archive_bytes: bytes, **_k: Any) -> Any:
        received.append(archive_bytes)
        raise backup_pkg.BackupRestoreError("stop here")

    monkeypatch.setattr(backup_pkg, "apply_backup_restore", _fake_restore)
    hdr = await _superadmin(db_session)
    target = await _target(db_session, tmp_path)
    (tmp_path / NAME).write_bytes(b"PK-restore")
    res = await client.post(
        f"/api/v1/backup/targets/{target.id}/archives/restore", json=_restore_body(), headers=hdr
    )
    assert res.status_code == 400, res.text
    assert "stop here" in res.text
    assert received == [b"PK-restore"]
    assert download_spy == [MAX_ARCHIVE_BYTES]
