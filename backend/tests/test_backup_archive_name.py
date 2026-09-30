"""Archive names that are not one plain path component are refused (#1243).

``safe_filename`` used to be ``os.path.basename``, and
``basename("..") == ".."``. On a WebDAV target ``urljoin`` then resolved
``..`` to the PARENT collection, so ``DELETE /backup/targets/{id}/archives/..``
sent a recursive WebDAV ``DELETE`` one level above the archives. Seven
drivers also carried their own inline ``basename`` instead of the shared
helper, which is how a hardening of one copy misses the others.

The tests that matter:

* the helper refuses ``..`` and every other non-component, and every
  driver's delete goes through it before touching storage;
* the WebDAV URL a name becomes can never be the parent collection,
  including for a name that arrives percent-encoded;
* the API answers 422 and never reaches the driver.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.backup import BackupTarget
from app.services.backup.targets import DESTINATIONS
from app.services.backup.targets.base import (
    BackupDestinationError,
    InvalidArchiveNameError,
    safe_filename,
)
from app.services.backup.targets.webdav import WebDAVDestination

_GOOD = "spatiumddi-backup-20260929-120000.zip"
_BAD = ["", ".", "..", "../x.zip", "a/b.zip", "a\\b.zip", "/abs.zip", "a\x00.zip", "a\r\nb.zip"]


# ── the helper ────────────────────────────────────────────────────────


def test_safe_filename_returns_a_plain_name_unchanged():
    assert safe_filename(_GOOD) == _GOOD


@pytest.mark.parametrize("bad", _BAD)
def test_safe_filename_refuses_anything_that_is_not_one_component(bad: str):
    with pytest.raises(InvalidArchiveNameError):
        safe_filename(bad)


def test_the_refusal_is_still_a_destination_error():
    # Every caller already catches BackupDestinationError; a refusal that
    # escaped that would turn a bad name into a 500.
    assert issubclass(InvalidArchiveNameError, BackupDestinationError)


# ── every driver ──────────────────────────────────────────────────────

# Enough config for each driver to get as far as composing the path. The
# refusal must come first, so none of these is ever contacted.
_CONFIGS: dict[str, dict[str, Any]] = {
    "local_volume": {"path": "/nonexistent-1243"},
    "s3": {"bucket": "b", "region": "us-east-1", "access_key_id": "a", "secret_access_key": "s"},
    "scp": {"host": "192.0.2.1", "username": "u", "password": "p", "remote_path": "/r"},
    "azure_blob": {"account_name": "a", "account_key": "a2V5", "container": "c"},
    "smb": {"server": "192.0.2.1", "share": "s", "username": "u", "password": "p"},
    "ftp": {"host": "192.0.2.1", "username": "u", "password": "p", "remote_path": "/r"},
    "gcs": {"bucket": "b", "service_account_json": "{}"},
    "webdav": {"url": "https://192.0.2.1/dav/backups", "username": "u", "password": "p"},
    "nfs": {"server": "192.0.2.1", "export": "/e"},
}


def test_every_readable_driver_is_covered():
    # https_put is write-only by construction and never reads or deletes.
    assert set(_CONFIGS) == set(DESTINATIONS) - {"https_put"}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", sorted(_CONFIGS))
@pytest.mark.parametrize("op", ["delete", "download"])
async def test_every_driver_refuses_dotdot_before_touching_storage(kind: str, op: str):
    driver = DESTINATIONS[kind]
    with pytest.raises(InvalidArchiveNameError):
        await getattr(driver, op)(config=_CONFIGS[kind], filename="..")


# ── WebDAV: the reported case ─────────────────────────────────────────

_DAV = {"url": "https://dav.example/backups", "username": "u", "password": "p"}


def test_webdav_url_for_a_plain_name_is_inside_the_collection():
    url = WebDAVDestination()._archive_url(_DAV, _GOOD)
    assert url == f"https://dav.example/backups/{_GOOD}"


def test_webdav_dotdot_never_becomes_the_parent_collection():
    with pytest.raises(InvalidArchiveNameError):
        WebDAVDestination()._archive_url(_DAV, "..")


def test_webdav_encoded_dotdot_is_sent_as_a_literal_name():
    # ``%2E%2E`` is one plain component to us, and a dot-segment to a
    # server that normalises after decoding. Encoding the ``%`` means the
    # server decodes it back to the literal characters, never to ``..``.
    url = WebDAVDestination()._archive_url(_DAV, "%2E%2E")
    assert url == "https://dav.example/backups/%252E%252E"


# ── API ───────────────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> str:
    user = User(
        username="archname",
        email="archname@example.com",
        display_name="archname",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _webdav_target(db: AsyncSession) -> BackupTarget:
    target = BackupTarget(
        name="dav",
        description="",
        kind="webdav",
        enabled=True,
        config=dict(_DAV),
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
    )
    db.add(target)
    await db.flush()
    return target


@pytest.fixture
def driver_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record what reaches the WebDAV driver instead of sending it."""
    calls: list[tuple[str, str]] = []
    driver = DESTINATIONS["webdav"]

    async def _delete(*, config: dict[str, Any], filename: str) -> None:
        calls.append(("delete", filename))

    async def _download(*, config: dict[str, Any], filename: str) -> bytes:
        calls.append(("download", filename))
        return b"PK\x05\x06" + b"\x00" * 18

    monkeypatch.setattr(driver, "delete", _delete)
    monkeypatch.setattr(driver, "download", _download)
    monkeypatch.setattr(
        "app.api.v1.backup.targets.decrypt_config_secrets", lambda _driver, cfg: cfg
    )
    return calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    # ``%2E%2E`` is how the reported ``..`` actually arrives: an HTTP
    # client normalises a literal ``/archives/..`` away before sending it
    # (to ``DELETE /backup/targets/{id}`` — a different route), while
    # Starlette decodes the escaped form into the ``filename`` parameter.
    ["%2E%2E", "notes.txt", "spatiumddi-backup-x.tar"],
    ids=["encoded-dotdot", "not-an-archive", "wrong-suffix"],
)
async def test_delete_refuses_a_name_that_is_not_one_of_our_archives(
    client: AsyncClient,
    db_session: AsyncSession,
    driver_calls: list[tuple[str, str]],
    name: str,
):
    token = await _superadmin(db_session)
    target = await _webdav_target(db_session)
    res = await client.delete(
        f"/api/v1/backup/targets/{target.id}/archives/{name}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422, res.text
    assert driver_calls == []


@pytest.mark.asyncio
async def test_delete_of_a_real_archive_name_reaches_the_driver(
    client: AsyncClient, db_session: AsyncSession, driver_calls: list[tuple[str, str]]
):
    token = await _superadmin(db_session)
    target = await _webdav_target(db_session)
    res = await client.delete(
        f"/api/v1/backup/targets/{target.id}/archives/{_GOOD}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 204, res.text
    assert driver_calls == [("delete", _GOOD)]


@pytest.mark.asyncio
async def test_download_refuses_dotdot_and_sends_a_safe_header_otherwise(
    client: AsyncClient, db_session: AsyncSession, driver_calls: list[tuple[str, str]]
):
    token = await _superadmin(db_session)
    target = await _webdav_target(db_session)
    headers = {"Authorization": f"Bearer {token}"}

    bad = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/%2E%2E/download", headers=headers
    )
    assert bad.status_code == 422, bad.text
    assert driver_calls == []

    ok = await client.get(
        f"/api/v1/backup/targets/{target.id}/archives/{_GOOD}/download", headers=headers
    )
    assert ok.status_code == 200, ok.text
    assert driver_calls == [("download", _GOOD)]
    assert ok.headers["content-disposition"] == (
        f"attachment; filename=\"{_GOOD}\"; filename*=UTF-8''{_GOOD}"
    )


@pytest.mark.asyncio
async def test_restore_from_archive_refuses_dotdot(
    client: AsyncClient, db_session: AsyncSession, driver_calls: list[tuple[str, str]]
):
    token = await _superadmin(db_session)
    target = await _webdav_target(db_session)
    res = await client.post(
        f"/api/v1/backup/targets/{target.id}/archives/restore",
        json={"filename": "..", "passphrase": "hunter2hunter2", "confirmation_phrase": "x"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422, res.text
    assert driver_calls == []


# ── the one uploader-controlled download name ─────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("slot.raw.xz", "slot.raw.xz"),
        ("C:\\Users\\op\\slot.raw.xz", "slot.raw.xz"),
        ("../../slot.raw.xz", "slot.raw.xz"),
        ("slot\r\n.raw.xz", "slot.raw.xz"),
        ("..", None),
        ("", None),
        (None, None),
        ("a" * 300, "a" * 255),
    ],
)
def test_stored_upgrade_image_name_is_one_printable_component(raw, expected):
    import uuid

    from app.api.v1.appliance.upgrade_images import _stored_upload_name

    image_id = uuid.uuid4()
    got = _stored_upload_name(raw, image_id)
    assert got == (expected if expected is not None else f"{image_id}.raw.xz")
