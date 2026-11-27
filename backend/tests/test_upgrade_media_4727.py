"""Upgrade images imported from a mounted removable disk (#4727)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import upgrade_images
from app.core.security import create_access_token, hash_password
from app.models.appliance import ApplianceUpgradeImage
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.appliance import upgrade_media

pytestmark = pytest.mark.asyncio

_BASE = "/api/v1/appliance/upgrade-images"
_NAME = "spatiumddi-appliance-slot-1.1.0-amd64.raw.xz"
_SIDECAR = "spatiumddi-appliance-slot-1.1.0-amd64.sha256"
_BYTES = b"not-really-an-xz-stream"
_SHA = hashlib.sha256(_BYTES).hexdigest()


@pytest.fixture
def media(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A removable root with one live mount ``stick`` and one plain dir ``ejected``."""
    root = tmp_path / "removable"
    (root / "stick").mkdir(parents=True)
    (root / "ejected").mkdir()
    monkeypatch.setattr(upgrade_media, "REMOVABLE_ROOT", str(root))
    monkeypatch.setattr(upgrade_media.os.path, "ismount", lambda p: Path(p).name == "stick")
    store = tmp_path / "store"
    store.mkdir()
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", store)
    return root / "stick"


def _put(stick: Path, name: str = _NAME, data: bytes = _BYTES, sidecar: str | None = "ok") -> None:
    (stick / name).write_bytes(data)
    if sidecar is not None:
        text = f"{_SHA}  {name}\n" if sidecar == "ok" else sidecar
        (stick / (name[: -len(".raw.xz")] + ".sha256")).write_text(text)


async def _token(db: AsyncSession, *, superadmin: bool = True) -> dict[str, str]:
    user = User(
        username="mediaadmin" if superadmin else "mediaplain",
        email="m@example.com",
        display_name="m",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _import(client, hdr, mount="stick", filename=_NAME):
    return await client.post(
        f"{_BASE}/import-from-media", headers=hdr, json={"mount": mount, "filename": filename}
    )


async def test_import_roundtrip_audited(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    _put(media)
    hdr = await _token(db_session)
    listed = await client.get(f"{_BASE}/media", headers=hdr)
    assert listed.status_code == 200
    (row,) = listed.json()["images"]
    assert row["appliance_version"] == "1.1.0" and row["architecture"] == "amd64"
    assert row["sha256"] == _SHA and row["problems"] == []

    resp = await _import(client, hdr)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sha256"] == _SHA and body["appliance_version"] == "1.1.0"
    assert body["architecture"] == "amd64" and body["size_bytes"] == len(_BYTES)
    stored = upgrade_images.SLOT_IMAGE_DIR / f"{body['id']}.raw.xz"
    assert stored.read_bytes() == _BYTES
    # The stick is only read.
    assert (media / _NAME).read_bytes() == _BYTES
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == body["id"])))
        .scalars()
        .all()
    )
    assert [a.action for a in audit] == ["appliance.upgrade_image_imported"]
    assert audit[0].new_value["source"] == "removable_media"
    # Re-import is idempotent.
    again = await _import(client, hdr)
    assert again.status_code == 200 and again.json()["id"] == body["id"]
    rows = (await db_session.execute(select(ApplianceUpgradeImage))).scalars().all()
    assert len(rows) == 1


async def test_image_in_upgrade_subdir_is_found(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    sub = media / upgrade_media.MEDIA_SUBDIR
    sub.mkdir()
    _put(sub)
    hdr = await _token(db_session)
    assert len((await client.get(f"{_BASE}/media", headers=hdr)).json()["images"]) == 1
    assert (await _import(client, hdr)).status_code == 200


async def test_non_superadmin_refused(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    _put(media)
    hdr = await _token(db_session, superadmin=False)
    assert (await client.get(f"{_BASE}/media", headers=hdr)).status_code == 403
    assert (await _import(client, hdr)).status_code == 403
    assert (await client.get(f"{_BASE}/media")).status_code in (401, 403)


async def test_checksum_mismatch_refused_and_nothing_kept(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    _put(media, data=b"tampered-bytes")  # sidecar still carries the hash of _BYTES
    hdr = await _token(db_session)
    resp = await _import(client, hdr)
    assert resp.status_code == 422 and "SHA-256 mismatch" in resp.text
    assert list(upgrade_images.SLOT_IMAGE_DIR.iterdir()) == []
    assert (await db_session.execute(select(ApplianceUpgradeImage))).first() is None


@pytest.mark.parametrize(
    ("sidecar", "needle"),
    [
        (None, "no spatiumddi-appliance-slot-1.1.0-amd64.sha256"),
        ("not a digest\n", "64-character sha256"),
        (f"{'a' * 64}  some-other-file.raw.xz\n", "some-other-file.raw.xz"),
        ("x" * 5000, "too large"),
    ],
)
async def test_bad_or_missing_sidecar_refused(
    db_session: AsyncSession, client: AsyncClient, media: Path, sidecar, needle
) -> None:
    _put(media, sidecar=sidecar)
    hdr = await _token(db_session)
    resp = await _import(client, hdr)
    assert resp.status_code == 422 and needle in resp.text
    listed = (await client.get(f"{_BASE}/media", headers=hdr)).json()["images"]
    assert listed[0]["problems"]


async def test_unversioned_name_refused(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    _put(media, name="spatiumddi-appliance-slot-amd64.raw.xz")
    resp = await _import(
        client, await _token(db_session), filename="spatiumddi-appliance-slot-amd64.raw.xz"
    )
    assert resp.status_code == 422 and "versioned" in resp.text


async def test_non_release_version_refused(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    name = "spatiumddi-appliance-slot-banana-amd64.raw.xz"
    _put(media, name=name)
    resp = await _import(client, await _token(db_session), filename=name)
    assert resp.status_code == 422 and "not a release version" in resp.text


async def test_unmounted_directory_refused(
    db_session: AsyncSession, client: AsyncClient, media: Path
) -> None:
    # A directory that is not a live mount holds nothing the appliance may trust.
    _put(media.parent / "ejected")
    hdr = await _token(db_session)
    assert (await client.get(f"{_BASE}/media", headers=hdr)).json()["images"] == []
    resp = await _import(client, hdr, mount="ejected")
    assert resp.status_code == 409 and "nothing is mounted" in resp.text


@pytest.mark.parametrize("mount", ["../etc", "UP PER", "a/b"])
async def test_bad_mount_name_422(
    db_session: AsyncSession, client: AsyncClient, media: Path, mount: str
) -> None:
    resp = await _import(client, await _token(db_session), mount=mount)
    assert resp.status_code == 422


@pytest.mark.parametrize("filename", ["../x.raw.xz", "a/b.raw.xz", "..", "sub\\x.raw.xz"])
async def test_path_in_filename_422(
    db_session: AsyncSession, client: AsyncClient, media: Path, filename: str
) -> None:
    resp = await _import(client, await _token(db_session), filename=filename)
    assert resp.status_code == 422


async def test_missing_file_404(db_session: AsyncSession, client: AsyncClient, media: Path) -> None:
    resp = await _import(client, await _token(db_session))
    assert resp.status_code == 404


async def test_symlink_is_not_offered_or_imported(
    db_session: AsyncSession, client: AsyncClient, media: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "secret.bin"
    outside.write_bytes(_BYTES)
    os.symlink(outside, media / _NAME)
    (media / _SIDECAR).write_text(f"{_SHA}  {_NAME}\n")
    hdr = await _token(db_session)
    assert (await client.get(f"{_BASE}/media", headers=hdr)).json()["images"] == []
    assert (await _import(client, hdr)).status_code == 404


async def test_oversize_refused(
    db_session: AsyncSession,
    client: AsyncClient,
    media: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _put(media)
    monkeypatch.setattr(upgrade_media, "UPGRADE_IMAGE_MAX_BYTES", 4)
    resp = await _import(client, await _token(db_session))
    assert resp.status_code == 422 and "limit" in resp.text


async def test_architecture_no_node_runs_refused(
    db_session: AsyncSession,
    client: AsyncClient,
    media: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.appliance.upgrade_image_catalog import FleetArchitectures

    async def _fleet(_db):
        return FleetArchitectures(
            architectures=["arm64"], unknown_count=0, counts={"arm64": 1}, restricted=True
        )

    monkeypatch.setattr(upgrade_images.catalog, "fleet_architectures", _fleet)
    _put(media)
    resp = await _import(client, await _token(db_session))
    assert resp.status_code == 422 and "arm64" in resp.text
    assert list(upgrade_images.SLOT_IMAGE_DIR.iterdir()) == []


async def test_stick_removed_mid_scan_is_409(
    db_session: AsyncSession,
    client: AsyncClient,
    media: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _put(media)
    real_open = upgrade_media.open_image

    def _gone(image):
        (media / _NAME).unlink()
        return real_open(image)

    monkeypatch.setattr(upgrade_media, "open_image", _gone)
    resp = await _import(client, await _token(db_session))
    assert resp.status_code == 409 and "removed" in resp.text
