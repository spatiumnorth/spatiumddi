"""Storing an upgrade image must leave the kubelet's eviction margin free (#2400).

evictionHard 5 % + evictionMinimumReclaim 10 %: once /var dips under 5 % the
node stays in DiskPressure until 15 % is free, so an image that "fits" can
still take the control plane down. The upload and GitHub-import paths refuse
with a 422 that names the numbers, before any byte is written.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import upgrade_images
from app.config import settings
from app.models.appliance import ApplianceUpgradeImage
from app.services.appliance import releases as releases_service
from app.services.appliance import upgrade_image_space
from tests.test_upgrade_images import _BASE, _hdr, _token

pytestmark = pytest.mark.asyncio

GIB = 1024**3
TOTAL = 15 * GIB
KEEP = TOTAL * 15 // 100  # 2.25 GiB


def _disk(monkeypatch: pytest.MonkeyPatch, free: int) -> None:
    def usage(_path):  # noqa: ANN001
        return SimpleNamespace(total=TOTAL, used=TOTAL - free, free=free)

    monkeypatch.setattr(upgrade_image_space, "shutil", SimpleNamespace(disk_usage=usage))


async def _image_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(ApplianceUpgradeImage))).scalar_one()


def test_margin_is_15_percent_after_the_image_lands() -> None:
    u = upgrade_image_space.StoreUsage(total_bytes=TOTAL, free_bytes=KEEP + 1000)
    assert upgrade_image_space.shortfall_message(u, 1000) is None
    msg = upgrade_image_space.shortfall_message(u, 1001)
    assert msg is not None
    assert "15%" in msg and "evict" in msg


async def test_upload_refused_when_it_would_leave_diskpressure(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _disk(monkeypatch, KEEP)  # above the 5% trigger, but nothing to spare
    token = await _token(db_session)
    content = b"x" * 4096
    resp = await client.post(
        _BASE,
        headers=_hdr(token),
        files={"file": ("img.raw.xz", content, "application/octet-stream")},
        data={"sha256": hashlib.sha256(content).hexdigest(), "appliance_version": "1.0.0"},
    )
    assert resp.status_code == 422, resp.text
    assert "free disk space" in resp.json()["detail"]
    assert list(tmp_path.iterdir()) == []
    assert await _image_count(db_session) == 0


async def test_upload_accepted_when_the_margin_survives(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _disk(monkeypatch, KEEP + 10 * 1024 * 1024)
    token = await _token(db_session)
    content = b"x" * 4096
    resp = await client.post(
        _BASE,
        headers=_hdr(token),
        files={"file": ("img.raw.xz", content, "application/octet-stream")},
        data={"sha256": hashlib.sha256(content).hexdigest(), "appliance_version": "1.0.0"},
    )
    assert resp.status_code == 200, resp.text


def _fake_github(monkeypatch: pytest.MonkeyPatch, body: bytes) -> list[str]:
    """Route the import's httpx traffic to an in-memory GitHub; returns the
    list of URLs requested."""
    sha = hashlib.sha256(body).hexdigest()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url).endswith(".sha256"):
            return httpx.Response(200, text=f"{sha}  img.raw.xz\n")
        return httpx.Response(200, content=body, headers={"content-length": str(len(body))})

    real = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(upgrade_images.httpx, "AsyncClient", factory)

    async def choice(tag: str, architecture: str | None = None):  # noqa: ANN001
        spec = releases_service.UpgradeImageRelease(
            tag=tag,
            name=tag,
            published_at=datetime.now(UTC),
            body="",
            html_url="",
            is_prerelease=False,
            is_installed=False,
            image_asset_url="https://example.invalid/img.raw.xz",
            checksum_asset_url="https://example.invalid/img.raw.xz.sha256",
            size_bytes=len(body),
            architecture="amd64",
        )
        return releases_service.UpgradeImageChoice(spec=spec, available=("amd64",))

    monkeypatch.setattr(releases_service, "resolve_upgrade_image_choice", choice)
    return seen


async def test_github_import_refused_before_any_byte_is_stored(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _disk(monkeypatch, KEEP + 1024 * 1024)  # 1 MiB spare
    _fake_github(monkeypatch, b"y" * (5 * 1024 * 1024))  # 5 MiB image
    token = await _token(db_session)
    resp = await client.post(
        f"{_BASE}/import-from-github",
        headers=_hdr(token),
        json={"release_tag": "1.0.0"},
    )
    assert resp.status_code == 422, resp.text
    assert "free disk space" in resp.json()["detail"]
    assert list(tmp_path.iterdir()) == []
    assert await _image_count(db_session) == 0


async def test_github_import_proceeds_with_room(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _disk(monkeypatch, KEEP + 50 * 1024 * 1024)
    _fake_github(monkeypatch, b"y" * (5 * 1024 * 1024))
    token = await _token(db_session)
    resp = await client.post(
        f"{_BASE}/import-from-github",
        headers=_hdr(token),
        json={"release_tag": "1.0.0"},
    )
    assert resp.status_code == 200, resp.text
    assert await _image_count(db_session) == 1


async def test_mirror_mode_checks_the_mirror_volume_not_the_api_pod(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(settings, "slot_image_mirror_url", "http://mirror.test")
    monkeypatch.setattr(settings, "slot_image_mirror_secret", "s3cret")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200, json={"path": "/x", "free_bytes": 7, "total_bytes": 100, "used_bytes": 93}
        )

    real = httpx.AsyncClient
    monkeypatch.setattr(
        upgrade_image_space.httpx,
        "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
    )
    _disk(monkeypatch, 999 * GIB)  # the api pod's own disk must be ignored
    usage = await upgrade_image_space.get_store_usage(tmp_path)
    assert usage == upgrade_image_space.StoreUsage(total_bytes=100, free_bytes=7)
    assert seen[0].url.path.endswith("/internal/slot-images/_/disk-usage")
    assert seen[0].headers["x-mirror-auth"]


async def test_unreachable_mirror_does_not_block_the_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(settings, "slot_image_mirror_url", "http://mirror.test")
    monkeypatch.setattr(settings, "slot_image_mirror_secret", "s3cret")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    real = httpx.AsyncClient
    monkeypatch.setattr(
        upgrade_image_space.httpx,
        "AsyncClient",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
    )
    assert await upgrade_image_space.get_store_usage(tmp_path) is None
