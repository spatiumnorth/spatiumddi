"""#787 — the download handler falls back to local FS when the mirror misses.

The appliance turns the slot-image mirror on at PROMOTE (the supervisor
derives ``slotImageMirror.enabled`` from the control-plane size), so an
image staged while the box was still single-node sits on the seed's
hostPath while the mirror's PVC comes up empty. Without a fallback the
first multi-node upgrade after a promote fails on a download the operator
cannot diagnose — the bytes are right there on the node.

Two of the three ways the mirror can fail mean "it cannot answer right
now", and both fall back when this replica holds the bytes:

* **404** — the image predates the promote that enabled the mirror.
* **unreachable** — the mirror's PVC is RWO local-path, so the single pod
  is pinned to one node; losing that node would otherwise block every
  upgrade in the fleet, including the one that repairs it.

The third — a mirror that ANSWERS with an error — does **not** fall back.
It is alive and refusing or failing, most likely a mismatched
``X-Mirror-Auth`` secret, which never self-heals. Falling back there would
let nodes holding a stale local copy quietly succeed while the rest of the
fleet 502s, so the fault would surface as an inexplicably half-working
upgrade rather than an error.

Serving local bytes in the two covered cases is safe because the host
runner verifies them against the stamped sha256 and ``delete_upgrade_image``
now clears local copies too, so a deleted image cannot resurface.

Also covers the two halves that make "re-upload it" a real remedy rather
than a no-op: both ingest paths re-store when the active store has lost
the bytes, and delete cleans local FS even in mirror mode.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException, status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import upgrade_images
from app.core.security import create_access_token, hash_password
from app.models.appliance import ApplianceUpgradeImage
from app.models.auth import User

pytestmark = pytest.mark.asyncio

_BASE = "/api/v1/appliance/upgrade-images"
_BYTES = b"\xfd7zXZ\x00fake-slot-image-payload"


async def _seed_image(db: AsyncSession) -> ApplianceUpgradeImage:
    image = ApplianceUpgradeImage(
        id=uuid.uuid4(),
        filename="spatiumddi-appliance-slot-2026.08.01-1-amd64.raw.xz",
        size_bytes=len(_BYTES),
        sha256="b" * 64,
        appliance_version="2026.08.01-1",
    )
    db.add(image)
    await db.flush()
    return image


def _stage_local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, image_id: uuid.UUID) -> Path:
    """Put real bytes where the pre-promote hostPath would have them."""
    path = tmp_path / f"{image_id}.raw.xz"
    path.write_bytes(_BYTES)
    monkeypatch.setattr(upgrade_images, "_image_path", lambda _id: tmp_path / f"{_id}.raw.xz")
    return path


def _mirror_raises(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", "http://mirror")

    async def _boom(*_args, **_kwargs):
        raise exc

    monkeypatch.setattr(upgrade_images, "_stream_download_from_mirror", _boom)


def _url(image: ApplianceUpgradeImage) -> str:
    token = upgrade_images.slot_image_download_token(image.id)
    return f"{_BASE}/{image.id}/raw.xz?t={token}"


async def test_mirror_miss_serves_the_pre_promote_local_copy(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    image = await _seed_image(db_session)
    _stage_local(monkeypatch, tmp_path, image.id)
    _mirror_raises(
        monkeypatch,
        HTTPException(status.HTTP_404_NOT_FOUND, "Upgrade image bytes missing on mirror"),
    )

    resp = await client.get(_url(image))

    assert resp.status_code == 200
    assert resp.content == _BYTES


async def test_mirror_miss_with_no_local_copy_still_404s(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Every node that did NOT serve the original upload lands here — the
    # fallback must not invent a different outcome for them.
    image = await _seed_image(db_session)
    monkeypatch.setattr(upgrade_images, "_image_path", lambda _id: tmp_path / f"{_id}.raw.xz")
    _mirror_raises(
        monkeypatch,
        HTTPException(status.HTTP_404_NOT_FOUND, "Upgrade image bytes missing on mirror"),
    )

    resp = await client.get(_url(image))

    assert resp.status_code == 404


async def test_unreachable_mirror_falls_back_and_warns(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The mirror pod is pinned to one node by its RWO PVC. Losing that node
    # must not block an upgrade on a replica that has the exact bytes — but
    # the degradation has to be visible, not silent.
    image = await _seed_image(db_session)
    _stage_local(monkeypatch, tmp_path, image.id)
    _mirror_raises(monkeypatch, upgrade_images.MirrorUnavailable("connect timeout"))
    warnings: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        upgrade_images.logger,
        "warning",
        lambda event, **kw: warnings.append((event, kw)),
    )

    resp = await client.get(_url(image))

    assert resp.status_code == 200
    assert resp.content == _BYTES
    assert [e for e, _ in warnings] == [
        "appliance_upgrade_image_served_from_local_mirror_unreachable"
    ]


async def test_unreachable_mirror_with_no_local_copy_still_502s(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Nothing to serve — the mirror's own error is the honest answer, and
    # must not be flattened into a 404 ("re-upload required") that would
    # send the operator down the wrong path.
    image = await _seed_image(db_session)
    monkeypatch.setattr(upgrade_images, "_image_path", lambda _id: tmp_path / f"{_id}.raw.xz")
    _mirror_raises(monkeypatch, upgrade_images.MirrorUnavailable("connect timeout"))

    resp = await client.get(_url(image))

    assert resp.status_code == 502


async def test_a_mirror_that_answers_with_an_error_is_not_masked(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The case that made the fallback too broad.

    A mismatched ``X-Mirror-Auth`` secret makes the mirror answer 401, which
    the proxy wraps as a 502. Serving the local copy there would let every
    node holding one succeed while the rest of the fleet 502s — so the
    operator meets a half-working upgrade instead of a configuration error,
    and the mirror stays misconfigured because nothing ever complained.
    """
    image = await _seed_image(db_session)
    _stage_local(monkeypatch, tmp_path, image.id)
    _mirror_raises(
        monkeypatch,
        HTTPException(status.HTTP_502_BAD_GATEWAY, "Mirror returned 401: b'forbidden'"),
    )

    resp = await client.get(_url(image))

    assert resp.status_code == 502
    assert "401" in resp.text


async def test_no_mirror_configured_still_serves_local_directly(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The single-node path is untouched by the fallback branch.
    image = await _seed_image(db_session)
    _stage_local(monkeypatch, tmp_path, image.id)
    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", "")

    resp = await client.get(_url(image))

    assert resp.status_code == 200
    assert resp.content == _BYTES


async def test_fallback_does_not_bypass_the_download_token(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Auth is checked before either storage path is consulted; the new
    # branch must not become a way in without a valid ``?t=``.
    image = await _seed_image(db_session)
    _stage_local(monkeypatch, tmp_path, image.id)
    _mirror_raises(
        monkeypatch,
        HTTPException(status.HTTP_404_NOT_FOUND, "Upgrade image bytes missing on mirror"),
    )

    assert (await client.get(f"{_BASE}/{image.id}/raw.xz")).status_code == 401
    assert (await client.get(f"{_BASE}/{image.id}/raw.xz?t=nope")).status_code == 403


# ── "Re-upload it" has to actually re-store ──────────────────────────


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-787"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _upload_files() -> dict:
    return {"file": ("image.raw.xz", _BYTES, "application/octet-stream")}


def _upload_form(image: ApplianceUpgradeImage) -> dict[str, str]:
    return {
        "sha256": image.sha256,
        "appliance_version": image.appliance_version,
    }


async def test_duplicate_upload_restores_bytes_missing_from_the_store(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The documented post-promote remedy, which used to be a no-op.

    The row exists (same sha256) but the mirror's PVC came up empty, so the
    duplicate short-circuit returned success while storing nothing — the
    operator could re-upload forever and change nothing.
    """
    image = await _seed_image(db_session)
    headers = await _superadmin_headers(db_session)
    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", "http://mirror")

    async def _absent(_id):
        return False

    stored: dict[str, uuid.UUID] = {}

    async def _store(image_id, source, expected_sha):
        written = 0
        async for chunk in source:
            written += len(chunk)
        stored["id"] = image_id
        return written

    monkeypatch.setattr(upgrade_images, "_bytes_present_in_active_store", _absent)
    monkeypatch.setattr(upgrade_images, "_store_verified_image", _store)

    resp = await client.post(
        _BASE, headers=headers, files=_upload_files(), data=_upload_form(image)
    )

    assert resp.status_code == 200
    # Re-stored under the EXISTING id — a fresh one would leave any
    # already-stamped desired_slot_image_url pointing at nothing.
    assert stored["id"] == image.id
    assert resp.json()["id"] == str(image.id)


async def test_duplicate_upload_still_short_circuits_when_bytes_are_present(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The idempotent path is the common one and must stay cheap: no re-store
    # of a 1-4 GiB body just because the operator clicked upload twice.
    image = await _seed_image(db_session)
    headers = await _superadmin_headers(db_session)
    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", "http://mirror")

    async def _present(_id):
        return True

    async def _never(*_args, **_kwargs):
        raise AssertionError("must not re-store when the bytes are already there")

    monkeypatch.setattr(upgrade_images, "_bytes_present_in_active_store", _present)
    monkeypatch.setattr(upgrade_images, "_store_verified_image", _never)

    resp = await client.post(
        _BASE, headers=headers, files=_upload_files(), data=_upload_form(image)
    )

    assert resp.status_code == 200
    assert resp.json()["id"] == str(image.id)


async def test_delete_clears_the_local_copy_in_mirror_mode(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The hostPath stays mounted with the mirror on, so a local copy can
    # exist. Leaving it behind would strand gigabytes per deleted image AND
    # let the download fallback serve something the operator deleted.
    image = await _seed_image(db_session)
    headers = await _superadmin_headers(db_session)
    local = _stage_local(monkeypatch, tmp_path, image.id)
    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", "http://mirror")

    async def _noop_delete(_id, **_kw):
        return None

    monkeypatch.setattr(upgrade_images, "_delete_from_mirror", _noop_delete)

    resp = await client.delete(f"{_BASE}/{image.id}", headers=headers)

    assert resp.status_code == 204
    assert not local.exists()
