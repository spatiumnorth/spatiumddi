"""Appliance OS upgrade — download integrity hints + fire-once nonce (#386).

Covers the backend half of the #386 fix:

* Scheduling an upgrade from an internal (uploaded/imported) upgrade
  image stamps the image's sha256 + ``tls_insecure=True`` on the
  appliance row, and appends a per-apply nonce fragment to
  ``desired_slot_image_url`` so the supervisor fires the slot-upgrade
  trigger exactly once per distinct desired-state (no silent re-fire
  loop). The bytes are verified against the hash host-side, which is
  what makes relaxing TLS for the self-served URL safe.
* Each apply mints a fresh nonce (same fetch URL, different fragment).
* An external operator-pasted URL stays fully verified (no sha256, no
  insecure flag) but still gets a nonce.
* ``clear-upgrade`` nulls the download hints.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    Appliance,
    ApplianceUpgradeImage,
)
from app.models.audit import AuditLog
from app.models.auth import User

_SHA = "a" * 64


async def _make_superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-386"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _seed_appliance(db: AsyncSession) -> Appliance:
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:8]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ff" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
        # The fire-once nonce fragment is gated on a supervisor new enough to
        # strip it before fetching (#419 / >= 2026.06.12). These tests assert
        # the nonce IS appended, so the fixture must present a capable box.
        supervisor_version="2026.06.13-2",
        installed_appliance_version="2026.06.13-2",
    )
    db.add(appliance)
    await db.flush()
    return appliance


async def _seed_image(db: AsyncSession) -> ApplianceUpgradeImage:
    image = ApplianceUpgradeImage(
        id=uuid.uuid4(),
        filename="spatiumddi-appliance-slot-2026.06.12-1-amd64.raw.xz",
        size_bytes=1234,
        sha256=_SHA,
        appliance_version="2026.06.12-1",
    )
    db.add(image)
    await db.flush()
    return image


@pytest.mark.asyncio
async def test_apply_internal_image_stamps_sha256_and_insecure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _make_superadmin(db_session)
    appliance = await _seed_appliance(db_session)
    image = await _seed_image(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json={
            "desired_appliance_version": "2026.06.12-1",
            "slot_image_id": str(image.id),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The bytes are verified against the stored hash, and the self-served
    # URL is flagged insecure so the host runner skips cert-verify for it.
    assert body["desired_slot_image_sha256"] == _SHA
    assert body["desired_slot_image_tls_insecure"] is True
    url = body["desired_slot_image_url"]
    assert f"/api/v1/appliance/upgrade-images/{image.id}/raw.xz" in url
    assert "?t=" in url
    # Fire-once nonce fragment.
    assert "#a=" in url


@pytest.mark.asyncio
async def test_apply_mints_unique_nonce_each_time(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _make_superadmin(db_session)
    appliance = await _seed_appliance(db_session)
    image = await _seed_image(db_session)
    await db_session.commit()

    payload = {
        "desired_appliance_version": "2026.06.12-1",
        "slot_image_id": str(image.id),
    }
    r1 = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json=payload,
    )
    r2 = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json=payload,
    )
    assert r1.status_code == 200 and r2.status_code == 200
    u1 = r1.json()["desired_slot_image_url"]
    u2 = r2.json()["desired_slot_image_url"]
    # Different nonce → the supervisor treats the re-apply as a fresh
    # desired-state and re-fires, even though the underlying image is
    # identical. The fetch URL (everything before the fragment) matches.
    assert u1 != u2
    assert u1.split("#", 1)[0] == u2.split("#", 1)[0]


@pytest.mark.asyncio
async def test_apply_external_url_stays_verified(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _make_superadmin(db_session)
    appliance = await _seed_appliance(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json={
            "desired_appliance_version": "2026.06.12-1",
            "desired_slot_image_url": (
                "https://example.com/spatiumddi-appliance-slot-amd64.raw.xz"
            ),
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # External public-CA URL — no hash, fully verified TLS.
    assert body["desired_slot_image_sha256"] is None
    assert body["desired_slot_image_tls_insecure"] is False
    assert "#a=" in body["desired_slot_image_url"]


@pytest.mark.asyncio
async def test_clear_upgrade_nulls_download_hints(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _make_superadmin(db_session)
    appliance = await _seed_appliance(db_session)
    image = await _seed_image(db_session)
    await db_session.commit()

    await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json={
            "desired_appliance_version": "2026.06.12-1",
            "slot_image_id": str(image.id),
        },
    )
    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/clear-upgrade",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["desired_appliance_version"] is None
    assert body["desired_slot_image_url"] is None
    assert body["desired_slot_image_sha256"] is None
    assert body["desired_slot_image_tls_insecure"] is False

    # Confirm at the DB layer too.
    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    assert refreshed.desired_slot_image_sha256 is None
    assert refreshed.desired_slot_image_tls_insecure is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "direction"),
    [
        # The fixture's box runs 2026.06.13-2.
        ("2026.07.01-1", "forward"),
        ("1.0.0", "forward"),
        ("2026.06.13-2", "same"),
        # Allowed: this is also the manual rollback path. But recorded.
        ("2026.06.12-1", "backward"),
        ("my-hand-built-image", "unknown"),
    ],
)
async def test_the_audit_row_records_which_way_the_upgrade_moves_the_node(
    client: AsyncClient, db_session: AsyncSession, target: str, direction: str
) -> None:
    """#1182: the per-box upgrade compared no versions, so a rollback and an
    upgrade looked identical in the audit log. It still refuses neither."""
    headers = await _make_superadmin(db_session)
    appliance = await _seed_appliance(db_session)
    image = await _seed_image(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json={"desired_appliance_version": target, "slot_image_id": str(image.id)},
    )
    assert resp.status_code == 200, resp.text
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "appliance.upgrade_scheduled",
                AuditLog.resource_id == str(appliance.id),
            )
        )
    ).scalar_one()
    assert row.new_value["direction"] == direction
    assert row.new_value["installed_appliance_version"] == "2026.06.13-2"
