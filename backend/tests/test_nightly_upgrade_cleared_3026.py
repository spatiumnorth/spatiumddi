"""A completed nightly upgrade stops being "pending" (#3026).

A nightly's release tag is ``nightly-YYYY.MM.DD`` while the slot it installs
reports ``0.0.0-nightly-YYYYMMDD+<sha>``. The auto-clear compared the two as
strings, so a finished upgrade stayed pending and the supervisor could fire it
again over the rollback slot.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.versions import is_installed_target
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

NIGHTLY = "0.0.0-nightly-20261028+623cc9f"


@pytest.mark.parametrize(
    ("installed", "target", "expected"),
    [
        (NIGHTLY, "nightly-2026.10.28", True),
        (NIGHTLY, "nightly-20261028", True),
        (NIGHTLY, NIGHTLY, True),
        (NIGHTLY, "nightly-2026.10.27", False),
        ("0.0.0-nightly-20261018+4be23dc", "nightly-2026.10.28", False),
        # Releases: tag == version.
        ("2026.10.03-1", "2026.10.03-1", True),
        ("2026.10.03-1", "2026.10.03-2", False),
        ("1.0.0", "1.0.0", True),
        ("1.0.0", "1.0.1", False),
        # A release tag never matches a nightly, and unknowns never match.
        (NIGHTLY, "2026.10.28-1", False),
        ("dev", "nightly-2026.10.28", False),
        (None, "nightly-2026.10.28", False),
        (NIGHTLY, None, False),
        (NIGHTLY, "", False),
    ],
)
def test_is_installed_target(installed: str | None, target: str | None, expected: bool) -> None:
    assert is_installed_target(installed, target) is expected


_URL = "/api/v1/appliance/supervisor/heartbeat"


async def _appliance(db: AsyncSession, *, installed: str, desired: str) -> tuple[Appliance, str]:
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:8]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ff" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
        supervisor_version=installed,
        installed_appliance_version=installed,
        desired_appliance_version=desired,
        desired_slot_image_url="https://cp.local/x.raw.xz",
        session_token_hash=token_hash,
    )
    db.add(appliance)
    await db.commit()
    return appliance, token


async def _beat(client: AsyncClient, db: AsyncSession, a: Appliance, token: str) -> Appliance:
    resp = await client.post(
        _URL,
        json={
            "appliance_id": str(a.id),
            "session_token": token,
            "installed_appliance_version": NIGHTLY,
            "last_upgrade_state": "ready",
        },
    )
    assert resp.status_code == 200, resp.text
    row = (await db.execute(select(Appliance).where(Appliance.id == a.id))).scalar_one()
    await db.refresh(row)
    return row


@pytest.mark.asyncio
async def test_finished_nightly_upgrade_is_cleared(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, token = await _appliance(
        db_session, installed="0.0.0-nightly-20261018+4be23dc", desired="nightly-2026.10.28"
    )
    row = await _beat(client, db_session, a, token)
    assert row.desired_appliance_version is None
    assert row.desired_slot_image_url is None


@pytest.mark.asyncio
async def test_a_genuinely_pending_nightly_upgrade_stays_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, token = await _appliance(
        db_session, installed="0.0.0-nightly-20261018+4be23dc", desired="nightly-2026.10.29"
    )
    row = await _beat(client, db_session, a, token)
    assert row.desired_appliance_version == "nightly-2026.10.29"
    assert row.desired_slot_image_url is not None
