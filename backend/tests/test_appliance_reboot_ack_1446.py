"""A Fleet reboot request is retired on proof it landed, not on a clock (#1446).

``reboot_requested`` used to clear 15 s after the stamp. A node with an
upgrade staged keeps ``desired_appliance_version`` set, which suppresses the
heartbeat long-poll, so its heartbeats arrive a full interval apart: the first
heartbeat after the stamp cleared the flag and carried ``false`` in its own
response, and the supervisor never saw the request. Found on a 3-node rolling
upgrade, where the member stayed up until rebooted by hand.

Now the first heartbeat after the stamp records the boot the request applies
to, the request is delivered until a heartbeat comes from another boot, and a
supervisor too old to report its boot gets it exactly once.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

_URL = "/api/v1/appliance/supervisor/heartbeat"
_BOOT_A = "11111111-1111-1111-1111-111111111111"
_BOOT_B = "22222222-2222-2222-2222-222222222222"


async def _appliance(db: AsyncSession, *, requested_ago: timedelta) -> tuple[Appliance, str]:
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
        supervisor_version="2026.10.03-1",
        installed_appliance_version="2026.10.02-1",
        # The reported case: an upgrade staged, so no long-poll.
        desired_appliance_version="2026.10.03-1",
        desired_slot_image_url="https://cp.local/x.raw.xz",
        session_token_hash=token_hash,
        reboot_requested=True,
        reboot_requested_at=datetime.now(UTC) - requested_ago,
    )
    db.add(appliance)
    await db.commit()
    return appliance, token


async def _beat(client: AsyncClient, appliance: Appliance, token: str, boot_id: str | None):
    body: dict[str, object] = {"appliance_id": str(appliance.id), "session_token": token}
    if boot_id is not None:
        body["boot_id"] = boot_id
    resp = await client.post(_URL, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _row(db: AsyncSession, appliance: Appliance) -> Appliance:
    row = (await db.execute(select(Appliance).where(Appliance.id == appliance.id))).scalar_one()
    await db.refresh(row)
    return row


@pytest.mark.asyncio
async def test_a_heartbeat_long_after_the_stamp_still_delivers_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reported failure: the first heartbeat lands past the old 15 s."""
    appliance, token = await _appliance(db_session, requested_ago=timedelta(seconds=40))

    body = await _beat(client, appliance, token, _BOOT_A)

    assert body["reboot_requested"] is True
    row = await _row(db_session, appliance)
    assert row.reboot_requested is True
    assert row.reboot_requested_boot_id == _BOOT_A


@pytest.mark.asyncio
async def test_it_keeps_being_delivered_from_the_same_boot_then_retires_on_a_new_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, requested_ago=timedelta(seconds=5))

    assert (await _beat(client, appliance, token, _BOOT_A))["reboot_requested"] is True
    assert (await _beat(client, appliance, token, _BOOT_A))["reboot_requested"] is True
    # The node came back: a heartbeat from another boot retires it, and is
    # not handed the request again (that would reboot it twice).
    assert (await _beat(client, appliance, token, _BOOT_B))["reboot_requested"] is False
    row = await _row(db_session, appliance)
    assert row.reboot_requested is False
    assert row.reboot_requested_at is None
    assert row.reboot_requested_boot_id is None


@pytest.mark.asyncio
async def test_an_old_supervisor_gets_it_exactly_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, requested_ago=timedelta(seconds=40))

    assert (await _beat(client, appliance, token, None))["reboot_requested"] is True
    assert (await _beat(client, appliance, token, None))["reboot_requested"] is False


@pytest.mark.asyncio
async def test_a_request_that_never_lands_is_given_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, requested_ago=timedelta(hours=1))
    row = await _row(db_session, appliance)
    row.reboot_requested_boot_id = _BOOT_A
    await db_session.commit()

    body = await _beat(client, appliance, token, _BOOT_A)

    assert body["reboot_requested"] is False
    assert (await _row(db_session, appliance)).reboot_requested is False


@pytest.mark.asyncio
async def test_a_new_request_does_not_inherit_an_earlier_boot(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reboot endpoint resets the recorded boot, so a request made while
    an earlier one waited on boot A is not retired by A's own heartbeat."""
    appliance, token = await _appliance(db_session, requested_ago=timedelta(seconds=5))
    row = await _row(db_session, appliance)
    row.reboot_requested_boot_id = _BOOT_A
    admin = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="admin",
        hashed_password=hash_password("test-pw-1446"),
        is_superadmin=True,
    )
    db_session.add(admin)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/reboot",
        headers={"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
    )
    assert resp.status_code == 200, resp.text
    assert (await _row(db_session, appliance)).reboot_requested_boot_id is None
    # So boot A's next heartbeat records A afresh and delivers the request.
    assert (await _beat(client, appliance, token, _BOOT_A))["reboot_requested"] is True
