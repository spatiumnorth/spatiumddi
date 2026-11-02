"""A Fleet Boot once is retired once a reboot has spent it (#3284).

``desired_next_boot_slot`` was cleared in one place only: once the node reported
the slot as its ``current_slot``. When the trial of that slot fell back to the
running slot, the request stayed on the row for good: the Fleet card's Boot
once button stayed disabled, the heartbeat long-poll stayed off, and the node
re-armed the slot that had just failed on every heartbeat.

The supervisor now reports the Boot once it ran for the standing request and
the boot it ran in. A run in an earlier boot than the heartbeat's was spent by
the reboot in between, so the request is retired.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

_URL = "/api/v1/appliance/supervisor/heartbeat"
_BOOT_A = "11111111-1111-1111-1111-111111111111"
_BOOT_B = "22222222-2222-2222-2222-222222222222"


async def _appliance(db: AsyncSession, desired: str | None = "slot_b") -> tuple[Appliance, str]:
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
        public_key_fingerprint="ee" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
        supervisor_version="2026.11.01-1",
        installed_appliance_version="2026.11.01-1",
        session_token_hash=token_hash,
        current_slot="slot_a",
        durable_default="slot_a",
        desired_next_boot_slot=desired,
    )
    db.add(appliance)
    await db.commit()
    return appliance, token


async def _beat(
    client: AsyncClient,
    appliance: Appliance,
    token: str,
    *,
    boot_id: str | None,
    current_slot: str = "slot_a",
    ran: tuple[str, str] | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {
        "appliance_id": str(appliance.id),
        "session_token": token,
        "current_slot": current_slot,
        "durable_default": "slot_a",
    }
    if boot_id is not None:
        body["boot_id"] = boot_id
    if ran is not None:
        body["next_boot_ran_slot"], body["next_boot_ran_boot_id"] = ran
    resp = await client.post(_URL, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _desired(db: AsyncSession, appliance: Appliance) -> str | None:
    row = (await db.execute(select(Appliance).where(Appliance.id == appliance.id))).scalar_one()
    await db.refresh(row)
    return row.desired_next_boot_slot


@pytest.mark.asyncio
async def test_a_boot_once_a_reboot_spent_is_retired(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reported fallback: armed in boot A, back on slot_a in boot B."""
    appliance, token = await _appliance(db_session)

    body = await _beat(client, appliance, token, boot_id=_BOOT_B, ran=("slot_b", _BOOT_A))

    assert body["desired_next_boot_slot"] is None
    assert await _desired(db_session, appliance) is None


@pytest.mark.asyncio
async def test_a_boot_once_armed_in_this_boot_stands_until_the_reboot(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session)

    body = await _beat(client, appliance, token, boot_id=_BOOT_A, ran=("slot_b", _BOOT_A))

    assert body["desired_next_boot_slot"] == "slot_b"
    assert await _desired(db_session, appliance) == "slot_b"


@pytest.mark.asyncio
async def test_a_run_of_another_request_retires_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Running slot_b, the node last ran a Boot once of slot_a in an earlier
    boot; the standing request (slot_a, sent since) is a new one."""
    appliance, token = await _appliance(db_session, desired="slot_a")

    body = await _beat(
        client, appliance, token, boot_id=_BOOT_B, current_slot="slot_b", ran=("slot_b", _BOOT_A)
    )

    assert body["desired_next_boot_slot"] == "slot_a"


@pytest.mark.asyncio
async def test_without_a_run_or_a_boot_id_the_request_stands(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A supervisor too old to report either keeps today's rule."""
    appliance, token = await _appliance(db_session)

    assert (await _beat(client, appliance, token, boot_id=_BOOT_B))[
        "desired_next_boot_slot"
    ] == "slot_b"
    assert (await _beat(client, appliance, token, boot_id=None, ran=("slot_b", _BOOT_A)))[
        "desired_next_boot_slot"
    ] == "slot_b"


@pytest.mark.asyncio
async def test_the_slot_booting_still_retires_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session)

    body = await _beat(client, appliance, token, boot_id=_BOOT_B, current_slot="slot_b")

    assert body["desired_next_boot_slot"] is None
