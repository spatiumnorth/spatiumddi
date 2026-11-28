"""#4646 — a role held back for a missing agent key reaches the Fleet row.

The supervisor holds back a DNS / DHCP role whose agent key the control plane
does not have; that used to be an info log only. The heartbeat now carries
``roles_awaiting_key`` and the appliance response returns it.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

HEARTBEAT = "/api/v1/appliance/supervisor/heartbeat"


async def _setup(db: AsyncSession) -> tuple[Appliance, str, dict[str, str]]:
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-4646"),
        is_superadmin=True,
    )
    db.add(user)
    token, token_hash = generate_session_token()
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:8]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ff" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
        session_token_hash=token_hash,
        assigned_roles=["dns-bind9", "dhcp"],
    )
    db.add(appliance)
    await db.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    await db.commit()
    return appliance, token, headers


async def _row(client: AsyncClient, headers: dict[str, str], appliance: Appliance) -> dict:
    resp = await client.get(f"/api/v1/appliance/appliances/{appliance.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_heartbeat_roles_awaiting_key_reach_the_appliance_response(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token, headers = await _setup(db_session)
    assert (await _row(client, headers, appliance))["roles_awaiting_key"] == []

    resp = await client.post(
        HEARTBEAT,
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "roles_awaiting_key": ["dns-bind9", "dhcp", "dhcp"],
        },
    )
    assert resp.status_code == 200, resp.text
    assert (await _row(client, headers, appliance))["roles_awaiting_key"] == ["dhcp", "dns-bind9"]

    listing = await client.get("/api/v1/appliance/appliances", headers=headers)
    mine = next(a for a in listing.json()["appliances"] if a["id"] == str(appliance.id))
    assert mine["roles_awaiting_key"] == ["dhcp", "dns-bind9"]


@pytest.mark.asyncio
async def test_an_older_supervisor_omitting_the_field_leaves_it_alone_and_empty_clears_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token, headers = await _setup(db_session)
    base = {"appliance_id": str(appliance.id), "session_token": token}
    await client.post(HEARTBEAT, json={**base, "roles_awaiting_key": ["dhcp"]})

    assert (await client.post(HEARTBEAT, json=base)).status_code == 200
    assert (await _row(client, headers, appliance))["roles_awaiting_key"] == ["dhcp"]

    await client.post(HEARTBEAT, json={**base, "roles_awaiting_key": []})
    assert (await _row(client, headers, appliance))["roles_awaiting_key"] == []
