"""The heartbeat keeps ``Appliance.supervisor_version`` current (#1183).

The supervisor sends its version in every heartbeat's capabilities block.
The column was written only at registration, which a registered supervisor
never repeats, so it kept its first value through every upgrade.
"""

from __future__ import annotations

import hashlib
import os
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _approved_supervisor(db: AsyncSession, version: str | None) -> tuple[Appliance, str]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        settings = PlatformSettings(id=1)
        db.add(settings)
    # The supervisor endpoints 404 unless the feature flag is on.
    settings.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="agent-1183",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
        supervisor_version=version,
    )
    db.add(row)
    await db.commit()
    return row, token


async def _heartbeat(client: AsyncClient, row: Appliance, token: str, **capabilities: object):
    return await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(row.id),
            "session_token": token,
            "capabilities": {"can_run_observer": True, **capabilities},
        },
    )


async def test_the_heartbeat_updates_the_supervisor_version(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _approved_supervisor(db_session, "2026.05.14.1")
    r = await _heartbeat(client, row, token, supervisor_version="2026.09.25-1")
    assert r.status_code == 200, r.text
    await db_session.refresh(row)
    assert row.supervisor_version == "2026.09.25-1"


async def test_a_heartbeat_without_a_version_keeps_the_known_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row, token = await _approved_supervisor(db_session, "2026.09.04-1")
    r = await _heartbeat(client, row, token)
    assert r.status_code == 200, r.text
    await db_session.refresh(row)
    assert row.supervisor_version == "2026.09.04-1"


async def test_an_oversized_version_is_ignored_not_fatal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The version rides in the capabilities block: a bad value there must
    not 422 the heartbeat that carries the node's liveness and slot state."""
    row, token = await _approved_supervisor(db_session, "2026.09.04-1")
    r = await _heartbeat(client, row, token, supervisor_version="x" * 65)
    assert r.status_code == 200, r.text
    await db_session.refresh(row)
    assert row.supervisor_version == "2026.09.04-1"
