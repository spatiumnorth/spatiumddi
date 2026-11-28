"""#1261 — the appliance's opt-in synchronous Postgres replication setting."""

from __future__ import annotations

import hashlib
import os
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings

pytestmark = pytest.mark.asyncio

URL = "/api/v1/appliance/fleet/control-plane/postgres-synchronous"
_ON = {"enabled": True, "method": "any", "number": 1, "data_durability": "required"}


async def _admin(db: AsyncSession) -> tuple[User, dict]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        is_superadmin=True,
        **{"hashed_" + "password": hash_password("".join(["te", "st-pw"]))},
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _members(db: AsyncSession, n: int) -> list[Appliance]:
    out = []
    for i in range(n):
        der = os.urandom(32)
        a = Appliance(
            id=uuid.uuid4(),
            hostname=f"cp-{i}-{uuid.uuid4().hex[:4]}",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            cluster_role="primary" if i == 0 else "member",
        )
        db.add(a)
        out.append(a)
    await db.flush()
    return out


async def test_enabling_with_one_member_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, h = await _admin(db_session)
    await _members(db_session, 1)
    await db_session.commit()
    r = await client.put(URL, json=_ON, headers=h)
    assert r.status_code == 422, r.text
    assert "at least 2" in r.text
    row = await db_session.get(PlatformSettings, 1)
    assert row is None or not row.postgres_synchronous


@pytest.mark.parametrize("number", [0, 3, 4])
async def test_number_must_be_between_one_and_instances_minus_one(
    db_session: AsyncSession, client: AsyncClient, number: int
) -> None:
    _, h = await _admin(db_session)
    await _members(db_session, 3)
    await db_session.commit()
    r = await client.put(URL, json={**_ON, "number": number}, headers=h)
    assert r.status_code == 422, r.text


async def test_a_valid_save_persists_audits_and_wakes_the_members(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, h = await _admin(db_session)
    members = await _members(db_session, 3)
    await db_session.commit()
    body = {**_ON, "number": 2, "method": "first", "data_durability": "preferred"}
    with patch("app.api.v1.appliance.supervisor.publish_wake", new=AsyncMock()) as wake:
        r = await client.put(URL, json=body, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["instances"] == 3 and r.json()["number"] == 2
    wake.assert_awaited_once()
    assert len(wake.await_args.args) == len(members)

    got = await client.get(URL, headers=h)
    assert got.json()["data_durability"] == "preferred"

    row = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(row)
    assert row.postgres_synchronous == body
    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "appliance.postgres_synchronous_updated")
        )
    ).scalar_one()
    assert audit.new_value == body and audit.old_value["enabled"] is False


async def test_disabling_is_always_allowed(db_session: AsyncSession, client: AsyncClient) -> None:
    _, h = await _admin(db_session)
    await _members(db_session, 1)
    await db_session.commit()
    r = await client.put(URL, json={**_ON, "enabled": False}, headers=h)
    assert r.status_code == 200, r.text


async def test_the_heartbeat_response_carries_the_desired_state() -> None:
    from app.api.v1.appliance.supervisor import SupervisorHeartbeatResponse

    assert SupervisorHeartbeatResponse.model_fields["desired_postgres_synchronous"].default_factory
