"""#4185 — a server group's ``max_cache_size`` (BIND ``max-cache-size``)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
async def test_create_update_and_clear(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/dns/groups",
        json={"name": f"g-{uuid.uuid4().hex[:6]}", "max_cache_size": " 128M "},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["max_cache_size"] == "128m"
    gid = r.json()["id"]

    r = await client.put(
        f"/api/v1/dns/groups/{gid}", json={"max_cache_size": "1g"}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["max_cache_size"] == "1g"

    r = await client.put(
        f"/api/v1/dns/groups/{gid}", json={"max_cache_size": None}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["max_cache_size"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", ["unlimited", "0", "00", "0m", "-1", "64mb", "1.5g", "default", "m"]
)
async def test_refuses_what_bind_ignores_or_cannot_parse(
    client: AsyncClient, db_session: AsyncSession, bad: str
) -> None:
    headers = await _superadmin(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}", json={"max_cache_size": bad}, headers=headers
    )
    assert r.status_code == 422, r.text
    assert "max_cache_size" in r.text


@pytest.mark.asyncio
async def test_bundle_carries_it_and_the_etag_shifts(db_session: AsyncSession) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(
        group_id=group.id,
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="bind9",
        host=f"h-{uuid.uuid4().hex[:6]}",
        port=53,
        is_primary=True,
        agent_id=uuid.uuid4(),
    )
    db_session.add(server)
    await db_session.flush()

    before = await build_config_bundle(db_session, server)
    # Unset: absent, so a group that never chose one keeps its etag.
    assert "max_cache_size" not in before["options"]

    group.max_cache_size = "64m"
    await db_session.flush()
    after = await build_config_bundle(db_session, server)
    assert after["options"]["max_cache_size"] == "64m"
    assert after["etag"] != before["etag"]
