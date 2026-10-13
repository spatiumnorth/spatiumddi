"""#1689 — Kea has no per-pool lifetime, so a pool ``lease_time_override`` is
refused (422) instead of being stored, echoed and never rendered."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DHCPScope]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([user, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.71.0.0/24", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.71.0.0/24", name="s")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, group])
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope", lease_time=86400)
    db.add(scope)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, scope


@pytest.mark.asyncio
async def test_pool_create_refuses_lease_time_override(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, scope = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/pools",
        json={"start_ip": "10.71.0.10", "end_ip": "10.71.0.20", "lease_time_override": 600},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert "lease_time_override" in r.text and "Kea" in r.text
    # Without it (or with explicit null) the pool is created as before.
    r = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/pools",
        json={"start_ip": "10.71.0.10", "end_ip": "10.71.0.20", "lease_time_override": None},
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text
    assert r.json()["lease_time_override"] is None


@pytest.mark.asyncio
async def test_pool_update_refuses_value_but_allows_clearing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, scope = await _setup(db_session)
    pool = DHCPPool(
        scope_id=scope.id,
        name="old",
        start_ip="10.71.0.30",
        end_ip="10.71.0.40",
        pool_type="dynamic",
        lease_time_override=600,  # a row stored before the refusal
    )
    db_session.add(pool)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/pools/{pool.id}", json={"lease_time_override": 300}, headers=headers
    )
    assert r.status_code == 422, r.text
    r = await client.put(f"/api/v1/dhcp/pools/{pool.id}", json={"name": "renamed"}, headers=headers)
    assert r.status_code == 200, r.text
    r = await client.put(
        f"/api/v1/dhcp/pools/{pool.id}", json={"lease_time_override": None}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["lease_time_override"] is None
