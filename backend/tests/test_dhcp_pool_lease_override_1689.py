"""#1689 — Kea has no per-pool lifetime, so a pool ``lease_time_override`` is
refused (422) instead of being stored, echoed and never rendered."""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pydantic
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents
from app.api.v1.dhcp.pools import PoolCreate
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


def test_every_accepted_pool_field_reaches_the_agent_or_is_refused() -> None:
    """The guard #1689 asked for: this is the third pool field (after #430 and
    #858) that the API accepted and the agent pool dict never carried. Every
    field ``PoolCreate`` accepts must be a key of that dict, be refused, or be
    listed here with the reason it is not rendered."""
    tree = ast.parse(Path(agents.__file__).read_text())
    pool_dicts = [
        {k.value for k in node.keys if isinstance(k, ast.Constant)}
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        and any(isinstance(k, ast.Constant) and k.value == "pd_prefix" for k in node.keys)
    ]
    assert len(pool_dicts) == 1, "expected exactly one agent pool dict in agents.py"
    sent = pool_dicts[0]

    refused = {"lease_time_override"}  # 422 on a non-null value (#1689)
    not_rendered = {"name"}  # a label for the UI; Kea pools have no name
    missing = set(PoolCreate.model_fields) - sent - refused - not_rendered
    assert not missing, f"pool fields accepted but never sent to the agent: {sorted(missing)}"
    assert not (refused & sent), "a refused field is also sent; drop it from one list"
    # ...and "refused" has to be true, not just a name on a list.
    for field in refused:
        with pytest.raises(pydantic.ValidationError):
            PoolCreate(start_ip="10.0.0.1", end_ip="10.0.0.9", **{field: 600})
