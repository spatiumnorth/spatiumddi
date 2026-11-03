"""#3439: growing a subnet takes space from its parent block and needs ``write`` on it."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_target_block_write_3425 import _grant, _holder


async def _world(db: AsyncSession) -> tuple[IPBlock, IPBlock, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    parent = IPBlock(space_id=space.id, network="10.0.0.0/16", name="P")
    db.add(parent)
    await db.flush()
    child = IPBlock(space_id=space.id, network="10.0.4.0/24", name="C", parent_block_id=parent.id)
    sub = Subnet(space_id=space.id, block_id=parent.id, network="10.0.8.0/25", name="s")
    db.add_all([child, sub])
    await db.flush()
    return parent, child, sub


@pytest.mark.asyncio
async def test_subnet_grow_needs_write_on_parent_block(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    parent, _, sub = await _world(db_session)
    weak = await _holder(db_session, [_grant("write", "subnet")])
    ok = await _holder(
        db_session, [_grant("write", "subnet"), _grant("write", "ip_block", parent.id)]
    )
    unscoped = await _holder(db_session, [_grant("write", "subnet"), _grant("write", "ip_block")])
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()
    base = f"/api/v1/ipam/subnets/{sub.id}/resize"
    body = {"new_cidr": "10.0.8.0/24"}

    r = await client.post(f"{base}/preview", json=body, headers=weak)
    assert r.status_code == 200, r.text
    perm = [c for c in r.json()["conflicts"] if c["type"] == "permission"]
    assert perm and str(parent.id) in perm[0]["detail"]
    r = await client.post(base, json=body, headers=weak)
    assert r.status_code == 403, r.text
    assert str(parent.id) in r.json()["detail"]
    assert "10.0.0.0/16" not in r.json()["detail"]  # cannot read the block

    for h in (ok, unscoped, sa):
        r = await client.post(f"{base}/preview", json=body, headers=h)
        assert r.status_code == 200, r.text
        assert not [c for c in r.json()["conflicts"] if c["type"] == "permission"]
    r = await client.post(base, json=body, headers=ok)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_top_level_block_grow_unaffected(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    parent, _, _ = await _world(db_session)
    # Shrink-free grow of a top-level block: no parent block to check.
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/blocks/{parent.id}/resize/preview",
        json={"new_cidr": "10.0.0.0/15"},
        headers=sa,
    )
    assert r.status_code == 200, r.text
    assert not any(c["type"] == "permission" for c in r.json()["conflicts"])
