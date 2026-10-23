"""A new subnet is in its block's allocated count at once (#2532)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "block_net,subnet_net", [("10.0.0.0/8", "10.1.1.0/29"), ("2001:db8::/32", "2001:db8:1::/64")]
)
async def test_block_counts_new_subnet_own_rows(
    client: AsyncClient, db_session: AsyncSession, block_net: str, subnet_net: str
) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db_session.add_all([user, space])
    await db_session.flush()
    await db_session.refresh(user, ["groups"])
    block = IPBlock(space_id=space.id, network=block_net, name="b")
    db_session.add(block)
    await db_session.flush()
    space_id, block_id = str(space.id), str(block.id)
    token = create_access_token(str(user.id))
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": subnet_net,
            "name": "s",
        },
    )
    assert resp.status_code == 201, resp.text
    sub_allocated = resp.json()["allocated_ips"]
    assert sub_allocated > 0
    block_allocated = await db_session.scalar(
        select(IPBlock.allocated_ips).where(IPBlock.id == uuid.UUID(block_id))
    )
    assert block_allocated == sub_allocated
