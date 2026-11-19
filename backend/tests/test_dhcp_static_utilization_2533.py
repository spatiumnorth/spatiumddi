"""A DHCP static's IPAM mirror moves the subnet + block counts at once (#2533)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _counts(db: AsyncSession, subnet_id: uuid.UUID, block_id: uuid.UUID) -> tuple[int, int]:
    sub = await db.scalar(select(Subnet.allocated_ips).where(Subnet.id == subnet_id))
    blk = await db.scalar(select(IPBlock.allocated_ips).where(IPBlock.id == block_id))
    return int(sub or 0), int(blk or 0)


@pytest.mark.asyncio
async def test_static_create_update_delete_recount(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, space, group])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.50.0.0/24", name="lan")
    db_session.add(subnet)
    db_session.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    await db_session.refresh(user, ["groups"])
    scope_id, subnet_id, block_id = scope.id, subnet.id, block.id
    token = create_access_token(str(user.id))
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    assert await _counts(db_session, subnet_id, block_id) == (0, 0)
    # From here the block also counts the /24's network + broadcast (#2982).

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": "10.50.0.11", "mac_address": "aa:bb:cc:dd:ee:01"},
    )
    assert resp.status_code == 201, resp.text
    static_id = resp.json()["id"]
    assert await _counts(db_session, subnet_id, block_id) == (1, 3)

    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": "10.50.0.12", "mac_address": "aa:bb:cc:dd:ee:02"},
    )
    assert resp.status_code == 201, resp.text
    assert await _counts(db_session, subnet_id, block_id) == (2, 4)

    # Re-addressing frees the old row and takes the new one: still two.
    resp = await client.put(
        f"/api/v1/dhcp/statics/{static_id}",
        headers=headers,
        json={"ip_address": "10.50.0.13"},
    )
    assert resp.status_code == 200, resp.text
    assert await _counts(db_session, subnet_id, block_id) == (2, 4)

    resp = await client.delete(f"/api/v1/dhcp/statics/{static_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _counts(db_session, subnet_id, block_id) == (1, 3)
