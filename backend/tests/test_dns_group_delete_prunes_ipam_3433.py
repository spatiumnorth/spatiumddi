"""Deleting a DNS server group clears its id from IPAM assignments (#3433)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet


async def test_group_delete_prunes_ipam_refs(client: AsyncClient, db_session: AsyncSession) -> None:
    db = db_session
    user = User(
        username=f"p-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="p",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    gone, keep = DNSServerGroup(name="gone3433"), DNSServerGroup(name="keep3433")
    db.add_all([gone, keep])
    await db.flush()
    g, k = str(gone.id), str(keep.id)
    space = IPSpace(name="s3433", description="", dns_group_ids=[g, k])
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.93.0.0/16", name="b", dns_group_ids=[g])
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.93.1.0/24", name="n", dns_group_ids=[g]
    )
    db.add(subnet)
    await db.flush()
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    r = await client.delete(f"/api/v1/dns/groups/{gone.id}", headers=headers)
    assert r.status_code == 204

    rows = (
        await db.execute(
            text(
                "SELECT (SELECT dns_group_ids FROM ip_space WHERE id=:s),"
                " (SELECT dns_group_ids FROM ip_block WHERE id=:b),"
                " (SELECT dns_group_ids FROM subnet WHERE id=:n)"
            ),
            {"s": space.id, "b": block.id, "n": subnet.id},
        )
    ).one()
    assert rows[0] == [k]
    assert rows[1] == []
    assert rows[2] == []
