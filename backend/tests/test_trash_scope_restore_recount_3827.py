"""#3827: a scope restored from the Trash gives its subnet and block back the
reservations it re-mirrors into IPAM."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from app.services.ipam.utilization import recount_subnets_and_blocks


@pytest.mark.asyncio
async def test_scope_restore_recounts_its_subnet_and_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([user, grp, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.20.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    for i in range(2):
        st = DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=f"10.20.1.{50 + i}",
            mac_address=f"aa:bb:cc:00:00:{i:02x}",
            hostname=f"h{i}",
            description="",
        )
        db.add(st)
        await db.flush()
        await upsert_ipam_for_static(db, scope, st)
    await recount_subnets_and_blocks(db, [subnet.id])
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    sid, bid, scid = subnet.id, block.id, scope.id
    await db.commit()

    async def _counts() -> tuple[int, int]:
        db.expunge_all()
        sub = await db.get(Subnet, sid)
        blk = await db.get(IPBlock, bid)
        assert sub is not None and blk is not None
        return sub.allocated_ips, blk.allocated_ips

    before = await _counts()
    assert before[0] >= 2
    gone = await client.delete(f"/api/v1/dhcp/scopes/{scid}", headers=headers)
    assert gone.status_code == 204, gone.text
    after_delete = await _counts()
    assert after_delete[0] == before[0] - 2

    back = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scid}/restore", headers=headers)
    assert back.status_code == 200, back.text
    assert await _counts() == before
