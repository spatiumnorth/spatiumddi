"""#3354 — a block delete recounts the subnets it just trashed.

The recount runs after the soft-delete stamp, and the global soft-delete
filter hides the stamped rows, so the trashed subnets (and the trashed block)
kept the counts they held before their scopes' mirrors were freed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ai.operations_risky import DeleteBlockArgs, _apply_delete_block
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from app.services.ipam.utilization import counts_toward_utilization, recount_subnets_and_blocks


async def _subnet_with_reservations(
    db: AsyncSession, grp: DHCPServerGroup, space: IPSpace, block: IPBlock, octet: int
) -> Subnet:
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=f"10.{octet}.0.0/24",
        name=f"sn{octet}",
        total_ips=254,
    )
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    for i in range(3):
        st = DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=f"10.{octet}.0.{10 + i}",
            mac_address=f"aa:bb:cc:00:{octet:02x}:{i:02x}",
            hostname=f"h{octet}-{i}",
            description="",
        )
        db.add(st)
        await db.flush()
        await upsert_ipam_for_static(db, scope, st)
    return subnet


@pytest.mark.asyncio
async def test_block_delete_recounts_trashed_subnets_and_block(db_session: AsyncSession) -> None:
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
    parent = IPBlock(space_id=space.id, network="10.0.0.0/8", name="parent")
    db.add(parent)
    await db.flush()
    block = IPBlock(space_id=space.id, parent_block_id=parent.id, network="10.0.0.0/9", name="b")
    db.add(block)
    await db.flush()
    s1 = await _subnet_with_reservations(db, grp, space, block, 31)
    s2 = await _subnet_with_reservations(db, grp, space, block, 32)
    await recount_subnets_and_blocks(db, [s1.id, s2.id])
    await db.commit()
    for s in (s1, s2):
        await db.refresh(s)
        assert s.allocated_ips == 3
    await db.refresh(block)
    assert block.allocated_ips > 0

    # What the stored static mirrors count as: freed by the delete.
    await _apply_delete_block(db, user, DeleteBlockArgs(block_id=block.id))

    # Read the trashed rows past the soft-delete filter.
    opts = {"include_deleted": True}
    for sid in (s1.id, s2.id):
        sub = (
            await db.execute(select(Subnet).where(Subnet.id == sid).execution_options(**opts))
        ).scalar_one()
        rows = await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == sid)
            .where(counts_toward_utilization())
        )
        assert sub.deleted_at is not None
        assert sub.allocated_ips == rows, (sub.allocated_ips, rows)
        assert sub.allocated_ips < 3
    trashed = (
        await db.execute(select(IPBlock).where(IPBlock.id == block.id).execution_options(**opts))
    ).scalar_one()
    expected = 0
    for sid in (s1.id, s2.id):
        sub = (
            await db.execute(select(Subnet).where(Subnet.id == sid).execution_options(**opts))
        ).scalar_one()
        expected += sub.allocated_ips + 2  # + network and broadcast (#2982)
    assert trashed.allocated_ips == expected, (trashed.allocated_ips, expected)
    live_parent = await db.get(IPBlock, parent.id)
    await db.refresh(live_parent)
    assert live_parent.allocated_ips == 0
