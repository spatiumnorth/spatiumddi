"""#3354 — freeing static_dhcp mirrors recounts subnet and block utilization."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import (
    remove_ipam_for_scope_statics,
    sweep_orphaned_static_mirrors,
    upsert_ipam_for_static,
)
from app.services.ipam.utilization import recount_subnets_and_blocks

_BLOCK_BASE: dict[uuid.UUID, int] = {}


async def _setup(db: AsyncSession) -> tuple[DHCPScope, Subnet, IPBlock, DHCPStaticAssignment]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([grp, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.31.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.31.0.0/24", name="sn", total_ips=254
    )
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    st = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address="10.31.0.10",
        mac_address="aa:bb:cc:00:03:01",
        hostname="printer",
        description="",
    )
    db.add(st)
    await db.flush()
    await upsert_ipam_for_static(db, scope, st)
    await recount_subnets_and_blocks(db, [subnet.id])
    await db.refresh(subnet)
    await db.refresh(block)
    assert subnet.allocated_ips == 1
    _BLOCK_BASE[block.id] = block.allocated_ips - 1  # the block's own non-mirror share
    return scope, subnet, block, st


async def _counts(db: AsyncSession, subnet: Subnet, block: IPBlock) -> tuple[int, int]:
    """(subnet allocated, block allocated minus what the block held with the
    reservation in place) — 0, 0 once the mirror's contribution is gone."""
    await db.refresh(subnet)
    await db.refresh(block)
    return subnet.allocated_ips, block.allocated_ips - _BLOCK_BASE[block.id]


@pytest.mark.asyncio
async def test_orphan_sweep_recounts_subnet_and_block(db_session: AsyncSession) -> None:
    _scope, subnet, block, st = await _setup(db_session)
    await db_session.execute(
        DHCPStaticAssignment.__table__.delete().where(DHCPStaticAssignment.id == st.id)
    )
    await db_session.flush()

    assert await sweep_orphaned_static_mirrors(db_session) == 1
    await db_session.commit()

    assert await _counts(db_session, subnet, block) == (0, 0)


@pytest.mark.asyncio
async def test_scope_statics_removal_recounts(db_session: AsyncSession) -> None:
    scope, subnet, block, _st = await _setup(db_session)

    assert await remove_ipam_for_scope_statics(db_session, scope.id) == 1
    await db_session.commit()

    assert await _counts(db_session, subnet, block) == (0, 0)


@pytest.mark.asyncio
async def test_trash_purge_release_recounts(db_session: AsyncSession) -> None:
    from app.tasks.trash_purge import _release_ipam_mirrors

    _scope, subnet, block, st = await _setup(db_session)
    st.deleted_at = datetime.now(UTC) - timedelta(days=400)
    await db_session.flush()

    assert await _release_ipam_mirrors(db_session, datetime.now(UTC) - timedelta(days=30)) == 1
    await db_session.commit()

    assert await _counts(db_session, subnet, block) == (0, 0)
