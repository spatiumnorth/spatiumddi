"""IPAM utilization recount sweep (issue #521).

The hourly ``recount_ipam_utilization`` task recomputes cached
``Subnet.allocated_ips`` / ``utilization_percent`` from the live row counts
and rolls the totals up the ``IPBlock`` tree, correcting drift left by the
estimate-a-delta code paths (the address importer, bulk reconcilers).
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.tasks.ipam_utilization_recount import recount_utilization


async def _seed(db: AsyncSession) -> tuple[Subnet, IPBlock, IPBlock]:
    """A /16 parent block → /24 child block → /24 subnet with 3 allocated +
    1 available address, and deliberately-wrong cached counters."""
    space = IPSpace(name=f"util-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()

    parent = IPBlock(space_id=space.id, network="10.50.0.0/16", name="parent")
    db.add(parent)
    await db.flush()
    child = IPBlock(
        space_id=space.id, network="10.50.0.0/24", name="child", parent_block_id=parent.id
    )
    db.add(child)
    await db.flush()

    subnet = Subnet(
        space_id=space.id,
        block_id=child.id,
        network="10.50.0.0/24",
        name="s",
        # Deliberately-wrong cache to prove the recount corrects it.
        total_ips=254,
        allocated_ips=999,
        utilization_percent=99.9,
    )
    db.add(subnet)
    await db.flush()

    for i, st in enumerate(("allocated", "allocated", "reserved", "available")):
        db.add(IPAddress(subnet_id=subnet.id, address=f"10.50.0.{10 + i}", status=st))
    await db.flush()
    return subnet, child, parent


async def test_recount_corrects_subnet_and_block_rollup(db_session: AsyncSession) -> None:
    subnet, child, parent = await _seed(db_session)

    result = await recount_utilization(db_session)

    assert result == {"subnets_corrected": 1, "blocks_corrected": 2}

    # 3 non-available addresses (2 allocated + 1 reserved); .13 is available.
    await db_session.refresh(subnet)
    assert subnet.allocated_ips == 3
    assert subnet.utilization_percent == round(3 / 254 * 100, 2)

    # Child /24 rollup: full-CIDR denominator (256), BIGINT-clamped total;
    # the subnet's network + broadcast count as used in the block (#2982).
    await db_session.refresh(child)
    assert child.allocated_ips == 5
    assert child.total_ips == 256
    assert child.utilization_percent == round(5 / 256 * 100, 2)

    # Parent /16 recursively includes the child's subnet allocation.
    await db_session.refresh(parent)
    assert parent.allocated_ips == 5
    assert parent.total_ips == 65536
    assert parent.utilization_percent == round(5 / 65536 * 100, 2)

    # A single audit row records the correction.
    audit = (await db_session.execute(AuditLog.__table__.select())).mappings().all()
    recount_rows = [a for a in audit if a["action"] == "ipam-utilization-recount"]
    assert len(recount_rows) == 1
    assert recount_rows[0]["new_value"]["subnets_corrected"] == 1
    assert recount_rows[0]["new_value"]["blocks_corrected"] == 2


async def test_recount_is_idempotent(db_session: AsyncSession) -> None:
    await _seed(db_session)

    first = await recount_utilization(db_session)
    assert first["subnets_corrected"] == 1

    # A converged install writes nothing on the second pass.
    second = await recount_utilization(db_session)
    assert second == {"subnets_corrected": 0, "blocks_corrected": 0}
