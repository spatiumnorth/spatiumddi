"""One network / broadcast rule for Split, Merge and Resize (#2976, #2977, #2978)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.resize import (
    ResizeError,
    commit_subnet_resize,
    preview_block_resize,
    preview_subnet_resize,
)
from app.services.ipam.subnet_merge import MergeError, commit_subnet_merge, preview_subnet_merge
from app.services.ipam.subnet_split import SplitError, commit_subnet_split, preview_subnet_split


async def _space_block(db: AsyncSession, block_cidr: str) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=block_cidr, name="b")
    db.add(block)
    await db.flush()
    return space, block


async def _subnet(db, space, block, cidr, **kw) -> Subnet:
    s = Subnet(space_id=space.id, block_id=block.id, network=cidr, name="s", total_ips=2, **kw)
    db.add(s)
    await db.flush()
    return s


def _row(subnet, addr, status="allocated", desc="", host=None):
    return IPAddress(
        subnet_id=subnet.id, address=addr, status=status, description=desc, hostname=host
    )


async def _rows(db, subnet_id) -> dict[str, str]:
    res = await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet_id))
    return {str(r.address): r.status for r in res.scalars().all()}


@pytest.mark.asyncio
async def test_merge_of_two_full_31s_is_refused_naming_the_hosts(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    a = await _subnet(db_session, space, block, "10.233.3.8/31")
    b = await _subnet(db_session, space, block, "10.233.3.10/31")
    for addr in ("10.233.3.8", "10.233.3.9"):
        db_session.add(_row(a, addr))
    for addr in ("10.233.3.10", "10.233.3.11"):
        db_session.add(_row(b, addr))
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    details = [c.detail for c in preview.conflicts if c.type == "host_on_merged_boundary"]
    assert any("10.233.3.8" in d and "network" in d for d in details)
    assert any("10.233.3.11" in d and "broadcast" in d for d in details)
    with pytest.raises(MergeError) as exc:
        await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.233.3.8/30")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_merge_of_31s_without_hosts_on_boundary_gets_rows(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    a = await _subnet(db_session, space, block, "10.233.3.8/31")
    b = await _subnet(db_session, space, block, "10.233.3.10/31")
    db_session.add(_row(a, "10.233.3.9"))
    db_session.add(_row(b, "10.233.3.10", status="network"))  # operator placeholder, not a host
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert not [c for c in preview.conflicts if c.type == "host_on_merged_boundary"]


@pytest.mark.asyncio
async def test_ipv6_split_keeps_network_rows_and_refuses_boundary_host(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    parent = await _subnet(db_session, space, block, "fd33:233:0:101::/64")
    db_session.add(_row(parent, "fd33:233:0:101::", status="network", desc="Network address"))
    await db_session.flush()
    result = await commit_subnet_split(db_session, parent, 65, confirm_cidr="fd33:233:0:101::/64")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert len(kids) == 2
    for k in kids:
        rows = await _rows(db_session, k.id)
        assert rows.get(str(k.network).split("/")[0]) == "network", (k.network, rows)
    assert result is not None


@pytest.mark.asyncio
async def test_ipv6_split_host_on_child_network_is_refused(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    parent = await _subnet(db_session, space, block, "fd33:233:0:102::/64")
    db_session.add(_row(parent, "fd33:233:0:102:8000::"))
    await db_session.flush()
    preview = await preview_subnet_split(db_session, parent, 65)
    details = [c.detail for c in preview.conflicts if c.type == "host_on_child_boundary"]
    assert len(details) == 1 and "fd33:233:0:102:8000::" in details[0]
    with pytest.raises(SplitError) as exc:
        await commit_subnet_split(db_session, parent, 65, confirm_cidr="fd33:233:0:102::/64")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_ipv6_merge_keeps_network_row(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    a = await _subnet(db_session, space, block, "fd33:233:0:103::/65")
    b = await _subnet(db_session, space, block, "fd33:233:0:103:8000::/65")
    db_session.add(_row(a, "fd33:233:0:103::", status="network", desc="Network address"))
    db_session.add(_row(b, "fd33:233:0:103:8000::", status="network", desc="Network address"))
    await db_session.flush()
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="fd33:233:0:103::/64")
    rows = await _rows(db_session, res.merged_subnet.id)
    assert rows == {"fd33:233:0:103::": "network"}


@pytest.mark.asyncio
async def test_resize_31_to_30_with_hosts_on_new_boundary_is_refused(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    s = await _subnet(db_session, space, block, "10.233.3.8/31")
    # grow target is 10.233.3.8/30: hosts at .8 (network) -> conflict
    db_session.add(_row(s, "10.233.3.8"))
    await db_session.flush()
    preview = await preview_subnet_resize(db_session, s, "10.233.3.8/30")
    assert any(
        c.type == "host_on_new_boundary" and "10.233.3.8" in c.detail for c in preview.conflicts
    )
    with pytest.raises(ResizeError) as exc:
        await commit_subnet_resize(db_session, s, "10.233.3.8/30")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_resize_ipv6_grow_creates_network_row(db_session):
    space, block = await _space_block(db_session, "fd33:233::/32")
    s = await _subnet(db_session, space, block, "fd33:233:0:5::/65")
    await commit_subnet_resize(db_session, s, "fd33:233:0:5::/64")
    assert (await _rows(db_session, s.id)).get("fd33:233:0:5::") == "network"


@pytest.mark.asyncio
async def test_block_resize_refusal_speaks_of_the_block(db_session):
    space, block = await _space_block(db_session, "10.233.16.0/22")
    preview = await preview_block_resize(db_session, block, "10.233.16.0/23")
    text = " ".join(c.detail for c in preview.conflicts)
    assert "reduce a block" in text and "reduce a subnet" not in text


@pytest.mark.asyncio
async def test_subnet_resize_refusal_still_speaks_of_the_subnet(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    s = await _subnet(db_session, space, block, "10.233.4.0/24")
    preview = await preview_subnet_resize(db_session, s, "10.233.4.0/25")
    assert "reduce a subnet" in " ".join(c.detail for c in preview.conflicts)


@pytest.mark.asyncio
async def test_split_children_keep_skip_reverse_zone(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    parent = await _subnet(db_session, space, block, "10.233.4.0/24", skip_reverse_zone=True)
    await commit_subnet_split(db_session, parent, 25, confirm_cidr="10.233.4.0/24")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert len(kids) == 2 and all(k.skip_reverse_zone for k in kids)


@pytest.mark.asyncio
async def test_split_of_default_subnet_keeps_false(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    parent = await _subnet(db_session, space, block, "10.233.4.0/24")
    await commit_subnet_split(db_session, parent, 25, confirm_cidr="10.233.4.0/24")
    kids = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert not any(k.skip_reverse_zone for k in kids)


@pytest.mark.asyncio
async def test_merge_keeps_skip_reverse_zone_and_warns_on_disagreement(db_session):
    space, block = await _space_block(db_session, "10.233.0.0/16")
    a = await _subnet(db_session, space, block, "10.233.6.0/25", skip_reverse_zone=True)
    b = await _subnet(db_session, space, block, "10.233.6.128/25", skip_reverse_zone=True)
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.233.6.0/24")
    assert res.merged_subnet.skip_reverse_zone is True

    c = await _subnet(db_session, space, block, "10.233.7.0/25", skip_reverse_zone=True)
    d = await _subnet(db_session, space, block, "10.233.7.128/25")
    preview = await preview_subnet_merge(db_session, c, [d.id])
    assert any("skip_reverse_zone" in w for w in preview.warnings)
