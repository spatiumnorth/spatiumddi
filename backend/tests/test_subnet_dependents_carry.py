"""Split / merge carry address sets, the OT zone and links (#3957)."""

from __future__ import annotations

import uuid
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address_set import AddressSet
from app.models.ipam import IPBlock, IPSpace, NATMapping, Subnet
from app.models.ot import OTZone
from app.services.ipam.subnet_merge import commit_subnet_merge, preview_subnet_merge
from app.services.ipam.subnet_split import commit_subnet_split, preview_subnet_split


async def _subnets(db: AsyncSession, *cidrs: str) -> list[Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    out = [
        Subnet(space_id=space.id, block_id=block.id, network=c, name="s", total_ips=100)
        for c in cidrs
    ]
    db.add_all(out)
    await db.flush()
    return out


def _set(subnet: Subnet, name: str, start: str, end: str) -> AddressSet:
    return AddressSet(
        subnet_id=subnet.id,
        name=name,
        range_kind="contiguous",
        start_address=start,
        end_address=end,
    )


@pytest.mark.asyncio
async def test_split_carries_sets_zone_links(db_session: AsyncSession) -> None:
    (p,) = await _subnets(db_session, "10.0.0.0/24")
    whole = _set(p, "low", "10.0.0.10", "10.0.0.20")
    straddle = _set(p, "wide", "10.0.0.100", "10.0.0.150")
    db_session.add_all(
        [whole, straddle, OTZone(subnet_id=p.id, purdue_level=Decimal("2"), name="z")]
    )
    nat = NATMapping(kind="static_1to1", name="n", internal_subnet_id=p.id)
    db_session.add(nat)
    await db_session.flush()
    whole_id, straddle_id, nat_id = whole.id, straddle.id, nat.id

    preview = await preview_subnet_split(db_session, p, 25)
    text = " ".join(preview.warnings)
    assert "address set" in text and "OT zone" in text and "NAT mapping" in text

    res = await commit_subnet_split(db_session, p, 25, confirm_cidr="10.0.0.0/24")
    c0, c1 = (c.id for c in res.children)
    db_session.expire_all()
    sets = (await db_session.execute(select(AddressSet))).scalars().all()
    by = {(s.name, s.subnet_id): s for s in sets}
    assert by[("low", c0)].id == whole_id
    wide0, wide1 = by[("wide", c0)], by[("wide", c1)]
    assert wide0.id == straddle_id
    assert (str(wide0.end_address), str(wide1.start_address)) == ("10.0.0.127", "10.0.0.128")
    zones = (await db_session.execute(select(OTZone))).scalars().all()
    assert {z.subnet_id for z in zones} == {c0, c1}
    assert (await db_session.get(NATMapping, nat_id)).internal_subnet_id == c0


@pytest.mark.asyncio
async def test_merge_carries_sets_zone_links(db_session: AsyncSession) -> None:
    a, b = await _subnets(db_session, "10.0.0.0/25", "10.0.0.128/25")
    s1 = _set(a, "one", "10.0.0.10", "10.0.0.20")
    db_session.add_all([s1, OTZone(subnet_id=b.id, purdue_level=Decimal("3"), name="z")])
    nat = NATMapping(kind="static_1to1", name="n", internal_subnet_id=b.id)
    db_session.add(nat)
    await db_session.flush()
    s1_id, nat_id = s1.id, nat.id

    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert preview.conflicts == []
    text = " ".join(preview.warnings)
    assert "address set" in text and "OT zone" in text and "NAT mapping" in text

    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    mid = res.merged_subnet.id
    db_session.expire_all()
    assert (await db_session.get(AddressSet, s1_id)).subnet_id == mid
    zones = (await db_session.execute(select(OTZone))).scalars().all()
    assert [z.subnet_id for z in zones] == [mid]
    assert (await db_session.get(NATMapping, nat_id)).internal_subnet_id == mid


@pytest.mark.asyncio
async def test_merge_conflicts_on_name_and_level(db_session: AsyncSession) -> None:
    a, b = await _subnets(db_session, "10.0.0.0/25", "10.0.0.128/25")
    db_session.add_all(
        [
            _set(a, "dup", "10.0.0.10", "10.0.0.20"),
            _set(b, "dup", "10.0.0.130", "10.0.0.140"),
            OTZone(subnet_id=a.id, purdue_level=Decimal("2")),
            OTZone(subnet_id=b.id, purdue_level=Decimal("3")),
        ]
    )
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, a, [b.id])
    types = {c.type for c in preview.conflicts}
    assert {"address_set_name_conflict", "ot_zone_level_conflict"} <= types
