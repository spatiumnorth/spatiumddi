"""Capped free-space walks say so, or stop being capped (#3848, #3849)."""

from __future__ import annotations

import ipaddress
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space_block(db: AsyncSession, network: str) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp3848-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name="b")
    db.add(block)
    await db.flush()
    return space, block


async def test_free_space_marks_a_capped_answer_with_the_rest(
    client: AsyncClient, db_session: AsyncSession
):
    """/48 with 25 /64s, one at the start of each of 25 /56s -> 206 free ranges."""
    h = await _headers(db_session)
    space, block = await _space_block(db_session, "fd5e:1110:a::/48")
    for i in range(1, 26):
        db_session.add(
            Subnet(
                space_id=space.id,
                block_id=block.id,
                network=f"fd5e:1110:a:{i * 0x100:x}::/64",
                name="s",
            )
        )
    await db_session.commit()

    r = await client.get(f"/api/v1/ipam/blocks/{block.id}/free-space", headers=h)
    assert r.status_code == 200, r.text
    ranges = r.json()
    assert len(ranges) == 200
    assert ranges[-1]["network"] == "fd5e:1110:a:1940::/58"
    # The cut is declared on the last range: 206 - 200 left out.
    assert ranges[-1]["more_after"] == 6
    assert all(x["more_after"] == 0 for x in ranges[:-1])

    # A caller can ask for the whole answer; then nothing is claimed omitted.
    r = await client.get(f"/api/v1/ipam/blocks/{block.id}/free-space?limit=1000", headers=h)
    full = r.json()
    assert len(full) == 206
    assert full[-1]["network"] == "fd5e:1110:a:8000::/49"
    assert all(x["more_after"] == 0 for x in full)


async def test_available_subnets_finds_a_64_past_a_child_52(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space, block = await _space_block(db_session, "fd5e:1110:b::/48")
    db_session.add(
        IPBlock(
            space_id=space.id,
            parent_block_id=block.id,
            network="fd5e:1110:b::/52",
            name="child",
        )
    )
    await db_session.commit()

    r = await client.get(
        f"/api/v1/ipam/blocks/{block.id}/available-subnets?prefix_len=64", headers=h
    )
    assert r.status_code == 200, r.text
    got = r.json()
    assert len(got) == 20
    assert got[0] == "fd5e:1110:b:1000::/64"
    child = ipaddress.ip_network("fd5e:1110:b::/52")
    assert not any(ipaddress.ip_network(n).overlaps(child) for n in got)


async def test_available_subnets_is_bounded_on_a_huge_block(
    client: AsyncClient, db_session: AsyncSession
):
    """A /8 at /128 would be 2^120 candidates; the free-range walk is instant."""
    h = await _headers(db_session)
    space, block = await _space_block(db_session, "fd00::/8")
    db_session.add(Subnet(space_id=space.id, block_id=block.id, network="fd00::/64", name="s"))
    await db_session.commit()
    r = await client.get(
        f"/api/v1/ipam/blocks/{block.id}/available-subnets?prefix_len=128&limit=5", headers=h
    )
    assert r.status_code == 200, r.text
    assert len(r.json()) == 5
    assert r.json()[0] == "fd00:0:0:1::/128"
