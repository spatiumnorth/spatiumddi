"""A block's utilisation is the share of its whole CIDR in use (#2982).

Maintainer decision (2026-10-28) on the question #2982 asked: a subnet's
network and broadcast addresses count as used in its block's allocated
figure, so a block fully carved into full subnets reads 100%. The block
total stays the full CIDR; the subnet's own count is unchanged (#2411).
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _update_block_utilization
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.tasks.ipam_utilization_recount import recount_utilization
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space_block(db: AsyncSession, net: str) -> tuple[str, str]:
    space = IPSpace(name=f"sp2982-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=net, name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    return str(space.id), str(block.id)


async def _subnet(client, h, space_id, block_id, cidr, **extra) -> dict:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": cidr,
            "skip_reverse_zone": True,
            **extra,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _get(client, h, kind, rid) -> dict:
    r = await client.get(f"/api/v1/ipam/{kind}/{rid}", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


async def _add(client, h, sid, addr, **extra):
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=h,
        json={"address": addr, "hostname": f"h{uuid.uuid4().hex[:6]}", **extra},
    )
    assert r.status_code == 201, r.text


async def _recount_matches(db: AsyncSession, client, h, bid: str) -> None:
    """The hourly recount reaches the same figures as the inline rollup."""
    before = await _get(client, h, "blocks", bid)
    await recount_utilization(db)
    await db.commit()
    after = await _get(client, h, "blocks", bid)
    assert (after["allocated_ips"], after["utilization_percent"]) == (
        before["allocated_ips"],
        before["utilization_percent"],
    )


async def test_full_slash30_in_slash30_block_reads_100(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    space_id, bid = await _space_block(db_session, "10.233.40.0/30")
    s = await _subnet(client, h, space_id, bid, "10.233.40.0/30")
    await _add(client, h, s["id"], "10.233.40.2")

    sub = await _get(client, h, "subnets", s["id"])
    assert (sub["allocated_ips"], sub["total_ips"], sub["utilization_percent"]) == (2, 2, 100.0)

    blk = await _get(client, h, "blocks", bid)
    assert (blk["allocated_ips"], blk["total_ips"], blk["utilization_percent"]) == (4, 4, 100.0)
    await _recount_matches(db_session, client, h, bid)


async def test_partial_block_counts_each_subnet_network_and_broadcast(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    space_id, bid = await _space_block(db_session, "10.234.0.0/24")
    # /29: gateway only -> subnet 1 / 6; block adds .0 + .7.
    s29 = await _subnet(client, h, space_id, bid, "10.234.0.0/29")
    # /31 and /32 have no network/broadcast: nothing added.
    s31 = await _subnet(client, h, space_id, bid, "10.234.0.8/31")
    await _add(client, h, s31["id"], "10.234.0.8")
    s32 = await _subnet(client, h, space_id, bid, "10.234.0.10/32")
    await _add(client, h, s32["id"], "10.234.0.10")

    assert (await _get(client, h, "subnets", s29["id"]))["allocated_ips"] == 1
    blk = await _get(client, h, "blocks", bid)
    assert blk["allocated_ips"] == (1 + 2) + 1 + 1
    await _recount_matches(db_session, client, h, bid)


async def test_ipv6_network_row_is_counted_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    space_id, bid = await _space_block(db_session, "fd29:82::/120")
    # /124 with placeholders: the v6 network row already counts toward the
    # subnet (its total keeps the whole range), so the block adds nothing.
    a = await _subnet(client, h, space_id, bid, "fd29:82::/124")
    sub_a = await _get(client, h, "subnets", a["id"])
    assert sub_a["allocated_ips"] == 2  # network row + gateway
    # /124 without placeholders: the network address is still not
    # usable host space, so the block counts it.
    b = await _subnet(client, h, space_id, bid, "fd29:82::10/124", skip_auto_addresses=True)
    assert (await _get(client, h, "subnets", b["id"]))["allocated_ips"] == 0
    # /127: nothing to add.
    await _subnet(client, h, space_id, bid, "fd29:82::20/127", skip_auto_addresses=True)

    blk = await _get(client, h, "blocks", bid)
    assert blk["allocated_ips"] == 2 + 1 + 0
    await _recount_matches(db_session, client, h, bid)


async def test_host_row_on_network_address_is_not_counted_twice(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A v4 subnet created without placeholders may hold an ordinary row
    on .0; the subnet counts it, and the block must not add .0 again."""
    h = await _headers(db_session)
    space_id, bid = await _space_block(db_session, "10.235.0.0/30")
    s = await _subnet(client, h, space_id, bid, "10.235.0.0/30", skip_auto_addresses=True)
    for addr in ("10.235.0.0", "10.235.0.1", "10.235.0.2", "10.235.0.3"):
        await _add(client, h, s["id"], addr)

    blk = await _get(client, h, "blocks", bid)
    assert blk["allocated_ips"] == 4
    assert blk["utilization_percent"] == 100.0
    await _recount_matches(db_session, client, h, bid)


async def test_block_never_reads_over_100_percent(db_session: AsyncSession) -> None:
    """A drifted-high subnet counter cannot push its block past its CIDR."""
    space = IPSpace(name=f"sp2982-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.236.0.0/30", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.236.0.0/30",
        name="s",
        total_ips=2,
        allocated_ips=50,  # drifted
    )
    db_session.add(subnet)
    await db_session.flush()
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.236.0.1", status="allocated"))
    await db_session.flush()

    await _update_block_utilization(db_session, block.id)
    assert (block.allocated_ips, block.utilization_percent) == (4, 100.0)
