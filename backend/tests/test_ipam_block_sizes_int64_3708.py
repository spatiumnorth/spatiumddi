"""Free-space, plan-allocation and aggregation sizes stay int64-safe (#3708).

#3322 saturated the other IPv6 address counts at 2^63 - 1 with the true figure
in a sibling ``*_exact`` string. The block's free-space ranges, Plan
allocation's subnets and free ranges, and the aggregation suggestions'
``total_size`` still sent a /64's 2^64 as a bare integer, which a generated
64-bit client fails to decode.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _headers

CAP = 2**63 - 1


async def _v6(db: AsyncSession, subnets: tuple[str, ...] = ()):
    space = IPSpace(name=f"sp3708-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="fd37:8::/48", name="b")
    db.add(block)
    await db.flush()
    for n in subnets:
        db.add(Subnet(space_id=space.id, block_id=block.id, network=n, name="s", total_ips=CAP))
    await db.commit()
    return block


async def test_free_space_sizes_saturate_with_an_exact_string(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    block = await _v6(db_session, ("fd37:8:0:1::/64",))
    r = await client.get(f"/api/v1/ipam/blocks/{block.id}/free-space", headers=h)
    assert r.status_code == 200, r.text
    ranges = r.json()
    assert ranges
    for fr in ranges:
        assert fr["size"] <= CAP
        assert int(fr["size_exact"]) == 2 ** (128 - fr["prefix_len"])
    assert any(int(fr["size_exact"]) > CAP for fr in ranges)


async def test_plan_allocation_sizes_saturate_with_an_exact_string(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    block = await _v6(db_session)
    r = await client.post(
        f"/api/v1/ipam/blocks/{block.id}/plan-allocation",
        headers=h,
        json={"items": [{"count": 2, "prefix_len": 56}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["allocations"]) == 2
    for a in body["allocations"]:
        assert a["size"] == CAP
        assert a["size_exact"] == str(2**72)
    assert body["remaining_free"]
    for fr in body["remaining_free"]:
        assert fr["size"] <= CAP
        assert int(fr["size_exact"]) == 2 ** (128 - fr["prefix_len"])


async def test_aggregation_total_size_saturates_with_an_exact_string(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    block = await _v6(db_session, ("fd37:8:0:0::/64", "fd37:8:0:1::/64"))
    r = await client.get(f"/api/v1/ipam/blocks/{block.id}/aggregation-suggestions", headers=h)
    assert r.status_code == 200, r.text
    (sug,) = r.json()
    assert sug["total_size"] == CAP
    assert sug["total_size_exact"] == str(2**65)


async def test_ipv4_sizes_are_unchanged(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space = IPSpace(name=f"sp3708-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.37.8.0/24", name="b")
    db_session.add(block)
    await db_session.flush()
    db_session.add(
        Subnet(
            space_id=space.id, block_id=block.id, network="10.37.8.0/25", name="s", total_ips=126
        )
    )
    await db_session.commit()
    r = await client.get(f"/api/v1/ipam/blocks/{block.id}/free-space", headers=h)
    (fr,) = r.json()
    assert fr["size"] == 128 and fr["size_exact"] == "128"


def test_openapi_keeps_the_sizes_typed():
    from app.main import app

    schemas = app.openapi()["components"]["schemas"]
    for model, field in (
        ("FreeCidrRange", "size"),
        ("PlannedSubnet", "size"),
        ("AggregationSuggestion", "total_size"),
    ):
        props = schemas[model]["properties"]
        assert props[field]["type"] == "integer", (model, field)
        assert props[f"{field}_exact"]["type"] == "string", (model, field)


async def test_aggregation_sorts_on_the_exact_size(client: AsyncClient, db_session: AsyncSession):
    """Both supernets saturate ``total_size``; the larger must still come first."""
    h = await _headers(db_session)
    block = await _v6(
        db_session,
        (
            "fd37:8:0:4::/64",
            "fd37:8:0:5::/64",
            "fd37:8:0:8::/63",
            "fd37:8:0:a::/63",
        ),
    )
    r = await client.get(f"/api/v1/ipam/blocks/{block.id}/aggregation-suggestions", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [s["supernet"] for s in body] == ["fd37:8:0:8::/62", "fd37:8:0:4::/63"]
    assert [s["total_size"] for s in body] == [CAP, CAP]
    assert [s["total_size_exact"] for s in body] == [str(2**66), str(2**65)]
