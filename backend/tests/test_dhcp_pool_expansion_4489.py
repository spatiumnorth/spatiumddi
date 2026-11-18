"""Pool expansion suggestions (#4489): free ranges to extend or add to a pool."""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import (
    DHCPPool,
    DHCPScope,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.pool_expansion import free_runs, usable_bounds


async def _user(db: AsyncSession, superadmin: bool = True) -> User:
    user = User(
        username=f"exp-{uuid.uuid4().hex[:6]}",
        email=f"exp-{uuid.uuid4().hex[:6]}@example.test",
        display_name="exp",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user


async def _scope(db: AsyncSession, cidr: str, gateway: str | None = None) -> DHCPScope:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=cidr, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=cidr, name="s", gateway=gateway)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, group])
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope")
    db.add(scope)
    await db.flush()
    return scope


async def _pool(db, scope, a, b, ptype="dynamic") -> DHCPPool:
    p = DHCPPool(scope_id=scope.id, name="p", start_ip=a, end_ip=b, pool_type=ptype)
    db.add(p)
    await db.flush()
    return p


async def _get(client, db, pool, **params):
    user = await _user(db)
    tok = create_access_token(str(user.id))
    return await client.get(
        f"/api/v1/dhcp/pools/{pool.id}/expansion-suggestions",
        params=params,
        headers={"Authorization": f"Bearer {tok}"},
    )


def test_free_runs_pure() -> None:
    assert free_runs(1, 10, [], []) == [(1, 10)]
    assert free_runs(1, 10, [5], [(7, 8)]) == [(1, 4), (6, 6), (9, 10)]
    assert free_runs(1, 10, [1, 10], []) == [(2, 9)]
    assert free_runs(1, 10, [], [(0, 20)]) == []
    assert usable_bounds(ipaddress.IPv4Network("10.0.0.0/24")) == (
        int(ipaddress.ip_address("10.0.0.1")),
        int(ipaddress.ip_address("10.0.0.254")),
    )


@pytest.mark.asyncio
async def test_adjacent_first_then_largest_and_exclusions(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    scope = await _scope(db_session, "10.70.0.0/24", gateway="10.70.0.1")
    pool = await _pool(db_session, scope, "10.70.0.50", "10.70.0.59")
    # Another pool further up.
    await _pool(db_session, scope, "10.70.0.100", "10.70.0.119", "excluded")
    # An IPAM-allocated address and a reservation inside the free space after the pool.
    db_session.add(IPAddress(subnet_id=scope.subnet_id, address="10.70.0.70", status="allocated"))
    db_session.add(
        DHCPStaticAssignment(
            scope_id=scope.id, ip_address="10.70.0.90", mac_address="aa:bb:cc:00:00:09"
        )
    )
    await db_session.flush()
    r = await _get(client, db_session, pool)
    assert r.status_code == 200
    sug = r.json()["suggestions"]
    # First: touching the pool, ending before the allocated .70.
    assert sug[0]["kind"] == "extends_after"
    assert (sug[0]["start_ip"], sug[0]["end_ip"], sug[0]["size"]) == (
        "10.70.0.60",
        "10.70.0.69",
        10,
    )
    assert (sug[0]["resulting_start"], sug[0]["resulting_end"]) == ("10.70.0.50", "10.70.0.69")
    # Then the before-run (gateway .1 excluded, so it starts at .2).
    assert sug[1]["kind"] == "extends_before"
    assert (sug[1]["start_ip"], sug[1]["end_ip"]) == ("10.70.0.2", "10.70.0.49")
    # Remaining runs largest first; none contain a blocked address.
    rest = sug[2:]
    assert [s["kind"] for s in rest] == ["separate"] * len(rest)
    assert rest[0]["start_ip"] == "10.70.0.120" and rest[0]["end_ip"] == "10.70.0.254"
    for s in sug:
        for blocked in ("10.70.0.1", "10.70.0.70", "10.70.0.90", "10.70.0.255", "10.70.0.0"):
            b = int(ipaddress.ip_address(blocked))
            assert not (
                int(ipaddress.ip_address(s["start_ip"]))
                <= b
                <= int(ipaddress.ip_address(s["end_ip"]))
            )
    sizes = [s["size"] for s in rest]
    assert sizes == sorted(sizes, reverse=True)


@pytest.mark.asyncio
async def test_pool_at_subnet_edge_has_no_extension_beyond(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    scope = await _scope(db_session, "10.71.0.0/24")
    pool = await _pool(db_session, scope, "10.71.0.200", "10.71.0.254")  # to the last host
    r = await _get(client, db_session, pool)
    kinds = [s["kind"] for s in r.json()["suggestions"]]
    assert kinds == ["extends_before"]
    s = r.json()["suggestions"][0]
    assert (s["start_ip"], s["end_ip"]) == ("10.71.0.1", "10.71.0.199")


@pytest.mark.asyncio
async def test_fully_packed_subnet_yields_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    scope = await _scope(db_session, "10.72.0.0/30")
    pool = await _pool(db_session, scope, "10.72.0.1", "10.72.0.2")
    r = await _get(client, db_session, pool)
    assert r.status_code == 200 and r.json()["suggestions"] == []


@pytest.mark.asyncio
async def test_fragmented_space_min_size_limit_and_seen(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from datetime import UTC, datetime

    scope = await _scope(db_session, "10.73.0.0/24")
    pool = await _pool(db_session, scope, "10.73.0.10", "10.73.0.19")
    for n in (30, 40, 50):  # leaves runs of 10, 9, 9 and the tail
        db_session.add(
            IPAddress(subnet_id=scope.subnet_id, address=f"10.73.0.{n}", status="reserved")
        )
    # A free-but-answering address (status available, seen by discovery).
    db_session.add(
        IPAddress(
            subnet_id=scope.subnet_id,
            address="10.73.0.25",
            status="available",
            last_seen_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    r = await _get(client, db_session, pool, min_size=10)
    sug = r.json()["suggestions"]
    assert all(s["size"] >= 10 for s in sug)
    after = sug[0]
    assert after["kind"] == "extends_after" and after["end_ip"] == "10.73.0.29"
    assert after["seen_answering"] == ["10.73.0.25"] and after["seen_answering_count"] == 1
    r2 = await _get(client, db_session, pool, limit=1)
    assert len(r2.json()["suggestions"]) == 1


@pytest.mark.asyncio
async def test_refusals_and_permission(client: AsyncClient, db_session: AsyncSession) -> None:
    scope = await _scope(db_session, "10.74.0.0/24")
    excluded = await _pool(db_session, scope, "10.74.0.10", "10.74.0.19", "excluded")
    r = await _get(client, db_session, excluded)
    assert r.status_code == 422
    r = await _get(client, db_session, type("P", (), {"id": uuid.uuid4()})())
    assert r.status_code == 404
    # v6
    v6 = await _scope(db_session, "2001:db8:74::/64")
    p6 = await _pool(db_session, v6, "2001:db8:74::100", "2001:db8:74::1ff")
    r = await _get(client, db_session, p6)
    assert r.status_code == 422 and "IPv4" in r.json()["detail"]
    # No grants at all: refused.
    pool = await _pool(db_session, scope, "10.74.0.30", "10.74.0.39")
    nobody = await _user(db_session, superadmin=False)
    tok = create_access_token(str(nobody.id))
    r = await client.get(
        f"/api/v1/dhcp/pools/{pool.id}/expansion-suggestions",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_mcp_tool(db_session: AsyncSession) -> None:
    from app.services.ai.tools.base import REGISTRY
    from app.services.ai.tools.dhcp import (
        FindDHCPPoolExpansionArgs,
        find_dhcp_pool_expansion,
    )

    scope = await _scope(db_session, "10.75.0.0/24")
    pool = await _pool(db_session, scope, "10.75.0.10", "10.75.0.19")
    user = await _user(db_session)
    out = await find_dhcp_pool_expansion(
        db_session, user, FindDHCPPoolExpansionArgs(pool_id=str(pool.id))
    )
    assert out["suggestions"][0]["kind"] == "extends_after"
    assert REGISTRY.get("find_dhcp_pool_expansion").default_enabled is True
