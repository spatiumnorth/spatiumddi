"""#3480: two agents posting the same new leases never deadlock on their order.

Both Kea agents of one DHCP server group report every lease, so their
lease-events batches hold the same new addresses: in a different order, or
cut at different points. The lease pass inserts the IPAM mirror row of each
new address and commits once, at the end of the batch, so every insert holds
its ``(subnet_id, address)`` key in ``uq_ip_address_subnet_address`` until
then. Inserted in each batch's own order, two batches could each hold a key
the other was about to insert: Postgres broke the wait cycle with 40P01 and
one request answered 500 (ddi-pg's qa-review walk of #3353).

These tests force the interleave rather than hope for it. Every request runs
on its own session and connection, and each is held at one point of its pass
until the other request has got there too. The hold has a timeout: when the
batches queue as they should, the second request is parked in the database
on the first one's row and never gets there, and the first goes on alone.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.dhcp import agents
from app.api.v1.dhcp.agents import _auth_agent
from app.db import get_db
from app.main import app
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

# How long a held request waits for the other one. Far longer than the other
# needs to reach the same point when nothing blocks it, and longer than
# Postgres' deadlock_timeout (1 s by default), so on the unfixed code the
# cycle is closed and detected before either hold runs out.
_HOLD_S = 3.0


@pytest.fixture
async def concurrent_client() -> AsyncGenerator[AsyncClient, None]:
    """A client whose every request runs on its own session + connection."""
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _own_session() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = _own_session
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(_auth_agent, None)
        await engine.dispose()


def _hold_after_first(monkeypatch: pytest.MonkeyPatch, owner: Any, name: str) -> list[str]:
    """Wrap ``owner.name`` so each request (one session each) is held after
    its first call until the other request has made its first call too."""
    real = getattr(owner, name)
    seen: set[int] = set()
    both = asyncio.Event()
    log: list[str] = []

    async def _held(db: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        result = await real(db, *args, **kwargs)
        if id(db) not in seen:
            seen.add(id(db))
            if len(seen) == 2:
                both.set()
            try:
                await asyncio.wait_for(both.wait(), timeout=_HOLD_S)
                log.append("met")
            except TimeoutError:
                log.append("went on alone")
        return result

    monkeypatch.setattr(owner, name, _held)
    return log


def _lease(ip: str, n: int) -> dict[str, Any]:
    now = datetime.now(UTC)
    end = (now + timedelta(hours=1)).isoformat()
    return {
        "ip_address": ip,
        "mac_address": f"aa:bb:cc:34:80:{n:02x}",
        "hostname": f"host-{n}",
        "state": "active",
        "starts_at": now.isoformat(),
        "ends_at": end,
        "expires_at": end,
    }


async def _two_agents(db: AsyncSession, subnets: list[Subnet]) -> list[DHCPServer]:
    """Two Kea servers in one group, with a scope on each subnet, and the
    agent auth answered from an ``x-test-server`` header."""
    tag = uuid.uuid4().hex[:6]
    grp = DHCPServerGroup(name=f"g-{tag}", description="")
    db.add(grp)
    await db.flush()
    servers = [
        DHCPServer(
            name=f"k{n}-{tag}",
            driver="kea",
            host="127.0.0.1",
            port=67,
            server_group_id=grp.id,
        )
        for n in range(2)
    ]
    db.add_all(servers)
    db.add_all([DHCPScope(group_id=grp.id, subnet_id=s.id, is_active=True) for s in subnets])
    await db.commit()
    by_id = {str(s.id): s for s in servers}

    def _agent(request: Request) -> tuple[DHCPServer, dict[str, Any]]:
        return by_id[request.headers["x-test-server"]], {}

    app.dependency_overrides[_auth_agent] = _agent
    return servers


async def _post_together(
    client: AsyncClient, batches: list[tuple[DHCPServer, list[dict[str, Any]]]], log: list[str]
) -> None:
    async def _post(server: DHCPServer, events: list[dict[str, Any]]) -> Any:
        return await client.post(
            "/api/v1/dhcp/agents/lease-events",
            headers={"x-test-server": str(server.id)},
            json={"leases": events},
        )

    results = await asyncio.wait_for(
        asyncio.gather(*(_post(s, e) for s, e in batches), return_exceptions=True), timeout=60
    )
    outcomes = [
        repr(r)[:300] if isinstance(r, BaseException) else (r.status_code, r.text[:300])
        for r in results
    ]
    assert all(
        not isinstance(r, BaseException) and r.status_code == 200 for r in results
    ), f"outcomes {outcomes}; holds {log}"


async def _fresh(db: AsyncSession, model: Any, row_id: Any) -> Any:
    return (
        await db.execute(
            select(model).where(model.id == row_id).execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _mirrors(db: AsyncSession, subnet_ids: list[Any]) -> list[tuple[str, str, bool]]:
    rows = (
        await db.execute(
            select(IPAddress.address, IPAddress.status, IPAddress.auto_from_lease).where(
                IPAddress.subnet_id.in_(subnet_ids)
            )
        )
    ).all()
    return sorted((str(a), s, bool(f)) for a, s, f in rows)


async def _active_leases(db: AsyncSession, server: DHCPServer) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(DHCPLease)
            .where(DHCPLease.server_id == server.id, DHCPLease.state == "active")
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_two_agents_posting_the_same_new_leases_in_opposite_orders_both_land(
    concurrent_client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue's case: peer B posts peer A's batch reversed. Held after
    their first insert, A holds 10.30.0.10 and B 10.30.2.11; on the unfixed
    code each then waits for the other's key."""
    log = _hold_after_first(monkeypatch, agents, "insert_ipam_mirror_row")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.30.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnets = [
        Subnet(space_id=space.id, block_id=block.id, network=f"10.30.{n}.0/23", name=f"s{n}")
        for n in (0, 2)
    ]
    db_session.add_all(subnets)
    await db_session.flush()
    peer_a, peer_b = await _two_agents(db_session, subnets)

    ips = ["10.30.0.10", "10.30.2.10", "10.30.0.11", "10.30.2.11"]
    batch = [_lease(ip, n) for n, ip in enumerate(ips)]
    await _post_together(concurrent_client, [(peer_a, batch), (peer_b, batch[::-1])], log)

    # One mirror row per address, owned by the leases, and every figure right.
    assert await _mirrors(db_session, [s.id for s in subnets]) == sorted(
        (ip, "dhcp", True) for ip in ips
    )
    assert await _active_leases(db_session, peer_a) == 4
    assert await _active_leases(db_session, peer_b) == 4
    for s in subnets:
        assert (await _fresh(db_session, Subnet, s.id)).allocated_ips == 2
    assert (await _fresh(db_session, IPBlock, block.id)).allocated_ips == 4 + 2 * 2


async def _ddns_subnet(db: AsyncSession) -> tuple[Subnet, IPBlock]:
    """A DDNS subnet published into a forward and a reverse zone that an
    agent-based DNS group serves, so every publish bumps the zones' serial."""
    tag = uuid.uuid4().hex[:6]
    grp = DNSServerGroup(name=f"dg-{tag}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"ns-{tag}",
            is_primary=True,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{tag}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.z{tag}.example.",
        admin_email=f"admin.z{tag}.example.",
    )
    space = IPSpace(name=f"sp-{tag}", description="")
    db.add_all([zone, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.31.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.31.1.0/24",
        name="s",
        dns_zone_id=str(zone.id),
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
        ddns_enabled=True,
        ddns_inherit_settings=False,
        ddns_hostname_policy="client_or_generated",
    )
    db.add(subnet)
    await db.flush()
    db.add(
        DNSZone(
            group_id=grp.id,
            name="1.31.10.in-addr.arpa.",
            zone_type="primary",
            kind="reverse",
            primary_ns=f"ns1.z{tag}.example.",
            admin_email=f"admin.z{tag}.example.",
            linked_subnet_id=subnet.id,
        )
    )
    await db.flush()
    return subnet, block


@pytest.mark.asyncio
async def test_batches_cut_at_different_points_both_land_with_ddns_on(
    concurrent_client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two batches in the same order, on a DDNS subnet. Every DDNS publish
    bumps its zone's serial, which holds the zone row until the batch
    commits. A's batch holds a new lease B's does not (10.31.1.10), ahead of
    the one they share (10.31.1.20). Made to happen in this order: A inserts
    and publishes .10, so it holds the zone rows; B inserts .20 and goes to
    publish it, waiting for the zone rows; A then reaches .20, which B holds."""
    from app.services.dns import ddns

    a_only_ip, shared_ip = "10.31.1.10", "10.31.1.20"
    real = ddns.apply_ddns_for_lease
    a_published = asyncio.Event()
    b_at_shared = asyncio.Event()
    log: list[str] = []

    async def _bounded(event: asyncio.Event, what: str) -> None:
        try:
            await asyncio.wait_for(event.wait(), timeout=_HOLD_S)
            log.append(f"{what}: met")
        except TimeoutError:
            log.append(f"{what}: went on alone")

    async def _choreographed(db: AsyncSession, **kw: Any) -> Any:
        ip = str(kw["ipam_row"].address)
        if ip == shared_ip:
            b_at_shared.set()
            if not a_published.is_set():
                await _bounded(a_published, "publish of .20 after A's publish of .10")
        result = await real(db, **kw)
        if ip == a_only_ip:
            a_published.set()
            await _bounded(b_at_shared, "A goes on once .20 is inserted")
        return result

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _choreographed)
    subnet, block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])

    a_only, shared = _lease(a_only_ip, 1), _lease(shared_ip, 2)
    await _post_together(concurrent_client, [(peer_a, [a_only, shared]), (peer_b, [shared])], log)

    assert await _mirrors(db_session, [subnet.id]) == [
        ("10.31.1.10", "dhcp", True),
        ("10.31.1.20", "dhcp", True),
    ]
    assert (await _fresh(db_session, Subnet, subnet.id)).allocated_ips == 2
    assert (await _fresh(db_session, IPBlock, block.id)).allocated_ips == 2 + 2
