"""#3345 — concurrent writers that recount utilization never deadlock.

The recount locks a subnet and its block chain before counting. Those locks
are taken after the request has inserted its row (the foreign key holds
FOR KEY SHARE on the parent subnet or block) and, in most handlers, after it
has staged its audit row (the audit-chain advisory lock). A recount that
took the rows FOR UPDATE waited on the other request's KEY SHARE while that
request waited on the audit lock: Postgres broke the cycle with 40P01 and
the API answered 500 (ddi-pg walk of PR #3353, cases 3 and 10).

These tests run the race for real: every request gets its own session on
its own connection (the shared ``db_session`` fixture is one connection and
would serialise everything), and the requests are issued together with
``asyncio.gather``.
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

from app.api.v1.dhcp.agents import _auth_agent
from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam.utilization import counts_toward_utilization

# Rounds per test: one round already deadlocked every time on the unfixed
# code; several make a lucky interleaving on a fixed one implausible.
_ROUNDS = 3


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


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("OldPass123!"),
        auth_source="local",
        is_active=True,
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _fresh(db: AsyncSession, model: Any, row_id: Any) -> Any:
    return (
        await db.execute(
            select(model).where(model.id == row_id).execution_options(populate_existing=True)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_concurrent_subnet_creates_under_one_block(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Eric's case 10: six subnet creates at once under one block."""
    headers = await _admin_headers(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    root = IPBlock(space_id=space.id, network="10.30.0.0/16", name="root")
    db_session.add(root)
    await db_session.flush()
    block = IPBlock(space_id=space.id, parent_block_id=root.id, network="10.30.0.0/17", name="b")
    db_session.add(block)
    await db_session.commit()

    for rnd in range(_ROUNDS):

        async def _create(i: int, rnd: int = rnd) -> Any:
            return await concurrent_client.post(
                "/api/v1/ipam/subnets",
                headers=headers,
                json={
                    "space_id": str(space.id),
                    "block_id": str(block.id),
                    "network": f"10.30.{rnd * 10 + i}.0/24",
                    "name": f"p{rnd}-{i}",
                    "skip_reverse_zone": True,
                },
            )

        responses = await asyncio.gather(*(_create(i) for i in range(6)))
        assert [r.status_code for r in responses] == [201] * 6, [
            (r.status_code, r.text[:300]) for r in responses if r.status_code != 201
        ]

    # The figures are right once the dust settles: every subnet's own
    # allocated count matches its rows, and both blocks sum them.
    subnets = (
        (await db_session.execute(select(Subnet).where(Subnet.block_id == block.id)))
        .scalars()
        .all()
    )
    assert len(subnets) == 6 * _ROUNDS
    expected = 0
    for s in subnets:
        s = await _fresh(db_session, Subnet, s.id)
        rows = (
            await db_session.execute(
                select(func.count())
                .select_from(IPAddress)
                .where(IPAddress.subnet_id == s.id)
                .where(counts_toward_utilization())
            )
        ).scalar_one()
        assert s.allocated_ips == rows
        expected += rows + 2  # a subnet's network + broadcast count in its block
    assert (await _fresh(db_session, IPBlock, block.id)).allocated_ips == expected
    assert (await _fresh(db_session, IPBlock, root.id)).allocated_ips == expected


def _ev(i: int) -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "ip_address": f"10.90.1.{i}",
        "mac_address": f"aa:bb:cc:01:{i // 256:02x}:{i % 256:02x}",
        "hostname": f"h{i}",
        "state": "active",
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end,
        "expires_at": end,
    }


@pytest.mark.asyncio
async def test_concurrent_lease_batches_into_one_subnet(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """Eric's case 3: two agents of one group post batches of new, different
    addresses into one subnet at the same moment."""
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add_all([grp, space])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.90.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.90.1.0/24", name="s")
    db_session.add(subnet)
    servers = [
        DHCPServer(
            name=f"k{n}-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            port=67,
            server_group_id=grp.id,
        )
        for n in range(2)
    ]
    db_session.add_all(servers)
    await db_session.flush()
    db_session.add(DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True))
    await db_session.commit()
    by_id = {str(s.id): s for s in servers}

    def _agent(request: Request) -> tuple[DHCPServer, dict[str, Any]]:
        return by_id[request.headers["x-test-server"]], {}

    app.dependency_overrides[_auth_agent] = _agent

    async def _post(server: DHCPServer, events: list[dict[str, Any]]) -> Any:
        return await concurrent_client.post(
            "/api/v1/dhcp/agents/lease-events",
            headers={"x-test-server": str(server.id)},
            json={"leases": events},
        )

    leased: set[int] = set()
    for rnd in range(_ROUNDS):
        base = 10 + rnd * 60
        batches = [
            [_ev(i) for i in range(base, base + 30)],
            [_ev(i) for i in range(base + 30, base + 60)],
        ]
        responses = await asyncio.gather(*(_post(s, b) for s, b in zip(servers, batches)))
        assert [r.status_code for r in responses] == [200, 200], [
            (r.status_code, r.text[:300]) for r in responses
        ]
        leased.update(range(base, base + 60))

    s = await _fresh(db_session, Subnet, subnet.id)
    assert s.allocated_ips == len(leased)
    assert (await _fresh(db_session, IPBlock, block.id)).allocated_ips == len(leased) + 2


def _audit_row(action: str) -> AuditLog:
    return AuditLog(
        user_display_name="<system>",
        auth_source="system",
        action=action,
        resource_type="subnet",
        resource_id="x",
        resource_display="x",
        result="success",
    )


@pytest.mark.asyncio
async def test_recount_before_audit_and_audit_before_recount(db_session: AsyncSession) -> None:
    """The order this test forces is the cycle ``FOR NO KEY UPDATE`` alone
    leaves: B recounts and only then writes its audit row (a manual lease
    Sync, a lease delete, a discovery run), while A writes its audit row and
    then recounts the same subnet (an address create). Without the recount
    taking the audit-chain lock first, B holds the subnet waiting for the
    audit lock while A holds the audit lock waiting for the subnet."""
    from app.services.ipam.utilization import recount_subnets_and_blocks

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.70.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.70.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.commit()

    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    b_recounted = asyncio.Event()
    a_waiting = asyncio.Event()

    async def _b() -> None:
        async with factory() as db:
            db.add(IPAddress(subnet_id=subnet.id, address="10.70.1.20", status="allocated"))
            await recount_subnets_and_blocks(db, [subnet.id])
            b_recounted.set()
            await a_waiting.wait()
            db.add(_audit_row("b"))
            await db.commit()

    async def _a() -> None:
        await b_recounted.wait()
        async with factory() as db:
            db.add(IPAddress(subnet_id=subnet.id, address="10.70.1.10", status="allocated"))
            db.add(_audit_row("a"))

            async def _go() -> None:
                await db.flush()  # the audit row: takes the audit-chain lock
                await recount_subnets_and_blocks(db, [subnet.id])
                await db.commit()

            task = asyncio.create_task(_go())
            # Long enough for A to be parked on a lock B holds.
            await asyncio.sleep(0.5)
            a_waiting.set()
            await task

    try:
        await asyncio.wait_for(asyncio.gather(_a(), _b()), timeout=30)
    finally:
        await engine.dispose()

    assert (await _fresh(db_session, Subnet, subnet.id)).allocated_ips == 2
    assert (await _fresh(db_session, IPBlock, block.id)).allocated_ips == 4
