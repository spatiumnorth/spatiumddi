"""#3624: a renewal that lands while the expiry sweep holds the lease row.

The sweep marks a lapsed lease ``expired`` and holds its row to commit. A
renewal that waited for the row used to land after the commit with the lease
still ``expired``: it had read the row before the sweep, so its session held
``state='active'`` and assigning ``active`` again was no change, never
written. The sweep's first pass takes only ``active`` leases, so the renewed
lease's IPAM mirror and DNS records were never cleaned when it later ran out.

Forced rather than hoped for: the sweep is parked after it has written the
lease (inside its DDNS revoke) while the renewal is posted, and released only
once the renewal is waiting on a lock.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dhcp import DHCPLease
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress
from tests.test_lease_events_insert_order_3480 import (  # noqa: F401
    _ddns_subnet,
    _lease,
    _two_agents,
    concurrent_client,
)

_DEADLINE_S = 20.0


async def _lock_waiters(conn: AsyncConnection | AsyncSession) -> int:
    # pg_stat_activity is a per-transaction snapshot; clear it before each poll.
    await conn.execute(text("SELECT pg_stat_clear_snapshot()"))
    return (
        await conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() AND wait_event_type = 'Lock'"
            )
        )
    ).scalar_one()


async def _wait_for_lock_waiter(conn: AsyncConnection | AsyncSession) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE_S
    while loop.time() < deadline:
        if await _lock_waiters(conn):
            return
        await asyncio.sleep(0.05)
    raise AssertionError("no backend ever waited on a lock")


@pytest.fixture
async def other_conn() -> AsyncGenerator[AsyncConnection, None]:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            yield conn
    finally:
        await engine.dispose()


async def _a_records(db: AsyncSession) -> int:
    rows = (
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.record_type == "A")
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return len(rows)


@pytest.mark.asyncio
async def test_a_renewal_landing_after_the_sweep_leaves_the_lease_active(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.dns import ddns
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet, _block = await _ddns_subnet(db_session)
    agent, _peer = await _two_agents(db_session, [subnet])
    ip = "10.31.1.10"

    async def _post(events: list[dict[str, Any]]) -> Any:
        return await concurrent_client.post(
            "/api/v1/dhcp/agents/lease-events",
            headers={"x-test-server": str(agent.id)},
            json={"leases": events},
        )

    first = await _post([_lease(ip, 0)])
    assert first.status_code == 200, first.text

    async def _lapse(hours: int) -> None:
        await db_session.execute(
            update(DHCPLease)
            .where(DHCPLease.server_id == agent.id)
            .values(expires_at=datetime.now(UTC) - timedelta(hours=hours))
        )
        await db_session.commit()

    await _lapse(1)
    a_records_before = await _a_records(db_session)
    assert a_records_before == 1

    parked = asyncio.Event()
    release = asyncio.Event()
    real_revoke = ddns.revoke_ddns_for_lease

    async def _revoke(db: AsyncSession, **kw: Any) -> Any:
        if not parked.is_set():
            parked.set()  # the sweep has written the lease: it holds the row
            await asyncio.wait_for(release.wait(), timeout=60)
        return await real_revoke(db, **kw)

    monkeypatch.setattr(ddns, "revoke_ddns_for_lease", _revoke)

    sweep = asyncio.create_task(_sweep())
    await asyncio.wait_for(parked.wait(), timeout=30)
    renewal = asyncio.create_task(_post([_lease(ip, 0)]))
    await _wait_for_lock_waiter(db_session)
    release.set()
    cleaned, _deleted = await asyncio.wait_for(sweep, timeout=60)
    resp = await asyncio.wait_for(renewal, timeout=60)
    assert resp.status_code == 200, resp.text
    assert cleaned == 1  # the sweep did expire the lease first

    lease = (
        await db_session.execute(
            select(DHCPLease)
            .where(DHCPLease.server_id == agent.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert lease.state == "active"
    assert lease.expires_at is not None and lease.expires_at > datetime.now(UTC)
    mirror = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == subnet.id, IPAddress.auto_from_lease.is_(True))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert mirror.status == "dhcp"
    assert await _a_records(db_session) == 1

    # The client leaves without an expiry event: the lease runs out and the
    # sweep, finding it ``active``, removes the mirror and its DNS record.
    await _lapse(1)
    cleaned, _deleted = await _sweep()
    assert cleaned == 1
    left = (
        await db_session.execute(
            select(IPAddress.id)
            .where(IPAddress.subnet_id == subnet.id, IPAddress.auto_from_lease.is_(True))
            .execution_options(populate_existing=True)
        )
    ).all()
    assert left == []
    assert await _a_records(db_session) == 0


@pytest.mark.asyncio
async def test_an_agentless_pull_renewal_after_the_sweep_leaves_the_lease_active(
    db_session: AsyncSession, other_conn: AsyncConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.dhcp import pull_leases as pl
    from tests.test_dhcp_pull_leases_serialised_2262 import _patch, _server

    srv = await _server(db_session)
    ip = "10.9.0.60"
    lease = DHCPLease(
        server_id=srv.id,
        ip_address=ip,
        mac_address="aa:bb:cc:36:24:01",
        state="active",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
        last_seen_at=datetime.now(UTC) - timedelta(hours=2),
    )
    db_session.add(lease)
    await db_session.commit()
    lease_id = lease.id

    # The sweep's write: the row marked expired and held to commit.
    trans = await other_conn.begin()
    await other_conn.execute(
        text("UPDATE dhcp_lease SET state = 'expired' WHERE id = :id"), {"id": lease_id}
    )
    renewed = datetime.now(UTC) + timedelta(hours=1)
    _patch(
        monkeypatch,
        [
            {
                "ip_address": ip,
                "mac_address": "aa:bb:cc:36:24:01",
                "hostname": "h",
                "expires_at": renewed,
            }
        ],
    )
    pull = asyncio.create_task(pl.pull_leases_from_server(db_session, srv, apply=True))
    await _wait_for_lock_waiter(other_conn)
    await trans.commit()
    result = await asyncio.wait_for(pull, timeout=30)
    await db_session.commit()
    assert result.errors == []

    state = (
        await db_session.execute(
            select(DHCPLease.state)
            .where(DHCPLease.id == lease_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert state == "active"
