"""#3605: the lease expiry sweep locks in the lease-events order.

The sweep used to interleave, per expired lease, the DDNS revoke (which bumps
the zone's serial row and holds it to commit) with that lease's IPAM mirror
delete. A lease-events batch holds the mirror rows first (``FOR UPDATE``, #2580)
and then wants the zone rows for its own DDNS publish. The sweep held a zone
and waited for a mirror row, the batch held the mirror row and waited for the
zone: Postgres broke the cycle with 40P01 and one side failed (#3601 fixed the
batch's own order; this is the sweep's half).

Forced rather than hoped for: the lease-events batch is held at its first DDNS
publish (after it holds every mirror row) until the sweep has either revoked
its first address's DDNS (the unfixed order) or parked on one of the batch's
locks (the fixed sweep, which locks before any DDNS work). Every hold polls
``pg_blocking_pids`` to a generous deadline instead of waiting a fixed window,
so a slow runner changes how long a test takes, never what it observes.
"""

from __future__ import annotations

import asyncio
import io
import os
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress
from tests.test_lease_events_insert_order_3480 import (  # noqa: F401
    _ddns_subnet,
    _lease,
    _two_agents,
    concurrent_client,
)

# How long to wait for the sweep to park on the other connection's lock. Far
# longer than it takes on an idle machine; a busy CI runner can be slow to
# schedule the sweep's connection, and the wait returns as soon as it parks.
_PARK_DEADLINE_S = 20.0


async def _anyone_blocked_by(conn: AsyncConnection | AsyncSession, pid: int) -> bool:
    """Is any backend waiting on a lock that backend ``pid`` holds?

    ``pg_stat_activity`` is a snapshot taken at its first read in a
    transaction and kept to the end of it, and every poll here runs inside the
    lock holder's open transaction. Without clearing the snapshot, a sweep
    that connected after the first poll is never seen, however long it waits.
    """
    await conn.execute(text("SELECT pg_stat_clear_snapshot()"))
    blocked = (
        await conn.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid))"),
            {"pid": pid},
        )
    ).scalar_one()
    return bool(blocked)


async def _hold_for_the_sweep(db: AsyncSession, revoked: asyncio.Event) -> str:
    """Hold the batch, mirror rows locked, until the sweep has either revoked
    DDNS (the unfixed order, which then deadlocks) or parked on one of the
    batch's locks (the fixed order). Polled to a generous deadline rather than
    a fixed window, so a slow runner cannot let the batch commit before the
    sweep has even started, which would test nothing."""
    with db.no_autoflush:
        pid = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _PARK_DEADLINE_S
        while loop.time() < deadline:
            if revoked.is_set():
                return "batch: met the sweep's revoke"
            if await _anyone_blocked_by(db, pid):
                return "batch: the sweep parked on its locks"
            await asyncio.sleep(0.05)
    return "batch: the sweep neither revoked nor parked"


@pytest.mark.asyncio
async def test_sweep_and_lease_events_on_the_same_addresses_do_not_deadlock(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.dns import ddns
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet, _block = await _ddns_subnet(db_session)
    peer_a, peer_b = await _two_agents(db_session, [subnet])
    ips = ["10.31.1.10", "10.31.1.20"]

    async def _post(server: Any, events: list[dict[str, Any]]) -> Any:
        return await concurrent_client.post(
            "/api/v1/dhcp/agents/lease-events",
            headers={"x-test-server": str(server.id)},
            json={"leases": events},
        )

    # A's leases create the mirrors and their DDNS records; then they lapse.
    first = await _post(peer_a, [_lease(ip, n) for n, ip in enumerate(ips)])
    assert first.status_code == 200, first.text
    await db_session.execute(
        update(DHCPLease)
        .where(DHCPLease.server_id == peer_a.id)
        .values(expires_at=datetime.now(UTC) - timedelta(hours=1))
    )
    await db_session.commit()

    batch_locked = asyncio.Event()
    revoked = asyncio.Event()
    log: list[str] = []
    real_apply, real_revoke = ddns.apply_ddns_for_lease, ddns.revoke_ddns_for_lease

    async def _apply(db: AsyncSession, **kw: Any) -> Any:
        if not batch_locked.is_set():
            batch_locked.set()  # every mirror row of the batch is locked by now
            log.append(await _hold_for_the_sweep(db, revoked))
        return await real_apply(db, **kw)

    async def _revoke(db: AsyncSession, **kw: Any) -> Any:
        result = await real_revoke(db, **kw)
        revoked.set()
        return result

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _apply)
    monkeypatch.setattr(ddns, "revoke_ddns_for_lease", _revoke)

    renamed = [{**_lease(ip, n), "hostname": f"renamed-{n}"} for n, ip in enumerate(ips)]
    batch = asyncio.create_task(_post(peer_b, renamed))
    await asyncio.wait_for(batch_locked.wait(), timeout=30)
    results = await asyncio.wait_for(
        asyncio.gather(_sweep(), batch, return_exceptions=True), timeout=60
    )
    assert not any(isinstance(r, BaseException) for r in results), f"{results!r}; {log}"
    assert results[1].status_code == 200, f"{results[1].text}; {log}"
    assert log == ["batch: the sweep parked on its locks"], log

    # The sweep expired A's leases; B's batch is committed and active.
    states = (
        await db_session.execute(
            select(DHCPLease.server_id, DHCPLease.state).execution_options(populate_existing=True)
        )
    ).all()
    assert {(s, st) for s, st in states if s == peer_a.id} == {(peer_a.id, "expired")}
    assert {st for s, st in states if s == peer_b.id} == {"active"}
    # B renewed every address while the sweep waited on the mirror rows, so
    # the mirrors are B's now: the sweep must not have deleted them (#1110).
    mirrors = (
        (
            await db_session.execute(
                select(IPAddress)
                .where(IPAddress.subnet_id == subnet.id, IPAddress.auto_from_lease.is_(True))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert sorted((str(m.address), m.hostname) for m in mirrors) == [
        ("10.31.1.10", "renamed-0"),
        ("10.31.1.20", "renamed-1"),
    ], log
    # The sweep is idempotent: a second run finds nothing to do.
    assert await _sweep() == (0, 0)


# ── Interleaves forced on a second, raw connection ──────────────────────────


@pytest.fixture
async def other_conn() -> AsyncGenerator[AsyncConnection, None]:
    """A connection of its own, standing in for a concurrent writer."""
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            yield conn
    finally:
        await engine.dispose()


async def _wait_until_blocked(conn: AsyncConnection, sweep: asyncio.Task[Any]) -> None:
    """Return once some backend waits on a lock that ``conn`` holds.

    Fails at once, with its outcome, if ``sweep`` finishes without waiting,
    and at the deadline with what every other backend was doing.
    """
    pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _PARK_DEADLINE_S
    while loop.time() < deadline:
        if sweep.done():
            outcome = sweep.exception() or sweep.result()
            raise AssertionError(f"the sweep finished without waiting on the lock: {outcome!r}")
        if await _anyone_blocked_by(conn, pid):
            return
        await asyncio.sleep(0.05)
    await conn.execute(text("SELECT pg_stat_clear_snapshot()"))
    activity = (
        await conn.execute(
            text(
                "SELECT pid, state, wait_event_type, wait_event, pg_blocking_pids(pid), "
                "left(query, 120) FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid()"
            )
        )
    ).all()
    stack = io.StringIO()
    sweep.print_stack(file=stack)
    raise AssertionError(
        f"the sweep did not wait on the lock held by pid {pid} within "
        f"{_PARK_DEADLINE_S:.0f} s; other backends: {activity!r}; sweep at:\n{stack.getvalue()}"
    )


async def _group_with_two_servers(db: AsyncSession) -> tuple[Any, DHCPServer, DHCPServer]:
    from tests.test_lease_events_insert_order_3480 import _ddns_subnet as make_subnet

    subnet, _block = await make_subnet(db)
    tag = uuid.uuid4().hex[:6]
    grp = DHCPServerGroup(name=f"g-{tag}", description="")
    db.add(grp)
    await db.flush()
    a, b = (
        DHCPServer(
            name=f"k{n}-{tag}", driver="kea", host="127.0.0.1", port=67, server_group_id=grp.id
        )
        for n in range(2)
    )
    db.add_all([a, b])
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    return subnet, a, b


@pytest.mark.asyncio
async def test_a_partner_renewal_while_the_sweep_waits_keeps_the_mirror(
    db_session: AsyncSession, other_conn: AsyncConnection
) -> None:
    """The sweep decides "is the address still held?" after it holds the
    mirror row, not before (#3605). A partner's renewal that commits while the
    sweep waits for that row keeps the mirror and its DDNS."""
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet, a, b = await _group_with_two_servers(db_session)
    past = datetime.now(UTC) - timedelta(hours=1)
    ip = "10.31.1.40"
    lease_a = DHCPLease(
        server_id=a.id,
        ip_address=ip,
        mac_address="aa:bb:cc:36:05:01",
        state="active",
        expires_at=past,
    )
    lease_b = DHCPLease(
        server_id=b.id,
        ip_address=ip,
        mac_address="aa:bb:cc:36:05:01",
        state="expired",
        expires_at=past,
    )
    mirror = IPAddress(
        subnet_id=subnet.id, address=ip, status="dhcp", auto_from_lease=True, hostname="kept"
    )
    db_session.add_all([lease_a, lease_b, mirror])
    await db_session.commit()

    # The partner's lease-events batch: holds the mirror row, renews B's lease.
    trans = await other_conn.begin()
    await other_conn.execute(
        text("SELECT id FROM ip_address WHERE id = :id FOR UPDATE"), {"id": mirror.id}
    )
    await other_conn.execute(
        text(
            "UPDATE dhcp_lease SET state = 'active', expires_at = now() + interval '1 hour' "
            "WHERE id = :id"
        ),
        {"id": lease_b.id},
    )
    sweep = asyncio.create_task(_sweep())
    await _wait_until_blocked(other_conn, sweep)
    await trans.commit()
    cleaned, _deleted = await asyncio.wait_for(sweep, timeout=30)

    assert cleaned == 0
    kept = (
        await db_session.execute(select(IPAddress.hostname).where(IPAddress.id == mirror.id))
    ).scalar_one_or_none()
    assert kept == "kept"
    states = dict(
        (
            await db_session.execute(
                select(DHCPLease.server_id, DHCPLease.state).execution_options(
                    populate_existing=True
                )
            )
        ).all()
    )
    assert states == {a.id: "expired", b.id: "active"}


@pytest.mark.asyncio
async def test_a_batch_renewing_leases_in_id_order_never_deadlocks_with_the_sweep(
    db_session: AsyncSession, other_conn: AsyncConnection
) -> None:
    """The sweep takes its lease rows in id order, as a lease-events flush
    writes them (#3605), and leaves a lease renewed while it waited alone.

    Two expired leases of one server, the lower id on the higher address. A
    batch renewing both updates the lower id first. The sweep used to update
    them in address order: it held the higher id, the batch the lower, and
    each waited for the other.
    """
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet, a, _b = await _group_with_two_servers(db_session)
    past = datetime.now(UTC) - timedelta(hours=1)
    leases = [
        DHCPLease(
            server_id=a.id,
            ip_address=f"10.31.1.{50 + n}",
            mac_address=f"aa:bb:cc:36:05:{0x10 + n:02x}",
            state="active",
            expires_at=past,
        )
        for n in range(2)
    ]
    db_session.add_all(leases)
    await db_session.flush()
    low, high = sorted(leases, key=lambda lease: lease.id)
    low.ip_address, high.ip_address = "10.31.1.60", "10.31.1.50"
    await db_session.commit()
    low_id, high_id = low.id, high.id

    renew = text("UPDATE dhcp_lease SET expires_at = now() + interval '1 hour' WHERE id = :id")
    trans = await other_conn.begin()
    await other_conn.execute(renew, {"id": low_id})
    sweep = asyncio.create_task(_sweep())
    await _wait_until_blocked(other_conn, sweep)
    await other_conn.execute(renew, {"id": high_id})
    await trans.commit()
    assert await asyncio.wait_for(sweep, timeout=30) == (0, 0)

    states = (
        (
            await db_session.execute(
                select(DHCPLease.state)
                .where(DHCPLease.id.in_([low_id, high_id]))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert sorted(states) == ["active", "active"]


@pytest.mark.asyncio
async def test_the_mirror_lock_pass_spans_chunks(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backlog bigger than one lookup chunk still tears every mirror down
    (the chunks keep asyncpg under its bind-parameter limit)."""
    from app.tasks import dhcp_lease_cleanup

    monkeypatch.setattr(dhcp_lease_cleanup, "_MIRROR_LOOKUP_CHUNK", 1)
    subnet, a, _b = await _group_with_two_servers(db_session)
    past = datetime.now(UTC) - timedelta(hours=1)
    ips = [f"10.31.1.{70 + n}" for n in range(3)]
    for n, ip in enumerate(ips):
        db_session.add(
            DHCPLease(
                server_id=a.id,
                ip_address=ip,
                mac_address=f"aa:bb:cc:36:05:{0x20 + n:02x}",
                state="active",
                expires_at=past,
            )
        )
        db_session.add(
            IPAddress(subnet_id=subnet.id, address=ip, status="dhcp", auto_from_lease=True)
        )
    await db_session.commit()

    assert await dhcp_lease_cleanup._sweep() == (3, 0)
    left = (
        await db_session.execute(
            select(IPAddress.id).where(
                IPAddress.subnet_id == subnet.id, IPAddress.auto_from_lease.is_(True)
            )
        )
    ).all()
    assert left == []
