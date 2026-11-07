"""#3617: the lease path's three remaining lock-order cycles.

One order for every writer of lease, mirror and zone rows
(``app.services.lock_order``): ``dhcp_lease`` rows, then ``ip_address``
rows, then ``dns_zone`` rows, each by id. Three writers broke it:

1. the agentless lease pull took lease, mirror and DDNS rows per lease, in
   wire order, so a pull holding one lease's mirror could wait for the next
   lease's row while the expiry sweep held that lease and waited for the
   mirror;
2. a subnet soft-delete deleted the lease mirrors before it purged the
   scope's leases, the opposite of the sweep;
3. a DDNS retraction took the reverse zone before the forward zone (PTR
   first, #1800) and a DDNS publish the forward zone first, so two DDNS
   writes on DIFFERENT addresses of one zone pair deadlocked.

Each test forces the interleave on two real sessions (own connections): the
first writer is held at the point where the unfixed code holds one row of the
cycle, until the second writer is parked on one of its locks. Unfixed, the
first then asks for the second's row and Postgres breaks the cycle with
40P01; fixed, the first already holds everything and commits, and the second
goes on. Every hold polls ``pg_blocking_pids`` to a generous deadline (after
``pg_stat_clear_snapshot``: ``pg_stat_activity`` is frozen for the rest of a
transaction at its first read), so a slow runner changes how long a test
takes, never what it observes.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.security import hash_password
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from tests.test_lease_events_insert_order_3480 import _ddns_subnet

_PARK_DEADLINE_S = 20.0


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    """Sessions of their own, each on its own connection."""
    eng = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        yield eng
    finally:
        await eng.dispose()


async def _anyone_blocked_by(db: AsyncSession, pid: int) -> bool:
    await db.execute(text("SELECT pg_stat_clear_snapshot()"))
    blocked = (
        await db.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid))"),
            {"pid": pid},
        )
    ).scalar_one()
    return bool(blocked)


def _hold_first_call(
    monkeypatch: pytest.MonkeyPatch,
    owner: Any,
    name: str,
    holder: dict[str, AsyncSession],
    reached: asyncio.Event,
    log: list[str],
    *,
    after: bool = False,
) -> None:
    """Wrap ``owner.name``: the first call made on ``holder["db"]`` flushes and
    then waits, before (or ``after``) the real call, until another backend is
    parked on one of that session's locks."""
    real = getattr(owner, name)
    done: set[int] = set()

    async def _hold(db: AsyncSession) -> None:
        with db.no_autoflush:
            pid = (await db.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            reached.set()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + _PARK_DEADLINE_S
            while loop.time() < deadline:
                if await _anyone_blocked_by(db, pid):
                    log.append("the other writer parked on our locks")
                    return
                await asyncio.sleep(0.05)
        log.append("the other writer never parked")

    async def _wrapped(db: AsyncSession, *args: Any, **kwargs: Any) -> Any:
        first = db is holder.get("db") and not done
        if first:
            done.add(1)
        if first and not after:
            await db.flush()
            await _hold(db)
        result = await real(db, *args, **kwargs)
        if first and after:
            await db.flush()
            await _hold(db)
        return result

    monkeypatch.setattr(owner, name, _wrapped)


async def _race(
    first: Callable[[], Awaitable[Any]],
    second: Callable[[], Awaitable[Any]],
    reached: asyncio.Event,
) -> list[Any]:
    """Start ``first``; once it reaches its hold, start ``second``; gather."""
    first_task = asyncio.create_task(first())
    await asyncio.wait_for(reached.wait(), timeout=30)
    return await asyncio.wait_for(
        asyncio.gather(first_task, second(), return_exceptions=True), timeout=90
    )


def _no_deadlock(results: list[Any], log: list[str]) -> None:
    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, f"{errors!r}; {log}"
    assert log == ["the other writer parked on our locks"], log


# ── 3. DDNS forward / reverse zone order ────────────────────────────────────


@pytest.mark.asyncio
async def test_ddns_publish_and_revoke_on_different_addresses_do_not_deadlock(
    db_session: AsyncSession, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A publish takes the forward zone first; a revoke retracts the PTR
    first, so it took the reverse zone first. Two of them on different
    addresses of one zone pair each held the zone the other wanted."""
    from app.api.v1.ipam import router as ipam_router
    from app.services.dns import ddns

    subnet, _block = await _ddns_subnet(db_session)
    leaving = IPAddress(
        subnet_id=subnet.id, address="10.31.1.30", status="dhcp", auto_from_lease=True
    )
    arriving = IPAddress(
        subnet_id=subnet.id, address="10.31.1.40", status="dhcp", auto_from_lease=True
    )
    db_session.add_all([leaving, arriving])
    await db_session.flush()
    assert await ddns.apply_ddns_for_lease(
        db_session, subnet=subnet, ipam_row=leaving, client_hostname="leaving"
    )
    await db_session.commit()
    subnet_id, leaving_id, arriving_id = subnet.id, leaving.id, arriving.id

    holder: dict[str, AsyncSession] = {}
    reached = asyncio.Event()
    log: list[str] = []
    # Held right after the publish's first record op: the forward zone's
    # serial is bumped and flushed, so the unfixed publish holds that zone.
    _hold_first_call(monkeypatch, ipam_router, "_enqueue_dns_op", holder, reached, log, after=True)

    async def _publish() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            holder["db"] = db
            sn = await db.get(Subnet, subnet_id)
            row = await db.get(IPAddress, arriving_id)
            assert await ddns.apply_ddns_for_lease(
                db, subnet=sn, ipam_row=row, client_hostname="arriving"
            )
            await db.commit()

    async def _revoke() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            sn = await db.get(Subnet, subnet_id)
            row = await db.get(IPAddress, leaving_id)
            assert await ddns.revoke_ddns_for_lease(db, subnet=sn, ipam_row=row)
            await db.commit()

    _no_deadlock(await _race(_publish, _revoke, reached), log)

    records = (
        await db_session.execute(
            select(DNSRecord.ip_address_id, DNSRecord.record_type).execution_options(
                populate_existing=True
            )
        )
    ).all()
    assert sorted((str(i), t) for i, t in records if i == arriving_id) == [
        (str(arriving_id), "A"),
        (str(arriving_id), "PTR"),
    ]
    assert not [r for r in records if r[0] == leaving_id]


# ── 1. The agentless lease pull against the expiry sweep ────────────────────


class _StubDriver:
    def __init__(self, leases: list[dict[str, Any]]) -> None:
        self._leases = leases

    async def get_leases(self, _server: DHCPServer) -> list[dict[str, Any]]:
        return self._leases


async def _plain_subnet(db: AsyncSession, network: str) -> Subnet:
    tag = uuid.uuid4().hex[:6]
    space = IPSpace(name=f"sp-{tag}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network.rsplit(".", 2)[0] + ".0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="s")
    db.add(subnet)
    await db.flush()
    return subnet


async def _server(db: AsyncSession, driver: str, subnet: Subnet) -> tuple[DHCPServer, DHCPScope]:
    tag = uuid.uuid4().hex[:6]
    grp = DHCPServerGroup(name=f"g-{tag}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{tag}", driver=driver, host="127.0.0.1", port=67, server_group_id=grp.id
    )
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add_all([srv, scope])
    await db.flush()
    return srv, scope


@pytest.mark.asyncio
async def test_lease_pull_and_expiry_sweep_do_not_deadlock(
    db_session: AsyncSession, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pull refreshed .10's lease and mirror, then went on to .20's lease.
    The sweep held .20's lapsed lease (and a partner's lapsed .10 lease) and
    wanted .10's mirror, which the pull held."""
    from app.services.dhcp import pull_leases as pl
    from app.services.dns import ddns
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet = await _plain_subnet(db_session, "10.36.17.0/24")
    windows, scope = await _server(db_session, "windows_dhcp", subnet)
    # The failover partner (#1110): its lapsed copy of .10 does not free the
    # mirror while the Windows server still holds the address.
    partner = DHCPServer(
        name=f"p-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="127.0.0.2",
        port=67,
        server_group_id=windows.server_group_id,
    )
    db_session.add(partner)
    await db_session.flush()
    soon = datetime.now(UTC) + timedelta(hours=1)
    past = datetime.now(UTC) - timedelta(hours=1)
    db_session.add_all(
        [
            DHCPLease(
                server_id=windows.id,
                scope_id=scope.id,
                ip_address="10.36.17.10",
                mac_address="aa:bb:cc:36:17:10",
                state="active",
                expires_at=soon,
            ),
            DHCPLease(
                server_id=windows.id,
                scope_id=scope.id,
                ip_address="10.36.17.20",
                mac_address="aa:bb:cc:36:17:20",
                state="active",
                expires_at=past,
            ),
            DHCPLease(
                server_id=partner.id,
                ip_address="10.36.17.10",
                mac_address="aa:bb:cc:36:17:99",
                state="active",
                expires_at=past,
            ),
        ]
        + [
            IPAddress(
                subnet_id=subnet.id,
                address=f"10.36.17.{n}",
                status="dhcp",
                auto_from_lease=True,
                hostname=f"h{n}",
            )
            for n in (10, 20)
        ]
    )
    await db_session.commit()
    windows_id, subnet_id = windows.id, subnet.id

    wire = [
        {
            "ip_address": f"10.36.17.{n}",
            "mac_address": f"aa:bb:cc:36:17:{n}",
            "hostname": f"h{n}",
            "expires_at": soon,
        }
        for n in (10, 20)
    ]
    monkeypatch.setattr(pl, "get_driver", lambda _drv: _StubDriver(wire))
    holder: dict[str, AsyncSession] = {}
    reached = asyncio.Event()
    log: list[str] = []
    # The pull's first DDNS call: unfixed, it comes right after .10's mirror
    # is refreshed and before .20's lease is.
    _hold_first_call(monkeypatch, ddns, "apply_ddns_for_lease", holder, reached, log)

    async def _pull() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            holder["db"] = db
            srv = await db.get(DHCPServer, windows_id)
            result = await pl.pull_leases_from_server(db, srv, apply=True)
            assert result.errors == [], result.errors
            await db.commit()

    _no_deadlock(await _race(_pull, _sweep, reached), log)

    leases = (
        await db_session.execute(
            select(DHCPLease.server_id, DHCPLease.ip_address, DHCPLease.state).execution_options(
                populate_existing=True
            )
        )
    ).all()
    # The pull refreshed both of the Windows server's leases; the sweep then
    # left them alone and expired only the partner's, keeping its mirror.
    assert sorted((str(ip), st) for s, ip, st in leases if s == windows_id) == [
        ("10.36.17.10", "active"),
        ("10.36.17.20", "active"),
    ]
    assert [st for s, _ip, st in leases if s != windows_id] == ["expired"]
    mirrors = (
        (
            await db_session.execute(
                select(IPAddress.address)
                .where(IPAddress.subnet_id == subnet_id)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert sorted(str(a) for a in mirrors) == ["10.36.17.10", "10.36.17.20"]


# ── 2. Subnet soft-delete against the expiry sweep ──────────────────────────


@pytest.mark.asyncio
async def test_subnet_soft_delete_and_expiry_sweep_do_not_deadlock(
    db_session: AsyncSession, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delete removed the lease mirror first and purged the scope's lease
    after; the sweep held that lapsed lease and wanted the mirror."""
    from app.services.ai.operations_risky import DeleteSubnetArgs, _apply_delete_subnet
    from app.services.dhcp import lease_cleanup
    from app.tasks.dhcp_lease_cleanup import _sweep

    subnet = await _plain_subnet(db_session, "10.36.18.0/24")
    kea, scope = await _server(db_session, "kea", subnet)
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add_all(
        [
            user,
            DHCPLease(
                server_id=kea.id,
                scope_id=scope.id,
                ip_address="10.36.18.10",
                mac_address="aa:bb:cc:36:18:10",
                state="active",
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            ),
            IPAddress(
                subnet_id=subnet.id,
                address="10.36.18.10",
                status="dhcp",
                auto_from_lease=True,
                hostname="h10",
            ),
        ]
    )
    await db_session.commit()
    subnet_id, user_id = subnet.id, user.id

    holder: dict[str, AsyncSession] = {}
    reached = asyncio.Event()
    log: list[str] = []
    # Unfixed, the delete reaches the lease purge holding the deleted mirror.
    _hold_first_call(monkeypatch, lease_cleanup, "delete_leases_for_scope", holder, reached, log)

    async def _delete() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            holder["db"] = db
            u = await db.get(User, user_id)
            await _apply_delete_subnet(db, u, DeleteSubnetArgs(subnet_id=subnet_id))

    _no_deadlock(await _race(_delete, _sweep, reached), log)

    left = (
        await db_session.execute(select(DHCPLease.id).where(DHCPLease.ip_address == "10.36.18.10"))
    ).all()
    assert left == []
    mirrors = (
        await db_session.execute(
            select(IPAddress.id)
            .where(IPAddress.subnet_id == subnet_id, IPAddress.auto_from_lease.is_(True))
            .execution_options(include_deleted=True)
        )
    ).all()
    assert mirrors == []


# ── A permanent subnet delete with scopes in two groups ─────────────────────


@pytest.mark.asyncio
async def test_permanent_subnet_delete_locks_every_scope_lease_first(
    db_session: AsyncSession,
) -> None:
    """A subnet served by two server groups has two scopes. The permanent
    delete tore them down one at a time, and each teardown locks the subnet's
    lease mirrors, so the second scope's lease rows were locked after the
    first's mirrors: lease rows after ``ip_address`` rows, the order the
    expiry sweep takes the other way round. The autouse row-lock guard
    (``tests/_row_lock_order_guard.py``) fails this test on that order."""
    from app.services.ai.operations_risky import DeleteSubnetArgs, _apply_delete_subnet

    subnet = await _plain_subnet(db_session, "10.36.19.0/24")
    kea_a, scope_a = await _server(db_session, "kea", subnet)
    kea_b, scope_b = await _server(db_session, "kea", subnet)
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    soon = datetime.now(UTC) + timedelta(hours=1)
    db_session.add(user)
    for n, (srv, scope) in ((10, (kea_a, scope_a)), (20, (kea_b, scope_b))):
        db_session.add_all(
            [
                DHCPLease(
                    server_id=srv.id,
                    scope_id=scope.id,
                    ip_address=f"10.36.19.{n}",
                    mac_address=f"aa:bb:cc:36:19:{n}",
                    state="active",
                    expires_at=soon,
                ),
                IPAddress(
                    subnet_id=subnet.id,
                    address=f"10.36.19.{n}",
                    status="dhcp",
                    auto_from_lease=True,
                    hostname=f"h{n}",
                ),
            ]
        )
    await db_session.commit()
    subnet_id = subnet.id

    await _apply_delete_subnet(
        db_session, user, DeleteSubnetArgs(subnet_id=subnet_id, force=True, permanent=True)
    )

    left = (
        await db_session.execute(
            select(DHCPLease.id).where(DHCPLease.scope_id.in_([scope_a.id, scope_b.id]))
        )
    ).all()
    assert left == []
    assert await db_session.get(Subnet, subnet_id, populate_existing=True) is None


# ── A Trash restore against another id-ordered zone writer (#3627) ──────────


@pytest.mark.asyncio
async def test_trash_restore_locks_its_zones_in_id_order(
    db_session: AsyncSession, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch holds a trashed reverse zone R (higher id) and a trashed record
    of a zone F that stayed (lower id). The restore un-stamped R, then
    re-pushed the record into F: it held R and wanted F, while a DDNS-style
    writer that takes F then R by id held F and wanted R. Now the restore
    pre-locks F and R in id order before it un-stamps anything."""
    from app.api.v1.admin import trash as trash_router
    from app.models.dns import DNSServerGroup, DNSZone
    from app.services.lock_order import lock_zone_rows

    tag = uuid.uuid4().hex[:6]
    grp = DNSServerGroup(name=f"dg-{tag}")
    db_session.add(grp)
    await db_session.flush()
    fwd = DNSZone(
        group_id=grp.id,
        name=f"f{tag}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(fwd)
    await db_session.flush()
    rev = DNSZone(
        group_id=grp.id,
        name=f"1.{tag[:2]}.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(rev)
    await db_session.flush()
    assert fwd.id < rev.id  # the suite makes zone ids ascend in creation order
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    batch = uuid.uuid4()
    now = datetime.now(UTC)
    db_session.add_all(
        [
            user,
            DNSRecord(
                zone_id=fwd.id,
                name="h1",
                fqdn=f"h1.{fwd.name}",
                record_type="A",
                value="10.9.1.1",
                deleted_at=now,
                deletion_batch_id=batch,
            ),
        ]
    )
    rev.deleted_at = now
    rev.deletion_batch_id = batch
    await db_session.commit()
    fwd_id, rev_id, user_id = fwd.id, rev.id, user.id

    holder: dict[str, AsyncSession] = {}
    reached = asyncio.Event()
    log: list[str] = []
    # Held where the unfixed restore has un-stamped R and not yet reached F.
    _hold_first_call(monkeypatch, trash_router, "push_records_restore", holder, reached, log)

    async def _restore() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            holder["db"] = db
            u = await db.get(User, user_id)
            await trash_router.restore_row("dns_zone", rev_id, db, u)

    async def _writer() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            await lock_zone_rows(db, [fwd_id, rev_id])
            await db.commit()

    _no_deadlock(await _race(_restore, _writer, reached), log)

    zone = await db_session.get(DNSZone, rev_id, populate_existing=True)
    assert zone is not None and zone.deleted_at is None
    rec = (
        await db_session.execute(
            select(DNSRecord.deleted_at)
            .where(DNSRecord.zone_id == fwd_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert rec is None


# ── The guard itself ────────────────────────────────────────────────────────


def test_row_lock_guard_does_not_count_an_inserted_zone_as_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zone the transaction inserted cannot be waited for by another one,
    so locking an older zone after it is no cycle. Counted as held, every
    path that creates a zone and then writes an existing one would fail the
    suite (in tests the new zone always has the highest id). A real out-of-
    order pair of existing zones is still recorded."""
    from sqlalchemy.orm import Session

    from app.models.dns import DNSZone
    from tests import _row_lock_order_guard as guard

    recorded: list[str] = []
    monkeypatch.setattr(guard, "_record", lambda _s, what, **_kw: recorded.append(what))
    older, old_b = guard._next_zone_id(), guard._next_zone_id()

    session = Session()
    session.add(DNSZone(name="new.example.com."))
    guard._before_flush(session, None, None)
    guard._lock_zones(session, {older}, "flush")
    assert recorded == []

    guard._lock_zones(session, {old_b}, "flush")  # higher than ``older``: in order
    assert recorded == []
    other = Session()
    guard._lock_zones(other, {old_b}, "flush")
    guard._lock_zones(other, {older}, "flush")  # lower than one held
    assert len(recorded) == 1 and "out of id order" in recorded[0]
