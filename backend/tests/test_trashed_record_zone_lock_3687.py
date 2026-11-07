"""#3687: a purge of an address's trashed DNS records runs after its zone is locked.

A permanent zone delete takes the zone row, then deletes the zone's records,
trashed ones included (#3652). A lease path that purged an address's trashed
auto record in zone Z before it locked Z, and later published or revoked a live
record in Z, held the record and waited for the zone while the delete held the
zone and waited for the record. The up-front zone lock named only the zones
holding LIVE records, so a zone holding only a trashed record of an address was
left out.

Each race test plays the delete by hand on its own session: it holds the zone
row (``FOR UPDATE``), lets the path run into it, then deletes the zone's
records, as the real delete does next. Unfixed, the path has already deleted a
trashed record that statement needs, and Postgres breaks the cycle with 40P01
on one side; fixed, the path is parked on the zone row before it touched a
record, and both finish.
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

from app.models.dhcp import DHCPLease, DHCPStaticAssignment
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress, Subnet
from tests.test_lease_events_insert_order_3480 import (  # noqa: F401 — the fixture
    _ddns_subnet,
    _lease,
    _two_agents,
    concurrent_client,
)
from tests.test_lock_order_3617 import _server

_PARK_DEADLINE_S = 20.0
_STEP = 30.0


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    eng = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        yield eng
    finally:
        await eng.dispose()


async def _blocked_by(probe: AsyncSession, pid: int) -> bool:
    await probe.execute(text("SELECT pg_stat_clear_snapshot()"))
    n = (
        await probe.execute(
            text("SELECT count(*) FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid))"),
            {"pid": pid},
        )
    ).scalar_one()
    return bool(n)


async def _zone_delete_race(
    engine: AsyncEngine,
    zone_id: uuid.UUID,
    path: Callable[[], Awaitable[Any]],
    *,
    take_chain_lock: bool = False,
) -> None:
    """Hold ``zone_id``, start ``path``, let it park on the zone, then delete
    the zone's records. Fails if either side errors (a deadlock, say).

    ``take_chain_lock`` has the delete take the audit-chain advisory lock next,
    as the real zone delete does at its audit flush, so a path that holds the
    chain lock while it waits for the zone deadlocks with it."""
    gate = AsyncSession(engine)
    probe = AsyncSession(engine)
    task: asyncio.Task[Any] | None = None
    try:
        await gate.execute(text("SELECT id FROM dns_zone WHERE id = :z FOR UPDATE"), {"z": zone_id})
        gate_pid = (await gate.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        task = asyncio.create_task(path())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _PARK_DEADLINE_S
        parked = False
        while loop.time() < deadline and not task.done():
            if await _blocked_by(probe, gate_pid):
                parked = True
                break
            await asyncio.sleep(0.05)
        assert parked, f"the path never waited on the zone: {task.done() and task.exception()!r}"
        gate_error: BaseException | None = None
        try:
            if take_chain_lock:
                from app.services.audit_chain import _AUDIT_CHAIN_LOCK_KEY  # noqa: PLC0415

                await asyncio.wait_for(
                    gate.execute(
                        text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_CHAIN_LOCK_KEY}
                    ),
                    _STEP,
                )
            await asyncio.wait_for(
                gate.execute(text("DELETE FROM dns_record WHERE zone_id = :z"), {"z": zone_id}),
                _STEP,
            )
            await gate.commit()
        except BaseException as exc:  # noqa: BLE001 — reported below
            gate_error = exc
            await gate.rollback()
        result = (await asyncio.gather(task, return_exceptions=True))[0]
        assert gate_error is None, f"the zone delete failed: {gate_error!r}"
        assert not isinstance(result, BaseException), f"the path failed: {result!r}"
    finally:
        if task is not None and not task.done():
            task.cancel()
        await gate.close()
        await probe.close()


async def _forward_zone(db: AsyncSession, subnet: Subnet) -> uuid.UUID:
    return uuid.UUID(str(subnet.dns_zone_id))


def _trashed(zone_id: uuid.UUID, ip_id: uuid.UUID, name: str, value: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone_id,
        name=name,
        fqdn=f"{name}.example.",
        record_type="A",
        value=value,
        auto_generated=True,
        ip_address_id=ip_id,
        deleted_at=datetime.now(UTC),
    )


async def _live_published(db: AsyncSession, subnet: Subnet, row: IPAddress, host: str) -> None:
    from app.services.dns import ddns

    assert await ddns.apply_ddns_for_lease(db, subnet=subnet, ipam_row=row, client_hostname=host)


# ── the lock set ────────────────────────────────────────────────────────────


async def _zone_is_locked(engine: AsyncEngine, zone_id: uuid.UUID) -> bool:
    async with AsyncSession(engine) as other:
        try:
            await other.execute(text("SET lock_timeout = '300ms'"))
            await other.execute(
                text("SELECT id FROM dns_zone WHERE id = :z FOR NO KEY UPDATE"), {"z": zone_id}
            )
        except Exception:  # noqa: BLE001 — lock_timeout
            return True
        return False


@pytest.mark.asyncio
async def test_the_lock_set_names_a_zone_holding_only_a_trashed_record(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    from app.services.lock_order import _published_zone_ids, lock_zones_for_addresses

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    row = IPAddress(subnet_id=subnet.id, address="10.31.1.40", status="dhcp", auto_from_lease=True)
    db_session.add(row)
    await db_session.flush()
    db_session.add(_trashed(zid, row.id, "gone", "10.31.1.40"))
    await db_session.commit()

    assert await _published_zone_ids(db_session, [row.id]) == {zid}
    assert not await _zone_is_locked(engine, zid)
    await lock_zones_for_addresses(db_session, retracting=[row])
    assert await _zone_is_locked(engine, zid)
    await db_session.rollback()


@pytest.mark.asyncio
async def test_lock_zones_for_lease_mirrors_names_a_trashed_only_zone(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    from app.services.lock_order import lock_zones_for_lease_mirrors

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    _srv, scope = await _server(db_session, "kea", subnet)
    srv_id = _srv.id
    row = IPAddress(subnet_id=subnet.id, address="10.31.1.41", status="dhcp", auto_from_lease=True)
    lease = DHCPLease(
        server_id=srv_id,
        scope_id=scope.id,
        ip_address="10.31.1.41",
        mac_address="aa:bb:cc:31:01:41",
        state="active",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add_all([row, lease])
    await db_session.flush()
    db_session.add(_trashed(zid, row.id, "gone", "10.31.1.41"))
    await db_session.commit()

    await lock_zones_for_lease_mirrors(db_session, [lease.id])
    assert await _zone_is_locked(engine, zid)
    await db_session.rollback()


# ── the races ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_orphan_mirror_sweep_does_not_deadlock_a_zone_delete(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    """A holds a live DDNS record in Z; B only a trashed one. The sweep purged
    B's, then revoked A's, which locks Z."""
    from app.services.dhcp.lease_cleanup import sweep_orphaned_lease_mirrors

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    a = IPAddress(subnet_id=subnet.id, address="10.31.1.30", status="dhcp", auto_from_lease=True)
    b = IPAddress(subnet_id=subnet.id, address="10.31.1.40", status="dhcp", auto_from_lease=True)
    db_session.add_all([a, b])
    await db_session.flush()
    await _live_published(db_session, subnet, a, "a-host")
    db_session.add(_trashed(zid, b.id, "b-host", "10.31.1.40"))
    await db_session.commit()

    async def _sweep() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            assert await sweep_orphaned_lease_mirrors(db) == 2
            await db.commit()

    await _zone_delete_race(engine, zid, _sweep)


@pytest.mark.asyncio
async def test_server_delete_does_not_deadlock_a_zone_delete(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    """B's lease sorts first: its purge ran before A's revoke locked Z."""
    from app.services.dhcp.lease_cleanup import delete_leases_for_server

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    srv, scope = await _server(db_session, "kea", subnet)
    a = IPAddress(subnet_id=subnet.id, address="10.31.1.30", status="dhcp", auto_from_lease=True)
    b = IPAddress(subnet_id=subnet.id, address="10.31.1.40", status="dhcp", auto_from_lease=True)
    db_session.add_all([a, b])
    await db_session.flush()
    await _live_published(db_session, subnet, a, "a-host")
    db_session.add(_trashed(zid, b.id, "b-host", "10.31.1.40"))
    soon = datetime.now(UTC) + timedelta(hours=1)
    db_session.add_all(
        DHCPLease(
            id=uuid.UUID(int=n),
            server_id=srv.id,
            scope_id=scope.id,
            ip_address=ip,
            mac_address=f"aa:bb:cc:31:01:{n:02x}",
            state="active",
            expires_at=soon,
        )
        for n, ip in ((1, "10.31.1.40"), (2, "10.31.1.30"))
    )
    await db_session.commit()
    srv_id = srv.id

    async def _delete() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            removed, _mirrors = await delete_leases_for_server(db, srv_id)
            assert removed == 2
            await db.commit()

    await _zone_delete_race(engine, zid, _delete)


@pytest.mark.asyncio
async def test_server_delete_route_audits_after_the_zone_locks(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    """``delete_server`` staged its audit row first; the teardown's first query
    autoflushed it, so the chain lock was held while the zone rows were
    waited for. A zone delete holds the zone and then wants the chain lock."""
    from app.api.v1.dhcp.servers import delete_server
    from app.core.security import hash_password
    from app.models.auth import User

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    srv, scope = await _server(db_session, "kea", subnet)
    a = IPAddress(subnet_id=subnet.id, address="10.31.1.30", status="dhcp", auto_from_lease=True)
    db_session.add(a)
    await db_session.flush()
    await _live_published(db_session, subnet, a, "a-host")
    db_session.add(
        DHCPLease(
            server_id=srv.id,
            scope_id=scope.id,
            ip_address="10.31.1.30",
            mac_address="aa:bb:cc:31:01:30",
            state="active",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    admin = User(
        username=f"sd-{uuid.uuid4().hex[:6]}",
        email=f"sd-{uuid.uuid4().hex[:6]}@example.test",
        display_name="sd",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    admin.groups = []
    db_session.add(admin)
    await db_session.commit()
    srv_id, admin_id = srv.id, admin.id

    async def _delete() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            user = await db.get(User, admin_id)
            assert user is not None
            await delete_server(srv_id, db, user)

    await _zone_delete_race(engine, zid, _delete, take_chain_lock=True)


@pytest.mark.asyncio
async def test_reservation_hand_over_does_not_deadlock_a_zone_delete(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    """The address has no live record, only a trashed A in Z. The detach
    purged it with no lock on Z, and the hand-over's publish locked Z."""
    from app.services.dhcp.static_ipam import detach_ipam_for_static, publish_handover_ddns

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    srv, scope = await _server(db_session, "kea", subnet)
    st = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address="10.31.1.50",
        mac_address="aa:bb:cc:31:01:50",
        hostname="res",
    )
    db_session.add(st)
    await db_session.flush()
    row = IPAddress(
        subnet_id=subnet.id,
        address="10.31.1.50",
        status="static_dhcp",
        static_assignment_id=str(st.id),
        hostname="res",
    )
    db_session.add(row)
    db_session.add(
        DHCPLease(
            server_id=srv.id,
            scope_id=scope.id,
            ip_address="10.31.1.50",
            mac_address="aa:bb:cc:31:01:50",
            state="active",
            hostname="res",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await db_session.flush()
    db_session.add(_trashed(zid, row.id, "res", "10.31.1.50"))
    await db_session.commit()
    st_id, row_id = st.id, row.id

    async def _delete() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            reservation = await db.get(DHCPStaticAssignment, st_id)
            assert reservation is not None
            handovers = await detach_ipam_for_static(db, reservation)
            assert handovers, "the address was not handed to its lease"
            await db.delete(reservation)
            await db.flush()
            await publish_handover_ddns(db, handovers)
            await db.commit()

    await _zone_delete_race(engine, zid, _delete)
    # The hand-over's DDNS is best-effort: a deadlock inside it is swallowed
    # and logged, so what shows it is the record it then did not publish.
    published = (
        await db_session.execute(
            select(DNSRecord.id).where(DNSRecord.ip_address_id == row_id, DNSRecord.zone_id == zid)
        )
    ).all()
    assert published, "the hand-over published nothing: its zone lock failed"


@pytest.mark.asyncio
async def test_auto_sync_reapply_does_not_deadlock_a_zone_delete(
    db_session: AsyncSession, engine: AsyncEngine
) -> None:
    """B has no name and only a trashed host record in Z, so its re-apply
    retracts and purges it; A's re-apply then publishes into Z. Each row's
    sync locks its own zones, trashed records' included, before it purges, so
    no up-front lock of every zone the run may write is needed (one would hold
    every DDNS zone for the whole run, every interval)."""
    from app.tasks.ipam_dns_sync import _reapply_ddns_for_active_leases

    subnet, _ = await _ddns_subnet(db_session)
    subnet.ddns_hostname_policy = "client_provided"
    zid = await _forward_zone(db_session, subnet)
    b = IPAddress(subnet_id=subnet.id, address="10.31.1.40", status="dhcp", auto_from_lease=True)
    db_session.add(b)
    await db_session.flush()
    a = IPAddress(
        subnet_id=subnet.id,
        address="10.31.1.30",
        status="dhcp",
        auto_from_lease=True,
        hostname="a-host",
    )
    db_session.add(a)
    await db_session.flush()
    db_session.add(_trashed(zid, b.id, "b-host", "10.31.1.40"))
    await db_session.commit()
    subnet_id, a_id = subnet.id, a.id

    async def _reapply() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            sub = await db.get(Subnet, subnet_id)
            assert sub is not None
            fired, errors = await _reapply_ddns_for_active_leases(db, sub)
            assert not errors, errors
            assert fired == 1
            await db.commit()

    await _zone_delete_race(engine, zid, _reapply)
    published = (
        await db_session.execute(
            select(DNSRecord.id).where(DNSRecord.ip_address_id == a_id, DNSRecord.zone_id == zid)
        )
    ).all()
    assert published


@pytest.mark.asyncio
async def test_lease_events_lock_a_mirror_made_in_the_pass_up_front(
    concurrent_client: Any,  # noqa: F811 — the imported fixture
    db_session: AsyncSession,
) -> None:
    """Y's mirror holds only a trashed record, in a zone made after the
    subnet's, so its id sorts last. X has no mirror and its first event is a
    release, so the grant after it creates the mirror inside the pass. Its
    publish took the subnet's zones after the up-front lock had taken Y's
    zone: out of id order (the row lock order guard fails the test then)."""
    from app.models.dns import DNSZone

    subnet, _ = await _ddns_subnet(db_session)
    late = DNSZone(
        group_id=(await db_session.get(DNSZone, await _forward_zone(db_session, subnet))).group_id,
        name=f"late{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.late.example.",
        admin_email="admin.late.example.",
    )
    db_session.add(late)
    await db_session.flush()
    y = IPAddress(subnet_id=subnet.id, address="10.31.1.60", status="dhcp", auto_from_lease=True)
    db_session.add(y)
    await db_session.flush()
    db_session.add(_trashed(late.id, y.id, "y-host", "10.31.1.60"))
    await db_session.commit()
    (server,) = (await _two_agents(db_session, [subnet]))[:1]
    x_id_subnet = subnet.id

    def _event(ip: str, n: int, state: str) -> dict[str, Any]:
        ev = _lease(ip, n)
        ev["state"] = state
        return ev

    events = [
        _event("10.31.1.60", 0x60, "released"),
        _event("10.31.1.70", 0x70, "released"),
        _event("10.31.1.70", 0x70, "active"),
    ]
    resp = await concurrent_client.post(
        "/api/v1/dhcp/agents/lease-events",
        headers={"x-test-server": str(server.id)},
        json={"leases": events},
    )
    assert resp.status_code == 200, resp.text
    x = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == x_id_subnet, IPAddress.address == "10.31.1.70")
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert (
        await db_session.execute(select(DNSRecord.id).where(DNSRecord.ip_address_id == x.id))
    ).all(), "the grant published nothing"
