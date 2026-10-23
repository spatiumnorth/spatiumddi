"""#2290 — deleting a DHCP server tears down its leases' IPAM mirrors + DDNS.

``dhcp_lease.server_id`` cascades, so the server delete used to drop the lease
rows and strand the ``status="dhcp"`` / ``auto_from_lease`` mirrors (and their
DDNS records) with nothing left to drive the expiry sweep. An HA peer that
still holds the lease must keep the shared mirror; already-stranded rows are
healed by the orphan sweep.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _token(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"sd-{uuid.uuid4().hex[:6]}",
        email=f"sd-{uuid.uuid4().hex[:6]}@example.test",
        display_name="sd",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _world(db: AsyncSession, n_servers: int = 1):
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    servers = []
    for i in range(n_servers):
        srv = DHCPServer(
            name=f"kea{i}-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host=f"10.0.0.{i + 3}",
            port=67,
            server_group_id=group.id,
        )
        db.add(srv)
        servers.append(srv)
    await db.flush()
    return subnet, scope, servers


async def _lease(db, server, scope, ip, *, mirror=True, subnet=None) -> DHCPLease:
    lease = DHCPLease(
        server_id=server.id,
        scope_id=scope.id,
        ip_address=ip,
        mac_address="aa:bb:cc:00:00:01",
        state="active",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db.add(lease)
    await db.flush()
    if mirror:
        db.add(
            IPAddress(
                subnet_id=subnet.id,
                address=ip,
                status="dhcp",
                auto_from_lease=True,
                hostname="h",
                mac_address="aa:bb:cc:00:00:01",
                dhcp_lease_id=str(lease.id),
            )
        )
        await db.flush()
    return lease


async def _addrs(db: AsyncSession, subnet_id: uuid.UUID) -> set[str]:
    db.expire_all()
    rows = (
        await db.execute(select(IPAddress.address).where(IPAddress.subnet_id == subnet_id))
    ).scalars()
    return {str(a) for a in rows}


@pytest.fixture
def revoked(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def _fake(db, *, subnet, ipam_row):  # type: ignore[no-untyped-def]
        calls.append(str(ipam_row.address))
        return True

    import app.services.dns.ddns as ddns_mod

    monkeypatch.setattr(ddns_mod, "revoke_ddns_for_lease", _fake)
    return calls


@pytest.mark.asyncio
async def test_server_delete_frees_mirrors_and_retracts_ddns(
    client: AsyncClient, db_session: AsyncSession, revoked: list[str]
) -> None:
    subnet, scope, (srv,) = await _world(db_session)
    await _lease(db_session, srv, scope, "10.77.1.10", subnet=subnet)
    await _lease(db_session, srv, scope, "10.77.1.11", subnet=subnet)
    sid = subnet.id
    headers = await _token(db_session)
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dhcp/servers/{srv.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    assert await _addrs(db_session, sid) == set()
    assert sorted(revoked) == ["10.77.1.10", "10.77.1.11"]
    left = (await db_session.execute(select(DHCPLease).where(DHCPLease.server_id == srv.id))).all()
    assert left == []


@pytest.mark.asyncio
async def test_server_delete_spares_mirror_an_ha_peer_still_holds(
    client: AsyncClient, db_session: AsyncSession, revoked: list[str]
) -> None:
    subnet, scope, (a, b) = await _world(db_session, 2)
    await _lease(db_session, a, scope, "10.77.1.20", subnet=subnet)  # shared + mirrored
    await _lease(db_session, b, scope, "10.77.1.20", mirror=False, subnet=subnet)
    await _lease(db_session, a, scope, "10.77.1.21", subnet=subnet)  # only a holds it
    sid = subnet.id
    headers = await _token(db_session)
    await db_session.commit()

    resp = await client.delete(f"/api/v1/dhcp/servers/{a.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    assert await _addrs(db_session, sid) == {"10.77.1.20"}
    assert revoked == ["10.77.1.21"]


@pytest.mark.asyncio
async def test_orphan_sweep_heals_already_stranded_mirrors(
    db_session: AsyncSession, revoked: list[str]
) -> None:
    subnet, scope, (srv, other) = await _world(db_session, 2)
    old = datetime.now(UTC) - timedelta(days=2)

    def _mirror(ip: str, **kw) -> IPAddress:
        return IPAddress(
            subnet_id=subnet.id,
            address=ip,
            status="dhcp",
            auto_from_lease=True,
            hostname="h",
            last_seen_at=old,
            **kw,
        )

    db_session.add(_mirror("10.77.1.30"))  # stranded: no lease anywhere
    db_session.add(_mirror("10.77.1.31"))  # backed by a lease on another server
    await _lease(db_session, other, scope, "10.77.1.31", mirror=False, subnet=subnet)
    recent = _mirror("10.77.1.32")  # inside the grace window
    recent.last_seen_at = datetime.now(UTC)
    db_session.add(recent)
    manual = IPAddress(subnet_id=subnet.id, address="10.77.1.33", status="allocated")
    db_session.add(manual)
    await db_session.flush()

    from app.services.dhcp.lease_cleanup import sweep_orphaned_lease_mirrors  # noqa: PLC0415

    sid = subnet.id
    freed = await sweep_orphaned_lease_mirrors(db_session)
    await db_session.flush()

    assert freed == 1
    assert revoked == ["10.77.1.30"]
    assert await _addrs(db_session, sid) == {"10.77.1.31", "10.77.1.32", "10.77.1.33"}


@pytest.mark.asyncio
async def test_inline_teardown_is_capped_and_sweep_heals_the_rest(
    db_session: AsyncSession, revoked: list[str]
) -> None:
    """Request time is bounded: past the cap the sweep finishes the job."""
    from app.services.dhcp.lease_cleanup import (
        delete_leases_for_server,
        sweep_orphaned_lease_mirrors,
    )

    subnet, scope, (srv,) = await _world(db_session)
    sid, subid = srv.id, subnet.id
    for i in range(5):
        await _lease(db_session, srv, scope, f"10.77.1.{10 + i}", subnet=subnet)
    removed, _ = await delete_leases_for_server(db_session, sid, max_leases=2)
    assert removed == 2
    assert len(await _addrs(db_session, subid)) == 3
    # Cascade drops the remaining lease rows; backdate sightings past the grace.
    old = datetime.now(UTC) - timedelta(hours=3)
    for row in (
        await db_session.execute(select(IPAddress).where(IPAddress.subnet_id == subid))
    ).scalars():
        row.last_seen_at = old
    await db_session.delete(await db_session.get(DHCPServer, sid))
    await db_session.flush()
    assert await sweep_orphaned_lease_mirrors(db_session) == 3
    assert await _addrs(db_session, subid) == set()


@pytest.mark.asyncio
async def test_inline_teardown_stops_at_the_deadline(
    db_session: AsyncSession, revoked: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """#2338 case 6 — with DDNS on a teardown costs ~100 ms, so the count cap
    alone ran a 1,600-lease delete past the proxy timeout. Time bounds it."""
    import app.services.dhcp.lease_cleanup as lc

    subnet, scope, (srv,) = await _world(db_session)
    sid, subid = srv.id, subnet.id
    for i in range(6):
        await _lease(db_session, srv, scope, f"10.77.1.{10 + i}", subnet=subnet)

    clock = {"t": 0.0}
    real_purge = lc.purge_lease

    async def _slow_purge(*a, **kw):  # type: ignore[no-untyped-def]
        clock["t"] += 10.0  # each teardown "costs" 10 s
        return await real_purge(*a, **kw)

    monkeypatch.setattr(lc, "purge_lease", _slow_purge)
    monkeypatch.setattr(lc.time, "monotonic", lambda: clock["t"])

    removed, mirrors = await lc.delete_leases_for_server(db_session, sid, deadline_s=25.0)
    # t=0 start; checks at 0, 10, 20 pass; 30 >= 25 stops: 3 torn down.
    assert removed == 3
    assert mirrors == 3
    assert len(await _addrs(db_session, subid)) == 3  # rest left for the sweep


@pytest.mark.asyncio
async def test_teardown_under_deadline_is_not_capped(
    db_session: AsyncSession, revoked: list[str]
) -> None:
    from app.services.dhcp.lease_cleanup import delete_leases_for_server

    subnet, scope, (srv,) = await _world(db_session)
    sid, subid = srv.id, subnet.id
    for i in range(3):
        await _lease(db_session, srv, scope, f"10.77.1.{10 + i}", subnet=subnet)
    removed, _ = await delete_leases_for_server(db_session, sid)
    assert removed == 3
    assert await _addrs(db_session, subid) == set()
