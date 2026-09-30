"""#1274 — deleting a reservation whose client still holds its lease.

The reserved client's grant arrives while the address row is ``static_dhcp``,
which the lease mirror leaves alone, and the agent sends a lease again only on
its own start, a control-plane recovery or the client's renewal. So freeing the
row to ``available`` at the delete (``detach_ipam_for_static``, #478) showed a
live device's address as free for hours. The row now becomes the live lease's
mirror. ``available`` stays right when no active lease holds the address, and a
lease in another IP space, an expired one, or a reserved hold changes nothing.
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
from app.models.dhcp import (
    DHCPLease,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import detach_ipam_for_static, upsert_ipam_for_static

IP = "10.0.0.20"
MAC = "aa:bb:cc:dd:ee:20"


async def _group(db: AsyncSession, servers: int = 1) -> tuple[DHCPServerGroup, list[DHCPServer]]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srvs = []
    for _ in range(servers):
        srv = DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            port=67,
            server_group_id=grp.id,
        )
        db.add(srv)
        srvs.append(srv)
    await db.flush()
    return grp, srvs


async def _scope(db: AsyncSession, grp: DHCPServerGroup) -> tuple[Subnet, DHCPScope]:
    """A fresh IP space, so two calls give two networks with the same CIDR."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    return subnet, scope


async def _reservation(
    db: AsyncSession, scope: DHCPScope, *, hostname: str = "printer-7"
) -> DHCPStaticAssignment:
    """A reservation and its IPAM mirror, made by the product's own upsert."""
    st = DHCPStaticAssignment(scope_id=scope.id, ip_address=IP, mac_address=MAC, hostname=hostname)
    db.add(st)
    await db.flush()
    await upsert_ipam_for_static(db, scope, st)
    await db.flush()
    return st


def _lease(
    srv: DHCPServer,
    scope: DHCPScope | None,
    *,
    state: str = "active",
    expires_in: timedelta | None = timedelta(hours=8),
    seen_ago: timedelta = timedelta(seconds=5),
    hostname: str | None = "printer-7",
    mac: str = MAC,
) -> DHCPLease:
    """A lease row as the agent's lease events leave it for a reserved client."""
    now = datetime.now(UTC)
    return DHCPLease(
        server_id=srv.id,
        scope_id=scope.id if scope is not None else None,
        ip_address=IP,
        mac_address=mac,
        hostname=hostname,
        state=state,
        starts_at=now - seen_ago,
        ends_at=now + expires_in if expires_in is not None else None,
        expires_at=now + expires_in if expires_in is not None else None,
        last_seen_at=now - seen_ago,
    )


async def _row(db: AsyncSession, subnet: Subnet) -> IPAddress:
    return (
        await db.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet.id, IPAddress.address == IP)
        )
    ).scalar_one()


async def _superadmin_token(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_deleting_the_reservation_hands_its_row_to_the_live_lease(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's steps through the API: reservation, grant, DELETE, read."""
    token = await _superadmin_token(db_session)
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    lease = _lease(srv, scope)
    db_session.add(lease)
    await db_session.commit()
    assert (await _row(db_session, subnet)).status == "static_dhcp"

    r = await client.delete(
        f"/api/v1/dhcp/statics/{st.id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 204, r.text

    row = await _row(db_session, subnet)
    await db_session.refresh(row)
    assert row.status == "dhcp"
    assert row.auto_from_lease is True
    assert row.dhcp_lease_id == str(lease.id)
    assert str(row.mac_address) == MAC
    assert row.hostname == "printer-7"
    assert row.static_assignment_id is None
    assert row.last_seen_method == "dhcp"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "lease_kw",
    [
        None,  # nothing holds the address
        {"state": "expired", "expires_in": timedelta(hours=-1)},
        {"state": "released"},
        # still "active" but past its expiry: the sweep has not reached it yet
        {"state": "active", "expires_in": timedelta(minutes=-5)},
    ],
    ids=["no-lease", "expired", "released", "active-past-expiry"],
)
async def test_the_row_is_freed_when_no_active_lease_holds_the_address(
    db_session: AsyncSession, lease_kw: dict | None
) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    if lease_kw is not None:
        db_session.add(_lease(srv, scope, **lease_kw))
    await db_session.flush()

    await detach_ipam_for_static(db_session, st)
    await db_session.flush()

    row = await _row(db_session, subnet)
    assert row.status == "available"
    assert row.auto_from_lease is False
    assert row.dhcp_lease_id is None
    assert row.static_assignment_id is None


@pytest.mark.asyncio
async def test_a_live_lease_on_the_same_address_in_another_ip_space_does_not_claim_it(
    db_session: AsyncSession,
) -> None:
    grp, _ = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    other_grp, (other_srv,) = await _group(db_session)
    _other_subnet, other_scope = await _scope(db_session, other_grp)
    db_session.add(_lease(other_srv, other_scope))
    await db_session.flush()

    await detach_ipam_for_static(db_session, st)
    await db_session.flush()

    assert (await _row(db_session, subnet)).status == "available"


@pytest.mark.asyncio
async def test_a_legacy_lease_with_no_scope_is_matched_by_its_subnet(
    db_session: AsyncSession,
) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    lease = _lease(srv, None)
    db_session.add(lease)
    await db_session.flush()

    await detach_ipam_for_static(db_session, st)
    await db_session.flush()

    row = await _row(db_session, subnet)
    assert (row.status, row.dhcp_lease_id) == ("dhcp", str(lease.id))


@pytest.mark.asyncio
async def test_under_ha_the_most_recently_seen_copy_of_the_lease_is_linked(
    db_session: AsyncSession,
) -> None:
    grp, (srv_a, srv_b) = await _group(db_session, servers=2)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    stale = _lease(srv_a, scope, seen_ago=timedelta(minutes=3))
    fresh = _lease(srv_b, scope, seen_ago=timedelta(seconds=2))
    db_session.add_all([stale, fresh])
    await db_session.flush()

    await detach_ipam_for_static(db_session, st)
    await db_session.flush()

    assert (await _row(db_session, subnet)).dhcp_lease_id == str(fresh.id)


@pytest.mark.asyncio
async def test_a_reserved_hold_stays_held_over_a_live_lease(db_session: AsyncSession) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    db_session.add(_lease(srv, scope))
    await db_session.flush()

    await detach_ipam_for_static(db_session, st, to_status="reserved")
    await db_session.flush()

    row = await _row(db_session, subnet)
    assert (row.status, row.auto_from_lease, row.dhcp_lease_id) == ("reserved", False, None)


@pytest.mark.asyncio
async def test_the_mirror_takes_the_leases_name_and_keeps_a_later_sighting(
    db_session: AsyncSession,
) -> None:
    """The lease's MAC and name win, as they do when the ingest takes a row
    over; a lease with no name keeps the row's. A sighting on the row newer
    than the lease's last report (a discovery sweep) is not moved back."""
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope, hostname="printer-7")
    swept = datetime.now(UTC) - timedelta(seconds=1)
    row = await _row(db_session, subnet)
    row.last_seen_at, row.last_seen_method = swept, "arp"
    db_session.add(_lease(srv, scope, hostname=None, seen_ago=timedelta(minutes=2)))
    await db_session.flush()

    await detach_ipam_for_static(db_session, st)
    await db_session.flush()

    row = await _row(db_session, subnet)
    assert row.status == "dhcp"
    assert row.hostname == "printer-7"
    assert (row.last_seen_at, row.last_seen_method) == (swept, "arp")


@pytest.mark.asyncio
async def test_the_leases_own_mac_and_name_win(db_session: AsyncSession) -> None:
    """A lease whose name and MAC differ from the reservation's stamps its own,
    as the ingest does when it takes a row over."""
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope, hostname="printer-7")
    db_session.add(_lease(srv, scope, hostname="laptop-9", mac="aa:bb:cc:dd:ee:99"))
    await db_session.flush()

    await detach_ipam_for_static(db_session, st)
    await db_session.flush()

    row = await _row(db_session, subnet)
    assert row.hostname == "laptop-9"
    assert str(row.mac_address) == "aa:bb:cc:dd:ee:99"


@pytest.mark.asyncio
async def test_in_a_ddns_subnet_the_mirror_gets_its_dns_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reservation's A record is torn down at the delete. The ingest
    publishes DDNS whenever it takes a row over, so the hand-over does too,
    under the LEASE's name: DDNS lets a reservation's hostname win, so a
    publish before the reservation is gone would put its name back."""
    token = await _superadmin_token(db_session)
    dns_group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(dns_group)
    await db_session.flush()
    zone = DNSZone(
        group_id=dns_group.id,
        name="lan.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.lan.example.",
        admin_email="admin.lan.example.",
    )
    db_session.add(zone)
    await db_session.flush()

    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    subnet.dns_zone_id = str(zone.id)
    subnet.dns_inherit_settings = False
    subnet.ddns_enabled = True
    subnet.ddns_inherit_settings = False
    subnet.ddns_hostname_policy = "client_or_generated"
    await db_session.flush()
    st = await _reservation(db_session, scope, hostname="printer-7")
    db_session.add(_lease(srv, scope, hostname="laptop-9"))
    await db_session.commit()

    r = await client.delete(
        f"/api/v1/dhcp/statics/{st.id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 204, r.text

    row = await _row(db_session, subnet)
    await db_session.refresh(row)
    assert row.status == "dhcp"
    assert row.hostname == "laptop-9"
    assert row.dns_record_id is not None
    names = (
        (
            await db_session.execute(
                select(DNSRecord.name).where(
                    DNSRecord.ip_address_id == row.id, DNSRecord.record_type == "A"
                )
            )
        )
        .scalars()
        .all()
    )
    assert names == ["laptop-9"]
