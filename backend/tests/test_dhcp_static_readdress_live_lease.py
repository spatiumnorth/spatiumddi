"""#1302 — moving a reservation while its client still holds the lease on the old address.

The reserved client's grant arrives while the old address's row is
``static_dhcp``, which the lease mirror leaves alone, and the agent sends a
lease again only at the client's renewal, the lease's expiry or its own
restart. So deleting that row when the reservation moved
(``upsert_ipam_for_static``, #620) showed a live device's address as free until
then. The old address now gets the live lease's mirror row, as the ingest would
create it. With no active lease on it the address is still freed, and the
reservation's own row still moves to the new address.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.core.security import create_access_token, hash_password
from app.main import app
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
from app.services.dhcp.static_ipam import upsert_ipam_for_static

OLD = "10.0.0.20"
NEW = "10.0.0.21"
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


async def _scope(
    db: AsyncSession, grp: DHCPServerGroup, *, network: str = "10.0.0.0/24", family: str = "ipv4"
) -> tuple[Subnet, DHCPScope]:
    """A fresh IP space, so two calls give two networks with the same CIDR."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block_net = "10.0.0.0/16" if family == "ipv4" else "2001:db8::/48"
    block = IPBlock(space_id=space.id, network=block_net, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True, address_family=family)
    db.add(scope)
    await db.flush()
    return subnet, scope


async def _reservation(
    db: AsyncSession,
    scope: DHCPScope,
    *,
    ip: str = OLD,
    hostname: str = "printer-7",
    duid: str | None = None,
) -> DHCPStaticAssignment:
    """A reservation and its IPAM mirror, made by the product's own upsert."""
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address=ip, mac_address=MAC, hostname=hostname, duid=duid
    )
    db.add(st)
    await db.flush()
    await upsert_ipam_for_static(db, scope, st)
    await db.flush()
    return st


def _lease(
    srv: DHCPServer,
    scope: DHCPScope | None,
    *,
    ip: str = OLD,
    state: str = "active",
    expires_in: timedelta | None = timedelta(hours=8),
    seen_ago: timedelta = timedelta(seconds=5),
    hostname: str | None = "printer-7",
    mac: str | None = MAC,
    duid: str | None = None,
    iaid: int | None = None,
) -> DHCPLease:
    """A lease row as the agent's lease events leave it for a reserved client."""
    now = datetime.now(UTC)
    return DHCPLease(
        server_id=srv.id,
        scope_id=scope.id if scope is not None else None,
        ip_address=ip,
        mac_address=mac,
        duid=duid,
        iaid=iaid,
        hostname=hostname,
        state=state,
        starts_at=now - seen_ago,
        ends_at=now + expires_in if expires_in is not None else None,
        expires_at=now + expires_in if expires_in is not None else None,
        last_seen_at=now - seen_ago,
    )


async def _move(
    db: AsyncSession, scope: DHCPScope, st: DHCPStaticAssignment, ip: str = NEW
) -> None:
    """The re-address as ``update_static`` runs it: the new address, flushed,
    then the mirror upsert."""
    st.ip_address = ip
    await db.flush()
    await upsert_ipam_for_static(db, scope, st, action="update")
    await db.flush()


async def _row(db: AsyncSession, subnet: Subnet, ip: str) -> IPAddress | None:
    return (
        await db.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet.id, IPAddress.address == ip)
        )
    ).scalar_one_or_none()


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
async def test_moving_the_reservation_hands_the_old_address_to_the_live_lease(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's steps through the API: reservation, grant, PUT, read both."""
    token = await _superadmin_token(db_session)
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    old_row = await _row(db_session, subnet, OLD)
    assert old_row is not None and old_row.status == "static_dhcp"
    old_row_id = old_row.id
    lease = _lease(srv, scope)
    db_session.add(lease)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/statics/{st.id}",
        json={"ip_address": NEW},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text

    db_session.expunge_all()
    row = await _row(db_session, subnet, OLD)
    assert row is not None, "the old address reads as free beside its live lease"
    assert row.id != old_row_id  # a new row, as the ingest would create it
    assert row.status == "dhcp"
    assert row.auto_from_lease is True
    assert row.dhcp_lease_id == str(lease.id)
    assert str(row.mac_address) == MAC
    assert row.hostname == "printer-7"
    assert row.static_assignment_id is None
    assert row.last_seen_method == "dhcp"
    moved = await _row(db_session, subnet, NEW)
    assert moved is not None
    assert (moved.status, moved.static_assignment_id) == ("static_dhcp", str(st.id))
    assert r.json()["ip_address_id"] == str(moved.id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "lease_kw",
    [
        None,  # nothing holds the address
        {"state": "expired", "expires_in": timedelta(hours=-1)},
        {"state": "released"},
        # still "active" but past its expiry: the sweep has not reached it yet
        {"state": "active", "expires_in": timedelta(minutes=-5)},
        # an active lease, but on the address the reservation moves TO
        {"ip": NEW},
    ],
    ids=["no-lease", "expired", "released", "active-past-expiry", "lease-on-new-address"],
)
async def test_the_old_address_is_freed_when_no_active_lease_holds_it(
    db_session: AsyncSession, lease_kw: dict[str, Any] | None
) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    if lease_kw is not None:
        db_session.add(_lease(srv, scope, **lease_kw))
    await db_session.flush()

    await _move(db_session, scope, st)

    assert await _row(db_session, subnet, OLD) is None
    moved = await _row(db_session, subnet, NEW)
    assert moved is not None
    assert (moved.status, moved.static_assignment_id) == ("static_dhcp", str(st.id))


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

    await _move(db_session, scope, st)

    assert await _row(db_session, subnet, OLD) is None


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

    await _move(db_session, scope, st)

    row = await _row(db_session, subnet, OLD)
    assert row is not None
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

    await _move(db_session, scope, st)

    row = await _row(db_session, subnet, OLD)
    assert row is not None and row.dhcp_lease_id == str(fresh.id)
    assert row.last_seen_at == fresh.last_seen_at


@pytest.mark.asyncio
async def test_the_leases_own_mac_and_name_win(db_session: AsyncSession) -> None:
    """A lease whose name and MAC differ from the reservation's stamps its own,
    as the ingest does — nothing of the reservation's is carried over."""
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope, hostname="printer-7")
    db_session.add(_lease(srv, scope, hostname="laptop-9", mac="aa:bb:cc:dd:ee:99"))
    await db_session.flush()

    await _move(db_session, scope, st)

    row = await _row(db_session, subnet, OLD)
    assert row is not None
    assert row.hostname == "laptop-9"
    assert str(row.mac_address) == "aa:bb:cc:dd:ee:99"


@pytest.mark.asyncio
async def test_a_lease_with_no_name_and_no_mac_leaves_them_empty(
    db_session: AsyncSession,
) -> None:
    """A DHCPv6 lease keyed on DUID + IAID carries no MAC (#1141), and a client
    may send no name: the new row takes neither from the reservation."""
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp, network="2001:db8::/64", family="ipv6")
    st = await _reservation(db_session, scope, ip="2001:db8::20", duid="00:03:00:01:aa:bb")
    lease = _lease(
        srv,
        scope,
        ip="2001:db8::20",
        hostname=None,
        mac=None,
        duid="00:03:00:01:aa:bb",
        iaid=7,
    )
    db_session.add(lease)
    await db_session.flush()

    await _move(db_session, scope, st, ip="2001:db8::21")

    row = await _row(db_session, subnet, "2001:db8::20")
    assert row is not None
    assert (row.status, row.dhcp_lease_id) == ("dhcp", str(lease.id))
    assert row.mac_address is None
    assert row.hostname == ""


@pytest.mark.asyncio
async def test_the_operators_fields_move_with_the_reservation_not_onto_the_leases_row(
    db_session: AsyncSession,
) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    old_row = await _row(db_session, subnet, OLD)
    assert old_row is not None
    old_row.description = "front-desk printer"
    old_row.tags = {"site": "hq"}
    old_row.custom_fields = {"asset": "P-0007"}
    db_session.add(_lease(srv, scope))
    await db_session.flush()

    await _move(db_session, scope, st)

    moved = await _row(db_session, subnet, NEW)
    assert moved is not None
    assert (moved.description, moved.tags, moved.custom_fields) == (
        "front-desk printer",
        {"site": "hq"},
        {"asset": "P-0007"},
    )
    row = await _row(db_session, subnet, OLD)
    assert row is not None and row.status == "dhcp"
    assert not row.description and not row.tags and not row.custom_fields


@pytest.mark.asyncio
async def test_in_a_ddns_subnet_the_old_address_gets_the_leases_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reservation's A record follows it to the new address. The ingest
    publishes DDNS whenever it creates a lease's row, so the hand-over does too,
    under the LEASE's name: the reservation no longer sits at the old address,
    so its name does not win there."""
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

    r = await client.put(
        f"/api/v1/dhcp/statics/{st.id}",
        json={"ip_address": NEW},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text

    db_session.expunge_all()
    row = await _row(db_session, subnet, OLD)
    moved = await _row(db_session, subnet, NEW)
    assert row is not None and moved is not None
    assert (row.status, row.hostname) == ("dhcp", "laptop-9")
    assert row.dns_record_id is not None

    async def a_names(ip_row: IPAddress) -> list[str]:
        return list(
            (
                await db_session.execute(
                    select(DNSRecord.name).where(
                        DNSRecord.ip_address_id == ip_row.id, DNSRecord.record_type == "A"
                    )
                )
            )
            .scalars()
            .all()
        )

    assert await a_names(row) == ["laptop-9"]
    assert await a_names(moved) == ["printer-7"]


@pytest.mark.asyncio
async def test_an_edit_that_keeps_the_address_changes_nothing_under_a_live_lease(
    db_session: AsyncSession,
) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    before = await _row(db_session, subnet, OLD)
    assert before is not None
    before_id = before.id
    db_session.add(_lease(srv, scope))
    await db_session.flush()

    st.hostname = "printer-8"
    await _move(db_session, scope, st, ip=OLD)

    row = await _row(db_session, subnet, OLD)
    assert row is not None
    assert (row.id, row.status, row.static_assignment_id, row.auto_from_lease) == (
        before_id,
        "static_dhcp",
        str(st.id),
        False,
    )
    assert row.hostname == "printer-8"


@pytest.mark.asyncio
async def test_a_row_the_operator_repurposed_is_left_to_the_operator(
    db_session: AsyncSession,
) -> None:
    """Only the reservation's own ``static_dhcp`` row is released; a row an
    operator moved to another status keeps it, live lease or not."""
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    row = await _row(db_session, subnet, OLD)
    assert row is not None
    row.status = "allocated"
    row_id = row.id
    db_session.add(_lease(srv, scope))
    await db_session.flush()

    await _move(db_session, scope, st)

    row = await _row(db_session, subnet, OLD)
    assert row is not None
    assert (row.id, row.status, row.static_assignment_id, row.auto_from_lease) == (
        row_id,
        "allocated",
        None,
        False,
    )


def _ev(ip: str, state: str) -> dict[str, Any]:
    end = datetime.now(UTC) + (timedelta(hours=1) if state == "active" else timedelta(0))
    return {
        "ip_address": ip,
        "mac_address": MAC,
        "hostname": "printer-7",
        "state": state,
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end.isoformat(),
        "expires_at": end.isoformat(),
    }


async def _post_events(
    client: AsyncClient, db: AsyncSession, server: DHCPServer, events: list[dict[str, Any]]
) -> None:
    db.expunge_all()  # the request must load its rows like production does
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": events})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_the_handed_over_row_goes_with_its_lease_when_the_client_moves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The client's next contact moves it to the reserved address: the old
    lease ends and the new one starts. The old address's row is the lease's,
    so it goes with the lease; the reservation's row at the new address is left
    alone by the lease, as before."""
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    db_session.add(_lease(srv, scope))
    await db_session.flush()
    await _move(db_session, scope, st)
    await db_session.commit()

    await _post_events(client, db_session, srv, [_ev(OLD, "released"), _ev(NEW, "active")])

    db_session.expunge_all()
    assert await _row(db_session, subnet, OLD) is None
    moved = await _row(db_session, subnet, NEW)
    assert moved is not None
    assert (moved.status, moved.static_assignment_id, moved.auto_from_lease) == (
        "static_dhcp",
        str(st.id),
        False,
    )
