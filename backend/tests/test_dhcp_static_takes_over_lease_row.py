"""#1404 — a reservation that takes a lease's IPAM row takes it whole.

Reserving an address whose IPAM row mirrors a DHCP lease (``status: dhcp``,
``auto_from_lease``, ``dhcp_lease_id``) made the row ``static_dhcp`` with the
reservation's name, MAC and back-link, but left it ``auto_from_lease`` and
linked to the lease. That happens on "pin this device to the address it
already has", and on moving a reservation back onto an address #1302 handed to
the live lease. The lease-event ingest takes those flags at their word: the
client's next lease event turned the reservation's row back into a ``dhcp``
row under a standing reservation, and a release or expiry of the lease deleted
the row, so the reserved address read as free. Reproduced on nightly-2026.09.30
(f838ab85) with a real client against Kea.

Once a reservation takes a row, the row is the reservation's:
``auto_from_lease`` false, ``dhcp_lease_id`` null. The lease mirror then leaves
it alone, as it does any ``static_dhcp`` row.
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
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import upsert_ipam_for_static

ADDR = "10.0.0.30"
OTHER = "10.0.0.31"
MAC = "aa:bb:cc:dd:ee:30"


async def _group(db: AsyncSession) -> tuple[DHCPServerGroup, DHCPServer]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()
    return grp, srv


async def _scope(db: AsyncSession, grp: DHCPServerGroup) -> tuple[Subnet, DHCPScope]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True, address_family="ipv4")
    db.add(scope)
    await db.flush()
    return subnet, scope


async def _row(db: AsyncSession, subnet: Subnet, ip: str) -> IPAddress | None:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == subnet.id, IPAddress.address == ip)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _token(db: AsyncSession) -> str:
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


def _ev(ip: str, state: str = "active", hostname: str = "client-30") -> dict[str, Any]:
    now = datetime.now(UTC)
    end = now + (timedelta(hours=1) if state == "active" else timedelta(0))
    return {
        "ip_address": ip,
        "mac_address": MAC,
        "hostname": hostname,
        "state": state,
        "starts_at": now.isoformat(),
        "ends_at": end.isoformat(),
        "expires_at": end.isoformat(),
    }


async def _post_events(
    client: AsyncClient, db: AsyncSession, server: DHCPServer, events: list[dict[str, Any]]
) -> None:
    """The agent's lease events, through the real route."""
    db.expunge_all()  # the request must load its rows like production does
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": events})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


def _flags(row: IPAddress) -> tuple[str, bool, str | None, str | None]:
    return (row.status, row.auto_from_lease, row.dhcp_lease_id, row.static_assignment_id)


async def _pin(client: AsyncClient, db: AsyncSession) -> tuple[Subnet, DHCPServer, uuid.UUID, str]:
    """The issue's steps 1-3: a client leases ADDR, then ADDR is reserved for
    the client's MAC through the API. Returns the subnet, the server, the
    mirror row's id and the reservation's id."""
    token = await _token(db)
    grp, srv = await _group(db)
    subnet, scope = await _scope(db, grp)
    scope_id = scope.id
    await db.commit()

    await _post_events(client, db, srv, [_ev(ADDR)])
    leased = await _row(db, subnet, ADDR)
    lease = (await db.execute(select(DHCPLease).where(DHCPLease.ip_address == ADDR))).scalar_one()
    assert leased is not None
    assert _flags(leased) == ("dhcp", True, str(lease.id), None)
    row_id = leased.id

    r = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        json={"ip_address": ADDR, "mac_address": MAC, "hostname": "pinned-30"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201, r.text
    return subnet, srv, row_id, r.json()["id"]


@pytest.mark.asyncio
async def test_pinning_a_leased_address_takes_the_leases_row_whole(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, _srv, row_id, st_id = await _pin(client, db_session)

    db_session.expunge_all()
    row = await _row(db_session, subnet, ADDR)
    assert row is not None
    assert row.id == row_id  # the lease's row, taken over, not a second one
    assert _flags(row) == ("static_dhcp", False, None, st_id)
    assert (row.hostname, str(row.mac_address)) == ("pinned-30", MAC)


@pytest.mark.asyncio
async def test_the_clients_next_lease_event_leaves_the_reservations_row_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's steps 4-5: the client renews (or re-runs DISCOVER) for the
    reserved address, and Kea's lease event follows."""
    subnet, srv, row_id, st_id = await _pin(client, db_session)

    await _post_events(client, db_session, srv, [_ev(ADDR)])

    row = await _row(db_session, subnet, ADDR)
    assert row is not None
    assert row.id == row_id
    assert _flags(row) == ("static_dhcp", False, None, st_id)
    assert row.hostname == "pinned-30"


@pytest.mark.asyncio
async def test_a_release_of_the_lease_leaves_the_reserved_address_its_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A released / expired event deletes a row the lease owns. The
    reservation's row is not the lease's, so the address stays reserved."""
    subnet, srv, row_id, st_id = await _pin(client, db_session)

    await _post_events(client, db_session, srv, [_ev(ADDR, "released")])

    row = await _row(db_session, subnet, ADDR)
    assert row is not None, "a reserved address reads as free after its lease's release"
    assert row.id == row_id
    assert _flags(row) == ("static_dhcp", False, None, st_id)


@pytest.mark.asyncio
async def test_moving_a_reservation_back_onto_the_address_it_handed_to_its_lease(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1302 hands the address a reservation leaves to the live lease there.
    Moved back while that lease lives, the reservation takes that row over,
    and it is the reservation's whole."""
    token = await _token(db_session)
    grp, srv = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    st = DHCPStaticAssignment(scope_id=scope.id, ip_address=ADDR, mac_address=MAC, hostname="pin")
    db_session.add(st)
    await db_session.flush()
    await upsert_ipam_for_static(db_session, scope, st)
    st_id = str(st.id)
    await db_session.commit()
    await _post_events(client, db_session, srv, [_ev(ADDR)])
    headers = {"Authorization": f"Bearer {token}"}

    r = await client.put(
        f"/api/v1/dhcp/statics/{st_id}", json={"ip_address": OTHER}, headers=headers
    )
    assert r.status_code == 200, r.text
    handed = await _row(db_session, subnet, ADDR)
    assert handed is not None and (handed.status, handed.auto_from_lease) == ("dhcp", True)

    r = await client.put(
        f"/api/v1/dhcp/statics/{st_id}", json={"ip_address": ADDR}, headers=headers
    )
    assert r.status_code == 200, r.text
    db_session.expunge_all()
    row = await _row(db_session, subnet, ADDR)
    assert row is not None
    assert _flags(row) == ("static_dhcp", False, None, st_id)

    await _post_events(client, db_session, srv, [_ev(ADDR)])
    row = await _row(db_session, subnet, ADDR)
    assert row is not None
    assert _flags(row) == ("static_dhcp", False, None, st_id)


@pytest.mark.asyncio
async def test_the_upsert_clears_the_lease_flags_of_a_row_it_takes_over(
    db_session: AsyncSession,
) -> None:
    """``upsert_ipam_for_static`` itself, over a lease-mirror row."""
    grp, srv = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    lease = DHCPLease(
        server_id=srv.id,
        scope_id=scope.id,
        ip_address=ADDR,
        mac_address=MAC,
        hostname="client-30",
        state="active",
        expires_at=datetime.now(UTC) + timedelta(hours=8),
        last_seen_at=datetime.now(UTC),
    )
    db_session.add(lease)
    await db_session.flush()
    mirror = IPAddress(
        subnet_id=subnet.id,
        address=ADDR,
        status="dhcp",
        hostname="client-30",
        mac_address=MAC,
        auto_from_lease=True,
        dhcp_lease_id=str(lease.id),
    )
    db_session.add(mirror)
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address=ADDR, mac_address=MAC, hostname="pinned-30"
    )
    db_session.add(st)
    await db_session.flush()

    await upsert_ipam_for_static(db_session, scope, st)
    await db_session.flush()

    row = await _row(db_session, subnet, ADDR)
    assert row is not None and row.id == mirror.id
    assert _flags(row) == ("static_dhcp", False, None, str(st.id))
    assert st.ip_address_id == mirror.id
