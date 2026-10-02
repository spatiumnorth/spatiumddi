"""#1110 — a shared IPAM mirror + DDNS is not torn down while a peer still leases it.

A Windows failover pair (or a Kea HA pair) replicates lease state, so both
partners report the same lease and ``dhcp_lease`` carries one row per
partner. The IPAM mirror and the DNS records it published are shared: one
row, one A/PTR, for the address. Every teardown path — the pull's
absence-delete (``purge_lease``), the expiry sweep, and the Kea
release/expire event — used to tear them down because ONE partner stopped
reporting the lease, while the other was still serving the client. Its next
poll recreated both, so the visible symptom was DDNS flapping.
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
from app.main import app
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.lease_cleanup import (
    delete_leases_for_scope,
    peer_holds_active_lease,
    purge_lease,
)

IP = "10.40.0.50"
MAC = "aa:bb:cc:dd:ee:50"


class _DDNSSpy:
    def __init__(self) -> None:
        self.revoked: list[str] = []


@pytest.fixture
def ddns(monkeypatch: pytest.MonkeyPatch) -> _DDNSSpy:
    import app.services.dns.ddns as ddns_mod

    spy = _DDNSSpy()

    async def _revoke(db: Any, *, subnet: Any, ipam_row: Any) -> None:
        spy.revoked.append(str(ipam_row.address))

    async def _apply(*_a: Any, **_kw: Any) -> bool:
        return False

    monkeypatch.setattr(ddns_mod, "revoke_ddns_for_lease", _revoke)
    monkeypatch.setattr(ddns_mod, "apply_ddns_for_lease", _apply)
    return spy


async def _pair(
    db: AsyncSession, *, driver: str = "windows_dhcp", grouped: bool = True
) -> tuple[DHCPServer, DHCPServer, DHCPScope, Subnet, IPAddress]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.40.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.40.0.0/24", name="sn")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([subnet, group])
    await db.flush()
    a = DHCPServer(
        name=f"a-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host="10.0.0.1",
        port=67,
        server_group_id=group.id if grouped else None,
    )
    b = DHCPServer(
        name=f"b-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host="10.0.0.2",
        port=67,
        server_group_id=group.id if grouped else None,
    )
    db.add_all([a, b])
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    mirror = IPAddress(
        subnet_id=subnet.id, address=IP, status="dhcp", mac_address=MAC, auto_from_lease=True
    )
    db.add(mirror)
    await db.flush()
    return a, b, scope, subnet, mirror


def _lease(server: DHCPServer, scope: DHCPScope, **kw: Any) -> DHCPLease:
    fields: dict[str, Any] = {
        "server_id": server.id,
        "scope_id": scope.id,
        "ip_address": IP,
        "mac_address": MAC,
        "state": "active",
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
    }
    fields.update(kw)
    return DHCPLease(**fields)


async def _mirror_exists(db: AsyncSession, mirror_id: Any) -> bool:
    return (
        await db.execute(select(IPAddress).where(IPAddress.id == mirror_id))
    ).scalar_one_or_none() is not None


# ── purge_lease (the pull's absence-delete + the delete-lease endpoint) ──


@pytest.mark.asyncio
async def test_purge_keeps_the_mirror_while_the_partner_still_leases(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    a, b, scope, _subnet, mirror = await _pair(db_session)
    la, lb = _lease(a, scope), _lease(b, scope)
    db_session.add_all([la, lb])
    await db_session.flush()

    removed = await purge_lease(db_session, la)
    await db_session.flush()

    assert removed is False
    assert await _mirror_exists(db_session, mirror.id)
    assert ddns.revoked == [], "DDNS must not be revoked while the partner serves the lease"
    # This server's copy of the lease is still gone — only the shared rows stay.
    assert (
        await db_session.execute(select(DHCPLease).where(DHCPLease.id == la.id))
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_purge_of_the_last_copy_tears_the_mirror_down(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    a, b, scope, _subnet, mirror = await _pair(db_session)
    la, lb = _lease(a, scope), _lease(b, scope)
    db_session.add_all([la, lb])
    await db_session.flush()

    assert await purge_lease(db_session, la) is False
    assert await purge_lease(db_session, lb) is True
    await db_session.flush()
    assert not await _mirror_exists(db_session, mirror.id)
    assert ddns.revoked == [IP]


@pytest.mark.asyncio
async def test_a_partners_expired_copy_does_not_count(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """A dead partner's frozen rows must not keep a mirror alive forever."""
    a, b, scope, _subnet, mirror = await _pair(db_session)
    la = _lease(a, scope)
    lb = _lease(b, scope, expires_at=datetime.now(UTC) - timedelta(minutes=1))
    db_session.add_all([la, lb])
    await db_session.flush()
    assert await purge_lease(db_session, la) is True
    assert not await _mirror_exists(db_session, mirror.id)


@pytest.mark.asyncio
async def test_a_released_copy_on_the_partner_does_not_count(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    a, b, scope, _subnet, mirror = await _pair(db_session)
    la, lb = _lease(a, scope), _lease(b, scope, state="released")
    db_session.add_all([la, lb])
    await db_session.flush()
    assert await purge_lease(db_session, la) is True


@pytest.mark.asyncio
async def test_the_same_address_in_another_group_is_not_a_peer(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """Same address, different group = a different network (VRF). It must
    not keep this group's mirror alive."""
    a, b, scope, _subnet, mirror = await _pair(db_session)
    other_group = DHCPServerGroup(name=f"g2-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(other_group)
    await db_session.flush()
    b.server_group_id = other_group.id
    la, lb = _lease(a, scope), _lease(b, scope)
    db_session.add_all([la, lb])
    await db_session.flush()
    assert await purge_lease(db_session, la) is True


@pytest.mark.asyncio
async def test_a_groupless_server_has_no_peers(db_session: AsyncSession, ddns: _DDNSSpy) -> None:
    a, b, scope, _subnet, _mirror = await _pair(db_session, grouped=False)
    la, lb = _lease(a, scope), _lease(b, scope)
    db_session.add_all([la, lb])
    await db_session.flush()
    assert await peer_holds_active_lease(db_session, la, now=datetime.now(UTC)) is False


@pytest.mark.asyncio
async def test_scope_deletion_removes_the_mirror_despite_peers(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """Every copy is going at once, so no copy's peer outlives it."""
    a, b, scope, _subnet, mirror = await _pair(db_session)
    db_session.add_all([_lease(a, scope), _lease(b, scope)])
    await db_session.flush()
    leases_removed, mirrors_removed = await delete_leases_for_scope(db_session, scope.id)
    await db_session.flush()
    assert leases_removed == 2
    assert mirrors_removed == 1
    assert not await _mirror_exists(db_session, mirror.id)


# ── the time-based expiry sweep ──────────────────────────────────────


@pytest.mark.asyncio
async def test_expiry_sweep_spares_a_mirror_the_partner_renewed(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """Server A stopped being polled, so its copy aged out; server B renewed
    the lease and still serves it."""
    import app.tasks.dhcp_lease_cleanup as cleanup

    a, b, scope, _subnet, mirror = await _pair(db_session)
    stale = _lease(a, scope, expires_at=datetime.now(UTC) - timedelta(hours=1))
    fresh = _lease(b, scope)
    db_session.add_all([stale, fresh])
    await db_session.commit()
    mirror_id, stale_id = mirror.id, stale.id

    cleaned, _deleted = await cleanup._sweep()

    assert cleaned == 0
    assert await _mirror_exists(db_session, mirror_id)
    assert ddns.revoked == []
    state = (
        await db_session.execute(select(DHCPLease.state).where(DHCPLease.id == stale_id))
    ).scalar_one()
    assert state == "expired", "the stale copy is still expired — only the shared rows stay"


@pytest.mark.asyncio
async def test_expiry_sweep_removes_the_mirror_when_every_copy_expired(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    import app.tasks.dhcp_lease_cleanup as cleanup

    a, b, scope, _subnet, mirror = await _pair(db_session)
    past = datetime.now(UTC) - timedelta(hours=1)
    db_session.add_all([_lease(a, scope, expires_at=past), _lease(b, scope, expires_at=past)])
    await db_session.commit()
    mirror_id = mirror.id

    cleaned, _deleted = await cleanup._sweep()
    assert cleaned == 1
    assert not await _mirror_exists(db_session, mirror_id)


# ── Kea lease events (HA pairs report every lease twice) ──────────────


def _event(state: str) -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "leases": [
            {
                "ip_address": IP,
                "mac_address": MAC,
                "hostname": "h",
                "state": state,
                "starts_at": datetime.now(UTC).isoformat(),
                "ends_at": end,
                "expires_at": end,
            }
        ]
    }


async def _post_as(client: AsyncClient, db: AsyncSession, server: DHCPServer, state: str) -> None:
    # The test client shares one session, and its identity map hands the
    # handler the objects the TEST created — with the Python strings they
    # were built from. A real request loads them from the database, where
    # INET decodes to ``IPv4Address``. Dropping the identity map makes this
    # request see what production sees; without it, the lookup bugs below
    # are invisible.
    db.expunge_all()
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json=_event(state))
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


async def _lease_rows(db: AsyncSession, server_id: Any) -> list[str]:
    return list(
        (await db.execute(select(DHCPLease.state).where(DHCPLease.server_id == server_id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_kea_repeat_event_updates_the_lease_it_already_has(
    client: AsyncClient, db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """The lookup compared the event's string address against the stored
    ``IPv4Address`` and never matched, so every renewal INSERTED another
    ``dhcp_lease`` row for the same lease."""
    a, _b, scope, _subnet, _mirror = await _pair(db_session, driver="kea")
    db_session.add(_lease(a, scope))
    await db_session.commit()
    a_id = a.id
    await _post_as(client, db_session, a, "active")
    await _post_as(client, db_session, a, "active")
    assert await _lease_rows(db_session, a_id) == ["active"]


@pytest.mark.asyncio
async def test_kea_release_tears_down_a_stored_mirror(
    client: AsyncClient, db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """The mirror map had the same mismatch, so a release found no mirror
    and left the IPAM row and its DNS records until the expiry sweep."""
    a, _b, scope, _subnet, mirror = await _pair(db_session, driver="kea")
    db_session.add(_lease(a, scope))
    await db_session.commit()
    mirror_id, a_id = mirror.id, a.id
    await _post_as(client, db_session, a, "released")
    assert not await _mirror_exists(db_session, mirror_id)
    assert ddns.revoked == [IP]
    assert await _lease_rows(db_session, a_id) == ["released"]


@pytest.mark.asyncio
async def test_kea_release_from_one_peer_keeps_the_mirror_until_the_other_reports(
    client: AsyncClient, db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    a, b, scope, _subnet, mirror = await _pair(db_session, driver="kea")
    db_session.add_all([_lease(a, scope), _lease(b, scope)])
    await db_session.commit()
    mirror_id = mirror.id

    await _post_as(client, db_session, a, "released")
    assert await _mirror_exists(db_session, mirror_id), "peer b still reports it active"
    assert ddns.revoked == []

    await _post_as(client, db_session, b, "released")
    assert not await _mirror_exists(db_session, mirror_id)
    assert ddns.revoked == [IP]


# ── One server, one address, two clients: a replayed release (#1318) ─────
#
# The agent re-reads its whole lease file on every start, so an old client's
# grant and release of an address are delivered again after the address has
# gone to a new client. The release must not take the new client's mirror.

OLD_MAC = "aa:bb:cc:dd:ee:51"
NEW_MAC = "aa:bb:cc:dd:ee:52"


def _ev(mac: str, state: str) -> dict[str, Any]:
    end = datetime.now(UTC) + (timedelta(hours=1) if state == "active" else timedelta(0))
    return {
        "ip_address": IP,
        "mac_address": mac,
        "hostname": f"h-{mac[-2:]}",
        "state": state,
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end.isoformat(),
        "expires_at": end.isoformat(),
    }


async def _post_events(
    client: AsyncClient, db: AsyncSession, server: DHCPServer, events: list[dict[str, Any]]
) -> None:
    db.expunge_all()  # as _post_as: the request must load its rows like production does
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": events})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


async def _mirror_of(db: AsyncSession, subnet_id: Any) -> IPAddress | None:
    db.expunge_all()
    return (
        await db.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == IP)
        )
    ).scalar_one_or_none()


async def _states(db: AsyncSession, server_id: Any) -> dict[str, str]:
    rows = (
        await db.execute(
            select(DHCPLease.mac_address, DHCPLease.state).where(DHCPLease.server_id == server_id)
        )
    ).all()
    return {str(mac): state for mac, state in rows}


async def _address_changes_hands(client: AsyncClient, db: AsyncSession, server: DHCPServer) -> None:
    """Live: the old client leases and releases the address, a new one takes it."""
    await _post_events(client, db, server, [_ev(OLD_MAC, "active")])
    await _post_events(client, db, server, [_ev(OLD_MAC, "released")])
    await _post_events(client, db, server, [_ev(NEW_MAC, "active")])


@pytest.mark.asyncio
async def test_a_replayed_release_keeps_the_mirror_of_the_client_holding_the_address(
    client: AsyncClient, db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """The old client's grant and release, delivered again after an agent
    restart, in a batch of their own: the new client still holds the address,
    so its mirror stays, and DDNS is not revoked."""
    a, _b, _scope, subnet, _mirror = await _pair(db_session, driver="kea", grouped=False)
    await db_session.commit()
    a_id, subnet_id = a.id, subnet.id
    await _address_changes_hands(client, db_session, a)
    before = await _mirror_of(db_session, subnet_id)
    assert before is not None and str(before.mac_address) == NEW_MAC
    before_id = before.id
    ddns.revoked.clear()

    await _post_events(client, db_session, a, [_ev(OLD_MAC, "active"), _ev(OLD_MAC, "released")])

    assert await _states(db_session, a_id) == {OLD_MAC: "released", NEW_MAC: "active"}
    kept = await _mirror_of(db_session, subnet_id)
    assert kept is not None, "the new client's lease is active but its address left IPAM"
    assert kept.id == before_id and kept.status == "dhcp"
    assert ddns.revoked == []

    # The replay goes on to the new client's own grant: the row is its again.
    await _post_events(client, db_session, a, [_ev(NEW_MAC, "active")])
    after = await _mirror_of(db_session, subnet_id)
    assert after is not None and after.id == before_id
    assert str(after.mac_address) == NEW_MAC


@pytest.mark.asyncio
async def test_a_replay_in_one_batch_keeps_the_same_mirror_row(
    client: AsyncClient, db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """Old grant, old release and the new client's grant in one batch: the row
    is kept, not deleted and re-created, so what hangs off it survives."""
    a, _b, _scope, subnet, _mirror = await _pair(db_session, driver="kea", grouped=False)
    await db_session.commit()
    subnet_id = subnet.id
    await _address_changes_hands(client, db_session, a)
    before = await _mirror_of(db_session, subnet_id)
    assert before is not None
    before_id = before.id

    await _post_events(
        client,
        db_session,
        a,
        [_ev(OLD_MAC, "active"), _ev(OLD_MAC, "released"), _ev(NEW_MAC, "active")],
    )

    after = await _mirror_of(db_session, subnet_id)
    assert after is not None and after.id == before_id
    assert str(after.mac_address) == NEW_MAC


@pytest.mark.asyncio
async def test_a_release_with_no_other_holder_still_removes_the_mirror(
    client: AsyncClient, db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """Only a lease that is active and unexpired spares the mirror: another
    client's ended lease on the address does not."""
    a, _b, _scope, subnet, _mirror = await _pair(db_session, driver="kea", grouped=False)
    await db_session.commit()
    subnet_id = subnet.id
    # The old client's lease has ended; the new client then leases and releases.
    await _post_events(client, db_session, a, [_ev(OLD_MAC, "active")])
    await _post_events(client, db_session, a, [_ev(OLD_MAC, "released")])
    await _post_events(client, db_session, a, [_ev(NEW_MAC, "active")])
    assert await _mirror_of(db_session, subnet_id) is not None
    ddns.revoked.clear()

    await _post_events(client, db_session, a, [_ev(NEW_MAC, "released")])

    assert await _mirror_of(db_session, subnet_id) is None
    assert ddns.revoked == [IP]


# ── #1318 on the other teardown paths: another client on the SAME server ──
#
# The lease-event release spares the mirror while another client on the
# same server holds the address. The expiry sweep and ``purge_lease`` (the
# pull's absence-delete and the delete-lease endpoint) tear the same mirror
# down, so they ask the same question.

SAME_SERVER_NEW_MAC = "aa:bb:cc:dd:ee:53"


@pytest.mark.asyncio
async def test_expiry_sweep_spares_the_mirror_of_the_client_holding_the_address_now(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    """The old client's row was left ``active`` past its expiry (Kea reused
    the address for a new client with no release line for the old one)."""
    import app.tasks.dhcp_lease_cleanup as cleanup

    a, _b, scope, _subnet, mirror = await _pair(db_session)
    old = _lease(a, scope, expires_at=datetime.now(UTC) - timedelta(hours=1))
    new = _lease(a, scope, mac_address=SAME_SERVER_NEW_MAC)
    db_session.add_all([old, new])
    await db_session.commit()
    mirror_id = mirror.id

    cleaned, _deleted = await cleanup._sweep()

    assert cleaned == 0
    assert await _mirror_exists(db_session, mirror_id)
    assert ddns.revoked == [], "the new client's DNS must stay"


@pytest.mark.asyncio
async def test_expiry_sweep_still_removes_the_mirror_when_both_clients_expired(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    import app.tasks.dhcp_lease_cleanup as cleanup

    a, _b, scope, _subnet, mirror = await _pair(db_session)
    past = datetime.now(UTC) - timedelta(hours=1)
    db_session.add_all(
        [
            _lease(a, scope, expires_at=past),
            _lease(a, scope, mac_address=SAME_SERVER_NEW_MAC, expires_at=past),
        ]
    )
    await db_session.commit()
    mirror_id = mirror.id

    cleaned, _deleted = await cleanup._sweep()
    assert cleaned == 1
    assert not await _mirror_exists(db_session, mirror_id)


@pytest.mark.asyncio
async def test_purging_the_old_clients_lease_keeps_the_new_clients_mirror(
    db_session: AsyncSession, ddns: _DDNSSpy
) -> None:
    a, _b, scope, _subnet, mirror = await _pair(db_session)
    old = _lease(a, scope, state="released", expires_at=datetime.now(UTC) - timedelta(hours=1))
    new = _lease(a, scope, mac_address=SAME_SERVER_NEW_MAC)
    db_session.add_all([old, new])
    await db_session.flush()

    assert await purge_lease(db_session, old) is False
    await db_session.flush()
    assert await _mirror_exists(db_session, mirror.id)
    assert ddns.revoked == []

    # With the new client's lease purged too, nothing holds the address.
    assert await purge_lease(db_session, new) is True
    await db_session.flush()
    assert not await _mirror_exists(db_session, mirror.id)
    assert ddns.revoked == [IP]
