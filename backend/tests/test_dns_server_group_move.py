"""Moving a DNS server between server groups (issue #934).

Discussion #933: an auto-registered agent lands in ``default``, the
operator creates the group they actually wanted, and there was no way to
move the server into it — while the DHCP side has carried
``server_group_id`` on its update payload since #430.

The interesting assertions here are not "the column changed". They are the
cross-row consequences a naive assignment would leave behind: stale
per-server zone state, record ops queued for the old group's zones, a
``config_apply_status`` that means "the live config is the saved one" and
stops being true at the instant of commit, and the primary flag — which
drops every record write when a group has none and 500s the agent
long-poll when a group has two.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSServerZoneState,
    DNSZone,
)
from app.services.dns.tsig import group_tsig_secret


async def _superadmin(db: AsyncSession, username: str = "root934") -> str:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _group(db: AsyncSession, name: str, **kw: object) -> DNSServerGroup:
    g = DNSServerGroup(name=name, description="", **kw)
    db.add(g)
    await db.flush()
    return g


async def _server(
    db: AsyncSession,
    group: DNSServerGroup,
    name: str,
    *,
    is_primary: bool = False,
    driver: str = "bind9",
    **kw: object,
) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver=driver,
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
        is_primary=is_primary,
        **kw,
    )
    db.add(s)
    await db.flush()
    return s


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _url(group_id: uuid.UUID, server_id: uuid.UUID) -> str:
    return f"/api/v1/dns/groups/{group_id}/servers/{server_id}"


# ── The move itself ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_move_reassigns_group_and_reports_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The discussion's exact case: one agent in ``default``, move it to
    the group the operator actually made."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal-resolvers")
    srv = await _server(db_session, default, "ns1", is_primary=True)

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["group_id"] == str(target.id)

    await db_session.refresh(srv)
    assert srv.group_id == target.id


@pytest.mark.asyncio
async def test_move_is_addressable_under_the_old_group_url(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The server is still addressed under the group it is LEAVING — the
    URL names where it is, the body names where it is going. A caller who
    guesses the reverse gets a 404 rather than a silent no-op."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(db_session, default, "ns1")

    wrong = await client.put(
        _url(target.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert wrong.status_code == 404


@pytest.mark.asyncio
async def test_resending_the_current_group_is_a_no_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An idempotent PUT that echoes the whole row back must not be
    treated as a move — it would purge zone state and re-run elections
    for no reason."""
    token = await _superadmin(db_session)
    grp = await _group(db_session, "default")
    srv = await _server(db_session, grp, "ns1", is_primary=True)
    zone = DNSZone(group_id=grp.id, name="example.com.", zone_type="primary")
    db_session.add(zone)
    await db_session.flush()
    db_session.add(DNSServerZoneState(server_id=srv.id, zone_id=zone.id, current_serial=7))
    await db_session.flush()

    resp = await client.put(
        _url(grp.id, srv.id),
        json={"group_id": str(grp.id), "notes": "unchanged"},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    rows = (
        (
            await db_session.execute(
                select(DNSServerZoneState).where(DNSServerZoneState.server_id == srv.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1, "a no-op move must not purge per-server zone state"


@pytest.mark.asyncio
async def test_move_to_unknown_group_404s(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _superadmin(db_session)
    grp = await _group(db_session, "default")
    srv = await _server(db_session, grp, "ns1")

    resp = await client.put(
        _url(grp.id, srv.id),
        json={"group_id": str(uuid.uuid4())},
        headers=_auth(token),
    )
    assert resp.status_code == 404


# ── State that belongs to the old group ─────────────────────────────────────


@pytest.mark.asyncio
async def test_move_purges_zone_state_and_pending_ops(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Both reference the OLD group's zones. Left behind, the Zone Sync
    pill reports convergence for zones this server no longer serves, and
    the queued RFC 2136 updates would be shipped to a daemon that has
    never heard of those zones."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(db_session, default, "ns1")
    zone = DNSZone(group_id=default.id, name="example.com.", zone_type="primary")
    db_session.add(zone)
    await db_session.flush()
    db_session.add(DNSServerZoneState(server_id=srv.id, zone_id=zone.id, current_serial=42))
    db_session.add(
        DNSRecordOp(
            server_id=srv.id,
            zone_name="example.com.",
            op="create",
            record={"name": "www", "type": "A", "value": "10.0.0.1"},
            state="pending",
        )
    )
    # Already shipped in a bundle but not yet acked. NOT finished with:
    # ``ack_op`` puts a NACKed op back to ``pending``, and that ack can
    # arrive after the move — re-queueing an old-group zone's update against
    # the new group's daemon.
    db_session.add(
        DNSRecordOp(
            server_id=srv.id,
            zone_name="example.com.",
            op="create",
            record={"name": "inflight", "type": "A", "value": "10.0.0.3"},
            state="in_flight",
        )
    )
    # An already-applied op is history, not queued work — it stays.
    db_session.add(
        DNSRecordOp(
            server_id=srv.id,
            zone_name="example.com.",
            op="create",
            record={"name": "old", "type": "A", "value": "10.0.0.2"},
            state="applied",
        )
    )
    await db_session.flush()

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    zone_state = (
        (
            await db_session.execute(
                select(DNSServerZoneState).where(DNSServerZoneState.server_id == srv.id)
            )
        )
        .scalars()
        .all()
    )
    assert zone_state == []

    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == srv.id)))
        .scalars()
        .all()
    )
    assert [o.state for o in ops] == ["applied"]


@pytest.mark.asyncio
async def test_move_clears_config_apply_verdict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``config_apply_status`` (#882) means "the LIVE config is the SAVED
    one". A move changes the saved one, so carrying ``ok`` across it is a
    false statement at the instant of commit. NULL is UNKNOWN, never ok."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(
        db_session,
        default,
        "ns1",
        config_apply_status="ok",
        config_apply_error=None,
        config_failed_etag="deadbeef",
        config_apply_at=datetime.now(UTC),
    )

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(srv)
    assert srv.config_apply_status is None
    assert srv.config_failed_etag is None
    assert srv.config_apply_at is None


@pytest.mark.asyncio
async def test_move_generates_a_tsig_key_for_a_ui_created_target_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A group created in the UI has never been through agent
    registration, where the legacy group key was historically generated —
    so without this the moved agent gets a bundle whose loopback RFC 2136
    path has no key to sign with."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal resolvers")
    assert group_tsig_secret(target) is None
    srv = await _server(db_session, default, "ns1")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(target)
    assert group_tsig_secret(target)
    assert target.tsig_key_algorithm == "hmac-sha256"
    # Spaces are not legal in a BIND key name.
    assert target.tsig_key_name == "spatium-internal-resolvers"


@pytest.mark.asyncio
async def test_move_leaves_an_existing_target_tsig_key_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Regenerating it would invalidate every agent in the target group
    that is already signing with the current secret."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(
        db_session,
        "internal",
        tsig_key_name="spatium-internal",
        tsig_key_secret_encrypted=encrypt_str("Zm9vYmFy"),
        tsig_key_algorithm="hmac-sha256",
    )
    srv = await _server(db_session, default, "ns1")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(target)
    assert group_tsig_secret(target) == "Zm9vYmFy"


# ── Primary bookkeeping, both sides ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_moving_the_primary_elects_a_replacement_in_the_old_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A group with no primary drops every record write to its zones with
    only a log line — no error reaches whoever made the change."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    primary = await _server(db_session, default, "ns1", is_primary=True)
    survivor = await _server(db_session, default, "ns2")

    resp = await client.put(
        _url(default.id, primary.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(survivor)
    assert survivor.is_primary is True


@pytest.mark.asyncio
async def test_election_prefers_an_enabled_unpaused_survivor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A disabled or paused server is skipped by the record-op dispatcher,
    so electing one would leave the group nominally covered and actually
    dead. Insertion order deliberately puts the unusable candidate first."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    primary = await _server(db_session, default, "ns1", is_primary=True)
    paused = await _server(db_session, default, "ns2", maintenance_mode=True)
    usable = await _server(db_session, default, "ns3")

    resp = await client.put(
        _url(default.id, primary.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(paused)
    await db_session.refresh(usable)
    assert usable.is_primary is True
    assert paused.is_primary is False


@pytest.mark.asyncio
async def test_moving_the_only_server_leaves_the_old_group_without_a_primary(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Nothing to elect. The move still succeeds — an empty group with no
    primary is a consistent state, and refusing would make the discussion's
    single-agent case unfixable."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(db_session, default, "ns1", is_primary=True)

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(srv)
    assert srv.group_id == target.id
    # Elected in the target, which had none.
    assert srv.is_primary is True


@pytest.mark.asyncio
async def test_move_into_a_group_that_has_a_primary_does_not_make_two(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two primaries in one group is not a tie-break — ``build_config_bundle``
    fetches the catalog-zone producer with ``scalar_one_or_none``, so a
    second one raises inside the agent long-poll and stops the WHOLE group
    converging."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    incoming = await _server(db_session, default, "ns1", is_primary=True)
    sitting = await _server(db_session, target, "ns2", is_primary=True)

    resp = await client.put(
        _url(default.id, incoming.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(incoming)
    await db_session.refresh(sitting)
    assert sitting.is_primary is True, "the operator's existing choice wins"
    assert incoming.is_primary is False

    count = (
        (
            await db_session.execute(
                select(DNSServer).where(
                    DNSServer.group_id == target.id, DNSServer.is_primary.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(count) == 1


# ── Refusals ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_move_refused_on_name_collision(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``uq_dns_server_group_name`` would raise anyway; the point is that
    the operator is told which name clashed."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(db_session, default, "ns1")
    await _server(db_session, target, "ns1")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 409
    assert "ns1" in resp.json()["detail"]

    await db_session.refresh(srv)
    assert srv.group_id == default.id


@pytest.mark.asyncio
async def test_rename_and_move_in_one_request_checks_the_new_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The collision check runs after the rename, so renaming out of the
    way and moving is a single request — and renaming INTO a clash is
    still caught."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(db_session, default, "ns1")
    await _server(db_session, target, "ns1")

    ok = await client.put(
        _url(default.id, srv.id),
        json={"name": "ns9", "group_id": str(target.id)},
        headers=_auth(token),
    )
    assert ok.status_code == 200, ok.text
    await db_session.refresh(srv)
    assert srv.group_id == target.id and srv.name == "ns9"


@pytest.mark.asyncio
async def test_move_refused_when_it_would_mix_drivers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A server group is single-driver: its rendered config, catalog-zone
    semantics and AXFR shape all assume one. Mixing is only caught today
    at operation time (DNSSEC sign / ALIAS), i.e. long after the mistake."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "pdns")
    srv = await _server(db_session, default, "ns1", driver="bind9")
    await _server(db_session, target, "pdns1", driver="powerdns")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 422
    assert "single-driver" in resp.json()["detail"]

    await db_session.refresh(srv)
    assert srv.group_id == default.id


@pytest.mark.asyncio
async def test_move_into_an_empty_group_of_any_driver_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The discussion's case — the operator makes a fresh group precisely
    to move a server into it. Nothing to disagree with."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "brand-new")
    srv = await _server(db_session, default, "ns1", driver="powerdns")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_move_requires_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    srv = await _server(db_session, default, "ns1")
    user = User(
        username="plain934",
        email="plain934@example.com",
        display_name="plain",
        hashed_password=hash_password("password123"),
        is_superadmin=False,
    )
    db_session.add(user)
    await db_session.flush()

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(create_access_token(str(user.id))),
    )
    assert resp.status_code == 403


# ── Explicit primary designation ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_promoting_a_server_demotes_the_incumbent(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Three separate comments told operators to flip this flag "later via
    the API" and no endpoint accepted it — including the hint shown when a
    record write is dropped for want of a primary."""
    token = await _superadmin(db_session)
    grp = await _group(db_session, "default")
    incumbent = await _server(db_session, grp, "ns1", is_primary=True)
    challenger = await _server(db_session, grp, "ns2")

    resp = await client.put(
        _url(grp.id, challenger.id),
        json={"is_primary": True},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(incumbent)
    await db_session.refresh(challenger)
    assert challenger.is_primary is True
    assert incumbent.is_primary is False


@pytest.mark.asyncio
async def test_promotion_only_demotes_within_the_same_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    grp = await _group(db_session, "default")
    other = await _group(db_session, "internal")
    challenger = await _server(db_session, grp, "ns1")
    untouched = await _server(db_session, other, "ns2", is_primary=True)

    resp = await client.put(
        _url(grp.id, challenger.id),
        json={"is_primary": True},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(untouched)
    assert untouched.is_primary is True


@pytest.mark.asyncio
async def test_clearing_the_only_primary_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """It re-creates exactly the footgun create-time auto-election exists
    to prevent, and the resulting write drops are silent."""
    token = await _superadmin(db_session)
    grp = await _group(db_session, "default")
    only = await _server(db_session, grp, "ns1", is_primary=True)
    await _server(db_session, grp, "ns2")

    resp = await client.put(
        _url(grp.id, only.id),
        json={"is_primary": False},
        headers=_auth(token),
    )
    assert resp.status_code == 422
    assert "only primary" in resp.json()["detail"]

    await db_session.refresh(only)
    assert only.is_primary is True


@pytest.mark.asyncio
async def test_move_and_promote_in_one_request_promotes_in_the_target(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The demotion sweep must target the group the server ENDS UP in."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    mover = await _server(db_session, default, "ns1")
    await _server(db_session, default, "ns0", is_primary=True)
    sitting = await _server(db_session, target, "ns2", is_primary=True)

    resp = await client.put(
        _url(default.id, mover.id),
        json={"group_id": str(target.id), "is_primary": True},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(mover)
    await db_session.refresh(sitting)
    assert mover.group_id == target.id
    assert mover.is_primary is True
    assert sitting.is_primary is False


# ── Durability against the agent ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_move_survives_agent_re_registration_with_a_stale_group_name(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent's ``AGENT_GROUP`` env still names the group it LEFT.

    This is what makes the move a real operator action rather than a
    setting the next agent restart undoes: ``/register`` resolves an
    existing row by ``agent_id`` first — globally, with no group filter —
    and its update branch deliberately never writes ``group_id``. Without
    that, a token expiry or a container restart would silently drag the
    server back into ``default``, and the operator would have no way to
    tell why.
    """
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-934")
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    agent_id = uuid.uuid4()
    srv = await _server(db_session, default, "ns1", agent_id=agent_id)

    moved = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert moved.status_code == 200, moved.text

    # The agent re-bootstraps (401 / 404 path) still advertising the OLD
    # group name, exactly as its unchanged env var says.
    reg = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-934"},
        json={
            "hostname": "ns1",
            "fingerprint": "fp-1",
            "driver": "bind9",
            "roles": ["authoritative"],
            "agent_id": str(agent_id),
            "group_name": "default",
        },
    )
    assert reg.status_code == 200, reg.text
    assert reg.json()["server_id"] == str(srv.id), "must reuse the row, not fork a new one"

    await db_session.refresh(srv)
    assert srv.group_id == target.id, "re-registration must not undo the operator's move"


# ── Code-review follow-ups ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_move_repoints_the_parent_appliance_dns_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """On the #170 appliance path the agent is not configured from its own
    environment — the supervisor derives ``AGENT_GROUP`` *and* the #50
    DoT/DoH/DoQ firewall ports from ``Appliance.assigned_dns_group_id``.
    Left on the old group, nftables keeps the old group's encrypted-transport
    ports open while the agent listens on the new group's: config-clean, and
    silently unreachable."""
    from app.models.appliance import Appliance

    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    appliance = Appliance(
        hostname="ddi1",
        public_key_der=b"\x00" * 32,
        public_key_fingerprint="fp-ddi1",
        state="approved",
        assigned_roles=["dns_bind9"],
        assigned_dns_group_id=default.id,
    )
    db_session.add(appliance)
    await db_session.flush()
    srv = await _server(db_session, default, "ns1", appliance_id=appliance.id)

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(appliance)
    assert appliance.assigned_dns_group_id == target.id


@pytest.mark.asyncio
async def test_move_leaves_an_appliance_assigned_elsewhere_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only repoint when the appliance currently names the group being
    left. One deliberately assigned somewhere else is not ours to redirect
    on the strength of one server row moving."""
    from app.models.appliance import Appliance

    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    elsewhere = await _group(db_session, "elsewhere")
    appliance = Appliance(
        hostname="ddi1",
        public_key_der=b"\x00" * 32,
        public_key_fingerprint="fp-ddi1",
        state="approved",
        assigned_roles=["dns_bind9"],
        assigned_dns_group_id=elsewhere.id,
    )
    db_session.add(appliance)
    await db_session.flush()
    srv = await _server(db_session, default, "ns1", appliance_id=appliance.id)

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(target.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(appliance)
    assert appliance.assigned_dns_group_id == elsewhere.id


@pytest.mark.asyncio
async def test_derived_tsig_key_name_is_safe_in_named_conf(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The key name is interpolated VERBATIM into ``key "<name>" { … };`` by
    both agent renderers. A group name that closes the statement early makes
    ``named-checkconf`` reject the file WHOLE, so the agent declines the
    entire bundle — one badly-named group stops its group converging.

    Sanitised rather than refused: the name is derived, not typed, and an
    operator naming a group ``Edge (DMZ)`` has done nothing wrong."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    hostile = await _group(db_session, 'edge"; }; key "evil')
    srv = await _server(db_session, default, "ns1")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(hostile.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(hostile)
    name = hostile.tsig_key_name
    assert name
    assert set(name) <= set("abcdefghijklmnopqrstuvwxyz0123456789_-"), name
    # Specifically: nothing that could terminate or open a BIND statement.
    for ch in '";{}\n\\':
        assert ch not in name


@pytest.mark.asyncio
async def test_derived_tsig_key_name_falls_back_to_the_group_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A name that is entirely punctuation leaves no label to fold, and an
    empty ``key "" { … }`` is not valid BIND either."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    punct = await _group(db_session, "!!! ***")
    srv = await _server(db_session, default, "ns1")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(punct.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(punct)
    assert punct.tsig_key_name == f"spatium-{punct.id}"


@pytest.mark.asyncio
async def test_derived_tsig_key_name_keeps_the_readable_form(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Sanitising must not make ordinary names unrecognisable — spaces and
    parentheses fold to single hyphens, not to the id fallback."""
    token = await _superadmin(db_session)
    default = await _group(db_session, "default")
    normal = await _group(db_session, "Edge (DMZ)")
    srv = await _server(db_session, default, "ns1")

    resp = await client.put(
        _url(default.id, srv.id),
        json={"group_id": str(normal.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(normal)
    assert normal.tsig_key_name == "spatium-edge-dmz"


# ── `server_drivers` on the group response (#934 follow-up) ─────────────────


@pytest.mark.asyncio
async def test_group_response_reports_its_server_drivers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The move picker needs to know which groups a server may go to. Without
    this it would have to fetch every group's server list to find out, so it
    offered groups the move then refused with a 422 on save."""
    token = await _superadmin(db_session)
    await _group(db_session, "empty")
    bind = await _group(db_session, "bind-only")
    pdns = await _group(db_session, "pdns-only")
    await _server(db_session, bind, "ns1", driver="bind9")
    await _server(db_session, bind, "ns2", driver="bind9")
    await _server(db_session, pdns, "pdns1", driver="powerdns")

    resp = await client.get("/api/v1/dns/groups", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    by_name = {g["name"]: g["server_drivers"] for g in resp.json()}

    # Empty group: compatible with anything, so no drivers to report.
    assert by_name["empty"] == []
    # Distinct, not one entry per server.
    assert by_name["bind-only"] == ["bind9"]
    assert by_name["pdns-only"] == ["powerdns"]


@pytest.mark.asyncio
async def test_group_response_reports_a_mixed_group_honestly(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A group is single-driver, but only the MOVE and the driver-gated
    operations enforce it — the create path does not, so mixed groups are
    reachable. Reporting one driver would let the picker offer it as
    compatible when the move will refuse."""
    token = await _superadmin(db_session)
    mixed = await _group(db_session, "mixed")
    await _server(db_session, mixed, "a", driver="bind9")
    await _server(db_session, mixed, "b", driver="powerdns")

    resp = await client.get(f"/api/v1/dns/groups/{mixed.id}", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    assert resp.json()["server_drivers"] == ["bind9", "powerdns"]


@pytest.mark.asyncio
async def test_newly_created_group_reports_no_drivers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The create response is the one the UI puts straight into its cache."""
    token = await _superadmin(db_session)
    resp = await client.post(
        "/api/v1/dns/groups",
        json={"name": "fresh", "description": "", "group_type": "custom"},
        headers=_auth(token),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["server_drivers"] == []


@pytest.mark.asyncio
async def test_group_drivers_track_a_move(client: AsyncClient, db_session: AsyncSession) -> None:
    """The field has to move with the server, or the picker keeps offering
    (or blocking) groups on the strength of where servers used to be."""
    token = await _superadmin(db_session)
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst")
    srv = await _server(db_session, src, "ns1", driver="bind9")

    resp = await client.put(
        _url(src.id, srv.id),
        json={"group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text

    listing = await client.get("/api/v1/dns/groups", headers=_auth(token))
    by_name = {g["name"]: g["server_drivers"] for g in listing.json()}
    assert by_name["src"] == []
    assert by_name["dst"] == ["bind9"]
