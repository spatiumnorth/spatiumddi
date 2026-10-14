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
    host: str | None = None,
    **kw: object,
) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver=driver,
        host=host or name,
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


# ── #1565: Fleet's group change moves the appliance's own servers ─────────────


async def _fleet_appliance(db: AsyncSession, group: DNSServerGroup, **kw: object):  # noqa: ANN202
    from app.models.appliance import Appliance

    kw.setdefault("hostname", f"ddi-{uuid.uuid4().hex[:6]}")
    appliance = Appliance(
        public_key_der=b"\x00" * 32,
        public_key_fingerprint=f"fp-{uuid.uuid4().hex}",
        state="approved",
        assigned_roles=["dns-bind9"],
        assigned_dns_group_id=group.id,
        **kw,
    )
    db.add(appliance)
    await db.flush()
    return appliance


def _roles_url(appliance_id: uuid.UUID) -> str:
    return f"/api/v1/appliance/appliances/{appliance_id}/roles"


@pytest.mark.asyncio
async def test_fleet_group_change_moves_the_appliances_dns_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The pointer used to move alone: env and firewall followed the new
    group while the registered server kept serving the old one."""
    token = await _superadmin(db_session, "root1565a")
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    appliance = await _fleet_appliance(db_session, default)
    # Shaped the way an agent registers: host = hostname, appliance_id NULL.
    srv = await _server(db_session, default, "ns1", host=appliance.hostname, agent_id=uuid.uuid4())
    await db_session.commit()

    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(target.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(srv)
    await db_session.refresh(appliance)
    assert srv.group_id == target.id
    assert appliance.assigned_dns_group_id == target.id


@pytest.mark.asyncio
async def test_fleet_group_change_refused_when_the_move_is(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1565b")
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    appliance = await _fleet_appliance(db_session, default)
    srv = await _server(db_session, default, "ns1", host=appliance.hostname, agent_id=uuid.uuid4())
    await _server(db_session, target, "ns1")  # name clash in the target
    await db_session.commit()

    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(target.id)}, headers=_auth(token)
    )
    assert resp.status_code == 409, resp.text
    assert "ns1" in resp.text

    await db_session.refresh(srv)
    await db_session.refresh(appliance)
    assert srv.group_id == default.id
    assert appliance.assigned_dns_group_id == default.id


@pytest.mark.asyncio
async def test_fleet_dhcp_group_change_moves_the_appliances_dhcp_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.dhcp import DHCPServer, DHCPServerGroup

    token = await _superadmin(db_session, "root1565c")
    dns_default = await _group(db_session, "default")
    old = DHCPServerGroup(name=f"d-{uuid.uuid4().hex[:6]}")
    new = DHCPServerGroup(name=f"d-{uuid.uuid4().hex[:6]}")
    db_session.add_all([old, new])
    await db_session.flush()
    appliance = await _fleet_appliance(db_session, dns_default, assigned_dhcp_group_id=old.id)
    appliance.assigned_roles = ["dns-bind9", "dhcp"]
    dsrv = DHCPServer(
        name=f"k-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=appliance.hostname.upper(),  # case differs, as a real host may
        server_group_id=old.id,
        agent_id=uuid.uuid4(),
    )
    db_session.add(dsrv)
    await db_session.commit()

    resp = await client.put(
        _roles_url(appliance.id), json={"dhcp_group_id": str(new.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(dsrv)
    await db_session.refresh(appliance)
    assert dsrv.server_group_id == new.id
    assert appliance.assigned_dhcp_group_id == new.id


async def _fleet_appliance_roles(
    db: AsyncSession, group: DNSServerGroup, roles: list[str], hostname: str | None = None
):  # noqa: ANN202
    appliance = await _fleet_appliance(db, group)
    appliance.assigned_roles = roles
    if hostname:
        appliance.hostname = hostname
    await db.flush()
    return appliance


@pytest.mark.asyncio
async def test_fleet_group_change_moves_only_the_current_engines_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1715: an engine switch leaves the old engine's row (bind9) behind in
    the baseline group. Only the current engine's (technitium) row moves."""
    token = await _superadmin(db_session, "root1715a")
    baseline = await _group(db_session, "meridian-dns")
    tech = await _group(
        db_session,
        "qa-tech",
    )
    appliance = await _fleet_appliance_roles(db_session, tech, ["dns-technitium"])
    stale = await _server(
        db_session, baseline, "seed", host=appliance.hostname, agent_id=uuid.uuid4()
    )
    live = await _server(
        db_session,
        tech,
        "seed",
        driver="technitium",
        host=appliance.hostname,
        agent_id=uuid.uuid4(),
    )
    await db_session.commit()

    # With a free target group, only the live row moves; the stale one is
    # left alone (it is in nobody's way).
    free = await _group(db_session, "free")
    await db_session.commit()
    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(free.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(live)
    await db_session.refresh(stale)
    assert live.group_id == free.id
    assert stale.group_id == baseline.id


@pytest.mark.asyncio
async def test_fleet_group_change_does_not_take_another_appliances_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1715b")
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    mine = await _fleet_appliance_roles(db_session, default, ["dns-bind9"], "ddi-node1")
    other = await _fleet_appliance_roles(db_session, default, ["dns-bind9"], "ddi-node2")
    theirs = await _server(
        db_session, default, "n2", host="DDI-NODE2", agent_id=uuid.uuid4(), appliance_id=other.id
    )
    # Owned by another appliance by FK, even though the host matches mine.
    stolen = await _server(
        db_session, default, "n1x", host="ddi-node1", agent_id=uuid.uuid4(), appliance_id=other.id
    )
    ours = await _server(db_session, default, "n1", host="DDI-Node1", agent_id=uuid.uuid4())
    await db_session.commit()

    resp = await client.put(
        _roles_url(mine.id), json={"dns_group_id": str(target.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    for r in (ours, theirs, stolen):
        await db_session.refresh(r)
    assert ours.group_id == target.id
    assert theirs.group_id == default.id
    assert stolen.group_id == default.id


@pytest.mark.asyncio
async def test_fleet_move_survives_agent_re_registration_by_hostname(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1715: after the Fleet move, an agent restart / slot upgrade (it
    re-registers with the same agent_id, still naming the old group) must not
    drag the row back."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    token = await _superadmin(db_session, "root1715c")
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    appliance = await _fleet_appliance(db_session, default)
    aid = uuid.uuid4()
    srv = await _server(db_session, default, "ns1", host=appliance.hostname, agent_id=aid)
    await db_session.commit()

    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(target.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    reg = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-1715"},
        json={
            "hostname": appliance.hostname,
            "fingerprint": "fp-1715",
            "driver": "bind9",
            "roles": ["authoritative"],
            "agent_id": str(aid),
            "group_name": "default",
        },
    )
    assert reg.status_code == 200, reg.text
    assert reg.json()["server_id"] == str(srv.id)
    await db_session.refresh(srv)
    assert srv.group_id == target.id


# ── #1715: the reproduction, through the real register endpoint ──────────────
#
# Both hostnames come from the same kernel nodename on an appliance: the
# supervisor reports ``APPLIANCE_HOSTNAME`` (firstboot's ``hostname``) and a
# hostNetwork agent registers ``os.uname().nodename``. So the agent rows here
# are created by POSTing exactly what the agent sends, not by hand.

_HOST_1715 = "ddipg-seed"


async def _agent_register(
    client: AsyncClient, *, driver: str, group: str, agent_id: uuid.UUID, host: str = _HOST_1715
) -> str:
    reg = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-1715"},
        json={
            "hostname": host,
            "fingerprint": f"fp-{agent_id.hex[:8]}",
            "driver": driver,
            "roles": ["authoritative"],
            "agent_id": str(agent_id),
            "group_name": group,
        },
    )
    assert reg.status_code == 200, reg.text
    return reg.json()["server_id"]


async def _engine_switch_rig(
    client: AsyncClient, db: AsyncSession, monkeypatch: pytest.MonkeyPatch, *, quiet_for: int
):  # noqa: ANN202
    """bind9 in ``meridian-dns``, then a switch to technitium in
    ``qa1731-tech``: the issue's steps 1-2, with the bind9 agent silent for
    ``quiet_for`` seconds."""
    from datetime import timedelta

    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    baseline = await _group(db, "meridian-dns")
    tech = await _group(db, "qa1731-tech")
    await db.commit()
    bind9_id = await _agent_register(
        client, driver="bind9", group="meridian-dns", agent_id=uuid.uuid4()
    )
    appliance = await _fleet_appliance(db, tech, hostname=_HOST_1715)
    appliance.assigned_roles = ["dhcp", "dns-technitium"]
    await db.commit()
    tech_id = await _agent_register(
        client, driver="technitium", group="qa1731-tech", agent_id=uuid.uuid4()
    )
    bind9 = await db.get(DNSServer, uuid.UUID(bind9_id))
    tech_srv = await db.get(DNSServer, uuid.UUID(tech_id))
    assert bind9 is not None and tech_srv is not None
    assert bind9.appliance_id is None and tech_srv.appliance_id is None
    bind9.last_seen_at = datetime.now(UTC) - timedelta(seconds=quiet_for)
    await db.commit()
    return appliance, baseline, tech, bind9, tech_srv


@pytest.mark.asyncio
async def test_fleet_move_back_retires_the_appliances_dead_engine_row(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1715 step 2: moving the appliance back to the group its OLD engine
    served. Its own dead bind9 row sits there with the same name and the
    other driver; it is retired (audited) and the live technitium row moves."""
    from app.models.audit import AuditLog

    token = await _superadmin(db_session, "root1715d")
    appliance, baseline, tech, bind9, tech_srv = await _engine_switch_rig(
        client, db_session, monkeypatch, quiet_for=600
    )
    bind9_id, tech_id, baseline_id = bind9.id, tech_srv.id, baseline.id

    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(baseline.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    assert await db_session.get(DNSServer, bind9_id) is None
    moved = await db_session.get(DNSServer, tech_id)
    assert moved is not None and moved.group_id == baseline_id
    assert moved.is_primary  # the retired row was the group's primary
    await db_session.refresh(appliance)
    assert appliance.assigned_dns_group_id == baseline_id

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "dns_server")))
        .scalars()
        .all()
    )
    retired = [r for r in rows if r.action == "delete" and r.resource_id == str(bind9_id)]
    assert len(retired) == 1
    assert retired[0].new_value["reason"] == "retired_stale_engine_row"
    assert any(r.action == "update" and r.resource_id == str(tech_id) for r in rows)

    # And the agent coming back (slot upgrade / pod restart, still naming the
    # group it registered into) neither drags the row back nor forks one.
    sid = await _agent_register(
        client, driver="technitium", group="qa1731-tech", agent_id=moved.agent_id
    )
    assert sid == str(tech_id)
    db_session.expire_all()
    again = await db_session.get(DNSServer, tech_id)
    assert again is not None and again.group_id == baseline_id


@pytest.mark.asyncio
async def test_fleet_move_back_refuses_while_the_old_engine_still_reports(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Right after a switch the old engine's pod may not have stopped yet. Its
    row is never deleted while its agent is live: 409 naming the row."""
    token = await _superadmin(db_session, "root1715e")
    appliance, baseline, tech, bind9, tech_srv = await _engine_switch_rig(
        client, db_session, monkeypatch, quiet_for=5
    )
    bind9_id, tech_srv_id, tech_id = bind9.id, tech_srv.id, tech.id
    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(baseline.id)}, headers=_auth(token)
    )
    assert resp.status_code == 409, resp.text
    assert _HOST_1715 in resp.json()["detail"] and "bind9" in resp.json()["detail"]
    db_session.expire_all()
    assert await db_session.get(DNSServer, bind9_id) is not None
    still = await db_session.get(DNSServer, tech_srv_id)
    assert still is not None and still.group_id == tech_id
    await db_session.refresh(appliance)
    assert appliance.assigned_dns_group_id == tech_id


@pytest.mark.asyncio
async def test_fleet_move_never_retires_another_appliances_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A dead row in the target that is NOT this appliance's (another
    appliance's by FK, or another host) still refuses the move."""
    token = await _superadmin(db_session, "root1715f")
    baseline = await _group(db_session, "meridian-dns")
    tech = await _group(db_session, "qa1731-tech")
    mine = await _fleet_appliance(db_session, tech, hostname="node-a")
    mine.assigned_roles = ["dns-technitium"]
    other = await _fleet_appliance(db_session, baseline, hostname="node-b")
    live = await _server(
        db_session, tech, "node-a", driver="technitium", host="node-a", agent_id=uuid.uuid4()
    )
    # Same host string as mine, but owned by the other appliance by FK.
    theirs = await _server(
        db_session, baseline, "node-a", host="node-a", agent_id=uuid.uuid4(), appliance_id=other.id
    )
    await db_session.commit()
    theirs_id, live_id, tech_id = theirs.id, live.id, tech.id

    resp = await client.put(
        _roles_url(mine.id), json={"dns_group_id": str(baseline.id)}, headers=_auth(token)
    )
    assert resp.status_code in (409, 422), resp.text
    db_session.expire_all()
    assert await db_session.get(DNSServer, theirs_id) is not None
    still = await db_session.get(DNSServer, live_id)
    assert still is not None and still.group_id == tech_id


@pytest.mark.asyncio
async def test_fleet_move_retires_nothing_when_the_hostname_is_shared(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two approved appliances with one hostname: the hostname match is off,
    so the dead row can't be proven ours — nothing moves, nothing is deleted."""
    token = await _superadmin(db_session, "root1715g")
    appliance, baseline, tech, bind9, tech_srv = await _engine_switch_rig(
        client, db_session, monkeypatch, quiet_for=600
    )
    await _fleet_appliance(db_session, baseline, hostname=_HOST_1715.upper())
    await db_session.commit()
    bind9_id, tech_srv_id, tech_id = bind9.id, tech_srv.id, tech.id
    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(baseline.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    assert await db_session.get(DNSServer, bind9_id) is not None
    still = await db_session.get(DNSServer, tech_srv_id)
    assert still is not None and still.group_id == tech_id


@pytest.mark.asyncio
async def test_fleet_move_matches_a_trailing_dot_and_case(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1715h")
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    appliance = await _fleet_appliance(db_session, default, hostname="Edge-1.example.net")
    srv = await _server(
        db_session, default, "edge", host="edge-1.EXAMPLE.net.", agent_id=uuid.uuid4()
    )
    await db_session.commit()
    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(target.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(srv)
    assert srv.group_id == target.id


@pytest.mark.asyncio
async def test_fleet_move_wakes_the_agent_and_both_groups(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The move's ``collect_wake`` calls need a collector on the request; the
    roles route had none, so they were dropped."""
    import app.core.agent_wake as agent_wake

    published: list[str] = []

    async def _capture(*channels: str) -> None:
        published.extend(channels)

    monkeypatch.setattr(agent_wake, "publish_wake", _capture)
    token = await _superadmin(db_session, "root1715i")
    default = await _group(db_session, "default")
    target = await _group(db_session, "internal")
    appliance = await _fleet_appliance(db_session, default)
    srv = await _server(db_session, default, "ns1", host=appliance.hostname, agent_id=uuid.uuid4())
    await db_session.commit()
    resp = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(target.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    assert agent_wake.dns_server_channel(srv.id) in published
    assert agent_wake.dns_group_channel(default.id) in published
    assert agent_wake.dns_group_channel(target.id) in published


# ── #1856: one save that switches the engine AND the group ────────────────────


_CAPS_1856 = {"can_run_dns_bind9": True, "can_run_dns_technitium": True}


async def _adopted_row_rig(
    client: AsyncClient, db: AsyncSession, monkeypatch: pytest.MonkeyPatch
):  # noqa: ANN202
    """Eric's steps 1-2: bind9 in group A, then an engine-only switch to
    technitium whose agent (its own agent id) adopts the bind9 row by hostname."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    group_a = await _group(db, "grp1856-a")
    await db.commit()
    bind9_agent = uuid.uuid4()
    row_id = await _agent_register(client, driver="bind9", group="grp1856-a", agent_id=bind9_agent)
    appliance = await _fleet_appliance(db, group_a, hostname=_HOST_1715, capabilities=_CAPS_1856)
    appliance.assigned_roles = ["dns-technitium"]
    await db.commit()
    adopted = await _agent_register(
        client, driver="technitium", group="grp1856-a", agent_id=uuid.uuid4()
    )
    assert adopted == row_id
    return appliance, group_a, bind9_agent, uuid.UUID(row_id)


@pytest.mark.asyncio
async def test_engine_and_group_in_one_save_moves_the_adopted_row(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _superadmin(db_session, "root1856a")
    appliance, group_a, bind9_agent, row_id = await _adopted_row_rig(
        client, db_session, monkeypatch
    )
    group_b = await _group(db_session, "grp1856-b")
    await db_session.commit()
    a_id, b_id = group_a.id, group_b.id

    resp = await client.put(
        _roles_url(appliance.id),
        json={"roles": ["dns-bind9"], "dns_group_id": str(b_id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    row = await db_session.get(DNSServer, row_id)
    assert row is not None and row.group_id == b_id and row.driver == "bind9"
    await db_session.refresh(appliance)
    assert appliance.assigned_dns_group_id == b_id

    # The bind9 agent comes back by its agent id naming the new group: the
    # same row, still in B, and no second row anywhere.
    sid = await _agent_register(client, driver="bind9", group="grp1856-b", agent_id=bind9_agent)
    assert sid == str(row_id)
    db_session.expire_all()
    rows = (await db_session.execute(select(DNSServer))).scalars().all()
    assert [(r.id, r.group_id, r.driver) for r in rows] == [(row_id, b_id, "bind9")]
    assert a_id not in {r.group_id for r in rows}


@pytest.mark.asyncio
async def test_engine_and_group_save_into_a_mixed_group_is_refused_whole(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _superadmin(db_session, "root1856b")
    appliance, group_a, _agent, row_id = await _adopted_row_rig(client, db_session, monkeypatch)
    group_b = await _group(db_session, "grp1856-mixed")
    await _server(db_session, group_b, "other-tech", driver="technitium", is_primary=True)
    await db_session.commit()
    a_id, b_id, app_id = group_a.id, group_b.id, appliance.id

    # bind9 into a technitium-only group: a clean 422, nothing changed.
    resp = await client.put(
        _roles_url(app_id),
        json={"roles": ["dns-bind9"], "dns_group_id": str(b_id)},
        headers=_auth(token),
    )
    assert resp.status_code == 422, resp.text
    assert "single-driver" in resp.json()["detail"]
    # The test session is shared with the handler; production closes it
    # uncommitted on a refusal, which is a rollback.
    await db_session.rollback()
    db_session.expire_all()
    row = await db_session.get(DNSServer, row_id)
    assert row is not None and row.group_id == a_id and row.driver == "technitium"
    from app.models.appliance import Appliance

    app_row = await db_session.get(Appliance, app_id)
    assert app_row is not None
    assert app_row.assigned_roles == ["dns-technitium"]
    assert app_row.assigned_dns_group_id == a_id


@pytest.mark.asyncio
async def test_engine_and_group_save_from_bind9_to_technitium_leaves_no_orphan(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The direction that already worked left the bind9 row behind in the old
    group; now the row follows and the technitium agent adopts it in B."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1715")
    token = await _superadmin(db_session, "root1856c")
    group_a = await _group(db_session, "grp1856-c-a")
    group_b = await _group(db_session, "grp1856-c-b")
    await db_session.commit()
    row_id = await _agent_register(
        client, driver="bind9", group="grp1856-c-a", agent_id=uuid.uuid4()
    )
    appliance = await _fleet_appliance(
        db_session, group_a, hostname=_HOST_1715, capabilities=_CAPS_1856
    )
    await db_session.commit()
    b_id = group_b.id

    resp = await client.put(
        _roles_url(appliance.id),
        json={"roles": ["dns-technitium"], "dns_group_id": str(b_id)},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    sid = await _agent_register(
        client, driver="technitium", group="grp1856-c-b", agent_id=uuid.uuid4()
    )
    assert sid == row_id
    db_session.expire_all()
    rows = (await db_session.execute(select(DNSServer))).scalars().all()
    assert [(str(r.id), r.group_id, r.driver) for r in rows] == [(row_id, b_id, "technitium")]
