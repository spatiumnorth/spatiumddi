"""#1171 — through an upgrade, no SOA of an edited zone goes out under a serial
that an older BIND9 agent served with the literal timers.

Before this release every BIND9 agent wrote ``3600 600 86400 300`` into every
zone's SOA. Moving the serial of the zones whose stored timers differ inside the
migration (as ``ff32b91acad8`` first did) let the agent of the release before,
still running when the new release's first bundle reached it, put the moved
serial on the wire with that literal. The new agent then served the stored
timers under the same serial. On a single node upgraded from 2026.10.02-1 that
lasted 44 s and 52 s, and an in-window transfer left a secondary holding the old
timers with "up to date" for an answer.

The rule now: a group's bundles carry each zone's own timers only while every
BIND9 agent in it says it renders them (``X-Spatium-Agent-Features:
soa-timers``). Until then they carry the literal, which agents old and new write
the same way. When the group switches, either way, the serial of each of its
zones whose timers differ from the literal moves in the same transaction.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import (
    ZONE_DEFAULT_EXPIRE,
    ZONE_DEFAULT_MINIMUM,
    ZONE_DEFAULT_REFRESH,
    ZONE_DEFAULT_RETRY,
    DNSServer,
    DNSServerGroup,
    DNSZone,
)
from app.services.dns import agent_token as dns_tokens
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.serial import compute_next_serial
from app.services.dns.soa_timers import (
    AGENT_FEATURES_HEADER,
    LITERAL_SOA_TIMERS,
    agent_features,
)

TIMERS = ("refresh", "retry", "expire", "minimum")
LITERAL = (3600, 600, 86400, 300)
EDITED = {"refresh": 7200, "retry": 900, "expire": 1209600, "minimum": 60}
RENDERS = {AGENT_FEATURES_HEADER: "soa-timers"}

HEARTBEAT = "/api/v1/dns/agents/heartbeat"
REGISTER = "/api/v1/dns/agents/register"


async def _group(db: AsyncSession, *, serves: bool) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", serves_soa_timers=serves)
    db.add(grp)
    await db.flush()
    return grp


async def _agent(
    db: AsyncSession, grp: DNSServerGroup, *, renders: bool, **kw: Any
) -> tuple[DNSServer, dict[str, str]]:
    """A server run by an agent, with a token its heartbeat can present."""
    fields: dict[str, Any] = {
        "driver": "bind9",
        "agent_id": uuid.uuid4(),
        "agent_fingerprint": "fp",
        **kw,
    }
    server = DNSServer(
        group_id=grp.id,
        host="10.0.0.53",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        agent_renders_soa_timers=renders,
        **fields,
    )
    db.add(server)
    await db.flush()
    headers: dict[str, str] = {}
    if server.agent_id is not None:
        token, _exp = dns_tokens.mint_agent_token(str(server.id), str(server.agent_id), "fp")
        server.agent_jwt_hash = dns_tokens.hash_token(token)
        headers = {"Authorization": f"Bearer {token}"}
    return server, headers


async def _zone(db: AsyncSession, grp: DNSServerGroup, serial: int, **timers: int) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.test.",
        zone_type="primary",
        kind="forward",
        last_serial=serial,
        **timers,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _heartbeat(
    client: AsyncClient, headers: dict[str, str], *, renders: bool
) -> dict[str, Any]:
    resp = await client.post(
        HEARTBEAT, headers={**headers, **(RENDERS if renders else {})}, json={}
    )
    assert resp.status_code == 200, resp.text
    out: dict[str, Any] = resp.json()
    return out


async def _shipped(db: AsyncSession, server: DNSServer, zone: DNSZone) -> tuple[int, tuple]:
    """(serial, timers) of the zone in the bundle the server is sent."""
    bundle = await build_config_bundle(db, server)
    copies = {
        (z["serial"], tuple(z[k] for k in TIMERS))
        for z in bundle["zones"]
        if z["id"] == str(zone.id)
    }
    assert len(copies) == 1, copies
    return copies.pop()


async def _state(db: AsyncSession, grp: DNSServerGroup, *zones: DNSZone) -> tuple:
    """The group's switch and each zone's serial, read from the database."""
    serves = await db.scalar(
        select(DNSServerGroup.serves_soa_timers)
        .where(DNSServerGroup.id == grp.id)
        .execution_options(populate_existing=True)
    )
    serials = []
    for z in zones:
        serials.append(
            await db.scalar(
                select(DNSZone.last_serial)
                .where(DNSZone.id == z.id)
                .execution_options(populate_existing=True)
            )
        )
    return (serves, *serials)


# ── The literal while an agent writes it ────────────────────────────────────


def test_the_literal_is_what_a_zone_at_the_defaults_stores() -> None:
    """A zone left at the defaults is shipped the same bytes either way, so a
    group switching never moves its serial (and never reloads it)."""
    assert tuple(LITERAL_SOA_TIMERS[k] for k in TIMERS) == LITERAL
    assert (
        ZONE_DEFAULT_REFRESH,
        ZONE_DEFAULT_RETRY,
        ZONE_DEFAULT_EXPIRE,
        ZONE_DEFAULT_MINIMUM,
    ) == LITERAL


@pytest.mark.parametrize(
    ("header", "tokens"),
    [
        (None, frozenset()),
        ("", frozenset()),
        ("soa-timers", frozenset({"soa-timers"})),
        (" SOA-Timers , other ", frozenset({"soa-timers", "other"})),
    ],
)
def test_agent_features_reads_a_comma_list(header: str | None, tokens: frozenset[str]) -> None:
    assert agent_features(header) == tokens


@pytest.mark.asyncio
async def test_a_group_with_an_agent_that_writes_the_literal_is_shipped_the_literal(
    db_session: AsyncSession,
) -> None:
    grp = await _group(db_session, serves=False)
    server, _ = await _agent(db_session, grp, renders=False)
    zone = await _zone(db_session, grp, 2026100301, **EDITED)
    await db_session.commit()

    assert await _shipped(db_session, server, zone) == (2026100301, LITERAL)


# ── Switching on: once, when the last BIND9 agent renders them ──────────────


@pytest.mark.asyncio
async def test_the_last_agent_to_render_them_switches_the_group_on_and_moves_the_serial_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = await _group(db_session, serves=False)
    server, headers = await _agent(db_session, grp, renders=False)
    edited = await _zone(db_session, grp, 1, **EDITED)
    minimum_only = await _zone(db_session, grp, 2026100300, minimum=120)
    untouched = await _zone(db_session, grp, 0)
    await db_session.commit()

    await _heartbeat(client, headers, renders=True)

    moved = (compute_next_serial(1), compute_next_serial(2026100300))
    assert await _state(db_session, grp, edited, minimum_only, untouched) == (True, *moved, 0)
    assert await _shipped(db_session, server, edited) == (moved[0], tuple(EDITED.values()))
    assert await _shipped(db_session, server, minimum_only) == (moved[1], (3600, 600, 86400, 120))
    assert await _shipped(db_session, server, untouched) == (0, LITERAL)

    # Every later heartbeat finds the group already serving them: no move.
    await _heartbeat(client, headers, renders=True)
    assert await _state(db_session, grp, edited, minimum_only, untouched) == (True, *moved, 0)


@pytest.mark.asyncio
async def test_a_group_waits_for_every_bind9_agent_in_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A cluster rolls its DNS pods one node at a time: the nodes still on the
    older agent keep writing the literal, so the group keeps shipping it."""
    grp = await _group(db_session, serves=False)
    first, first_headers = await _agent(db_session, grp, renders=False)
    _second, second_headers = await _agent(db_session, grp, renders=False)
    zone = await _zone(db_session, grp, 2026100500, **EDITED)
    await db_session.commit()

    await _heartbeat(client, first_headers, renders=True)

    assert await _state(db_session, grp, zone) == (False, 2026100500)
    assert await _shipped(db_session, first, zone) == (2026100500, LITERAL)

    await _heartbeat(client, second_headers, renders=True)

    assert await _state(db_session, grp, zone) == (True, compute_next_serial(2026100500))
    assert await _shipped(db_session, first, zone) == (
        compute_next_serial(2026100500),
        tuple(EDITED.values()),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bystander",
    [
        {"is_enabled": False},
        {"pending_approval": True},
        {"agent_id": None},
        {"driver": "powerdns"},
        {"driver": "windows_dns", "agent_id": None},
    ],
    ids=["disabled", "pending-approval", "no-agent", "powerdns", "agentless"],
)
async def test_a_server_that_renders_no_bind9_bundle_does_not_hold_the_group_back(
    client: AsyncClient, db_session: AsyncSession, bystander: dict[str, Any]
) -> None:
    grp = await _group(db_session, serves=False)
    _server, headers = await _agent(db_session, grp, renders=False)
    await _agent(db_session, grp, renders=False, **bystander)
    zone = await _zone(db_session, grp, 7, **EDITED)
    await db_session.commit()

    await _heartbeat(client, headers, renders=True)

    assert await _state(db_session, grp, zone) == (True, compute_next_serial(7))


@pytest.mark.asyncio
async def test_a_zone_with_the_literal_timers_never_moves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = await _group(db_session, serves=False)
    _server, headers = await _agent(db_session, grp, renders=False)
    at_defaults = await _zone(db_session, grp, 0)
    set_to_the_literal = await _zone(
        db_session, grp, 2026100102, refresh=3600, retry=600, expire=86400, minimum=300
    )
    await db_session.commit()

    await _heartbeat(client, headers, renders=True)

    assert await _state(db_session, grp, at_defaults, set_to_the_literal) == (
        True,
        0,
        2026100102,
    )


@pytest.mark.asyncio
async def test_the_switch_is_audited_with_the_zones_it_moved(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = await _group(db_session, serves=False)
    _server, headers = await _agent(db_session, grp, renders=False)
    await _zone(db_session, grp, 3, **EDITED)
    await _zone(db_session, grp, 0)
    await db_session.commit()

    await _heartbeat(client, headers, renders=True)

    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dns_server_group",
                    AuditLog.resource_id == str(grp.id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert [(r.action, r.old_value, r.new_value) for r in rows] == [
        (
            "dns.group.soa_timers",
            {"serves_soa_timers": False},
            {"serves_soa_timers": True, "zones_serial_moved": 1},
        )
    ]


# ── Switching off: an agent that writes the literal comes (back) ────────────


@pytest.mark.asyncio
async def test_an_agent_that_writes_the_literal_switches_the_group_off_and_moves_the_serial(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The release before this one, back on a node (a rolled-back pod), would
    write the current serial with the literal while the others serve the zone's
    own timers under it. The group goes back to the literal under a new serial."""
    grp = await _group(db_session, serves=True)
    server, headers = await _agent(db_session, grp, renders=True)
    zone = await _zone(db_session, grp, 2026100401, **EDITED)
    await db_session.commit()

    await _heartbeat(client, headers, renders=False)

    assert await _state(db_session, grp, zone) == (False, compute_next_serial(2026100401))
    assert await _shipped(db_session, server, zone) == (compute_next_serial(2026100401), LITERAL)


@pytest.mark.asyncio
async def test_register_records_what_the_agent_renders_before_it_can_poll(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An older agent registering into a group that serves the zones' own timers
    switches it off in the registration itself: its first bundle already has
    the literal and a serial nobody served the stored timers under."""
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1171")
    grp = await _group(db_session, serves=True)
    await _agent(db_session, grp, renders=True)
    zone = await _zone(db_session, grp, 2026100402, **EDITED)
    await db_session.commit()

    newer = await client.post(
        REGISTER,
        headers={"X-DNS-Agent-Key": "psk-1171", **RENDERS},
        json={"hostname": "ns-new", "fingerprint": "fp-new", "group_name": grp.name},
    )
    assert newer.status_code == 200, newer.text
    assert await _state(db_session, grp, zone) == (True, 2026100402)

    older = await client.post(
        REGISTER,
        headers={"X-DNS-Agent-Key": "psk-1171"},
        json={"hostname": "ns-old", "fingerprint": "fp-old", "group_name": grp.name},
    )
    assert older.status_code == 200, older.text

    flags = dict(
        (
            await db_session.execute(
                select(DNSServer.name, DNSServer.agent_renders_soa_timers)
                .where(DNSServer.group_id == grp.id)
                .execution_options(populate_existing=True)
            )
        ).all()
    )
    assert flags["ns-new"] is True and flags["ns-old"] is False
    assert await _state(db_session, grp, zone) == (False, compute_next_serial(2026100402))


@pytest.mark.asyncio
async def test_a_failed_switch_never_fails_the_heartbeat(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The heartbeat carries op acks and liveness; the switch is retried by the
    next one."""

    async def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("simulated")

    monkeypatch.setattr("app.api.v1.dns.agents.reconcile_soa_timers", _boom)
    grp = await _group(db_session, serves=False)
    server, headers = await _agent(db_session, grp, renders=False)
    await db_session.commit()

    body = await _heartbeat(client, headers, renders=True)

    assert body["server_id"] == str(server.id)
    renders = await db_session.scalar(
        select(DNSServer.agent_renders_soa_timers)
        .where(DNSServer.id == server.id)
        .execution_options(populate_existing=True)
    )
    assert renders is True
