"""#2044 — two live DNS agent processes on one server identity.

#2043 (#2042) returns an op ``in_flight`` to another agent instance to
``pending`` when a newer poll arrives, so a replaced agent's leftover
long-poll does not strand a record change. With two agent processes LIVE on
one server identity (a cloned VM that kept its ``agent_id``, two containers on
one state dir), each one's polls took the op back from the other and it
bounced between them, one retry attempt per bounce, until its eight were gone.

Pinned here: one instance owns the server. A new instance takes over at once
(the #2042 replacement stays seamless and raises nothing); the instance it
displaced is refused with 409 if it polls again while the owner is live, so
ops go to one agent only; the episode surfaces on the server row and in the
``dns_agent_duplicate_instance`` alert once it persists; and the survivor
takes the server back by itself when the owner stops polling.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.alerts import _matching_dns_agent_duplicate_instance_subjects
from app.services.dns import agent_instance
from app.services.dns.agent_token import mint_agent_token

CONFIG_URL = "/api/v1/dns/agents/config"
INSTANCE = "X-Spatium-Agent-Instance"
SERIAL = 2026102001


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)


async def _agent(db: AsyncSession) -> tuple[DNSServer, DNSZone, dict[str, str]]:
    grp = DNSServerGroup(name=f"g2044-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="powerdns",
        host="10.0.0.1",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        last_serial=SERIAL,
    )
    db.add(zone)
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, zone, {"Authorization": f"Bearer {token}"}


def _op(server: DNSServer, zone: DNSZone, name: str) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server.id,
        zone_name=zone.name,
        op="create",
        record={"name": name, "type": "A", "value": "192.0.2.44"},
        target_serial=SERIAL,
        state="pending",
        created_at=datetime.now(UTC) - timedelta(seconds=5),
    )


async def _reload_op(db: AsyncSession, op_id: uuid.UUID) -> DNSRecordOp:
    return (
        await db.execute(
            select(DNSRecordOp)
            .where(DNSRecordOp.id == op_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _reload_server(db: AsyncSession, server_id: uuid.UUID) -> DNSServer:
    return (
        await db.execute(
            select(DNSServer)
            .where(DNSServer.id == server_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _poll(client: AsyncClient, headers: dict[str, str], instance: str, etag: str | None):
    h = {**headers, INSTANCE: instance}
    if etag:
        h["If-None-Match"] = etag
    return await client.get(CONFIG_URL, headers=h)


def _op_ids(resp) -> list[str]:  # type: ignore[no-untyped-def]
    return [o["op_id"] for o in resp.json().get("pending_record_ops", [])]


async def _user_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u2044-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_two_live_instances_ops_go_to_one_and_do_not_ping_pong(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone, headers = await _agent(db_session)
    op = _op(server, zone, "first")
    db_session.add(op)
    await db_session.commit()
    op_id, server_id = op.id, server.id

    a = await _poll(client, headers, "agent-a", None)
    assert a.status_code == 200, a.text
    assert _op_ids(a) == [str(op_id)]
    etag = a.headers["etag"]

    # B starts while A is still alive: the newest arrival wins, and the op A
    # holds unacked comes to B (#2043's take-back, once).
    b = await _poll(client, headers, "agent-b", etag)
    assert b.status_code == 200, b.text
    assert _op_ids(b) == [str(op_id)]

    # A and B keep polling. Before #2044 every poll took the op back from the
    # other, one attempt each, until its retries ran out. Now A is refused.
    for _ in range(4):
        again = await _poll(client, headers, "agent-a", etag)
        assert again.status_code == 409, again.text
        assert again.headers[agents_api.DUPLICATE_INSTANCE_HEADER] == "1"
        assert "Another agent process" in again.json()["detail"]
        held = await _poll(client, headers, "agent-b", etag)
        assert held.status_code == 304

    row = await _reload_op(db_session, op_id)
    assert (row.state, row.dispatched_to, row.attempts) == ("in_flight", "agent-b", 1)

    # A new change goes to B only.
    op2 = _op(server, zone, "second")
    db_session.add(op2)
    await db_session.commit()
    op2_id = op2.id
    assert (await _poll(client, headers, "agent-a", etag)).status_code == 409
    b2 = await _poll(client, headers, "agent-b", etag)
    assert b2.status_code == 200
    assert _op_ids(b2) == [str(op2_id)]
    assert (await _reload_op(db_session, op2_id)).dispatched_to == "agent-b"

    srv = await _reload_server(db_session, server_id)
    assert srv.agent_instance == "agent-b"
    assert srv.duplicate_agent_last_at is not None
    assert srv.duplicate_agent_ip


@pytest.mark.asyncio
async def test_a_persisting_duplicate_is_surfaced_on_the_row_and_alerts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _zone, headers = await _agent(db_session)
    user = await _user_headers(db_session)
    await db_session.commit()
    server_id, group_id = server.id, server.group_id

    assert (await _poll(client, headers, "agent-a", None)).status_code == 200
    assert (await _poll(client, headers, "agent-b", None)).status_code == 200
    assert (await _poll(client, headers, "agent-a", None)).status_code == 409

    # One refusal is an overlapping rollout's old pod as much as a clone:
    # nothing is reported yet.
    srv = await _reload_server(db_session, server_id)
    assert not agent_instance.duplicate_active(srv)
    assert await _matching_dns_agent_duplicate_instance_subjects(db_session, None) == []  # type: ignore[arg-type]

    # Still refused minutes later: a real second agent.
    srv.duplicate_agent_first_at = datetime.now(UTC) - timedelta(minutes=3)
    await db_session.commit()
    assert (await _poll(client, headers, "agent-a", None)).status_code == 409

    srv = await _reload_server(db_session, server_id)
    assert agent_instance.duplicate_active(srv)
    hits = await _matching_dns_agent_duplicate_instance_subjects(db_session, None)  # type: ignore[arg-type]
    assert [h[0] for h in hits] == [f"dns_server:{server_id}"]
    assert "Two DNS agent processes" in hits[0][2]

    listed = await client.get(f"/api/v1/dns/groups/{group_id}/servers", headers=user)
    assert listed.status_code == 200, listed.text
    row = next(s for s in listed.json() if s["id"] == str(server_id))
    assert row["duplicate_agent"] is True
    assert row["duplicate_agent_ip"]
    assert row["duplicate_agent_since"] is not None

    # The extra agent is stopped: ten minutes later the episode is over.
    srv.duplicate_agent_last_at = datetime.now(UTC) - timedelta(minutes=11)
    srv.duplicate_agent_first_at = datetime.now(UTC) - timedelta(minutes=15)
    await db_session.commit()
    assert await _matching_dns_agent_duplicate_instance_subjects(db_session, None) == []  # type: ignore[arg-type]
    listed = await client.get(f"/api/v1/dns/groups/{group_id}/servers", headers=user)
    row = next(s for s in listed.json() if s["id"] == str(server_id))
    assert row["duplicate_agent"] is False
    assert row["duplicate_agent_ip"] is None


@pytest.mark.asyncio
async def test_a_replacement_takes_over_at_once_and_raises_no_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone, headers = await _agent(db_session)
    op = _op(server, zone, "replaced")
    db_session.add(op)
    await db_session.commit()
    op_id, server_id = op.id, server.id

    old = await _poll(client, headers, "old-agent", None)
    assert _op_ids(old) == [str(op_id)]
    etag = old.headers["etag"]

    # The old process exited; its replacement's first poll gets the op now.
    new = await _poll(client, headers, "new-agent", etag)
    assert new.status_code == 200, new.text
    assert _op_ids(new) == [str(op_id)]
    for _ in range(3):
        assert (await _poll(client, headers, "new-agent", etag)).status_code == 304

    # A second replacement (another pod roll) is just as seamless.
    newer = await _poll(client, headers, "newer-agent", etag)
    assert newer.status_code == 200
    assert _op_ids(newer) == [str(op_id)]

    srv = await _reload_server(db_session, server_id)
    assert srv.agent_instance == "newer-agent"
    assert srv.agent_instances_displaced == ["old-agent", "new-agent"]
    assert srv.duplicate_agent_last_at is None
    assert not agent_instance.duplicate_active(srv)
    assert await _matching_dns_agent_duplicate_instance_subjects(db_session, None) == []  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_poll_that_loses_ownership_while_it_waits_pages_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The departed agent's leftover long-poll is still running when its
    replacement takes over. On its next pass it must stop, not page the op
    into a response nobody reads."""
    server, zone, headers = await _agent(db_session)
    op = _op(server, zone, "leftover")
    db_session.add(op)
    await db_session.commit()
    op_id = op.id

    real_refresh = agents_api.refresh_agent_server

    async def _taken_over(db: AsyncSession, srv: DNSServer) -> None:
        await real_refresh(db, srv)
        # What the replacement's claim committed while this poll waited.
        srv.agent_instance = "new-agent"

    monkeypatch.setattr(agents_api, "refresh_agent_server", _taken_over)
    resp = await _poll(client, headers, "old-agent", None)
    assert resp.status_code == 409
    row = await _reload_op(db_session, op_id)
    assert (row.state, row.dispatched_to, row.attempts) == ("pending", None, 0)


@pytest.mark.asyncio
async def test_the_survivor_takes_the_server_back_when_the_owner_stops(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id

    assert (await _poll(client, headers, "agent-a", None)).status_code == 200
    assert (await _poll(client, headers, "agent-b", None)).status_code == 200
    assert (await _poll(client, headers, "agent-a", None)).status_code == 409

    # B was shut down: it has not polled past the owner-gone window.
    srv = await _reload_server(db_session, server_id)
    srv.agent_instance_seen_at = datetime.now(UTC) - agent_instance.OWNER_GONE_AFTER * 2
    op = _op(srv, zone, "after")
    db_session.add(op)
    await db_session.commit()
    op_id = op.id

    a = await _poll(client, headers, "agent-a", None)
    assert a.status_code == 200, a.text
    assert _op_ids(a) == [str(op_id)]
    srv = await _reload_server(db_session, server_id)
    assert srv.agent_instance == "agent-a"
    assert srv.agent_instances_displaced == ["agent-b"]


@pytest.mark.asyncio
async def test_an_agent_that_sends_no_instance_is_never_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, _zone, headers = await _agent(db_session)
    await db_session.commit()
    assert (await _poll(client, headers, "agent-a", None)).status_code == 200
    plain = await client.get(CONFIG_URL, headers=headers)
    assert plain.status_code == 200
