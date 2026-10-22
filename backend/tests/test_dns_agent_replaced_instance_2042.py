"""#2042 — a record op shipped on a replaced agent's leftover long-poll.

When a DNS agent is replaced (a pod roll after a slot upgrade), the API can
still be holding a long-poll for the agent that went away. A record change
committed in the next seconds was paged into that poll, committed
``in_flight`` and written to a connection nobody read; the replacement never
received it, and only the heartbeat's 5-minute unacknowledged reset brought
it back. Meanwhile the new agent's startup zone-state report matched the
target serial, so server-state read ``in_sync`` while the record answered
NXDOMAIN.

Pinned here: an op in flight to a previous agent instance ships to the new
instance on its first poll, not five minutes later; it is not re-shipped to
the instance that holds it; a handler whose client is gone does not commit a
page; and server-state is not in sync while a server has an unacknowledged op
for the zone, and is once it is acknowledged.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSServerZoneState, DNSZone
from app.services.dns.agent_token import mint_agent_token
from app.services.dns.record_ops import apply_acks, return_ops_dispatched_elsewhere

CONFIG_URL = "/api/v1/dns/agents/config"
INSTANCE = "X-Spatium-Agent-Instance"
SERIAL = 2026101701


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)


async def _agent(db: AsyncSession) -> tuple[DNSServer, DNSZone, dict[str, str]]:
    grp = DNSServerGroup(name=f"g2042-{uuid.uuid4().hex[:6]}")
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


def _op(server: DNSServer, zone: DNSZone) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server.id,
        zone_name=zone.name,
        op="create",
        record={"name": "op4", "type": "A", "value": "192.0.2.164"},
        target_serial=SERIAL,
        state="pending",
        created_at=datetime.now(UTC) - timedelta(seconds=5),
    )


async def _reload(db: AsyncSession, op_id: uuid.UUID) -> DNSRecordOp:
    return (
        await db.execute(
            select(DNSRecordOp)
            .where(DNSRecordOp.id == op_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _shipped_to_old_agent(
    client: AsyncClient, db: AsyncSession
) -> tuple[DNSServer, DNSZone, dict[str, str], DNSRecordOp, str]:
    """The leftover long-poll of the agent that went away pages the op. Its
    response is the one nobody reads."""
    server, zone, headers = await _agent(db)
    op = _op(server, zone)
    db.add(op)
    await db.commit()
    old = await client.get(CONFIG_URL, headers={**headers, INSTANCE: "old-agent"})
    assert old.status_code == 200, old.text
    assert [o["op_id"] for o in old.json()["pending_record_ops"]] == [str(op.id)]
    shipped = await _reload(db, op.id)
    assert shipped.state == "in_flight"
    assert shipped.dispatched_to == "old-agent"
    assert shipped.dispatched_poll_at is not None
    return server, zone, headers, op, old.headers["etag"]


@pytest.mark.asyncio
async def test_an_op_in_flight_to_a_replaced_agent_ships_on_the_new_agents_first_poll(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, _zone, headers, op, etag = await _shipped_to_old_agent(client, db_session)

    # The replacement's first poll — with the same cached ETag, so nothing
    # but the op could make it answer 200. Not five minutes later: now.
    started = time.monotonic()
    new = await client.get(
        CONFIG_URL, headers={**headers, INSTANCE: "new-agent", "If-None-Match": etag}
    )
    elapsed = time.monotonic() - started
    assert new.status_code == 200, new.text
    assert [o["op_id"] for o in new.json()["pending_record_ops"]] == [str(op.id)]
    assert elapsed < 0.9  # answered at once, not held to the poll's deadline

    row = await _reload(db_session, op.id)
    assert row.state == "in_flight"
    assert row.dispatched_to == "new-agent"
    # Counted as an attempt (the old agent may have applied it and died), and
    # the dispatch the agent echoes moved with it.
    assert row.attempts == 1
    assert new.json()["pending_record_ops"][0]["dispatch"] == 1
    assert row.next_attempt_at is None


@pytest.mark.asyncio
async def test_an_op_in_flight_to_this_instance_is_not_shipped_again(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, _zone, headers, op, etag = await _shipped_to_old_agent(client, db_session)

    # The same agent's next poll, before its heartbeat acks: it holds the op,
    # so the poll settles on 304 rather than re-sending it.
    again = await client.get(
        CONFIG_URL, headers={**headers, INSTANCE: "old-agent", "If-None-Match": etag}
    )
    assert again.status_code == 304
    row = await _reload(db_session, op.id)
    assert (row.state, row.dispatched_to, row.attempts) == ("in_flight", "old-agent", 0)


@pytest.mark.asyncio
async def test_the_departed_agents_older_poll_does_not_take_an_op_from_its_replacement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Both polls are held at once: the leftover one for the agent that went
    away (started first) and the replacement's. An op the replacement's poll
    shipped, received and not yet acked must stay with it — taken back by the
    older poll, it would go to nobody and then reach the replacement twice."""
    server, zone, _headers = await _agent(db_session)
    leftover_started = datetime.now(UTC) - timedelta(seconds=20)
    op = _op(server, zone)
    op.state = "in_flight"
    op.dispatched_to = "new-agent"
    op.dispatched_poll_at = datetime.now(UTC) - timedelta(seconds=2)
    db_session.add(op)
    await db_session.commit()

    taken = await return_ops_dispatched_elsewhere(
        db_session, server.id, "old-agent", poll_started_at=leftover_started
    )
    await db_session.commit()
    assert taken == 0
    row = await _reload(db_session, op.id)
    assert (row.state, row.dispatched_to, row.attempts) == ("in_flight", "new-agent", 0)

    # A poll from another instance that started AFTER the shipping one does
    # take it back: the ranking, not the instance alone, decides.
    assert (
        await return_ops_dispatched_elsewhere(
            db_session, server.id, "next-agent", poll_started_at=datetime.now(UTC)
        )
        == 1
    )


@pytest.mark.asyncio
async def test_an_agent_that_sends_no_instance_leaves_the_op_to_the_5_minute_reset(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, _zone, headers, op, etag = await _shipped_to_old_agent(client, db_session)

    # An agent too old to name itself cannot be told apart from the one the
    # op went to; nothing is reset on its say-so.
    held = await client.get(CONFIG_URL, headers={**headers, "If-None-Match": etag})
    assert held.status_code == 304
    row = await _reload(db_session, op.id)
    assert (row.state, row.dispatched_to, row.attempts) == ("in_flight", "old-agent", 0)


@pytest.mark.asyncio
async def test_a_poll_whose_client_is_gone_does_not_commit_its_page(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, zone, headers = await _agent(db_session)
    op = _op(server, zone)
    db_session.add(op)
    await db_session.commit()
    op_id = op.id  # the handler's rollback expires the session's instances

    async def _gone(self: Request) -> bool:  # noqa: ARG001
        return True

    monkeypatch.setattr(Request, "is_disconnected", _gone)
    resp = await client.get(CONFIG_URL, headers={**headers, INSTANCE: "old-agent"})
    assert resp.status_code == 304
    row = await _reload(db_session, op_id)
    assert (row.state, row.dispatched_to, row.attempts) == ("pending", None, 0)


async def _user_token(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u2042-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_server_state_is_not_in_sync_while_the_server_has_an_unacked_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone, _headers = await _agent(db_session)
    user = await _user_token(db_session)
    op = _op(server, zone)
    op.state = "in_flight"
    op.dispatched_to = "old-agent"
    db_session.add(op)
    # The new agent's startup report: it serves the target serial (adopted
    # from its cached bundle) while the op's record is not there.
    db_session.add(
        DNSServerZoneState(
            server_id=server.id,
            zone_id=zone.id,
            current_serial=SERIAL,
            reported_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    zone_url = f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/server-state"
    server_url = f"/api/v1/dns/servers/{server.id}/zone-state"

    state = await client.get(zone_url, headers=user)
    assert state.status_code == 200, state.text
    body = state.json()
    assert body["servers"][0]["current_serial"] == body["target_serial"] == SERIAL
    assert body["servers"][0]["pending_ops"] == 1
    assert body["in_sync"] is False
    per_server = (await client.get(server_url, headers=user)).json()
    assert per_server["zones"][0]["in_sync"] is False
    assert per_server["zones"][0]["pending_ops"] == 1
    assert per_server["summary"]["in_sync"] == 0

    # A pending op (returned for retry) is just as undelivered.
    op_row = await _reload(db_session, op.id)
    op_row.state = "pending"
    await db_session.commit()
    assert (await client.get(zone_url, headers=user)).json()["in_sync"] is False

    # Acknowledged: in sync.
    await apply_acks(db_session, server.id, [{"op_id": str(op.id), "result": "ok"}])
    await db_session.commit()
    body = (await client.get(zone_url, headers=user)).json()
    assert body["servers"][0]["pending_ops"] == 0
    assert body["in_sync"] is True
    per_server = (await client.get(server_url, headers=user)).json()
    assert per_server["zones"][0]["in_sync"] is True
    assert per_server["summary"]["in_sync"] == 1

    # An op given up on (``failed``) is terminal, not queued: it does not hold
    # the zone out of sync forever. Its failure surfaces on the op itself.
    op_row = await _reload(db_session, op.id)
    op_row.state = "failed"
    await db_session.commit()
    body = (await client.get(zone_url, headers=user)).json()
    assert body["servers"][0]["pending_ops"] == 0
    assert body["in_sync"] is True
