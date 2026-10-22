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

import asyncio
import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.alerts import (
    RULE_TYPE_DNS_AGENT_DUPLICATE_INSTANCE,
    RULE_TYPES,
    _matching_dns_agent_duplicate_instance_subjects,
)
from app.services.dns import agent_instance
from app.services.dns.agent_token import mint_agent_token
from app.services.dns.server_move import move_server_to_group
from tests.conftest import _TestSessionLocal
from tests.test_dns_server_move_render_deadlock_1703 import (
    _STEP,
    _cleanup,
    _prepare,
    _render_finish,
    _render_insert,
    _wait_blocked,
)

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


# ── the refused agent's heartbeat ──────────────────────────────────────────

HEARTBEAT_URL = "/api/v1/dns/agents/heartbeat"


@pytest.mark.asyncio
async def test_a_displaced_agents_heartbeat_keeps_its_reports_off_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The refused half of a duplicate pair still heartbeats every 30 s. Its
    config / daemon verdict describes a process that is not served; written
    alternately with the owner's it would flap the row and could invent (or
    hide) an ``agent_config_rejected`` / ``agent_daemon_degraded`` alert."""
    server, _zone, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id

    assert (await _poll(client, headers, "agent-a", None)).status_code == 200
    assert (await _poll(client, headers, "agent-b", None)).status_code == 200

    owner = await client.post(
        HEARTBEAT_URL,
        headers={**headers, INSTANCE: "agent-b"},
        # An ``ok`` carries the etag it applied; without one it is a
        # pre-first-apply placeholder and is not stored (#2258).
        json={"config": {"status": "ok", "etag": "e1"}, "daemon": {"status": "ok"}},
    )
    assert owner.status_code == 200, owner.text
    srv = await _reload_server(db_session, server_id)
    seen_before = srv.last_seen_at
    assert srv.config_apply_status == "ok"

    refused = await client.post(
        HEARTBEAT_URL,
        headers={**headers, INSTANCE: "agent-a"},
        json={
            "config": {"status": "reverted", "error": "named-checkconf: boom"},
            "daemon": {"status": "degraded", "reason": "not serving"},
        },
    )
    assert refused.status_code == 200, refused.text
    srv = await _reload_server(db_session, server_id)
    assert srv.config_apply_status == "ok"
    assert srv.config_apply_error is None
    assert srv.daemon_status == "ok"
    # Liveness still counts: the agent is up, just not served.
    assert srv.last_seen_at is not None and seen_before is not None
    assert srv.last_seen_at >= seen_before

    # An agent that sends no instance id (older) is not judged at all.
    legacy = await client.post(
        HEARTBEAT_URL, headers=headers, json={"config": {"status": "reverted", "error": "x"}}
    )
    assert legacy.status_code == 200
    srv = await _reload_server(db_session, server_id)
    assert srv.config_apply_status == "reverted"


@pytest.mark.asyncio
async def test_a_new_process_heartbeating_before_its_first_poll_is_reported(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A replacement registers and heartbeats before its first poll claims the
    server: never seen, so not displaced, and its reports land."""
    server, _zone, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    assert (await _poll(client, headers, "old", None)).status_code == 200
    resp = await client.post(
        HEARTBEAT_URL,
        headers={**headers, INSTANCE: "new"},
        json={"config": {"status": "reverted", "error": "boom"}},
    )
    assert resp.status_code == 200, resp.text
    srv = await _reload_server(db_session, server_id)
    assert srv.config_apply_status == "reverted"


# ── the alert rule is seeded once, by the migration ────────────────────────

_MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "f4c2a8e61b93_dns_server_agent_instance.py"
)


def _load_migration() -> Any:
    spec = importlib.util.spec_from_file_location("_mig_f4c2a8e61b93", _MIGRATION)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.asyncio
async def test_migration_seeds_one_enabled_rule_and_respects_an_existing_one(
    db_session: AsyncSession,
) -> None:
    mig = _load_migration()

    async def count() -> int:
        return int(
            await db_session.scalar(
                select(func.count())
                .select_from(AlertRule)
                .where(AlertRule.rule_type == RULE_TYPE_DNS_AGENT_DUPLICATE_INSTANCE)
            )
            or 0
        )

    async def run_seed() -> None:
        await db_session.execute(mig.SEED_DUPLICATE_INSTANCE_RULE_SQL, mig.seed_params())
        await db_session.commit()

    await run_seed()
    await run_seed()
    assert await count() == 1
    rule = await db_session.scalar(
        select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_DNS_AGENT_DUPLICATE_INSTANCE)
    )
    assert rule is not None
    assert rule.enabled and rule.severity == "warning"
    assert rule.name == "Two DNS agents on one server"
    assert rule.notify_syslog and rule.notify_webhook and not rule.notify_smtp
    # The catalogue knows the type the migration hard-codes.
    assert RULE_TYPE_DNS_AGENT_DUPLICATE_INSTANCE in RULE_TYPES

    # An operator's own rule of the type, under another name, suppresses it.
    await db_session.delete(rule)
    db_session.add(
        AlertRule(
            name="mine",
            rule_type=RULE_TYPE_DNS_AGENT_DUPLICATE_INSTANCE,
            severity="critical",
            enabled=True,
        )
    )
    await db_session.commit()
    await run_seed()
    assert await count() == 1


def test_the_rule_is_not_seeded_at_startup() -> None:
    """A startup seed keyed on "none exists" brings a DELETED rule back on
    every restart (#2138). The migration seeds it, once."""
    import inspect  # noqa: PLC0415

    import app.main as main_mod  # noqa: PLC0415
    from app.services import alerts  # noqa: PLC0415

    assert "seed_dns_agent_duplicate_instance_alert_rule" not in inspect.getsource(main_mod)
    assert not hasattr(alerts, "seed_dns_agent_duplicate_instance_alert_rule")


# ── the claim's row lock against every other writer of the server row ──────
#
# A deadlock on the long-poll stops a group converging, so these run the claim
# in a real session against another real session holding the row the way the
# bundle store (#1703 / #2031), a server move (#934 / #1929) and registration
# do. The harness is the #1703 one: every await bounded, backends terminated.


async def _committed_server(db: AsyncSession) -> uuid.UUID:
    server, _zone, _headers = await _agent(db)
    await db.commit()
    return server.id


async def _claim_in(session: AsyncSession, server_id: uuid.UUID, instance: str) -> bool:
    srv = await asyncio.wait_for(session.get(DNSServer, server_id), _STEP)
    assert srv is not None
    return await asyncio.wait_for(agent_instance.claim_poll(session, srv, instance), _STEP)


@pytest.mark.asyncio
async def test_the_claim_does_not_wait_for_a_render_inserting_its_bundle(
    db_session: AsyncSession,
) -> None:
    """The render's bundle INSERT holds FOR KEY SHARE on the server row. The
    claim takes FOR NO KEY UPDATE, which does not conflict: a poll is never
    held up behind a render (or a record write enqueuing this server's ops)."""
    server_id = await _committed_server(db_session)
    render = _TestSessionLocal()
    claimer = _TestSessionLocal()
    pids: list[int] = []
    try:
        pids.append(await _prepare(render))
        pids.append(await _prepare(claimer))
        await _render_insert(render, server_id)
        assert await asyncio.wait_for(_claim_in(claimer, server_id, "agent-a"), 5)
        await _render_finish(render, server_id)
    finally:
        await _cleanup(None, [render, claimer], pids)
    async with _TestSessionLocal() as check:
        row = await check.get(DNSServer, server_id)
        assert row is not None and row.agent_instance == "agent-a"
        assert row.bundle_render_count == 1


@pytest.mark.asyncio
async def test_the_claim_waits_out_a_render_holding_the_row_without_deadlock(
    db_session: AsyncSession,
) -> None:
    server_id = await _committed_server(db_session)
    render = _TestSessionLocal()
    claimer = _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[bool] | None = None
    try:
        pids.append(await _prepare(render))
        claimer_pid = await _prepare(claimer)
        pids.append(claimer_pid)
        await _render_insert(render, server_id)
        await asyncio.wait_for(
            render.execute(
                update(DNSServer)
                .where(DNSServer.id == server_id)
                .values(bundle_render_count=DNSServer.bundle_render_count + 1)
            ),
            _STEP,
        )
        task = asyncio.create_task(_claim_in(claimer, server_id, "agent-a"))
        await _wait_blocked(claimer_pid, task)
        await asyncio.wait_for(render.commit(), _STEP)
        assert await asyncio.wait_for(task, _STEP)
    finally:
        await _cleanup(task, [render, claimer], pids)


@pytest.mark.asyncio
async def test_the_claim_waits_out_a_server_move_without_deadlock(
    db_session: AsyncSession,
) -> None:
    """A move writes ``group_id`` (FOR UPDATE) and deletes the server's ops
    and zone state; the claim waits for it, then claims the moved row."""
    server_id = await _committed_server(db_session)
    dst = DNSServerGroup(name=f"dst2044-{uuid.uuid4().hex[:6]}")
    db_session.add(dst)
    await db_session.commit()
    dst_id = dst.id
    mover = _TestSessionLocal()
    claimer = _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[bool] | None = None
    try:
        pids.append(await _prepare(mover))
        claimer_pid = await _prepare(claimer)
        pids.append(claimer_pid)
        srv = await asyncio.wait_for(mover.get(DNSServer, server_id), _STEP)
        target = await asyncio.wait_for(mover.get(DNSServerGroup, dst_id), _STEP)
        assert srv is not None and target is not None
        assert await asyncio.wait_for(move_server_to_group(mover, srv, target), _STEP)
        await asyncio.wait_for(mover.flush(), _STEP)

        task = asyncio.create_task(_claim_in(claimer, server_id, "agent-a"))
        await _wait_blocked(claimer_pid, task)
        await asyncio.wait_for(mover.commit(), _STEP)
        assert await asyncio.wait_for(task, _STEP)
    finally:
        await _cleanup(task, [mover, claimer], pids)
    async with _TestSessionLocal() as check:
        row = await check.get(DNSServer, server_id)
        assert row is not None and row.group_id == dst_id and row.agent_instance == "agent-a"


@pytest.mark.asyncio
async def test_two_replicas_claiming_at_once_leave_one_owner(
    db_session: AsyncSession,
) -> None:
    """Two api replicas serve the two agents' polls: the row lock serialises
    the claims, the second reads the first's owner, and exactly one wins."""
    server_id = await _committed_server(db_session)
    holder = _TestSessionLocal()
    first = _TestSessionLocal()
    second = _TestSessionLocal()
    pids: list[int] = []
    t1: asyncio.Task[bool] | None = None
    t2: asyncio.Task[bool] | None = None
    try:
        pids.append(await _prepare(holder))
        p1 = await _prepare(first)
        p2 = await _prepare(second)
        pids += [p1, p2]
        # Owner A is established and live; two new processes race. Hold the
        # row so both claims queue on it.
        async with _TestSessionLocal() as setup:
            assert await _claim_in(setup, server_id, "agent-a")
        await asyncio.wait_for(
            holder.execute(
                select(DNSServer).where(DNSServer.id == server_id).with_for_update(key_share=True)
            ),
            _STEP,
        )
        t1 = asyncio.create_task(_claim_in(first, server_id, "agent-b"))
        await _wait_blocked(p1, t1)
        t2 = asyncio.create_task(_claim_in(second, server_id, "agent-c"))
        await _wait_blocked(p2, t2)
        await asyncio.wait_for(holder.commit(), _STEP)
        results = await asyncio.wait_for(asyncio.gather(t1, t2), _STEP)
    finally:
        await _cleanup(t1, [holder], [])
        await _cleanup(t2, [first, second], pids)
    # Both are new processes, so each takes over in turn (the replacement
    # rule); what matters is that the row ends with one owner and the other
    # recorded as displaced, never a lost update.
    assert results == [True, True]
    async with _TestSessionLocal() as check:
        row = await check.get(DNSServer, server_id)
        assert row is not None
        assert row.agent_instance in ("agent-b", "agent-c")
        loser = "agent-c" if row.agent_instance == "agent-b" else "agent-b"
        assert loser in (row.agent_instances_displaced or [])
        assert "agent-a" in (row.agent_instances_displaced or [])


@pytest.mark.asyncio
async def test_the_long_poll_claims_with_no_lock_already_held(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The structural half: the claim's transaction has written nothing and
    locked no row when it asks for the server row (no xid assigned), so it can
    wait behind another writer but never be one side of a deadlock cycle."""
    _server, _zone, headers = await _agent(db_session)
    await db_session.commit()
    seen: list[object] = []
    real = agents_api.claim_poll

    async def _probe(db: AsyncSession, *args: Any, **kwargs: Any) -> bool:
        seen.append(
            (await db.execute(text("SELECT pg_current_xact_id_if_assigned()"))).scalar_one()
        )
        return await real(db, *args, **kwargs)

    monkeypatch.setattr(agents_api, "claim_poll", _probe)
    assert (await _poll(client, headers, "agent-a", None)).status_code == 200
    assert seen == [None]
