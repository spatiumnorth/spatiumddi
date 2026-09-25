"""The long-poll serves the newest stored bundle, current or not (#1111).

Under a write storm marks arrive faster than renders finish, so no render
is current until the writes stop. Serving a current bundle and nothing
else held every agent on its last config for the whole storm. On a 12 GiB
lab appliance a 250k-record seed kept a pool failover off ``named`` for
339 s while 74 worker renders landed unserved; the unbounded inline
fallback had hidden that by rebuilding the bundle in the api on every
poll. Each render the worker lands now reaches the agent.

That is safe only because a body's ops page carries the ops its snapshot
covers and nothing else (``test_dns_agent_bundle_ops_gate.py``). The
sequence test here walks an agent through stale bodies, a write that
straddles a render, and a structural change, and checks the invariant
#1122 rests on at every step: each body the agent receives reflects every
op it has applied.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import text
from sqlalchemy.exc import NoResultFound
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.http_etag import etag_matches
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import agent_bundle_render
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_token import mint_agent_token

CONFIG_URL = "/api/v1/dns/agents/config"


@pytest.fixture
def worker_only(monkeypatch: pytest.MonkeyPatch) -> list[list[Any]]:
    """Only the worker renders (the tests render explicitly); the poll holds
    for one second; the enqueues it makes are recorded."""
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)
    enqueued: list[list[Any]] = []

    async def _record_enqueue(ids):  # noqa: ANN001, ANN202
        enqueued.append(list(ids))

    monkeypatch.setattr(agents_api, "enqueue_renders", _record_enqueue)
    return enqueued


async def _agent(db: AsyncSession) -> tuple[DNSServer, DNSZone, dict[str, str]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    zone = await _zone(db, grp.id)
    db.add(_record(zone, "h1"))
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, zone, {"Authorization": f"Bearer {token}"}


async def _zone(db: AsyncSession, group_id: uuid.UUID) -> DNSZone:
    zone = DNSZone(
        group_id=group_id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return zone


def _record(zone: DNSZone, name: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id, name=name, fqdn=f"{name}.{zone.name}", record_type="A", value="10.9.9.9"
    )


def _op(server_id: uuid.UUID, zone: DNSZone, name: str) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server_id,
        zone_name=zone.name,
        op="create",
        record={"name": name, "type": "A", "value": "10.9.9.9"},
        state="pending",
    )


async def _change(db: AsyncSession, server: DNSServer, zone: DNSZone, name: str) -> None:
    """One committed record change, with its op, as a write path makes it."""
    db.add(_record(zone, name))
    db.add(_op(server.id, zone, name))
    await db.commit()


async def _render(db: AsyncSession, server: DNSServer) -> store.DNSAgentBundle:
    outcome = await render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
    await db.commit()
    assert outcome.bundle is not None
    return outcome.bundle


async def _poll(client: AsyncClient, headers: dict[str, str], etag: str | None) -> Response:
    if etag is None:
        return await client.get(CONFIG_URL, headers=headers)
    return await client.get(CONFIG_URL, headers={**headers, "If-None-Match": etag})


def _names(body: dict[str, Any]) -> set[str]:
    return {r["name"] for z in body["zones"] for r in z["records"]}


@pytest.mark.asyncio
async def test_a_stale_bundle_newer_than_the_agents_is_served(
    client: AsyncClient, db_session: AsyncSession, worker_only: list[list[Any]]
) -> None:
    server, zone, headers = await _agent(db_session)
    await db_session.commit()
    first = await _render(db_session, server)
    held = await _poll(client, headers, None)
    assert held.status_code == 200 and etag_matches(held.headers["etag"], first.etag)

    # A change lands and the worker renders it, then another change commits
    # before the agent polls: the newest render is already behind.
    await _change(db_session, server, zone, "a")
    second = await _render(db_session, server)
    await _change(db_session, server, zone, "b")
    await db_session.refresh(server)
    assert not store.is_current(server)

    served = await _poll(client, headers, first.etag)
    assert served.status_code == 200, (
        "the worker's newest render was not served because a later change had already "
        "committed: under a write storm every agent waits for the writes to stop"
    )
    assert etag_matches(served.headers["etag"], second.etag)
    body = served.json()
    assert "a" in _names(body) and "b" not in _names(body)
    assert [op["record"]["name"] for op in body["pending_record_ops"]] == ["a"]
    assert [server.id] in worker_only, "the stale bundle's render was requested"

    # Nothing newer than what the agent holds: the poll holds, 304.
    again = await _poll(client, headers, second.etag)
    assert again.status_code == 304
    assert etag_matches(again.headers["etag"], second.etag)

    # The render that catches up is served next.
    third = await _render(db_session, server)
    caught_up = await _poll(client, headers, second.etag)
    assert caught_up.status_code == 200 and etag_matches(caught_up.headers["etag"], third.etag)
    assert "b" in _names(caught_up.json())


@pytest.mark.asyncio
async def test_during_a_write_storm_every_render_that_lands_reaches_the_agent(
    client: AsyncClient, db_session: AsyncSession, worker_only: list[list[Any]]
) -> None:
    server, zone, headers = await _agent(db_session)
    await db_session.commit()
    held = (await _render(db_session, server)).etag
    await _poll(client, headers, None)
    for k in range(5):
        await _change(db_session, server, zone, f"s{k}")
        landed = await _render(db_session, server)
        # The storm goes on: the next change commits before anyone polls.
        await _change(db_session, server, zone, f"s{k}-next")
        await db_session.refresh(server)
        assert not store.is_current(server)
        resp = await _poll(client, headers, held)
        assert resp.status_code == 200, f"render {k} landed and never reached the agent"
        assert etag_matches(resp.headers["etag"], landed.etag)
        assert f"s{k}" in _names(resp.json())
        held = landed.etag


@asynccontextmanager
async def _straddling_write(
    server_id: uuid.UUID, zone: DNSZone, name: str
) -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as t:
            t.add(_record(zone, name))
            t.add(_op(server_id, zone, name))
            await t.flush()
            await asyncio.sleep(0.05)
            yield t
    finally:
        await engine.dispose()


class _Agent:
    """What an agent holds and has applied, checked on every body it takes."""

    def __init__(self) -> None:
        self.etag: str | None = None
        self.structural_etag: str | None = None
        self.applied: set[str] = set()
        self.structural_reloads = 0

    def take(self, body: dict[str, Any]) -> list[str]:
        names = _names(body)
        missing = self.applied - names
        assert not missing, (
            f"a body the agent took lacks ops it already applied: {sorted(missing)}; a "
            "structural reload (or a restart replaying this body) drops those records, "
            "and their ops are acked, so nothing brings them back"
        )
        shipped = [op["record"]["name"] for op in body["pending_record_ops"]]
        unseen = [n for n in shipped if n not in names]
        assert not unseen, f"ops shipped with a body that lacks their records: {unseen}"
        if self.structural_etag is not None and body["structural_etag"] != self.structural_etag:
            self.structural_reloads += 1
        self.applied.update(shipped)
        self.etag = body["etag"]
        self.structural_etag = body["structural_etag"]
        return [op["op_id"] for op in body["pending_record_ops"]]


async def _ack(db: AsyncSession, op_ids: list[str]) -> None:
    """The agent's heartbeat ack of the ops it applied."""
    if op_ids:
        await db.execute(
            text("update dns_record_op set state = 'applied' where id = any(:ids)"),
            {"ids": [uuid.UUID(i) for i in op_ids]},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_the_agent_never_drops_an_applied_op_across_stale_bodies_and_a_structural_reload(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    worker_only: list[list[Any]],
) -> None:
    server, zone, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    agent = _Agent()

    b1 = await _render(db_session, server)
    r = await _poll(client, headers, agent.etag)
    assert r.status_code == 200 and etag_matches(r.headers["etag"], b1.etag)
    await _ack(db_session, agent.take(r.json()))

    # Change A, then a bulk write C that straddles the next render, b3: open
    # before it reads, committed after.
    await _change(db_session, server, zone, "a")
    async with _straddling_write(server_id, zone, "c") as t:
        real = agent_bundle_render.render_bundle_body

        async def _read_then_commit(db, srv):  # noqa: ANN001, ANN202
            rendered = await real(db, srv)
            await t.commit()
            return rendered

        monkeypatch.setattr(agent_bundle_render, "render_bundle_body", _read_then_commit)
        b3 = await _render(db_session, server)
        monkeypatch.setattr(agent_bundle_render, "render_bundle_body", real)
    await db_session.refresh(server)
    assert not store.is_current(server), "C's commit left b3 behind"

    # The stale b3 is served; its page carries A and not C.
    r = await _poll(client, headers, agent.etag)
    assert r.status_code == 200, "the newest render (behind the sequence) was not served"
    assert etag_matches(r.headers["etag"], b3.etag)
    await _ack(db_session, agent.take(r.json()))
    assert agent.applied == {"a"}

    # A structural change (a new zone) and the render that follows it: the
    # agent reloads from the new body, which must still carry A — and C,
    # whose op now ships with it.
    await _zone(db_session, server.group_id)
    await db_session.commit()
    b4 = await _render(db_session, server)
    assert b4.structural_etag != b3.structural_etag
    r = await _poll(client, headers, agent.etag)
    assert r.status_code == 200 and etag_matches(r.headers["etag"], b4.etag)
    await _ack(db_session, agent.take(r.json()))
    assert agent.applied == {"a", "c"}
    assert agent.structural_reloads == 1


@pytest.mark.asyncio
async def test_a_bundle_pruned_between_its_read_and_its_body_load_serves_the_newest(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    worker_only: list[list[Any]],
) -> None:
    """Under a write storm the api's loop is saturated and a poll can wait
    seconds between reading the newest bundle and loading its body. The worker
    keeps two versions per server, so two renders that store in that gap
    delete the one the poll read. Seen live on the revised head during storm
    runs (agents/config 500, NoResultFound in load_body). The poll must serve
    the newest bundle instead, with its ops re-paged against THAT bundle's
    snapshot: never the page it built for the pruned one."""
    server, zone, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id
    first = await _render(db_session, server)
    r = await _poll(client, headers, None)
    assert r.status_code == 200 and etag_matches(r.headers["etag"], first.etag)

    # Change A, rendered: the bundle the next poll reads.
    await _change(db_session, server, zone, "a")
    read = await _render(db_session, server)

    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    real = store.load_body
    newest: dict[str, str] = {}

    async def _two_renders_then_load(db, bundle):  # noqa: ANN001, ANN202
        """The first body load waits while two renders store elsewhere (the
        second prunes ``read``), and a change commits after the second
        render read (its op is not covered by it)."""
        if not newest:
            async with factory() as other:
                srv = await other.get(DNSServer, server_id)
                assert srv is not None
                for name in ("b", "c"):
                    await _change(other, srv, zone, name)
                    outcome = await render_and_store(
                        other, srv, rendered_by=store.RENDERED_BY_WORKER
                    )
                    await other.commit()
                    assert outcome.bundle is not None
                    newest["etag"] = outcome.etag
                await _change(other, srv, zone, "d")
        return await real(db, bundle)

    monkeypatch.setattr(store, "load_body", _two_renders_then_load)
    try:
        try:
            resp = await _poll(client, headers, first.etag)
        except NoResultFound as exc:
            pytest.fail(
                f"the long-poll raised {exc!r}, a 500 to the agent: the bundle it had read "
                "was pruned by two newer renders before its body was loaded"
            )
    finally:
        await engine.dispose()

    assert resp.status_code == 200, resp.text
    assert etag_matches(resp.headers["etag"], newest["etag"]), (
        f"served {resp.headers['etag']}, want the newest render {newest['etag']} "
        f"(the one read, {read.etag}, was pruned)"
    )
    body = resp.json()
    assert {"a", "b", "c"} <= _names(body) and "d" not in _names(body)
    shipped = sorted(op["record"]["name"] for op in body["pending_record_ops"])
    assert shipped == ["a", "b", "c"], (
        f"ops shipped with the newest body: {shipped}; want its own gated set [a, b, c]: "
        "not the page built for the pruned bundle ([a]) and not d, committed after "
        "the newest render read"
    )
