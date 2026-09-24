"""Which queued ops a stored bundle covers (#1111).

A stored bundle ships the ops page gated to what its body reflects, and a
split-horizon render retires the queued ops its body folded in. Both gated
on ``created_at <= snapshot_at``. ``created_at`` is ``now()``: the op's
transaction START. A bulk write that starts before a render and commits
after the render's records query therefore passes that gate with a record
the body never read:

* the inline fallback served its own render at once, shipping such an op
  with a body that lacks its record (the superset invariant: every body an
  agent holds must reflect every op it applied, or a later structural reload
  drops the record);
* a split-horizon render retired such an op as applied though its body never
  read the record (an ACME DNS-01 wait then reads the TXT as live);
* the worker path's page for that body carries it too, which only the
  long-poll's rule of serving current bundles alone kept from agents.

The gate is now commit visibility in the snapshot the render took before it
read anything. Each straddling test holds a second connection's transaction
open across the render's read and commits it before the gate is applied, the
way a bulk-create overlaps a render during a write storm. They exercise the
gate through names that exist on both sides of the change, so a build
without it fails them on behaviour.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.models.dns import (
    DNSAgentBundle,
    DNSRecord,
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSView,
    DNSZone,
)
from app.services.dns import agent_bundle_render
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import page_pending_ops, retire_queued_ops
from app.services.dns.agent_token import mint_agent_token

CONFIG_URL = "/api/v1/dns/agents/config"


async def _agent(
    db: AsyncSession, *, views: bool = False
) -> tuple[DNSServer, DNSZone, dict[str, str]]:
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
    if views:
        db.add(DNSView(group_id=grp.id, name="internal", match_clients=["10.0.0.0/8"]))
        await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    db.add(_record(zone, "h1"))
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, zone, {"Authorization": f"Bearer {token}"}


def _record(zone: DNSZone, name: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value="10.9.9.9",
    )


def _op(
    server_id: uuid.UUID, zone: DNSZone, name: str, created_at: datetime | None = None
) -> DNSRecordOp:
    op = DNSRecordOp(
        server_id=server_id,
        zone_name=zone.name,
        op="create",
        record={"name": name, "type": "A", "value": "10.9.9.9"},
        state="pending",
    )
    if created_at is not None:
        op.created_at = created_at
    return op


@asynccontextmanager
async def _straddling_write(
    server_id: uuid.UUID, zone: DNSZone, name: str
) -> AsyncIterator[AsyncSession]:
    """A second connection's transaction that adds record ``name`` and its op
    and stays open: the op's ``created_at`` is this transaction's start. The
    caller commits it (``await t.commit()``) wherever the overlap needs it."""
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as t:
            t.add(_record(zone, name))
            t.add(_op(server_id, zone, name))
            await t.flush()
            # The render that follows reads the DB clock strictly later than
            # this transaction's now().
            await asyncio.sleep(0.05)
            yield t
    finally:
        await engine.dispose()


def _commit_after_the_read(monkeypatch: pytest.MonkeyPatch, t: AsyncSession) -> None:
    """Commit ``t`` right after the render has read the records, before it
    stores (and, under split-horizon, retires)."""
    real = agent_bundle_render.render_bundle_body

    async def _read_then_commit(db, server):  # noqa: ANN001, ANN202
        rendered = await real(db, server)
        await t.commit()
        return rendered

    monkeypatch.setattr(agent_bundle_render, "render_bundle_body", _read_then_commit)


def _gate(bundle: DNSAgentBundle) -> dict[str, Any]:
    """The stored bundle's gate, as the long-poll passes it. A build without
    the commit gate has neither the column nor the argument: its page then
    runs on the time gate alone, which is what these tests pin as wrong."""
    if hasattr(bundle, "visible_xacts"):
        return {"visible_xacts": bundle.visible_xacts}
    return {}


async def _body_names(db: AsyncSession, bundle: DNSAgentBundle) -> set[str]:
    raw = await store.load_body(db, bundle)
    body = json.loads(gzip.decompress(raw))
    return {r["name"] for z in body["zones"] for r in z["records"]}


async def _op_state(db: AsyncSession, server_id: uuid.UUID, name: str) -> str:
    return (
        await db.execute(
            select(DNSRecordOp.state).where(
                DNSRecordOp.server_id == server_id,
                DNSRecordOp.record["name"].astext == name,
            )
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_an_op_committed_after_the_render_read_is_not_paged_with_that_body(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker path: the page for a stored body never carries the op of a
    write its render did not read, however early that write began."""
    server, zone, _headers = await _agent(db_session)
    db_session.add(_op(server.id, zone, "early"))
    db_session.add(_record(zone, "early"))
    await db_session.commit()
    server_id = server.id

    async with _straddling_write(server_id, zone, "late") as t:
        _commit_after_the_read(monkeypatch, t)
        outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
        await db_session.commit()
    bundle = outcome.bundle
    assert bundle is not None

    names = await _body_names(db_session, bundle)
    assert "early" in names and "late" not in names, names
    page, _remaining = await page_pending_ops(
        db_session, server, up_to=bundle.snapshot_at, **_gate(bundle)
    )
    shipped = [op["record"]["name"] for op in page]
    assert "early" in shipped, "an op committed before the render read is covered by its body"
    assert "late" not in shipped, (
        "the op of a write that committed after the render read its records rides with a body "
        "that lacks the record: its transaction started before the render, so created_at alone "
        "says the body saw it"
    )


@pytest.mark.asyncio
async def test_the_inline_render_never_ships_an_op_its_body_did_not_read(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The api's fallback serves the render it just stored, current or not."""
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    if "dns_agent_bundle_inline_fallback_after_seconds" in type(settings).model_fields:
        monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)
    server, zone, headers = await _agent(db_session)
    await db_session.commit()
    server_id = server.id

    async with _straddling_write(server_id, zone, "late") as t:
        _commit_after_the_read(monkeypatch, t)
        resp = await client.get(CONFIG_URL, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    names = {r["name"] for z in body["zones"] for r in z["records"]}
    assert "late" not in names, "the inline render read before the write committed"
    shipped = [op["record"]["name"] for op in body["pending_record_ops"]]
    assert "late" not in shipped, (
        "the inline render shipped the op of a write it never read: the agent applies it "
        "incrementally on top of a body without the record"
    )


@pytest.mark.asyncio
async def test_a_split_horizon_render_never_retires_an_op_its_body_did_not_read(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under views the render retires the ops its body folds in as applied;
    an ACME DNS-01 solve waits on exactly that state."""
    server, zone, _headers = await _agent(db_session, views=True)
    db_session.add(_op(server.id, zone, "early"))
    db_session.add(_record(zone, "early"))
    await db_session.commit()
    server_id = server.id

    async with _straddling_write(server_id, zone, "late") as t:
        _commit_after_the_read(monkeypatch, t)
        outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
        await db_session.commit()
    assert outcome.bundle is not None
    names = await _body_names(db_session, outcome.bundle)
    assert "early" in names and "late" not in names, names
    assert await _op_state(db_session, server_id, "early") == "applied"
    assert (
        await _op_state(db_session, server_id, "late") == "pending"
    ), "a render retired as applied the op of a write it never read"


@pytest.mark.asyncio
async def test_ops_and_bundles_from_before_the_commit_gate_keep_the_time_gate(
    db_session: AsyncSession,
) -> None:
    """``xact_id`` / ``visible_xacts`` are NULL on rows from before the
    migration; either NULL falls back to ``created_at <= snapshot_at``. So
    does an id or a snapshot this cluster has not reached yet (rows restored
    from another cluster's backup): visibility across clusters means nothing."""
    server, zone, _headers = await _agent(db_session)
    await db_session.commit()
    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    bundle = outcome.bundle
    assert bundle is not None and bundle.visible_xacts
    past = bundle.snapshot_at - timedelta(minutes=1)
    future = bundle.snapshot_at + timedelta(hours=1)

    # Committed after the render, so the render's snapshot cannot see any of
    # them; created_at is set explicitly to put them either side of it.
    db_session.add_all(
        [
            _op(server.id, zone, "legacy-before", created_at=past),
            _op(server.id, zone, "legacy-after", created_at=future),
            _op(server.id, zone, "new-backdated", created_at=past),
            _op(server.id, zone, "restored-before", created_at=past),
        ]
    )
    await db_session.commit()
    await db_session.execute(
        text(
            "update dns_record_op set xact_id = null "
            "where server_id = :s and record->>'name' like 'legacy-%'"
        ),
        {"s": server.id},
    )
    await db_session.execute(
        text(
            "update dns_record_op set xact_id = "
            "(pg_snapshot_xmax(pg_current_snapshot())::text::bigint + 1000000000) "
            "where server_id = :s and record->>'name' = 'restored-before'"
        ),
        {"s": server.id},
    )
    await db_session.commit()

    snapshot_at, visible_xacts = bundle.snapshot_at, bundle.visible_xacts

    async def _names(gate: str | None) -> list[str]:
        page, _ = await page_pending_ops(db_session, server, up_to=snapshot_at, visible_xacts=gate)
        await db_session.commit()
        # Put the paged ops back to pending for the next read.
        await db_session.execute(
            text("update dns_record_op set state = 'pending' where server_id = :s"),
            {"s": server.id},
        )
        await db_session.commit()
        return sorted(op["record"]["name"] for op in page)

    # A bundle with the snapshot: a legacy or restored op by its time, a new
    # op by commit.
    assert await _names(visible_xacts) == ["legacy-before", "restored-before"]
    # A bundle from before the column: the time gate for every op.
    assert await _names(None) == ["legacy-before", "new-backdated", "restored-before"]
    # A bundle restored from another cluster, its snapshot ahead of this one's:
    # the time gate for every op too.
    xmin, xmax, _xip = visible_xacts.split(":")
    ahead = f"{int(xmin) + 1_000_000_000}:{int(xmax) + 1_000_000_000}:"
    assert await _names(ahead) == ["legacy-before", "new-backdated", "restored-before"]

    # The split-horizon retire takes the same gate.
    retired = await retire_queued_ops(
        db_session, server, up_to=snapshot_at, visible_xacts=visible_xacts
    )
    await db_session.commit()
    assert retired == 2
    assert await _op_state(db_session, server.id, "legacy-before") == "applied"
    assert await _op_state(db_session, server.id, "restored-before") == "applied"
    assert await _op_state(db_session, server.id, "new-backdated") == "pending"
    assert await _op_state(db_session, server.id, "legacy-after") == "pending"


@pytest.mark.asyncio
async def test_the_render_stores_the_snapshot_it_read_under(db_session: AsyncSession) -> None:
    server, _zone, _headers = await _agent(db_session)
    await db_session.commit()
    before = datetime.now(UTC)
    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    bundle = outcome.bundle
    assert bundle is not None
    # pg_snapshot's text form, xmin:xmax:xip_list, and a real one.
    xmin, xmax, _xip = bundle.visible_xacts.split(":")
    assert int(xmin) <= int(xmax)
    assert bundle.snapshot_at >= before - timedelta(seconds=5)
    ok = (
        await db_session.execute(
            text(
                "select pg_snapshot_xmax(cast(cast(:s as text) as pg_snapshot))::text::bigint > 0"
            ),
            {"s": bundle.visible_xacts},
        )
    ).scalar_one()
    assert ok is True
