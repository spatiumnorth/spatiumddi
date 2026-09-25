"""``GET /api/v1/dns/agents/config`` serves the stored bundle (#1111).

The bundle is rendered once per (server, watermark) and stored; the
long-poll reads one small row per wake, compares If-None-Match with the
stored ETag, splices the per-server ops page in front of the stored bytes
and streams them. These tests pin what the agent sees across the migration
release (inline fallback on) and after it (fallback off, the worker
renders), the ops-page gate, and the one deliberate contract change: a page
no longer rotates the ETag.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.core.http_etag import etag_matches
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_token import mint_agent_token

CONFIG_URL = "/api/v1/dns/agents/config"


async def _agent(
    db: AsyncSession, records: int, *, views: bool = False
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
    db.add_all(
        DNSRecord(
            zone_id=zone.id,
            name=f"h{i:04d}",
            fqdn=f"h{i:04d}.{zone.name}",
            record_type="A",
            value=f"10.0.{i // 250}.{i % 250}",
        )
        for i in range(records)
    )
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, zone, {"Authorization": f"Bearer {token}"}


def _op(server: DNSServer, zone: DNSZone, name: str, created_at: datetime) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server.id,
        zone_name=zone.name,
        op="create",
        record={"name": name, "type": "A", "value": "10.9.9.9"},
        state="pending",
        created_at=created_at,
    )


@pytest.mark.asyncio
async def test_the_first_poll_renders_inline_once_and_serves_the_stored_bytes(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    # The unbounded fallback (the bound is pinned in
    # test_dns_agents_config_inline_fallback.py): any stale bundle is eligible.
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)
    server, zone, headers = await _agent(db_session, records=300)
    await db_session.commit()

    resp = await client.get(CONFIG_URL, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The wire body is one JSON object with the per-poll keys first and is
    # byte-identical to Starlette's own encoding of it (#958's contract).
    assert list(body)[:3] == ["etag", "pending_record_ops", "pending_ops_remaining"]
    assert resp.content == JSONResponse(resp.json()).body
    assert len({z["name"]: z for z in body["zones"]}[zone.name]["records"]) == 300

    await db_session.refresh(server)
    assert server.bundle_watermark == server.bundle_dirty_seq
    assert server.bundle_render_count == 1
    assert etag_matches(resp.headers["etag"], server.bundle_etag)
    assert body["etag"] == server.bundle_etag
    current = await store.current(db_session, server)
    assert current is not None and current.rendered_by == store.RENDERED_BY_API

    # Same ETag back, nothing pending: 304 from the stored row, no rebuild.
    again = await client.get(CONFIG_URL, headers={**headers, "If-None-Match": resp.headers["etag"]})
    assert again.status_code == 304
    assert again.headers["etag"] == resp.headers["etag"]
    await db_session.refresh(server)
    assert server.bundle_render_count == 1


@pytest.mark.asyncio
async def test_with_the_fallback_off_a_missing_bundle_holds_and_the_workers_render_is_served(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)
    enqueued: list[list] = []

    async def _fake_enqueue(ids):  # noqa: ANN001
        enqueued.append(list(ids))

    monkeypatch.setattr(agents_api, "enqueue_renders", _fake_enqueue)
    server, _zone, headers = await _agent(db_session, records=5)
    await db_session.commit()

    # Nothing stored: the render is requested once and the poll holds to
    # its deadline. Never an improvised 200.
    held = await client.get(CONFIG_URL, headers=headers)
    assert held.status_code == 304
    assert "etag" not in held.headers
    assert enqueued == [[server.id]]
    await db_session.refresh(server)
    assert server.bundle_render_count == 0

    # The worker renders (same function, same session shape) — and the next
    # poll serves it, ETag and all.
    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    served = await client.get(CONFIG_URL, headers=headers)
    assert served.status_code == 200, served.text
    assert etag_matches(served.headers["etag"], outcome.etag)
    assert served.json()["etag"] == outcome.etag
    assert served.json()["structural_etag"] == outcome.structural_etag


@pytest.mark.asyncio
async def test_pages_share_the_stored_etag_and_the_last_ack_settles_on_304(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    # The unbounded fallback (the bound is pinned in
    # test_dns_agents_config_inline_fallback.py): any stale bundle is eligible.
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)
    monkeypatch.setattr(settings, "dns_agent_ops_batch", 4)
    server, zone, headers = await _agent(db_session, records=10)
    base = datetime.now(UTC) - timedelta(minutes=10)
    for i in range(6):
        db_session.add(_op(server, zone, f"n{i}", base + timedelta(seconds=i)))
    await db_session.commit()

    first = await client.get(CONFIG_URL, headers=headers)
    assert first.status_code == 200, first.text
    body = first.json()
    assert [op["record"]["name"] for op in body["pending_record_ops"]] == ["n0", "n1", "n2", "n3"]
    assert body["pending_ops_remaining"] == 2

    # The next page rides the fast path with the SAME ETag: the ETag is the
    # body's validator now, and a page is not a change to the body.
    second = await client.get(
        CONFIG_URL, headers={**headers, "If-None-Match": first.headers["etag"]}
    )
    assert second.status_code == 200, second.text
    assert second.headers["etag"] == first.headers["etag"]
    body2 = second.json()
    assert [op["record"]["name"] for op in body2["pending_record_ops"]] == ["n4", "n5"]
    assert body2["pending_ops_remaining"] == 0

    # Everything is in flight: the poll after the last page holds and
    # answers 304 instead of re-sending the whole body.
    settled = await client.get(
        CONFIG_URL, headers={**headers, "If-None-Match": first.headers["etag"]}
    )
    assert settled.status_code == 304
    assert settled.headers["etag"] == first.headers["etag"]
    await db_session.refresh(server)
    assert server.bundle_render_count == 1  # three polls, one render


@pytest.mark.asyncio
async def test_an_op_newer_than_the_stored_snapshot_waits_for_the_next_render(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate: an op ships only with a body that reflects the record
    behind it. Every body an agent holds is a superset of every op it has
    applied, so a later structural re-render (or a restart replaying the
    cached bundle) can never drop a record applied incrementally."""
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    # The unbounded fallback (the bound is pinned in
    # test_dns_agents_config_inline_fallback.py): any stale bundle is eligible.
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)
    server, zone, headers = await _agent(db_session, records=3)
    await db_session.commit()
    first = await client.get(CONFIG_URL, headers=headers)
    assert first.status_code == 200
    etag = first.headers["etag"]
    stored = await store.current(db_session, server)
    assert stored is not None

    # A record change after the snapshot: its op is newer than the stored
    # bundle, and its commit made the bundle stale.
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)
    monkeypatch.setattr(agents_api, "enqueue_renders", _noop)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="late",
            fqdn=f"late.{zone.name}",
            record_type="A",
            value="10.9.9.9",
        )
    )
    db_session.add(_op(server, zone, "late", datetime.now(UTC) + timedelta(seconds=1)))
    await db_session.commit()
    await db_session.refresh(server)
    assert not store.is_current(server)

    # Not served against the old body: the poll holds and answers 304, and
    # the op stays pending (never marked in_flight by a body that lacks it).
    held = await client.get(CONFIG_URL, headers={**headers, "If-None-Match": etag})
    assert held.status_code == 304
    await db_session.refresh(server)
    op_rows = (
        (
            await db_session.execute(
                __import__("sqlalchemy")
                .select(DNSRecordOp.state)
                .where(DNSRecordOp.server_id == server.id)
            )
        )
        .scalars()
        .all()
    )
    assert op_rows == ["pending"]

    # The render that reflects the record ships the op with it.
    await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    served = await client.get(CONFIG_URL, headers={**headers, "If-None-Match": etag})
    assert served.status_code == 200, served.text
    assert served.headers["etag"] != etag
    body = served.json()
    assert [op["record"]["name"] for op in body["pending_record_ops"]] == ["late"]
    assert "late" in {r["name"] for z in body["zones"] for r in z["records"]}


async def _noop(ids):  # noqa: ANN001
    return None


@pytest.mark.asyncio
async def test_split_horizon_never_pages_ops_and_the_render_retires_them(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    # The unbounded fallback (the bound is pinned in
    # test_dns_agents_config_inline_fallback.py): any stale bundle is eligible.
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)
    server, zone, headers = await _agent(db_session, records=4, views=True)
    db_session.add(_op(server, zone, "queued", datetime.now(UTC) - timedelta(minutes=1)))
    await db_session.commit()

    resp = await client.get(CONFIG_URL, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["pending_record_ops"] == []
    assert body["pending_ops_remaining"] == 0
    assert body["views"][0]["name"] == "internal"
    stored = await store.current(db_session, server)
    assert stored is not None and stored.ships_ops is False
    states = (
        (
            await db_session.execute(
                __import__("sqlalchemy")
                .select(DNSRecordOp.state)
                .where(DNSRecordOp.server_id == server.id)
            )
        )
        .scalars()
        .all()
    )
    assert states == ["applied"]


@pytest.mark.asyncio
async def test_an_inline_render_that_raises_holds_the_poll_and_leaves_the_verdict_to_the_worker(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The api's inline attempt is opportunistic: when it raises (at a million
    records, the api's 30 s command_timeout) the poll falls back to the worker
    path — the render is enqueued and the poll holds, 304 at the deadline —
    and the server row is left alone. Recording it as the render verdict fired
    the render-failed alert while the worker was fine and kept the sweep
    backing the server off (tests/test_dns_agents_config_inline_fallback.py)."""
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    # The unbounded fallback (the bound is pinned in
    # test_dns_agents_config_inline_fallback.py): any stale bundle is eligible.
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)
    enqueued: list[list] = []

    async def _fake_enqueue(ids):  # noqa: ANN001
        enqueued.append(list(ids))

    monkeypatch.setattr(agents_api, "enqueue_renders", _fake_enqueue)
    server, _zone, headers = await _agent(db_session, records=1)
    await db_session.commit()
    server_id = server.id

    async def _boom(db, server, *, rendered_by):  # noqa: ANN001
        raise RuntimeError("synthetic render failure")

    monkeypatch.setattr(agents_api, "render_and_store", _boom)
    failures_before = agents_api.AGENT_BUNDLE_INLINE_FAILURES.labels(family="dns")._value.get()
    held = await client.get(CONFIG_URL, headers=headers)
    assert held.status_code == 304, held.text
    assert "etag" not in held.headers
    assert enqueued == [[server_id]], "the worker's render was requested"
    assert (
        agents_api.AGENT_BUNDLE_INLINE_FAILURES.labels(family="dns")._value.get()
        == failures_before + 1
    )
    await db_session.refresh(server)
    assert server.bundle_render_status is None, "the row carries no verdict from the api"
    assert server.bundle_render_error is None
    assert server.bundle_watermark is None
