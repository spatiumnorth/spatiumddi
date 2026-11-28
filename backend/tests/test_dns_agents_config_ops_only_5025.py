"""``GET /api/v1/dns/agents/config`` answers an ops page alone (#5025).

An agent that holds the body for its ``If-None-Match`` says so with
``X-Spatium-Ops-Only: 1``; with the stored bundle's ETag and ops pending the
reply is the ops page with no body behind it. Every other poll is answered
exactly as before: an agent that does not send the header, an ETag that is not
the stored one, nothing pending.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_token import mint_agent_token

CONFIG_URL = "/api/v1/dns/agents/config"
OPS_ONLY = {"X-Spatium-Ops-Only": "1"}


async def _agent(db: AsyncSession, ops: int) -> tuple[DNSServer, dict[str, str]]:
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
    db.add(
        DNSRecord(
            zone_id=zone.id, name="h1", fqdn=f"h1.{zone.name}", record_type="A", value="10.0.0.1"
        )
    )
    await db.flush()
    base = datetime.now(UTC) - timedelta(minutes=10)
    for i in range(ops):
        db.add(
            DNSRecordOp(
                server_id=server.id,
                zone_name=zone.name,
                op="create",
                record={"name": f"n{i}", "type": "A", "value": "10.9.9.9"},
                state="pending",
                created_at=base + timedelta(seconds=i),
            )
        )
    # Committed before the render, so the render's snapshot covers them.
    await db.commit()
    await render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
    await db.commit()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    return server, {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _short_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)
    monkeypatch.setattr(settings, "dns_agent_ops_batch", 3)
    monkeypatch.setattr(agents_api, "enqueue_renders", _noop_enqueue)


async def _noop_enqueue(ids):  # noqa: ANN001
    return None


async def _held_etag(client: AsyncClient, headers: dict[str, str]) -> str:
    """The ETag of the stored bundle, as an agent that fetched it holds it.
    A GET with no If-None-Match is a full reply; its ops page is discarded by
    returning the ops to pending below via a fresh agent per test."""
    resp = await client.get(CONFIG_URL, headers=headers)
    assert resp.status_code == 200, resp.text
    assert "zones" in resp.json()
    assert len(resp.json()["pending_record_ops"]) <= 3
    return resp.json()["etag"]


@pytest.mark.asyncio
async def test_an_advertising_agent_with_the_stored_etag_gets_the_ops_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _agent(db_session, ops=5)
    etag = await _held_etag(client, headers)  # first page (3 ops) rode a full body

    resp = await client.get(
        CONFIG_URL, headers={**headers, **OPS_ONLY, "If-None-Match": f'W/"{etag}"'}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert list(body)[:3] == ["etag", "pending_record_ops", "pending_ops_remaining"]
    assert body["etag"] == etag
    assert [op["record"]["name"] for op in body["pending_record_ops"]] == ["n3", "n4"]
    assert body["pending_ops_remaining"] == 0
    # No body: neither the zones nor any structural field, and nothing like it
    # in size.
    assert "zones" not in body and "structural_etag" not in body
    assert len(resp.content) < 4096
    assert resp.headers["etag"]
    # The ops were marked in flight and the server row records the ETag it
    # was served, exactly as a full reply does.
    await db_session.refresh(server)
    assert server.last_config_etag == etag


@pytest.mark.asyncio
async def test_an_agent_without_the_header_still_gets_the_full_body(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, headers = await _agent(db_session, ops=5)
    etag = await _held_etag(client, headers)

    resp = await client.get(CONFIG_URL, headers={**headers, "If-None-Match": f'W/"{etag}"'})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["etag"] == etag
    assert [op["record"]["name"] for op in body["pending_record_ops"]] == ["n3", "n4"]
    assert "zones" in body and "structural_etag" in body


@pytest.mark.asyncio
async def test_a_mismatched_etag_gets_the_full_body_even_when_advertising(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, headers = await _agent(db_session, ops=5)
    await _held_etag(client, headers)

    resp = await client.get(
        CONFIG_URL, headers={**headers, **OPS_ONLY, "If-None-Match": 'W/"not-the-stored-one"'}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "zones" in body and "structural_etag" in body
    assert [op["record"]["name"] for op in body["pending_record_ops"]] == ["n3", "n4"]

    # And with no If-None-Match at all (a restart, a quarantine retry).
    _server2, headers2 = await _agent(db_session, ops=2)
    bare = await client.get(CONFIG_URL, headers={**headers2, **OPS_ONLY})
    assert bare.status_code == 200
    assert "zones" in bare.json()


@pytest.mark.asyncio
async def test_nothing_pending_still_settles_on_304_when_advertising(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _server, headers = await _agent(db_session, ops=0)
    etag = await _held_etag(client, headers)

    resp = await client.get(
        CONFIG_URL, headers={**headers, **OPS_ONLY, "If-None-Match": f'W/"{etag}"'}
    )
    assert resp.status_code == 304
