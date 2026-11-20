"""The blocklist entries travel in their own versioned stream (#4041).

An entry edit moved the whole config bundle's ETag, so every agent re-fetched
a bundle whose entries are most of its size. A server whose agent sends
``blocklist-stream`` is sent a bundle WITHOUT its RPZ zones' entries and
fetches them from ``GET /dns/agents/blocklist``, whose ETag (named in the
bundle's ``blocklist_etag``) is all an entry edit moves. Every other agent is
sent the entries embedded, as before.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.api.v1.dns.agents import _set_packed_blocklists
from app.config import settings
from app.models.dns import DNSBlockListEntry, DNSServer
from app.models.settings import PlatformSettings
from app.services.dns import agent_bundle_store as store
from app.services.dns import agent_config
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import RPZ_CONTENT_HASH_KEY, render_bundle_body
from app.services.dns.agent_token import mint_agent_token
from tests.test_dns_agent_bundle_blocklist_stream_1662 import _fixture, _id

_FEATURES = "soa-timers,packed-blocklists,blocklist-stream"


async def _setup(db: AsyncSession, *, views: bool = False, stream: bool = True) -> DNSServer:
    db.add(PlatformSettings(id=1))
    await db.flush()
    server = await _fixture(db, views=views)
    await db.commit()
    await db.execute(
        update(DNSServer)
        .where(DNSServer.id == server.id)
        .values(agent_reads_blocklist_stream=stream, agent_renders_packed_blocklists=stream)
    )
    await db.commit()
    return server


async def _encode(db: AsyncSession, server: DNSServer) -> agent_config.EncodedBody:
    db.expunge_all()
    fresh = await db.get(DNSServer, server.id)
    assert fresh is not None
    return await agent_config.encode_bundle_body(db, fresh)


async def _edit_entry(db: AsyncSession, n: int, domain: str) -> None:
    db.add(
        DNSBlockListEntry(
            id=_id(n),
            list_id=_id(0x4000 + 0x10000),
            domain=domain,
            entry_type="block",
            is_wildcard=False,
        )
    )
    await db.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("views", [False, True])
async def test_the_stream_holds_what_the_bundle_used_to(
    db_session: AsyncSession, views: bool
) -> None:
    server = await _setup(db_session, views=views, stream=False)
    db_session.expunge_all()
    row = await db_session.get(DNSServer, server.id)
    assert row is not None
    legacy = (await render_bundle_body(db_session, row)).body["blocklists"]
    assert legacy and any(z["entries"] for z in legacy)

    await db_session.execute(
        update(DNSServer).where(DNSServer.id == server.id).values(agent_reads_blocklist_stream=True)
    )
    await db_session.commit()
    encoded = await _encode(db_session, server)
    assert encoded.blocklist_stream and encoded.blocklist_gz is not None
    body = json.loads(gzip.decompress(encoded.body_gz))
    doc_raw = gzip.decompress(encoded.blocklist_gz)
    doc = json.loads(doc_raw)

    assert encoded.blocklist_etag == "sha256:" + hashlib.sha256(doc_raw).hexdigest()
    by_name = {(z["rpz_zone_name"], z["view_name"]): z for z in legacy}
    assert [(z["rpz_zone_name"], z["view_name"]) for z in body["blocklists"]] == [
        (z["rpz_zone_name"], z["view_name"]) for z in legacy
    ]
    for zone in body["blocklists"]:
        assert zone["entries"] == [] and RPZ_CONTENT_HASH_KEY not in zone
    assert len(doc["blocklists"]) == len(legacy)
    for held in doc["blocklists"]:
        want = by_name[(held["rpz_zone_name"], held["view_name"])]
        assert held["entries"] == want["entries"]
        assert held[RPZ_CONTENT_HASH_KEY] == want[RPZ_CONTENT_HASH_KEY]


@pytest.mark.asyncio
async def test_an_entry_edit_moves_the_stream_and_not_the_bundle(
    db_session: AsyncSession,
) -> None:
    server = await _setup(db_session)
    before = await _encode(db_session, server)
    await _edit_entry(db_session, 0x4E0A1, "changed.example")
    after = await _encode(db_session, server)
    assert after.etag == before.etag
    assert after.structural_etag == before.structural_etag
    assert after.blocklist_etag != before.blocklist_etag

    # Negative control: the embedded form moves the bundle's ETag.
    await _edit_entry(db_session, 0x4E0A2, "changed-again.example")
    await db_session.execute(
        update(DNSServer)
        .where(DNSServer.id == server.id)
        .values(agent_reads_blocklist_stream=False)
    )
    await db_session.commit()
    legacy_before = await _encode(db_session, server)
    await _edit_entry(db_session, 0x4E0A3, "and-again.example")
    legacy_after = await _encode(db_session, server)
    assert legacy_after.etag != legacy_before.etag
    assert not legacy_after.blocklist_stream and legacy_after.blocklist_gz is None


@pytest.mark.asyncio
async def test_exceptions_and_zone_set_stay_in_the_bundle(db_session: AsyncSession) -> None:
    server = await _setup(db_session)
    encoded = await _encode(db_session, server)
    body = json.loads(gzip.decompress(encoded.body_gz))
    assert any(z["exceptions"] for z in body["blocklists"])


@pytest.mark.asyncio
async def test_registering_the_feature_re_renders_the_server(db_session: AsyncSession) -> None:
    server = await _setup(db_session, stream=False)
    row = await db_session.get(DNSServer, server.id)
    assert row is not None
    seq = int(row.bundle_dirty_seq)
    await _set_packed_blocklists(db_session, row, _FEATURES)
    await db_session.commit()
    assert row.agent_reads_blocklist_stream is True
    db_session.expunge_all()
    row = await db_session.get(DNSServer, server.id)
    assert row is not None and int(row.bundle_dirty_seq) > seq


@pytest.mark.asyncio
async def test_the_longpoll_serves_each_agent_its_own_shape_and_the_stream(
    client: Any, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)
    server = await _setup(db_session)
    token, _ = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    auth = {"Authorization": f"Bearer {token}"}
    new = {**auth, "X-Spatium-Agent-Features": _FEATURES}

    async def render() -> None:
        db_session.expunge_all()
        row = await db_session.get(DNSServer, server.id)
        assert row is not None
        out = await render_and_store(db_session, row, rendered_by=store.RENDERED_BY_WORKER)
        await db_session.commit()
        assert out.bundle is not None

    await render()
    first = await client.get("/api/v1/dns/agents/config", headers=new)
    assert first.status_code == 200
    bundle = first.json()
    etag, bl_etag = bundle["etag"], bundle["blocklist_etag"]
    assert bl_etag and all(z["entries"] == [] for z in bundle["blocklists"])

    doc = await client.get("/api/v1/dns/agents/blocklist", headers=new)
    assert doc.status_code == 200
    assert doc.headers["etag"].strip('"').removeprefix("W/").strip('"') == bl_etag
    assert hashlib.sha256(doc.content).hexdigest() == bl_etag.removeprefix("sha256:")
    assert any(z["entries"] for z in doc.json()["blocklists"])

    # Holding both versions: nothing to send.
    held = {**new, "If-None-Match": f'W/"{etag}"', "X-Spatium-Blocklist-Etag": bl_etag}
    assert (await client.get("/api/v1/dns/agents/config", headers=held)).status_code == 304

    # An entry edit: the bundle's ETag is the same, the stream's is not, and
    # the poll answers an agent that holds the old stream.
    await _edit_entry(db_session, 0x4E0B1, "fresh.example")
    await render()
    moved = await client.get("/api/v1/dns/agents/config", headers=held)
    assert moved.status_code == 200
    assert moved.json()["etag"] == etag and moved.json()["blocklist_etag"] != bl_etag
    held2 = {**held, "X-Spatium-Blocklist-Etag": moved.json()["blocklist_etag"]}
    assert (await client.get("/api/v1/dns/agents/config", headers=held2)).status_code == 304
    again = await client.get("/api/v1/dns/agents/blocklist", headers=new)
    assert any(
        e.get("domain") == "fresh.example" or "packed" in e
        for z in again.json()["blocklists"]
        for e in z["entries"]
    )

    # An agent that did not advertise is never served the stripped bundle, and
    # has no stream to read.
    assert (await client.get("/api/v1/dns/agents/config", headers=auth)).status_code == 304
    assert (await client.get("/api/v1/dns/agents/blocklist", headers=auth)).status_code == 503
