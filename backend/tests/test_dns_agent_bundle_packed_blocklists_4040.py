"""Packed blocklist entries in the DNS agent bundle (#4040).

Three lists made a 69 MB bundle because every entry was its own JSON object.
A server whose agent sends ``packed-blocklists`` is sent runs of consecutive
alike entries as gzip + base64 instead; every other server is sent the
per-entry objects it always was. What has to hold: the packed shape expands to
exactly the per-entry list (same order, since the first writer of an owner
name wins), the ETag moves with every entry in either shape and differs
between them, the zone content hash — and so the agent's RPZ serial and reuse
check — does not depend on the shape, both renders agree, and the bundle is
a fraction of the size.
"""

from __future__ import annotations

import base64
import gzip
import json
from typing import Any

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _set_packed_blocklists
from app.models.dns import DNSBlockListEntry, DNSServer
from app.models.settings import PlatformSettings
from app.services.dns import agent_config, blocklist_pack
from app.services.dns.agent_config import RPZ_CONTENT_HASH_KEY, render_bundle_body
from app.services.dns.blocklist_pack import EntryPacker, pack_entries
from tests.test_dns_agent_bundle_blocklist_stream_1662 import _fixture, _id


def _expand(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in entries:
        if "packed" not in item:
            out.append(item)
            continue
        text = gzip.decompress(base64.b64decode(item["domains_gz"])).decode("utf-8")
        domains = text.split("\n")
        assert len(domains) == item["count"]
        out.extend({**item["packed"], "domain": d} for d in domains)
    return out


async def _setup(db: AsyncSession, monkeypatch: pytest.MonkeyPatch, *, views: bool) -> DNSServer:
    monkeypatch.setattr(blocklist_pack, "PACK_MIN_RUN", 2)
    db.add(PlatformSettings(id=1))
    await db.flush()
    server = await _fixture(db, views=views)
    await db.commit()
    return server


async def _set_flag(db: AsyncSession, server: DNSServer, packed: bool) -> None:
    await db.execute(
        update(DNSServer)
        .where(DNSServer.id == server.id)
        .values(agent_renders_packed_blocklists=packed)
    )
    await db.commit()


async def _materialised(db: AsyncSession, server: DNSServer) -> tuple[dict[str, Any], str]:
    db.expunge_all()
    fresh = await db.get(DNSServer, server.id)
    assert fresh is not None
    rendered = await render_bundle_body(db, fresh)
    return rendered.body, rendered.etag


async def _streamed(db: AsyncSession, server: DNSServer) -> tuple[dict[str, Any], str]:
    db.expunge_all()
    fresh = await db.get(DNSServer, server.id)
    assert fresh is not None
    encoded = await agent_config.encode_bundle_body(db, fresh)
    return json.loads(gzip.decompress(encoded.body_gz)), encoded.etag


def _zones(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {z["rpz_zone_name"]: z for z in body["blocklists"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("views", [False, True])
async def test_packed_expands_to_the_per_entry_list_and_both_renders_agree(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, views: bool
) -> None:
    server = await _setup(db_session, monkeypatch, views=views)
    legacy_body, legacy_etag = await _materialised(db_session, server)
    await _set_flag(db_session, server, True)

    body, etag = await _materialised(db_session, server)
    streamed_body, streamed_etag = await _streamed(db_session, server)

    assert streamed_body == body
    assert streamed_etag == etag
    assert etag != legacy_etag, "a packed bundle must not share an ETag with the per-entry one"
    packed_zones, legacy_zones = _zones(body), _zones(legacy_body)
    assert packed_zones.keys() == legacy_zones.keys() and packed_zones
    saw_run = False
    for name, zone in packed_zones.items():
        saw_run |= any("packed" in e for e in zone["entries"])
        assert _expand(zone["entries"]) == legacy_zones[name]["entries"], name
        assert zone["exceptions"] == legacy_zones[name]["exceptions"]
        assert zone[RPZ_CONTENT_HASH_KEY] == legacy_zones[name][RPZ_CONTENT_HASH_KEY]
    assert saw_run, "the fixture must exercise a run"


@pytest.mark.asyncio
async def test_a_server_that_did_not_advertise_gets_the_per_entry_shape(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = await _setup(db_session, monkeypatch, views=False)
    for render in (_materialised, _streamed):
        body, _ = await render(db_session, server)
        for zone in body["blocklists"]:
            assert all("packed" not in e and "domain" in e for e in zone["entries"])


@pytest.mark.asyncio
@pytest.mark.parametrize("packed", [False, True])
async def test_the_etag_moves_with_any_entry_in_either_shape(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, packed: bool
) -> None:
    server = await _setup(db_session, monkeypatch, views=False)
    await _set_flag(db_session, server, packed)
    for render in (_materialised, _streamed):
        _, before = await render(db_session, server)
        db_session.add(
            DNSBlockListEntry(
                id=_id(0x4E0A1 + (render is _streamed)),
                list_id=_id(0x4000 + 0x10000),
                domain=f"changed-{render.__name__}.example",
                entry_type="block",
                is_wildcard=False,
            )
        )
        await db_session.commit()
        _, after = await render(db_session, server)
        assert after != before, render.__name__


@pytest.mark.asyncio
async def test_a_change_of_what_the_agent_reads_marks_the_bundle_dirty_once(
    db_session: AsyncSession,
) -> None:
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    server = await _fixture(db_session, views=False)
    await db_session.commit()
    seq = (await db_session.get(DNSServer, server.id)).bundle_dirty_seq  # type: ignore[union-attr]

    async def bumped() -> int:
        db_session.expunge_all()
        row = await db_session.get(DNSServer, server.id)
        assert row is not None
        return int(row.bundle_dirty_seq)

    row = await db_session.get(DNSServer, server.id)
    assert row is not None
    await _set_packed_blocklists(db_session, row, "soa-timers,packed-blocklists")
    await db_session.commit()
    assert row.agent_renders_packed_blocklists is True
    after_on = await bumped()
    assert after_on > seq

    row = await db_session.get(DNSServer, server.id)
    assert row is not None
    await _set_packed_blocklists(db_session, row, "soa-timers,packed-blocklists")
    await db_session.commit()
    assert await bumped() == after_on, "an unchanged heartbeat must not re-render"

    row = await db_session.get(DNSServer, server.id)
    assert row is not None
    await _set_packed_blocklists(db_session, row, "soa-timers")  # rolled back
    await db_session.commit()
    assert row.agent_renders_packed_blocklists is False
    assert await bumped() > after_on


def _synthetic(n: int) -> list[dict[str, Any]]:
    return [
        {
            "domain": f"host-{i:07d}.tracker{i % 977}.example.com",
            "action": "block",
            "block_mode": "nxdomain",
            "target": None,
            "is_wildcard": True,
        }
        for i in range(n)
    ]


def test_runs_are_consecutive_never_regrouped() -> None:
    alike = _synthetic(blocklist_pack.PACK_MIN_RUN)
    odd = {**alike[0], "domain": "odd.example", "action": "redirect", "target": "t.example."}
    wildcard_off = [{**e, "is_wildcard": False} for e in _synthetic(blocklist_pack.PACK_MIN_RUN)]
    entries = [*alike, odd, *wildcard_off, *alike]
    packed = pack_entries(entries)
    assert [("packed" in p) for p in packed] == [True, False, True, True]
    assert _expand(packed) == entries


def test_an_entry_a_run_cannot_carry_stays_an_object() -> None:
    entries = _synthetic(blocklist_pack.PACK_MIN_RUN * 2)
    entries[5] = {**entries[5], "domain": "new\nline.example"}
    entries[9] = {**entries[9], "domain": ""}
    packed = pack_entries(entries)
    assert _expand(packed) == entries
    assert sum("packed" not in p for p in packed) >= 2


def test_a_run_is_cut_at_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(blocklist_pack, "PACK_MAX_RUN", 100)
    entries = _synthetic(250)
    packer = EntryPacker()
    packed = packer.feed(entries) + packer.finish()
    assert [p["count"] for p in packed] == [100, 100, 50]
    assert _expand(packed) == entries


def test_the_bundle_is_a_fraction_of_the_size() -> None:
    entries = _synthetic(300_000)
    before = len(json.dumps(entries, separators=(",", ":")))
    after = len(json.dumps(pack_entries(entries), separators=(",", ":")))
    print(f"per-entry {before} B, packed {after} B ({before / after:.1f}x)")
    assert after * 5 < before


# ── the long-poll serves the shape the polling agent can read ──────────────


@pytest.mark.asyncio
async def test_a_rolled_back_agent_is_never_served_the_packed_bundle(
    client: Any, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An agent rolled back to an older image polls before it heartbeats, and
    the stored flag still says it reads packed runs: the stored bundle is
    packed, and the older agent would crash on it. The request's own header
    decides, and the packed bundle waits for the re-render."""
    from app.api.v1.dns import agents as agents_api
    from app.config import settings
    from app.services.dns import agent_bundle_store as store
    from app.services.dns.agent_bundle_render import render_and_store
    from app.services.dns.agent_token import mint_agent_token

    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", False)
    server = await _setup(db_session, monkeypatch, views=False)
    await _set_flag(db_session, server, True)
    token, _ = mint_agent_token(str(server.id), str(server.agent_id), "fp")
    auth = {"Authorization": f"Bearer {token}"}
    new = {**auth, "X-Spatium-Agent-Features": "soa-timers,packed-blocklists"}

    async def render() -> None:
        db_session.expunge_all()
        row = await db_session.get(DNSServer, server.id)
        assert row is not None
        out = await render_and_store(db_session, row, rendered_by=store.RENDERED_BY_WORKER)
        await db_session.commit()
        assert out.bundle is not None

    await render()
    served = await client.get("/api/v1/dns/agents/config", headers=new)
    assert served.status_code == 200
    assert any("packed" in e for z in served.json()["blocklists"] for e in z["entries"])

    # Rolled back: no features header on the very next poll.
    old = await client.get("/api/v1/dns/agents/config", headers=auth)
    assert old.status_code == 304, "the packed bundle was served to an agent that cannot read it"
    db_session.expunge_all()
    row = await db_session.get(DNSServer, server.id)
    assert row is not None and row.agent_renders_packed_blocklists is False

    await render()
    legacy = await client.get("/api/v1/dns/agents/config", headers=auth)
    assert legacy.status_code == 200
    entries = [e for z in legacy.json()["blocklists"] for e in z["entries"]]
    assert entries and all("packed" not in e and "domain" in e for e in entries)

    # And the upgrade: the new agent is not served the legacy bundle either.
    again = await client.get("/api/v1/dns/agents/config", headers=new)
    assert again.status_code == 304
    await render()
    packed = await client.get("/api/v1/dns/agents/config", headers=new)
    assert packed.status_code == 200
    assert any("packed" in e for z in packed.json()["blocklists"] for e in z["entries"])
