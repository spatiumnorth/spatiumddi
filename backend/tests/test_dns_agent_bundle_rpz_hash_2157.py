"""Each RPZ zone in a BIND9 bundle carries a content hash (#2157).

The BIND9 agent used to re-serialise every RPZ zone on every structural
apply, ~11 MB per catalog list per agent for an edit that touched no
blocklist. It now keys "is this file still current?" on ``rpz_sha256``, so
the hash has to be exactly as sensitive as the file: it must move with
anything that changes the zone's bytes, and must NOT move with anything that
does not — an unrelated zone, an option, a record. Both directions are
pinned here, along with the streamed render (#1662) computing the same hash
as the materialised one, and the hash staying out of every other driver's
bundle so their ETags do not move for a field nothing there reads.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServer,
    DNSServerOptions,
    DNSZone,
)
from app.models.settings import PlatformSettings
from app.services.dns import agent_bundle_store as store
from app.services.dns import agent_config
from app.services.dns.agent_config import RPZ_CONTENT_HASH_KEY, render_bundle_body
from tests.test_dns_agent_bundle_blocklist_stream_1662 import _fixture, _id


async def _zones(db: AsyncSession, server: DNSServer) -> dict[str, dict[str, Any]]:
    """The materialised render's RPZ zones, by name."""
    db.expunge_all()
    fresh = await db.get(DNSServer, server.id)
    assert fresh is not None
    body = (await render_bundle_body(db, fresh)).body
    return {z["rpz_zone_name"]: z for z in body["blocklists"]}


async def _streamed_zones(db: AsyncSession, server: DNSServer) -> dict[str, dict[str, Any]]:
    db.expunge_all()
    fresh = await db.get(DNSServer, server.id)
    assert fresh is not None
    encoded = await agent_config.encode_bundle_body(db, fresh)
    body = json.loads(gzip.decompress(encoded.body_gz))
    return {z["rpz_zone_name"]: z for z in body["blocklists"]}


def _independent_hash(zone: dict[str, Any]) -> str:
    """The definition, written out without the helper it tests."""
    h = hashlib.sha256()
    h.update(
        json.dumps(
            {"exceptions": zone["exceptions"], "rpz_zone_name": zone["rpz_zone_name"]},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    )
    h.update(b"\n")
    h.update(json.dumps(zone["entries"], sort_keys=True, default=str).encode("utf-8"))
    return "sha256:" + h.hexdigest()


async def _setup(db: AsyncSession, *, views: bool) -> DNSServer:
    db.add(PlatformSettings(id=1))
    await db.flush()
    server = await _fixture(db, views=views)
    await db.commit()
    return server


@pytest.mark.asyncio
@pytest.mark.parametrize("views", [False, True])
@pytest.mark.parametrize("batch", [1, 3, 5000])
async def test_every_rpz_zone_carries_its_content_hash_in_both_renders(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, views: bool, batch: int
) -> None:
    monkeypatch.setattr(agent_config, "BLOCKLIST_RENDER_BATCH", batch)
    server = await _setup(db_session, views=views)

    materialised = await _zones(db_session, server)
    streamed = await _streamed_zones(db_session, server)

    assert materialised, "the fixture must ship RPZ zones"
    assert streamed == materialised
    hashes = [z[RPZ_CONTENT_HASH_KEY] for z in materialised.values()]
    for zone in materialised.values():
        assert zone[RPZ_CONTENT_HASH_KEY] == _independent_hash(zone)
    assert len(set(hashes)) == len(hashes), "two zones must never share a hash"


@pytest.mark.asyncio
async def test_the_hash_ignores_what_does_not_change_the_zone_file(
    db_session: AsyncSession,
) -> None:
    """The reported case: a structural edit with no blocklist in it."""
    server = await _setup(db_session, views=False)
    before = await _zones(db_session, server)

    db_session.add(
        DNSZone(
            id=_id(0x4F001),
            group_id=server.group_id,
            name="unrelated.test.",
            zone_type="forward",
            kind="forward",
            forwarders=["192.0.2.1"],
        )
    )
    db_session.add(DNSServerOptions(group_id=server.group_id, forwarders=["192.0.2.9"]))
    await db_session.commit()

    after = await _zones(db_session, server)
    assert {n: z[RPZ_CONTENT_HASH_KEY] for n, z in after.items()} == {
        n: z[RPZ_CONTENT_HASH_KEY] for n, z in before.items()
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["entry_added", "entry_removed", "wildcard", "exception"])
async def test_the_hash_moves_with_the_zone_content(db_session: AsyncSession, change: str) -> None:
    server = await _setup(db_session, views=False)
    before = (await _zones(db_session, server))["spatium-blocklist.rpz."]
    alpha_id = _id(0x4000 + 0x10000)

    if change == "entry_added":
        db_session.add(
            DNSBlockListEntry(
                id=_id(0x4E001),
                list_id=alpha_id,
                domain="new.example",
                entry_type="block",
                is_wildcard=False,
                source="manual",
            )
        )
    elif change == "entry_removed":
        await db_session.execute(
            delete(DNSBlockListEntry).where(DNSBlockListEntry.domain == "ads.example")
        )
    elif change == "wildcard":
        await db_session.execute(
            update(DNSBlockListEntry)
            .where(DNSBlockListEntry.domain == "ads.example")
            .values(is_wildcard=True)
        )
    else:
        db_session.add(
            DNSBlockListException(id=_id(0x4E002), list_id=alpha_id, domain="new-allowed.example")
        )
    await db_session.commit()

    after = (await _zones(db_session, server))["spatium-blocklist.rpz."]
    assert after[RPZ_CONTENT_HASH_KEY] != before[RPZ_CONTENT_HASH_KEY]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["sinkhole_ip", "sinkhole_ip_cleared", "block_mode", "feed_exception"],
)
async def test_the_hash_moves_with_the_2124_rpz_inputs(
    db_session: AsyncSession, change: str
) -> None:
    """#2124 changed what an RPZ zone renders from: a sinkhole list's address
    rides on its entries, the list's block mode picks the policy, and a feed's
    own ``@@`` rules join the exceptions when they carve its own wildcard. An
    unchanged hash over any of them would make the agent hard-link a stale
    file (#2157): a silent wrong answer, not a slow one."""
    server = await _setup(db_session, views=False)
    before = (await _zones(db_session, server))["spatium-blocklist.rpz."]
    alpha_id = _id(0x4000 + 0x10000)
    bravo_id = _id(0x4000 + 0x20000)

    if change == "sinkhole_ip":
        await db_session.execute(
            update(DNSBlockList)
            .where(DNSBlockList.id == bravo_id)
            .values(sinkhole_ip="192.0.2.100")
        )
    elif change == "sinkhole_ip_cleared":
        await db_session.execute(
            update(DNSBlockList).where(DNSBlockList.id == bravo_id).values(sinkhole_ip=None)
        )
    elif change == "block_mode":
        await db_session.execute(
            update(DNSBlockList).where(DNSBlockList.id == alpha_id).values(block_mode="sinkhole")
        )
    else:
        # ``sink.example`` is bravo's own wildcard and no other list blocks
        # anything under it, so bravo's feed exception takes effect.
        db_session.add(
            DNSBlockListException(
                id=_id(0x4E003),
                list_id=bravo_id,
                domain="cdn.sink.example",
                source="feed",
            )
        )
    await db_session.commit()

    after = (await _zones(db_session, server))["spatium-blocklist.rpz."]
    assert after != before, "the change must reach the zone the agent renders"
    assert after[RPZ_CONTENT_HASH_KEY] != before[RPZ_CONTENT_HASH_KEY]
    assert after[RPZ_CONTENT_HASH_KEY] == _independent_hash(after)


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["powerdns", "technitium"])
async def test_only_a_bind9_bundle_carries_the_hash(db_session: AsyncSession, driver: str) -> None:
    """Nothing in the other agents reads it, and shipping it would move
    their ETags (and re-render them) for no change."""
    server = await _setup(db_session, views=False)
    await db_session.execute(
        update(DNSServer).where(DNSServer.id == server.id).values(driver=driver)
    )
    await db_session.commit()

    for render in (_zones, _streamed_zones):
        zones = await render(db_session, server)
        assert zones
        assert all(RPZ_CONTENT_HASH_KEY not in z for z in zones.values())


@pytest.mark.asyncio
async def test_a_bundle_without_a_blocklist_carries_no_hash_and_no_change(
    db_session: AsyncSession,
) -> None:
    """The bytes the revision guard pins: a group with no blocklist renders
    exactly as before #2157, so the RENDERER_REVISION bump moves no ETag."""
    db_session.add(PlatformSettings(id=1))
    from tests.test_dns_agent_bundle_blocklist_stream_1662 import _server

    _group, server = await _server(db_session, 0x7A00, "rpz-hash-none")
    await db_session.commit()
    body = (await render_bundle_body(db_session, server)).body
    assert body["blocklists"] == []
    assert RPZ_CONTENT_HASH_KEY not in store.encode_body(body).decode()
