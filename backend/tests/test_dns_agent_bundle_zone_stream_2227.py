"""A group's records go into the stored DNS agent bundle a batch at a time (#2227).

At about two million records in twenty thousand zones in one group, rendering
one server's bundle took every control-plane worker past its 4 GiB limit in
turn, so no bundle was ever stored. The render held the group whole several
times over: a row per record (~700 B each as fetched, most of the peak), a
dict per record, and three whole serialisations of the payload (the
structural ETag, the ETag and the body). Measured on a synthetic group of
20k zones: 1.0 GB peak at 1M records, 1.8 GB at 2M; after this change
about 230 MB at both.

These pin both halves of the fix. The render's peak follows the batch, not
the group (tracemalloc, two group sizes, the same zones). And what it stores
is byte for byte what the renderer stored before: the materialised build of
the same state, and the body, ETag and structural ETag origin/main stored for
a fixture that exercises every branch of the zone section — batch boundaries
inside and between zones, split-horizon copies, Technitium's per-zone transfer
key annotations and the blocklists that the zones interleave with. Agents
compare ETags, so a byte of difference would re-render and reload the fleet.
"""

from __future__ import annotations

import gzip
import hashlib
import tracemalloc
import uuid
from typing import Any

import pytest
from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    dns_blocklist_group_assoc,
)
from app.models.settings import PlatformSettings
from app.services.dns import agent_bundle_store as store
from app.services.dns import agent_config
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import render_bundle_body


def _id(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


async def _group(db: AsyncSession, n: int, name: str, driver: str) -> tuple[Any, DNSServer]:
    group = DNSServerGroup(id=_id(n), name=name, description="zone stream")
    db.add(group)
    await db.flush()
    server = DNSServer(
        id=_id(n + 1),
        agent_id=_id(n + 2),
        group_id=group.id,
        name=f"{name}-ns1",
        host=f"192.0.2.{n % 200 + 1}",
        port=53,
        driver=driver,
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return group, server


async def _fixture(db: AsyncSession, *, driver: str, views: bool) -> DNSServer:
    """Zones whose names sort in another order than their ids, records that
    tie on name and differ in every other shipped column, an empty zone, a
    zone larger than a batch, a forward zone with its own transport, a TTL
    stored negative, non-ASCII values, (``views``) records and a zone pinned
    to views, (Technitium) secondaries whose masters do and do not share a key
    with this group, and a blocklist."""
    base = {"bind9": 0x9000, "technitium": 0xA000}[driver] + (0x800 if views else 0)
    group, server = await _group(db, base, f"zs-{driver}-{'v' if views else 'p'}", driver)
    view_ids: list[Any] = [None]
    if views:
        internal = DNSView(
            id=_id(base + 0x10),
            group_id=group.id,
            name="internal",
            match_clients=["192.0.2.0/24"],
            order=0,
        )
        external = DNSView(
            id=_id(base + 0x11), group_id=group.id, name="external", match_clients=["any"], order=1
        )
        db.add_all([internal, external])
        await db.flush()
        view_ids = [None, internal.id, external.id]

    zones: list[DNSZone] = []

    def zone(i: int, name: str, **kw: Any) -> DNSZone:
        z = DNSZone(
            id=_id(base + 0x100 + i),
            group_id=group.id,
            name=name,
            primary_ns=f"ns1.{name}",
            admin_email=f"hostmaster.{name}",
            last_serial=2026102000 + i,
            **kw,
        )
        zones.append(z)
        return z

    # Ids ascend opposite to the names, so the zone order and the order the
    # records query reads zone ids in disagree.
    big = zone(1, "zz-big.example.")
    corp = zone(2, "corp.example.", ttl=-5)
    rev = zone(3, "2.0.192.in-addr.arpa.", kind="reverse")
    zone(4, "empty.example.")
    zone(
        5,
        "fwd.example.",
        zone_type="forward",
        forwarders=["192.0.2.1", "192.0.2.2"],
        forward_transport="dot",
        forward_tls_hostname="dns.example",
    )
    pinned = zone(6, "pinned.example.", view_id=view_ids[-1])
    bulk = [zone(10 + i, f"bulk{i:02d}.example.") for i in range(9)]
    if driver == "technitium":
        zone(30, "sec-shared.example.", zone_type="secondary", masters=["198.51.100.10"])
        zone(31, "sec-unshared.example.", zone_type="secondary", masters=["198.51.100.20"])
        zone(32, "sec-foreign.example.", zone_type="secondary", masters=["203.0.113.9"])
    db.add_all(zones)
    await db.flush()

    rows: list[dict[str, Any]] = []

    def rec(z: DNSZone, name: str, rtype: str, value: str, **kw: Any) -> None:
        rows.append(
            {
                "id": _id(base + 0x10000 + len(rows)),
                "zone_id": z.id,
                "name": name,
                "fqdn": f"{name}.{z.name}",
                "record_type": rtype,
                "value": value,
                # One key set for every row: an executemany binds them all.
                **{"ttl": None, "priority": None, "weight": None, "port": None, "view_id": None},
                **kw,
            }
        )

    for i in range(23):
        rec(big, f"h{i % 7}", "A", f"10.0.{i}.{i % 5}", ttl=None if i % 3 else 60 + i)
    rec(corp, "@", "MX", "mail.corp.example.", priority=10, ttl=-1)
    rec(corp, "@", "MX", "mail2.corp.example.", priority=20)
    rec(corp, "_sip._tcp", "SRV", "sip.corp.example.", priority=5, weight=50, port=5060)
    rec(corp, "txt", "TXT", '"bücher — ünïcode"')
    rec(corp, "www", "CNAME", "corp.example.", ttl=300)
    rec(corp, "www", "A", "192.0.2.7", ttl=300)
    for v, view_id in enumerate(view_ids):
        rec(corp, "split", "A", f"192.0.2.{50 + v}", view_id=view_id)
    for i in range(6):
        rec(rev, str(i + 1), "PTR", f"host{i}.corp.example.")
    rec(pinned, "@", "A", "203.0.113.1", view_id=view_ids[-1])
    for i, z in enumerate(bulk):
        for j in range(i % 4):
            rec(z, f"n{j}", "AAAA", f"2001:db8::{i}:{j}", view_id=view_ids[j % len(view_ids)])
    await db.execute(insert(DNSRecord), rows)

    if driver == "technitium":
        # A master in another group sharing the key "xfer" (resolved), one
        # sharing none (unresolved), and an unmanaged one (no annotation).
        for k, (gname, host, shares) in enumerate(
            (("m-shared", "198.51.100.10", True), ("m-none", "198.51.100.20", False))
        ):
            mgroup, master = await _group(db, base + 0x400 + 0x10 * k, f"{gname}-{base:x}", "bind9")
            master.host = host
            if shares:
                db.add(
                    DNSTSIGKey(
                        id=_id(base + 0x500 + k),
                        group_id=mgroup.id,
                        name="xfer",
                        secret_encrypted=encrypt_str("c2VjcmV0LXhmZXI="),
                    )
                )
        db.add(
            DNSTSIGKey(
                id=_id(base + 0x510),
                group_id=group.id,
                name="xfer",
                secret_encrypted=encrypt_str("c2VjcmV0LXhmZXI="),
            )
        )
        await db.flush()

    bl = DNSBlockList(id=_id(base + 0x600), name=f"zs-bl-{base:x}")
    db.add(bl)
    await db.flush()
    for i, domain in enumerate(("ads.example", "track.example", "x.example", "zz.example")):
        db.add(
            DNSBlockListEntry(
                id=_id(base + 0x700 + i),
                list_id=bl.id,
                domain=domain,
                entry_type="block",
                is_wildcard=bool(i % 2),
                source="manual",
            )
        )
    await db.execute(
        insert(dns_blocklist_group_assoc).values(blocklist_id=bl.id, group_id=group.id)
    )
    await db.flush()
    return server


# What origin/main stored for ``_fixture``, before #2227: the body's SHA-256,
# the ETag and the structural ETag. The streamed render must store exactly
# these. Pinned at 945f539d; the two BIND9 shapes re-pinned at 2935d758,
# whose bundles carry #2157's ``rpz_sha256`` on their blocklist zone (the
# fixture assigns one), so main's own render of the fixture moved.
PINNED_ON_MAIN: dict[str, dict[str, str]] = {
    "bind9-plain": {
        "body_sha256": "d428928f453052f2be079128ffdd34af6d7a97b1a3630172279938aa5bdd59b0",
        "etag": "sha256:af2ea15b4a15bd9f049f5576818273dded46a68e03741058314c34bbcfcaf624",
        "structural_etag": (
            "sha256:43cd44203ba0f64c673533c43858c29b96f139e208b3474f326d893700f90d96"
        ),
    },
    "bind9-views": {
        "body_sha256": "6773b252daeacad6a00dc6accddad346a3eca682c32e14f8aae0d1159171f591",
        "etag": "sha256:5a77b7f714146b61fba00804b43b5efc9c61ba5fd3837a7c6feb41e6d6e5ecbd",
        "structural_etag": (
            "sha256:b7a807264097c2f09589d7ebb21a55fb68d478ddaabc9ce2b73c49fc5e27c6d4"
        ),
    },
    "technitium-plain": {
        "body_sha256": "78787cb705bb73eda98541c8860a0bebc15a9b9534252981c3c542840f2e3a14",
        "etag": "sha256:354015931e4c37fdf06577b5d7cbe3162eedea59f3cad685d046815576be0f27",
        "structural_etag": (
            "sha256:91b2a4b14fd3eeff89c7ff6cfb63e3bf005f9aac6e50a435b2f275db51173c71"
        ),
    },
    "technitium-views": {
        "body_sha256": "34c958e8ea8d669e61f2f17a39d5c24a187494820545f312667db28c714cbb76",
        "etag": "sha256:a14d69ad8bf3b58b59eda2cd7908dc2f65db8e231bdb72e1dc532f64b3dcba09",
        "structural_etag": (
            "sha256:83074d0d30c5e0b462c41519524998524d30c9c284aef11ba197b9360b64c33a"
        ),
    },
}

SHAPES = [("bind9", False), ("bind9", True), ("technitium", False), ("technitium", True)]


def _shape_id(shape: tuple[str, bool]) -> str:
    return f"{shape[0]}-{'views' if shape[1] else 'plain'}"


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", SHAPES, ids=_shape_id)
async def test_the_streamed_zones_are_the_bundle_stored_before(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, shape: tuple[str, bool]
) -> None:
    # Tiny batches, so a batch boundary falls inside the big zone, between
    # zones, and inside the blocklist; and a spool small enough to go to disk.
    monkeypatch.setattr(agent_config, "RECORD_RENDER_BATCH", 3, raising=False)
    monkeypatch.setattr(agent_config, "ZONE_RENDER_BATCH", 2, raising=False)
    monkeypatch.setattr(agent_config, "SPOOL_MEMORY_BYTES", 64, raising=False)
    monkeypatch.setattr(agent_config, "BLOCKLIST_RENDER_BATCH", 3, raising=False)
    driver, views = shape
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    server = await _fixture(db_session, driver=driver, views=views)
    await db_session.commit()

    reference = await render_bundle_body(db_session, server)
    reference_json = store.encode_body(reference.body)
    if driver == "technitium":
        # The fixture reaches the annotation branch in both directions.
        secondaries = {z["name"]: z for z in reference.body["zones"] if z["type"] == "secondary"}
        assert secondaries["sec-shared.example."]["masters_tsig_key"] == "xfer"
        assert secondaries["sec-unshared.example."]["masters_tsig_unresolved"] is True
        assert "masters_tsig_key" not in secondaries["sec-foreign.example."]

    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    row = outcome.bundle
    assert row is not None
    stored = await store.load_body(db_session, row)
    assert stored is not None
    body = gzip.decompress(stored)
    got = {
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "etag": row.etag,
        "structural_etag": row.structural_etag,
    }
    # Against the materialised render of the same state ...
    assert body == reference_json
    assert stored == store.compress_body(reference_json)
    assert (row.etag, row.structural_etag) == (reference.etag, reference.structural_etag)
    assert outcome.records == reference.records == row.records
    assert row.body_bytes == outcome.body_bytes == len(reference_json)
    # ... and against what origin/main stored.
    assert got == PINNED_ON_MAIN[_shape_id(shape)], f"{_shape_id(shape)}: {got!r}"


@pytest.mark.asyncio
async def test_a_group_with_no_zones_streams_an_empty_list(db_session: AsyncSession) -> None:
    db_session.add(PlatformSettings(id=1))
    _group_row, server = await _group(db_session, 0xB000, "zs-none", "bind9")
    await db_session.commit()

    reference = await render_bundle_body(db_session, server)
    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert outcome.bundle is not None
    stored = await store.load_body(db_session, outcome.bundle)
    assert stored == store.compress_body(store.encode_body(reference.body))
    assert (outcome.etag, outcome.structural_etag) == (reference.etag, reference.structural_etag)
    assert '"zones":[]' in store.encode_body(reference.body).decode()


# ── Memory ────────────────────────────────────────────────────────────────────

ZONES = 40
SMALL, LARGE = 20_000, 120_000


async def _grow(db: AsyncSession, zone_ids: list[uuid.UUID], start: int, stop: int) -> None:
    """Records ``start .. stop - 1`` spread over the zones, A records of the
    scale lab's shape."""
    await db.execute(
        text(
            "INSERT INTO dns_record (id, zone_id, name, fqdn, record_type, value, ttl,"
            " auto_generated, created_at, modified_at)"
            " SELECT gen_random_uuid(), (CAST(:zones AS uuid[]))[1 + g % :n],"
            " 'host' || lpad(g::text, 7, '0'), '', 'A',"
            " '10.' || (g % 250) || '.' || ((g / 250) % 250) || '.' || (g % 7),"
            " NULL, false, now(), now()"
            " FROM generate_series(:start, :stop - 1) AS g"
        ),
        {"zones": [str(z) for z in zone_ids], "n": len(zone_ids), "start": start, "stop": stop},
    )


async def _render_peak(db: AsyncSession, server_id: uuid.UUID) -> tuple[int, int, int, int]:
    """(peak bytes traced during one render, the body bytes it stored, their
    gzip size, records)."""
    await db.execute(
        text("UPDATE dns_server SET bundle_dirty_seq = bundle_dirty_seq + 1 WHERE id = :id"),
        {"id": server_id},
    )
    await db.commit()
    db.expunge_all()
    server = await db.get(DNSServer, server_id)
    assert server is not None
    tracemalloc.start()
    try:
        outcome = await render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
        _now, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    await db.commit()
    assert outcome.bundle is not None
    return peak, outcome.body_bytes, outcome.bundle.body_gzip_bytes, outcome.records


@pytest.mark.asyncio
async def test_rendering_a_large_group_holds_a_batch_not_the_group(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same zones, six times the records: the render's peak must not grow
    with them. Before #2227 it grew by every record's row, dict and three
    serialisations, ~10x the body; now by the gzip of what it wrote."""
    monkeypatch.setattr(agent_config, "RECORD_RENDER_BATCH", 1000, raising=False)
    monkeypatch.setattr(agent_config, "SPOOL_MEMORY_BYTES", 64 << 10, raising=False)
    db_session.add(PlatformSettings(id=1))
    group, server = await _group(db_session, 0xC000, "zs-big", "bind9")
    server_id = server.id
    zone_ids = [_id(0xC100 + i) for i in range(ZONES)]
    db_session.add_all(
        [
            DNSZone(id=zid, group_id=group.id, name=f"site{i:03d}.corp.example.")
            for i, zid in enumerate(zone_ids)
        ]
    )
    await db_session.flush()
    await _grow(db_session, zone_ids, 0, SMALL)
    await db_session.commit()
    # Once unmeasured: the first render in a process fills caches (compiled
    # statements, the mapper's lazy state) that would otherwise count against
    # the small render alone and hide part of the growth.
    await _render_peak(db_session, server_id)
    peak_small, body_small, gz_small, n_small = await _render_peak(db_session, server_id)

    await _grow(db_session, zone_ids, SMALL, LARGE)
    await db_session.commit()
    peak_large, body_large, gz_large, n_large = await _render_peak(db_session, server_id)
    assert (n_small, n_large) == (SMALL, LARGE)

    per_record = (peak_large - peak_small) / (LARGE - SMALL)
    body_per_record = (body_large - body_small) / (LARGE - SMALL)
    gz_per_record = (gz_large - gz_small) / (LARGE - SMALL)
    detail = (
        f"peak {peak_small} B at {SMALL} records, {peak_large} B at {LARGE};"
        f" body {body_small} B and {body_large} B (gzip {gz_small} B and {gz_large} B);"
        f" the peak grew {per_record:.1f} B per record, the body {body_per_record:.1f} B,"
        f" its gzip {gz_per_record:.1f} B"
    )
    print(detail)
    # Before #2227 the peak grew ~931 B per record here, ~8.5x the body: a
    # row, a dict and three serialisations of every record. Streamed, it holds
    # one batch and the compressed body — the stored bytes and the copy the
    # driver sends — so it grows by a few times the gzip, never by one
    # uncompressed copy of what it writes.
    assert per_record < 3 * gz_per_record + 4, detail
    assert per_record < body_per_record / 3, detail
    assert peak_large < body_large, detail
