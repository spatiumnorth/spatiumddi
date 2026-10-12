"""A blocklist goes into the stored DNS agent bundle a batch at a time (#1662).

The catalog's "Hagezi Gambling" feed is ~582k domains. Rendering the bundle of
a server whose group carries it held the whole list several times over: the
rows ``_collect_lists`` fetched, an ``EffectiveEntry`` per row, a payload dict
per entry, three whole serialisations of the payload (the structural ETag, the
ETag and the body) and the body itself. The Celery child grew ~400 MB to store
a 60.8 MB body, which took the whole 1 GiB worker of an appliance at the
sizing floor and once had the kernel OOM-kill it, with every DHCP, DNS, IPAM
and default task beside it.

These pin both halves of the fix. The render's peak follows the batch, not the
list (tracemalloc, two list sizes). And what it stores is byte for byte what
the renderer stored before the fix, for a fixture that exercises every branch
of the blocklist section: the body, the ETag and the structural ETag are
pinned to their values at 1c00a7e4, and the gzip bytes to ``compress_body`` of
that body, so no agent sees a change and no ``RENDERER_REVISION`` bump is
owed.
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

from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServer,
    DNSServerGroup,
    DNSView,
    dns_blocklist_group_assoc,
    dns_blocklist_view_assoc,
)
from app.models.settings import PlatformSettings
from app.services.dns import agent_bundle_store as store
from app.services.dns import agent_config
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import render_bundle_body


def _id(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


async def _server(db: AsyncSession, n: int, name: str) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(id=_id(n), name=name, description="blocklist stream")
    db.add(group)
    await db.flush()
    server = DNSServer(
        id=_id(n + 1),
        agent_id=_id(n + 2),
        group_id=group.id,
        name=f"{name}-ns1",
        host="192.0.2.53",
        port=53,
        driver="bind9",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return group, server


async def _blocklist(
    db: AsyncSession,
    n: int,
    name: str,
    entries: list[tuple[str, str, str | None, bool]],
    *,
    exceptions: tuple[str, ...] = (),
    **kw: Any,
) -> DNSBlockList:
    bl = DNSBlockList(id=_id(n), name=name, **kw)
    db.add(bl)
    await db.flush()
    for i, (domain, entry_type, target, wildcard) in enumerate(entries):
        db.add(
            DNSBlockListEntry(
                id=_id(n + 0x100 + i),
                list_id=bl.id,
                domain=domain,
                entry_type=entry_type,
                target=target,
                is_wildcard=wildcard,
                source="manual",
            )
        )
    for i, domain in enumerate(exceptions):
        db.add(DNSBlockListException(id=_id(n + 0x800 + i), list_id=bl.id, domain=domain))
    await db.flush()
    return bl


async def _assign(
    db: AsyncSession, bl: DNSBlockList, *, group: Any = None, view: Any = None
) -> None:
    if group is not None:
        await db.execute(
            insert(dns_blocklist_group_assoc).values(blocklist_id=bl.id, group_id=group.id)
        )
    if view is not None:
        await db.execute(
            insert(dns_blocklist_view_assoc).values(blocklist_id=bl.id, view_id=view.id)
        )


async def _fixture(db: AsyncSession, *, views: bool) -> DNSServer:
    """Every branch of the blocklist section: two lists with a duplicate owner
    name, upper case, a wildcard, a redirect with a target, a sinkhole list,
    a non-ASCII name, exceptions (one in upper case), a disabled list, an
    enabled list with no entries, and (``views``) a view-level list."""
    base = 0x5000 if views else 0x4000
    group, server = await _server(db, base, "stream-views" if views else "stream-plain")
    alpha = await _blocklist(
        db,
        base + 0x10000,
        f"alpha-{base:x}",
        [
            ("ads.example", "block", None, False),
            ("Track.EXAMPLE", "block", None, True),
            ("dup.example", "block", None, False),
            ("redirect.example", "redirect", "walled.example.", False),
            ("nx.example", "nxdomain", None, False),
            ("bücher.example", "block", None, False),
            *((f"bulk{i:02d}.example", "block", None, i % 3 == 0) for i in range(11)),
        ],
        exceptions=("Allowed.example", "also-allowed.example"),
    )
    bravo = await _blocklist(
        db,
        base + 0x20000,
        f"bravo-{base:x}",
        [
            ("dup.example", "block", None, False),
            ("sink.example", "block", None, True),
            *((f"more{i:02d}.example", "block", None, False) for i in range(5)),
        ],
        exceptions=("bravo-allowed.example",),
        block_mode="sinkhole",
        sinkhole_ip="192.0.2.99",
    )
    disabled = await _blocklist(
        db,
        base + 0x30000,
        f"charlie-off-{base:x}",
        [("off.example", "block", None, False)],
        exceptions=("off-allowed.example",),
        enabled=False,
    )
    empty = await _blocklist(
        db, base + 0x40000, f"delta-empty-{base:x}", [], exceptions=("empty-allowed.example",)
    )
    for bl in (alpha, bravo, disabled, empty):
        await _assign(db, bl, group=group)
    if views:
        internal = DNSView(
            id=_id(base + 0x50),
            group_id=group.id,
            name="internal",
            match_clients=["192.0.2.0/24"],
            order=0,
        )
        external = DNSView(
            id=_id(base + 0x51),
            group_id=group.id,
            name="external",
            match_clients=["any"],
            order=1,
        )
        db.add_all([internal, external])
        await db.flush()
        echo = await _blocklist(
            db,
            base + 0x60000,
            f"echo-view-{base:x}",
            [("view-only.example", "block", None, False), ("dup.example", "block", None, True)],
            exceptions=("view-allowed.example",),
            block_mode="refused",
        )
        await _assign(db, echo, view=internal)
    await db.flush()
    return server


# The stored body, ETag and structural ETag of ``_fixture`` as rendered at
# 1c00a7e4, before #1662: the streamed render must store exactly these bytes.
# Re-pinned for #1786, which adds ``options.allow_recursion`` to a BIND9
# bundle (RENDERER_REVISION 8): the only change to the bytes.
# The gzip bytes are deliberately not pinned: deflate's output is a property of
# the zlib build, not of the render (the desk's pin, taken in another image,
# does not reproduce in the dev image for the identical body). The test pins
# them against ``compress_body`` of the same body in the same process.
PINNED_AT_1C00A7E4: dict[str, dict[str, str]] = {
    "plain": {
        "body_sha256": "55c507248af553d70dee3cd33dd5568e4f49de92779cb9fe4a71cfa6eb615ccc",
        "etag": "sha256:4776aa9e5bfe5067aeaf121d4bde31bb7f4f2536a69f8c1c0714655068a60852",
        "structural_etag": (
            "sha256:0d55af6a39dac9600745946742a61bbaa19ae11e3cdd4b9da3b5b0fa853da8e5"
        ),
    },
    "views": {
        "body_sha256": "1c118ebe7e84e4f36a3f61515570e7f76acbb1ab99758b08b7b4ee5d989e1c76",
        "etag": "sha256:5f28e37868b38013d691bd17afa8160a99aa25cb8985bdd874aeff2de5ee9c94",
        "structural_etag": (
            "sha256:2b7ef50767d00ee784b02ae6f371e3f84b95db6889e1f1776c6aea7b0b7b807b"
        ),
    },
}


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["plain", "views"])
async def test_the_streamed_bundle_is_the_one_stored_before(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    # A handful of rows per batch, so every list spans several batches and a
    # batch boundary falls inside each of them.
    monkeypatch.setattr(agent_config, "BLOCKLIST_RENDER_BATCH", 3, raising=False)
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    server = await _fixture(db_session, views=shape == "views")
    await db_session.commit()

    reference = await render_bundle_body(db_session, server)
    reference_json = store.encode_body(reference.body)

    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    row = outcome.bundle
    assert row is not None
    stored = await store.load_body(db_session, row)  # the body column is deferred
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
    assert row.body_bytes == outcome.body_bytes == len(reference_json)
    # ... and against what the renderer stored before #1662.
    assert got == PINNED_AT_1C00A7E4[shape], f"{shape}: {got!r}"


@pytest.mark.asyncio
async def test_a_bundle_without_a_blocklist_is_stored_as_before(db_session: AsyncSession) -> None:
    """No list: nothing is streamed, and the body goes through the gzip writer
    in one piece."""
    db_session.add(PlatformSettings(id=1))
    _group, server = await _server(db_session, 0x7000, "stream-none")
    await db_session.commit()

    reference = await render_bundle_body(db_session, server)
    reference_json = store.encode_body(reference.body)
    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    row = outcome.bundle
    assert row is not None
    stored = await store.load_body(db_session, row)
    assert stored == store.compress_body(reference_json)
    assert (row.etag, row.structural_etag) == (reference.etag, reference.structural_etag)
    assert '"blocklists":[]' in reference_json.decode()


async def _big_list(db: AsyncSession, group: DNSServerGroup, n: int) -> DNSBlockList:
    bl = DNSBlockList(name=f"big-{uuid.uuid4().hex[:8]}", category="gambling")
    db.add(bl)
    await db.flush()
    await _assign(db, bl, group=group)
    await _grow(db, bl, 0, n)
    return bl


async def _grow(db: AsyncSession, bl: DNSBlockList, start: int, stop: int) -> None:
    # Names of the Hagezi Gambling feed's length (~15 characters on average).
    await db.execute(
        text(
            "INSERT INTO dns_blocklist_entry"
            " (id, list_id, domain, entry_type, source, is_wildcard, reason)"
            " SELECT gen_random_uuid(), :list_id,"
            " 'bet' || lpad(g::text, 7, '0') || '.example', 'block', 'feed', true, ''"
            " FROM generate_series(:start, :stop - 1) AS g"
        ),
        {"list_id": bl.id, "start": start, "stop": stop},
    )


async def _render_peak(db: AsyncSession, server_id: uuid.UUID) -> tuple[int, int]:
    """(peak bytes traced during one render, the body bytes it stored)."""
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
    assert outcome.stored
    return peak, outcome.body_bytes


SMALL, LARGE = 40_000, 160_000


@pytest.mark.asyncio
async def test_rendering_a_large_list_holds_a_batch_not_the_list(db_session: AsyncSession) -> None:
    db_session.add(PlatformSettings(id=1))
    group, server = await _server(db_session, 0x6000, "stream-big")
    server_id = server.id
    bl = await _big_list(db_session, group, SMALL)
    await db_session.commit()

    peak_small, body_small = await _render_peak(db_session, server_id)

    bl = await db_session.get(DNSBlockList, bl.id)
    assert bl is not None
    await _grow(db_session, bl, SMALL, LARGE)
    await db_session.execute(
        text("UPDATE dns_server SET bundle_dirty_seq = bundle_dirty_seq + 1 WHERE id = :id"),
        {"id": server_id},
    )
    await db_session.commit()
    peak_large, body_large = await _render_peak(db_session, server_id)

    per_entry = (peak_large - peak_small) / (LARGE - SMALL)
    body_per_entry = (body_large - body_small) / (LARGE - SMALL)
    detail = (
        f"peak {peak_small} B at {SMALL} entries, {peak_large} B at {LARGE};"
        f" body {body_small} B and {body_large} B;"
        f" the peak grew {per_entry:.1f} B per entry, the body {body_per_entry:.1f} B"
    )
    print(detail)
    # Before #1662 the render held every entry several times over plus whole
    # copies of the section: the peak grew ~826 B per entry, ~8x the body's
    # 106 B. Streamed, it holds one batch (``BLOCKLIST_RENDER_BATCH``) and
    # the compressed body it stores, ~3 B per entry: never even one
    # uncompressed copy of what it writes.
    assert per_entry < body_per_entry / 4, detail
    assert peak_large < body_large, detail


# ── Adversarial shapes (port review of #1662) ─────────────────────────────────


async def _tricky_fixture(db: AsyncSession, *, view_only: bool) -> DNSServer:
    """Shapes the pinned fixture does not reach. ``view_only=False``: one list
    assigned to a view AND the group (``setdefault`` keeps it once in that
    view's zone), names that JSON must escape (quote, backslash, tab, U+2028,
    a non-BMP code point, upper-case non-ASCII), a quoted redirect target, a
    view with no list of its own, and a view whose own list is disabled.
    ``view_only=True``: every group-level list disabled, so the bundle carries
    view zones and no group zone."""
    base = 0x9000 if view_only else 0x8000
    group, server = await _server(db, base, "tricky-vo" if view_only else "tricky")
    shared = await _blocklist(
        db,
        base + 0x10000,
        f"shared-{base:x}",
        [
            ('quo"te.example', "block", None, False),
            ("back\\slash.example", "block", None, True),
            ("tab\there.example", "block", None, False),
            ("line sep.example", "block", None, False),
            ("\U0001f600.example", "block", None, False),
            ("ÄÖÜ.Example", "redirect", 'walled "garden".example.', False),
            *((f"s{i:03d}.example", "block", None, i % 2 == 0) for i in range(13)),
        ],
        exceptions=("ÄÖÜ.EXAMPLE", 'x"y.example'),
        enabled=not view_only,
    )
    group_only = await _blocklist(
        db,
        base + 0x20000,
        f"group-only-{base:x}",
        [('quo"te.example', "block", None, True), ("g.example", "block", None, False)],
        block_mode="sinkhole",
        sinkhole_ip="192.0.2.7",
        enabled=not view_only,
    )
    for bl in (shared, group_only):
        await _assign(db, bl, group=group)
    views = [
        DNSView(
            id=_id(base + 0x50 + i),
            group_id=group.id,
            name=name,
            match_clients=[f"198.51.100.{i}/32"] if i < 2 else ["any"],
            order=i,
        )
        for i, name in enumerate(("internal", "lab", "external"))
    ]
    db.add_all(views)
    await db.flush()
    internal, lab, _external = views
    own = await _blocklist(
        db,
        base + 0x60000,
        f"internal-own-{base:x}",
        [("g.example", "block", None, True), ("own.example", "nxdomain", None, False)],
        exceptions=("own-allowed.example",),
    )
    await _assign(db, own, view=internal)
    await _assign(db, shared, view=internal)  # also on the group
    off = await _blocklist(
        db,
        base + 0x70000,
        f"lab-off-{base:x}",
        [("lab.example", "block", None, False)],
        enabled=False,
    )
    await _assign(db, off, view=lab)
    await db.flush()
    return server


# ``_tricky_fixture`` rendered by origin/main's renderer (c36b6c91, before
# #1662): body sha256, ETag, structural ETag.
PINNED_TRICKY_AT_MAIN: dict[bool, tuple[str, str, str]] = {
    False: (
        "d16890acb874a355de0266326fb820ae7a0dc795733ccf2ec61a0b3adc5383e4",
        "sha256:9213fd4bbbc684e1a3a3a582ff00b16944d3cc07d85a980b16bdb8e6e2d49acd",
        "sha256:65015507eb01af612290b79bc18f821bd89fff4dc77612212d3d73524f7fba35",
    ),
    True: (
        "91aaff4dbf25189d3c85658a93e12f27926a7260dbbf2d015af3ef3f6caeb571",
        "sha256:aa20f2dd903d99b5e84a5416fe4a05b4512ca48f6fdc93ecb579af56c6995e4a",
        "sha256:296c9b340e16e481f038a01fb9396067f9fc5c443bc3018e81a2ce24adbcf42f",
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("view_only", [False, True])
@pytest.mark.parametrize("batch", [1, 2, 7, 5000])
async def test_adversarial_shapes_stream_to_the_materialised_bytes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, view_only: bool, batch: int
) -> None:
    monkeypatch.setattr(agent_config, "BLOCKLIST_RENDER_BATCH", batch)
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    server = await _tricky_fixture(db_session, view_only=view_only)
    await db_session.commit()

    reference = await render_bundle_body(db_session, server)
    reference_json = store.encode_body(reference.body)
    zones = [z["rpz_zone_name"] for z in reference.body["blocklists"]]
    if view_only:
        # No group zone; the lab view's only own list is disabled, and the
        # group's are too, so lab and external carry nothing.
        assert zones == ["spatium-blocklist-internal.rpz."]
    else:
        assert zones == [
            "spatium-blocklist-internal.rpz.",
            "spatium-blocklist-lab.rpz.",
            "spatium-blocklist-external.rpz.",
            "spatium-blocklist.rpz.",
        ]

    encoded = await agent_config.encode_bundle_body(db_session, server)
    assert gzip.decompress(encoded.body_gz) == reference_json
    assert encoded.body_gz == store.compress_body(reference_json)
    assert encoded.body_bytes == len(reference_json)
    assert (encoded.etag, encoded.structural_etag) == (
        reference.etag,
        reference.structural_etag,
    )
    assert (
        hashlib.sha256(reference_json).hexdigest(),
        encoded.etag,
        encoded.structural_etag,
    ) == PINNED_TRICKY_AT_MAIN[view_only]


@pytest.mark.asyncio
async def test_a_failure_mid_stream_stores_nothing_and_closes_the_cursor(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An error after the first batch leaves the stored bundle as it was: the
    render raises before ``store`` is reached, the list's cursor is closed
    before the error reaches the caller, and the session is usable after the
    caller's rollback."""
    db_session.add(PlatformSettings(id=1))
    await db_session.flush()
    server = await _fixture(db_session, views=False)
    server_id = server.id
    await db_session.commit()
    first = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert first.bundle is not None
    good_etag = first.bundle.etag

    await db_session.execute(
        text("UPDATE dns_server SET bundle_dirty_seq = bundle_dirty_seq + 1 WHERE id = :id"),
        {"id": server_id},
    )
    await db_session.commit()

    real = agent_config.stream_entries
    closed: list[bool] = []

    async def _tracked(db: AsyncSession, lists: Any, batch: int) -> Any:
        try:
            async for rows in real(db, lists, batch):
                yield rows
        finally:
            closed.append(True)

    # The failure is the consumer's (serialising the second batch), not the
    # generator's: that is the case where only ``aclosing`` closes the cursor
    # before the error propagates.
    real_entry = agent_config._entry_dict
    calls = 0

    def _fail_in_second_batch(*args: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls > 3:
            raise RuntimeError("injected mid-stream failure")
        return real_entry(*args)

    monkeypatch.setattr(agent_config, "BLOCKLIST_RENDER_BATCH", 3)
    monkeypatch.setattr(agent_config, "stream_entries", _tracked)
    monkeypatch.setattr(agent_config, "_entry_dict", _fail_in_second_batch)
    server = await db_session.get(DNSServer, server_id)
    assert server is not None
    with pytest.raises(RuntimeError, match="injected"):
        await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    assert closed == [True]
    await db_session.rollback()

    rows = (
        await db_session.execute(
            text("SELECT etag FROM dns_agent_bundle WHERE server_id = :id"), {"id": server_id}
        )
    ).all()
    assert [r.etag for r in rows] == [good_etag]
