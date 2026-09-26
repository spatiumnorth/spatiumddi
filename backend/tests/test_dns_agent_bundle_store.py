"""The stored DNS agent bundle (#1111): rendered once per (server, watermark),
gzip at rest without the per-poll keys, the same ETag the inline build
produced, mirrored onto the server row, idempotent on the watermark, pruned
to ``dns_agent_bundle_keep_versions``.
"""

from __future__ import annotations

import gzip
import json
import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.dns import DNSAgentBundle, DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import build_config_bundle


async def _agent(db: AsyncSession, records: int = 20) -> tuple[DNSServer, DNSZone]:
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
    return server, zone


def _add_record(db: AsyncSession, zone: DNSZone, name: str) -> None:
    db.add(
        DNSRecord(
            zone_id=zone.id,
            name=name,
            fqdn=f"{name}.{zone.name}",
            record_type="A",
            value="10.9.9.9",
        )
    )


@pytest.mark.asyncio
async def test_render_and_store_stores_the_body_once_per_watermark(
    db_session: AsyncSession,
) -> None:
    server, _zone = await _agent(db_session, records=20)
    await db_session.commit()

    first = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert first.stored and first.bundle is not None
    assert first.records == 20
    assert server.bundle_watermark == first.watermark == server.bundle_dirty_seq
    assert server.bundle_etag == first.etag
    assert server.bundle_render_count == 1
    assert server.bundle_render_status == store.RENDER_STATUS_OK
    assert server.bundle_render_error is None
    assert store.is_current(server)

    # The same watermark again — another replica, or the worker racing the
    # api's inline fallback — writes nothing and reports the same ETag.
    again = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_API)
    await db_session.commit()
    assert not again.stored and again.bundle is None
    assert again.etag == first.etag
    assert server.bundle_render_count == 1

    # gzip of the #958 compact body, without the per-poll keys.
    body_gz = await store.load_body(db_session, first.bundle)
    body = json.loads(gzip.decompress(body_gz))
    assert set(store.DYNAMIC_KEYS).isdisjoint(body)
    assert body["structural_etag"] == first.structural_etag
    assert body["server_id"] == str(server.id)
    assert sum(len(z["records"]) for z in body["zones"]) == 20
    assert first.bundle.body_bytes == len(gzip.decompress(body_gz))
    assert 0 < first.bundle.body_gzip_bytes < first.bundle.body_bytes
    assert first.bundle.ships_ops is True
    assert first.bundle.rendered_by == store.RENDERED_BY_WORKER


@pytest.mark.asyncio
async def test_the_stored_etag_is_the_inline_builds_etag_when_nothing_is_pending(
    db_session: AsyncSession,
) -> None:
    server, _zone = await _agent(db_session, records=10)
    await db_session.commit()
    legacy = await build_config_bundle(db_session, server)
    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    assert outcome.etag == legacy["etag"]
    assert outcome.structural_etag == legacy["structural_etag"]


@pytest.mark.asyncio
async def test_a_change_makes_the_stored_bundle_stale_and_the_next_render_supersedes_it(
    db_session: AsyncSession,
) -> None:
    server, zone = await _agent(db_session, records=5)
    await db_session.commit()
    first = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert store.is_current(server)

    _add_record(db_session, zone, "newer")
    await db_session.commit()  # the after_flush listener bumped the sequence
    await db_session.refresh(server)
    assert server.bundle_dirty_seq > first.watermark
    assert not store.is_current(server)
    assert await store.current(db_session, server) is None

    second = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert second.stored and second.bundle is not None
    assert second.watermark == server.bundle_dirty_seq
    assert second.etag != first.etag
    assert store.is_current(server)
    current = await store.current(db_session, server)
    assert current is not None and current.id == second.bundle.id
    assert server.bundle_render_count == 2


@pytest.mark.asyncio
async def test_prune_keeps_the_newest_keep_versions_rows(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "dns_agent_bundle_keep_versions", 2)
    server, zone = await _agent(db_session, records=3)
    await db_session.commit()
    watermarks = []
    for i in range(4):
        _add_record(db_session, zone, f"r{i}")
        await db_session.commit()
        outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
        await db_session.commit()
        assert outcome.stored
        watermarks.append(outcome.watermark)
    kept = (
        (
            await db_session.execute(
                select(DNSAgentBundle.dirty_watermark).where(DNSAgentBundle.server_id == server.id)
            )
        )
        .scalars()
        .all()
    )
    assert sorted(kept) == sorted(watermarks)[-2:]
    assert server.bundle_watermark == max(watermarks)


@pytest.mark.asyncio
async def test_record_failure_surfaces_on_the_server_row_and_is_cleared_by_a_good_render(
    db_session: AsyncSession,
) -> None:
    server, _zone = await _agent(db_session, records=1)
    await db_session.commit()
    await store.record_failure(db_session, server.id, "boom: could not render")
    await db_session.commit()
    await db_session.refresh(server)
    assert server.bundle_render_status == store.RENDER_STATUS_FAILED
    assert server.bundle_render_error == "boom: could not render"
    assert server.bundle_render_at is not None
    assert server.bundle_watermark is None  # nothing served as converged

    await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert server.bundle_render_status == store.RENDER_STATUS_OK
    assert server.bundle_render_error is None


async def _revisions(db: AsyncSession, server: DNSServer) -> list[int | None]:
    rows = (
        (
            await db.execute(
                select(DNSAgentBundle)
                .where(DNSAgentBundle.server_id == server.id)
                .order_by(DNSAgentBundle.dirty_watermark)
            )
        )
        .scalars()
        .all()
    )
    return [r.renderer_revision for r in rows]


@pytest.mark.asyncio
async def test_a_newer_renderer_revision_replaces_an_older_render(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A release that changes what the renderer emits bumps the revision and
    re-renders every server once, rather than serving the older renderer's
    bytes until something unrelated marks it. Same watermark, so the row is
    replaced in place (#1185)."""
    server, _zone = await _agent(db_session, records=3)
    await db_session.commit()
    first = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert store.is_current(server)
    assert server.bundle_renderer_revision == store.RENDERER_REVISION

    # A new release that leaves the renderer alone re-renders nothing: the
    # release string no longer decides.
    monkeypatch.setattr(settings, "version", "next-release")
    assert store.is_current(server)

    monkeypatch.setattr(store, "RENDERER_REVISION", store.RENDERER_REVISION + 1)
    assert not store.is_current(server), "rendered by an older revision"
    assert await store.current(db_session, server) is None

    again = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert again.stored, "an older revision's row at this watermark is replaced"
    assert again.watermark == first.watermark
    assert again.etag == first.etag, "same state, same ETag"
    assert server.bundle_renderer_revision == store.RENDERER_REVISION
    assert store.is_current(server)
    assert await _revisions(db_session, server) == [store.RENDERER_REVISION]

    # The same revision rendering the same watermark again is still a no-op.
    dup = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_API)
    await db_session.commit()
    assert not dup.stored


@pytest.mark.asyncio
async def test_an_older_renderer_never_replaces_a_newer_render(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rolling upgrade: the new pods render at revision 2 while old pods at
    revision 1 still run. Under the ``app_version`` equality check each side
    replaced the other's row every 30 s. Now the old pods treat the newer
    render as current and serve it, and a render they finish at the same
    watermark writes nothing."""
    server, zone = await _agent(db_session, records=3)
    await db_session.commit()
    old = store.RENDERER_REVISION
    monkeypatch.setattr(store, "RENDERER_REVISION", old + 1)
    newer = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert newer.stored

    monkeypatch.setattr(store, "RENDERER_REVISION", old)
    assert store.is_current(server), "a newer revision is current for an older process"
    served = await store.newest(db_session, server)
    assert served is not None and served.renderer_revision == old + 1
    late = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_API)
    await db_session.commit()
    assert not late.stored, "an older render never replaces a newer one"
    assert await _revisions(db_session, server) == [old + 1]

    # A change the old pod renders first is stored (it is newer data), and the
    # new pod re-renders that watermark once. No ping-pong.
    _add_record(db_session, zone, "after-upgrade")
    await db_session.commit()
    await db_session.refresh(server)
    assert (await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_API)).stored
    await db_session.commit()
    monkeypatch.setattr(store, "RENDERER_REVISION", old + 1)
    assert not store.is_current(server)
    assert (await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)).stored
    await db_session.commit()
    monkeypatch.setattr(store, "RENDERER_REVISION", old)
    assert store.is_current(server)
    assert not (
        await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_API)
    ).stored


@pytest.mark.asyncio
async def test_a_bundle_from_before_the_revision_is_stale(db_session: AsyncSession) -> None:
    """Rows stored before #1185 carry NULL: each server re-renders once."""
    server, _zone = await _agent(db_session, records=3)
    await db_session.commit()
    await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    server.bundle_renderer_revision = None
    await db_session.execute(
        update(DNSAgentBundle)
        .where(DNSAgentBundle.server_id == server.id)
        .values(renderer_revision=None)
    )
    await db_session.commit()
    assert not store.is_current(server)
    assert await store.newest(db_session, server) is None
    again = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert again.stored
    assert await _revisions(db_session, server) == [store.RENDERER_REVISION]


@pytest.mark.asyncio
async def test_bundle_dirty_at_tracks_how_long_the_stored_bundle_has_been_behind(
    db_session: AsyncSession,
) -> None:
    server, zone = await _agent(db_session, records=3)
    await db_session.commit()
    await db_session.refresh(server)
    assert server.bundle_dirty_at is not None, "marked by the records insert"

    await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert server.bundle_dirty_at is None, "caught up"

    _add_record(db_session, zone, "later")
    await db_session.commit()
    await db_session.refresh(server)
    first_mark = server.bundle_dirty_at
    assert first_mark is not None

    _add_record(db_session, zone, "later-still")
    await db_session.commit()
    await db_session.refresh(server)
    assert server.bundle_dirty_at == first_mark, "kept across further marks"
