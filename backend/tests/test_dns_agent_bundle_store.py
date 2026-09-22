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
from sqlalchemy import select
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
