"""The cost of one record change, as the render counter sees it (#2242).

Without views a record change is an op: the structural ETag does not move,
the stored bundle ships its ops, and no server needs more than an ETag-only
re-render. With views the record is part of the structural fingerprint, the
op path is off (``ships_ops`` False) and the queued ops are retired, so every
server in the group renders the whole record set again: N servers, N renders
of reason ``structural``.

These tests pin that cost as it is today so the change that ships view-scoped
ops (slice 4 of docs/design/SPLIT_HORIZON_INCREMENTAL_OPS.md) flips the
assertions on purpose, and so a regression in the flat path is visible.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.metrics import AGENT_BUNDLE_RENDERS
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import RenderOutcome, render_and_store
from app.services.dns.record_ops import enqueue_record_op

N_SERVERS = 3
REASONS = ("initial", "revision", "structural", "records", "unchanged")


def _counts() -> dict[str, float]:
    return {r: AGENT_BUNDLE_RENDERS.labels(reason=r)._value.get() for r in REASONS}


def _delta(before: dict[str, float]) -> dict[str, int]:
    now = _counts()
    return {r: int(now[r] - before[r]) for r in REASONS if now[r] != before[r]}


async def _group(db: AsyncSession, *, views: bool) -> tuple[list[DNSServer], DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    servers = []
    for i in range(N_SERVERS):
        s = DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            name=f"srv-{i}-{uuid.uuid4().hex[:6]}",
            is_primary=i == 0,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
        db.add(s)
        servers.append(s)
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
    db.add(
        DNSRecord(
            zone_id=zone.id,
            name="h1",
            fqdn=f"h1.{zone.name}",
            record_type="A",
            value="10.9.9.9",
        )
    )
    await db.flush()
    return servers, zone


async def _render_all(db: AsyncSession, servers: list[DNSServer]) -> list[RenderOutcome]:
    out = []
    for s in servers:
        out.append(await render_and_store(db, s, rendered_by=store.RENDERED_BY_WORKER))
        await db.commit()
    return out


async def _one_record_change(db: AsyncSession, zone: DNSZone) -> None:
    rec = DNSRecord(
        zone_id=zone.id,
        name="h2",
        fqdn=f"h2.{zone.name}",
        record_type="A",
        value="10.9.9.10",
    )
    db.add(rec)
    await db.flush()
    await enqueue_record_op(db, zone, "create", {"name": "h2", "type": "A", "value": "10.9.9.10"})
    await db.commit()


@pytest.mark.asyncio
async def test_a_record_change_with_views_renders_every_server_in_full(
    db_session: AsyncSession,
) -> None:
    servers, zone = await _group(db_session, views=True)
    await db_session.commit()
    first = _counts()
    await _render_all(db_session, servers)
    assert _delta(first) == {"initial": N_SERVERS}

    await _one_record_change(db_session, zone)
    before = _counts()
    outcomes = await _render_all(db_session, servers)

    # Today: the record is structural under views, so each of the N servers
    # re-renders the group's whole record set for one record.
    assert _delta(before) == {"structural": N_SERVERS}
    # ...and none of those bundles ships ops: the op path is off under views.
    assert all(o.bundle is not None and o.bundle.ships_ops is False for o in outcomes)


@pytest.mark.asyncio
async def test_a_record_change_without_views_moves_no_structural_etag(
    db_session: AsyncSession,
) -> None:
    servers, zone = await _group(db_session, views=False)
    await db_session.commit()
    await _render_all(db_session, servers)

    await _one_record_change(db_session, zone)
    before = _counts()
    outcomes = await _render_all(db_session, servers)

    # The flat group still re-renders the stored body (the ETag covers it) but
    # never for a structural reason, and the bundle ships its ops.
    assert _delta(before) == {"records": N_SERVERS}
    assert all(o.bundle is not None and o.bundle.ships_ops is True for o in outcomes)
