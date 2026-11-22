"""Per-view record ops (#2242, slice 4).

A group with views ships record ops to a BIND9 agent that says it applies them
per view (``per-view-ops``): the structural payload then carries the zones'
placement (which views hold a copy) but not their records, each op names its
view and carries the RRset of that view's copy, and the queued ops are retired
only by a render that moved something the agent re-applies from the body.
Everything else keeps today's path: an agent that does not say so, a signed
zone, a group without the product's own key. Geo steering is on the per-view
path since slice 5 (``test_dns_geo_per_view_ops_2242.py``).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _set_per_view_ops
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import page_pending_ops, render_bundle_body
from app.services.dns.record_ops import (
    _successors,
    enqueue_record_op,
    enqueue_record_ops_batch,
    op_rrset_key,
)
from app.services.dns.tsig import (
    ensure_group_tsig_key,
    legacy_group_key,
    view_transfer_key,
    view_update_key,
)


async def _group(
    db: AsyncSession,
    *,
    caps: tuple[bool, ...] = (True,),
    views: tuple[str, ...] = ("internal", "external"),
    key: bool = True,
) -> tuple[DNSServerGroup, list[DNSServer], dict[str, DNSView]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    if key:
        ensure_group_tsig_key(grp)
    db.add(grp)
    await db.flush()
    servers = [
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            name=f"srv{i}-{uuid.uuid4().hex[:4]}",
            is_primary=i == 0,
            is_enabled=True,
            agent_id=uuid.uuid4(),
            agent_per_view_ops=cap,
        )
        for i, cap in enumerate(caps)
    ]
    vs = {
        n: DNSView(group_id=grp.id, name=n, order=i, match_clients=["10.0.0.0/8"])
        for i, n in enumerate(views)
    }
    db.add_all([*servers, *vs.values()])
    await db.flush()
    return grp, servers, vs


async def _zone(db: AsyncSession, grp: DNSServerGroup, **kw: Any) -> DNSZone:
    name = f"z{uuid.uuid4().hex[:6]}.example."
    zone = DNSZone(
        group_id=grp.id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        **kw,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _rec(
    db: AsyncSession,
    zone: DNSZone,
    name: str,
    value: str,
    view: DNSView | None = None,
) -> DNSRecord:
    rec = DNSRecord(
        zone_id=zone.id,
        view_id=view.id if view else None,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value=value,
    )
    db.add(rec)
    await db.flush()
    return rec


def _payload(rec: DNSRecord) -> dict[str, Any]:
    return {
        "record_id": str(rec.id),
        "name": rec.name,
        "type": rec.record_type,
        "value": rec.value,
        "ttl": None,
    }


async def _render(db: AsyncSession, server: DNSServer) -> Any:
    out = await render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
    await db.commit()
    return out


async def _ops(db: AsyncSession, server: DNSServer) -> list[DNSRecordOp]:
    return list(
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.server_id == server.id)
                .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_records_leave_the_structural_payload_but_placement_stays(
    db_session: AsyncSession,
) -> None:
    grp, (srv,), views = await _group(db_session)
    zone = await _zone(db_session, grp)
    await _rec(db_session, zone, "h1", "10.0.0.1")
    before = await render_bundle_body(db_session, srv)
    assert before.per_view_ops is True
    assert {z["view_name"] for z in before.body["zones"]} == {"internal", "external"}

    # A record that places the zone in no new view: structural etag unmoved.
    await _rec(db_session, zone, "h2", "10.0.0.2")
    same = await render_bundle_body(db_session, srv)
    assert same.etag != before.etag
    assert same.structural_etag == before.structural_etag

    # A record scoped to one view: the zone now renders in that view alone,
    # the external copy is gone, and the structural etag moves.
    await _rec(db_session, zone, "h3", "10.0.0.3", views["internal"])
    moved = await render_bundle_body(db_session, srv)
    assert {z["view_name"] for z in moved.body["zones"]} == {"internal"}
    assert moved.structural_etag != same.structural_etag


@pytest.mark.asyncio
async def test_a_placement_change_still_re_renders_and_retires_its_ops(
    db_session: AsyncSession,
) -> None:
    grp, (srv,), views = await _group(db_session)
    zone = await _zone(db_session, grp)
    await _rec(db_session, zone, "h1", "10.0.0.1")
    await db_session.commit()
    await _render(db_session, srv)

    scoped = await _rec(db_session, zone, "h2", "10.0.0.2", views["internal"])
    await enqueue_record_op(db_session, zone, "create", _payload(scoped))
    await db_session.commit()
    out = await _render(db_session, srv)

    # The render moved the placement, so the agent re-applies the body and the
    # op it covers is retired, not shipped.
    assert out.bundle is not None and out.bundle.ships_ops is True
    assert {o.state for o in await _ops(db_session, srv)} == {"applied"}


@pytest.mark.asyncio
async def test_two_views_serving_one_name_each_get_their_own_rrset(
    db_session: AsyncSession,
) -> None:
    grp, (srv,), views = await _group(db_session)
    zone = await _zone(db_session, grp)
    # Same name, a different address in each view (both scoped, so the zone
    # renders in both).
    inner = await _rec(db_session, zone, "www", "10.1.1.1", views["internal"])
    await _rec(db_session, zone, "www", "203.0.113.5", views["external"])
    await db_session.commit()
    await _render(db_session, srv)

    await enqueue_record_op(db_session, zone, "update", _payload(inner))
    await db_session.commit()

    ops = await _ops(db_session, srv)
    by_view = {o.view_name: o for o in ops}
    assert set(by_view) == {"internal"}  # the record is scoped: one op, its view
    members = [m["value"] for m in by_view["internal"].record["rrset"]["members"]]
    assert members == ["10.1.1.1"]  # not the external view's address

    # A shared record at the same name fans out, and each view's op carries
    # that view's own members next to it.
    shared = await _rec(db_session, zone, "www", "192.0.2.7")
    await enqueue_record_op(db_session, zone, "create", _payload(shared))
    await db_session.commit()
    latest = [o for o in await _ops(db_session, srv) if o.record["value"] == "192.0.2.7"]
    sets = {o.view_name: sorted(m["value"] for m in o.record["rrset"]["members"]) for o in latest}
    assert sets == {
        "internal": ["10.1.1.1", "192.0.2.7"],
        "external": ["192.0.2.7", "203.0.113.5"],
    }
    pages, _ = await page_pending_ops(db_session, srv)
    assert {p["view_name"] for p in pages} == {"internal", "external"}


@pytest.mark.asyncio
async def test_a_batch_stamps_each_view_from_its_own_copy(db_session: AsyncSession) -> None:
    grp, (srv,), views = await _group(db_session)
    zone = await _zone(db_session, grp)
    await _rec(db_session, zone, "www", "10.1.1.1", views["internal"])
    await _rec(db_session, zone, "www", "203.0.113.5", views["external"])
    shared = await _rec(db_session, zone, "www", "192.0.2.7")
    await db_session.commit()

    await enqueue_record_ops_batch(
        db_session, zone, [{"op": "create", "record": _payload(shared), "target_serial": 5}]
    )
    await db_session.commit()
    sets = {
        o.view_name: sorted(m["value"] for m in o.record["rrset"]["members"])
        for o in await _ops(db_session, srv)
    }
    assert sets == {
        "internal": ["10.1.1.1", "192.0.2.7"],
        "external": ["192.0.2.7", "203.0.113.5"],
    }


@pytest.mark.asyncio
async def test_an_op_for_one_view_is_not_superseded_by_its_sibling_views_op(
    db_session: AsyncSession,
) -> None:
    grp, (srv,), _ = await _group(db_session)
    zone = await _zone(db_session, grp)
    rec = await _rec(db_session, zone, "www", "192.0.2.7")
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    await db_session.commit()
    ops = await _ops(db_session, srv)
    assert {o.view_name for o in ops} == {"internal", "external"}
    keys = {op_rrset_key(o) for o in ops}
    assert len(keys) == 2  # one RRset key per view

    # The external op is the newer of the two (same transaction, higher seq):
    # without the view in the key it would supersede the internal one.
    assert await _successors(db_session, ops) == {}

    # A later op for the SAME view does supersede.
    await enqueue_record_op(db_session, zone, "update", _payload(rec))
    await db_session.commit()
    again = await _ops(db_session, srv)
    succ = await _successors(db_session, [o for o in again if o.id in {x.id for x in ops}])
    assert {o.id: o.view_name for o in again if o.id in succ} == {o.id: o.view_name for o in ops}
    newer = {o.view_name: o.id for o in again if o.id not in {x.id for x in ops}}
    assert {succ[o.id] for o in ops if o.view_name == "internal"} == {newer["internal"]}
    assert {succ[o.id] for o in ops if o.view_name == "external"} == {newer["external"]}


@pytest.mark.asyncio
async def test_a_mixed_fleet_keeps_the_old_path_for_the_old_agent(
    db_session: AsyncSession,
) -> None:
    grp, (new, old), _ = await _group(db_session, caps=(True, False))
    zone = await _zone(db_session, grp)
    await _rec(db_session, zone, "h1", "10.0.0.1")
    await db_session.commit()
    await _render(db_session, new)
    await _render(db_session, old)

    rec = await _rec(db_session, zone, "h2", "10.0.0.2")
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    await db_session.commit()
    new_out = await _render(db_session, new)
    old_out = await _render(db_session, old)

    # The capable server keeps its ops queued and its structural etag; the old
    # one re-renders in full, retires, and ships nothing.
    assert new_out.bundle is not None and new_out.bundle.ships_ops is True
    assert old_out.bundle is not None and old_out.bundle.ships_ops is False
    assert new_out.structural_etag != old_out.structural_etag
    assert {o.state for o in await _ops(db_session, new)} == {"pending"}
    assert {o.state for o in await _ops(db_session, old)} == {"applied"}
    new_body = await render_bundle_body(db_session, new)
    old_body = await render_bundle_body(db_session, old)
    assert all("update_key" in v for v in new_body.body["views"])
    assert not any("update_key" in v for v in old_body.body["views"])


@pytest.mark.asyncio
async def test_what_keeps_a_group_on_the_re_render_path(db_session: AsyncSession) -> None:
    # A signed zone.
    grp, (srv,), _ = await _group(db_session)
    await _zone(db_session, grp, dnssec_enabled=True)
    assert (await render_bundle_body(db_session, srv)).per_view_ops is False

    # No product group key, so no per-view keys to derive.
    grp2, (srv2,), _ = await _group(db_session, key=False)
    await _zone(db_session, grp2)
    assert (await render_bundle_body(db_session, srv2)).per_view_ops is False

    # No views.
    grp3, (srv3,), _ = await _group(db_session, views=())
    await _zone(db_session, grp3)
    body3 = await render_bundle_body(db_session, srv3)
    assert body3.per_view_ops is False and body3.has_views is False


@pytest.mark.asyncio
async def test_the_update_key_is_its_own_key(db_session: AsyncSession) -> None:
    grp, _, _ = await _group(db_session)
    key = legacy_group_key(grp)
    assert key is not None
    upd = view_update_key(key, "internal")
    xfr = view_transfer_key(key, "internal")
    assert upd.name != xfr.name and upd.secret != xfr.secret
    assert upd.name.startswith("spatium_upd_")
    assert view_update_key(key, "internal") == upd
    assert view_update_key(key, "external").secret != upd.secret


@pytest.mark.asyncio
async def test_the_capability_comes_from_the_agent_header(db_session: AsyncSession) -> None:
    grp, (srv,), _ = await _group(db_session, caps=(False,))
    await db_session.commit()
    await _set_per_view_ops(db_session, srv, "soa-timers,per-view-ops")
    assert srv.agent_per_view_ops is True
    await _set_per_view_ops(db_session, srv, "soa-timers")  # rolled back
    assert srv.agent_per_view_ops is False
    srv.driver = "powerdns"
    await _set_per_view_ops(db_session, srv, "per-view-ops")
    assert srv.agent_per_view_ops is False  # only BIND9 can apply per view
