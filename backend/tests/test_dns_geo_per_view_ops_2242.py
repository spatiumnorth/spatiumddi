"""Geo steering on the per-view op path (#2242, slice 5).

A group whose views are (partly) synthesized geo views ships record ops to a
BIND9 agent that applies them per view. The contract these tests pin: an op's
RRset for a view is exactly what the full re-render puts in that view for that
server, member filtering included, so applying the queued ops to the previous
render gives the fresh render's per-view RRsets, for every server in the group.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import (
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSView,
    DNSZone,
)
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_config import render_bundle_body
from app.services.dns.pool_apply import apply_pool_state
from app.services.dns.tsig import ensure_group_tsig_key

GEO_A = ["203.0.113.0/24"]
GEO_B = ["198.51.100.0/24"]

# (view, zone) -> {(name, type): sorted values}
Sets = dict[tuple[str | None, str], dict[tuple[str, str], list[str]]]


async def _group(
    db: AsyncSession, *, operator_view: bool
) -> tuple[DNSServerGroup, list[DNSServer]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
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
            agent_per_view_ops=True,
        )
        for i in range(2)
    ]
    db.add_all(servers)
    if operator_view:
        db.add(DNSView(group_id=grp.id, name="internal", order=0, match_clients=["10.0.0.0/8"]))
    await db.flush()
    return grp, servers


async def _zone(db: AsyncSession, grp: DNSServerGroup) -> DNSZone:
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
    return zone


async def _pool(
    db: AsyncSession, grp: DNSServerGroup, zone: DNSZone, name: str, members: list[dict[str, Any]]
) -> DNSPool:
    pool = DNSPool(
        group_id=grp.id,
        zone_id=zone.id,
        name=name,
        record_name=name,
        record_type="A",
        ttl=30,
        hc_type="none",
        enabled=True,
    )
    db.add(pool)
    await db.flush()
    for m in members:
        db.add(
            DNSPoolMember(
                pool_id=pool.id,
                address=m["address"],
                enabled=True,
                last_check_state=m.get("state", "healthy"),
                serving_cidrs=m.get("cidrs", []),
            )
        )
    await db.flush()
    await db.refresh(pool)
    await apply_pool_state(db, pool)
    await db.flush()
    return pool


def _sets(body: dict[str, Any]) -> Sets:
    out: Sets = {}
    for z in body["zones"]:
        sets: dict[tuple[str, str], list[str]] = {}
        for r in z["records"]:
            sets.setdefault((r["name"], r["type"]), []).append(r["value"])
        out[(z["view_name"], z["name"])] = {k: sorted(v) for k, v in sets.items()}
    return out


async def _apply_ops(db: AsyncSession, server: DNSServer, prev: Sets) -> Sets:
    """What the agent would do with the queued ops, in order, on ``prev``."""
    ops = (
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.server_id == server.id, DNSRecordOp.state == "pending")
                .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
            )
        )
        .scalars()
        .all()
    )
    cur = {k: {kk: list(vv) for kk, vv in v.items()} for k, v in prev.items()}
    for o in ops:
        assert o.view_name is not None, "an op under views must name its view"
        rec = o.record
        key = ((rec.get("name") or "@").lower(), str(rec["type"]).upper())
        copy = cur[(o.view_name, o.zone_name)]
        rrset = rec.get("rrset")
        action = (rec.get("rrset_action") or "").lower()
        if isinstance(rrset, dict) and rrset.get("members") is not None:
            values = sorted(m["value"] for m in rrset["members"])
            if values:
                copy[key] = values
            else:
                copy.pop(key, None)
        elif o.op in ("create", "update"):
            if action == "add":
                copy[key] = sorted({*copy.get(key, []), rec["value"]})
            else:
                copy[key] = [rec["value"]]
        elif action == "delete_value":
            left = [v for v in copy.get(key, []) if v != rec["value"]]
            if left:
                copy[key] = left
            else:
                copy.pop(key, None)
        else:
            copy.pop(key, None)
    return cur


async def _ship(db: AsyncSession, servers: list[DNSServer]) -> dict[uuid.UUID, Any]:
    out = {}
    for s in servers:
        out[s.id] = await render_and_store(db, s, rendered_by=store.RENDERED_BY_WORKER)
    await db.commit()
    return out


@pytest.mark.asyncio
@pytest.mark.parametrize("operator_view", [False, True])
async def test_ops_applied_to_the_previous_render_equal_a_fresh_render(
    db_session: AsyncSession, operator_view: bool
) -> None:
    grp, servers = await _group(db_session, operator_view=operator_view)
    zone = await _zone(db_session, grp)
    # A pool with a default member and one member per geo scope, an all-geo
    # pool (its members fall back into the non-geo views), a shared record.
    www = await _pool(
        db_session,
        grp,
        zone,
        "www",
        [
            {"address": "10.1.0.1"},
            {"address": "10.1.0.2", "cidrs": GEO_A},
            {"address": "10.1.0.3", "cidrs": GEO_B},
            {"address": "10.1.0.4", "state": "unhealthy"},
            {"address": "10.1.0.5", "cidrs": GEO_B, "state": "unhealthy"},
        ],
    )
    api = await _pool(
        db_session,
        grp,
        zone,
        "api",
        [{"address": "10.2.0.1", "cidrs": GEO_A}, {"address": "10.2.0.2", "cidrs": GEO_B}],
    )
    shared = DNSRecord(
        zone_id=zone.id, name="plain", fqdn=f"plain.{zone.name}", record_type="A", value="192.0.2.1"
    )
    db_session.add(shared)
    await db_session.commit()

    first = await _ship(db_session, servers)
    prev: dict[uuid.UUID, Sets] = {}
    for s in servers:
        body = await render_bundle_body(db_session, s)
        assert body.per_view_ops is True
        names = {z["view_name"] for z in body.body["zones"]}
        assert {"spatium-geo-1", "spatium-geo-2", "spatium-geo-default"} <= names
        prev[s.id] = _sets(body.body)
        assert first[s.id].bundle is not None

    # Changes (health and enablement, which write records but do not move the
    # geo plan): a geo member goes unhealthy, a default and a geo member come
    # healthy, an all-geo member is disabled, a shared record changes.
    for m in www.members:
        if m.address == "10.1.0.2":
            m.last_check_state = "unhealthy"
        elif m.address in ("10.1.0.4", "10.1.0.5"):
            m.last_check_state = "healthy"
    await db_session.flush()
    await apply_pool_state(db_session, www)
    for m in api.members:
        if m.address == "10.2.0.2":
            m.enabled = False
    await db_session.flush()
    await apply_pool_state(db_session, api)
    shared.value = "192.0.2.9"
    from app.services.dns.record_ops import enqueue_record_op

    await enqueue_record_op(
        db_session,
        zone,
        "update",
        {
            "record_id": str(shared.id),
            "name": "plain",
            "type": "A",
            "value": "192.0.2.9",
            "ttl": None,
        },
    )
    await db_session.commit()

    after = await _ship(db_session, servers)
    for s in servers:
        # Ships ops: the geo plan did not change, so nothing was re-rendered.
        bundle = after[s.id].bundle
        assert bundle is not None and bundle.ships_ops is True
        fresh = _sets((await render_bundle_body(db_session, s)).body)
        assert await _apply_ops(db_session, s, prev[s.id]) == fresh


@pytest.mark.asyncio
async def test_a_change_of_the_geo_plan_moves_the_structural_etag(
    db_session: AsyncSession,
) -> None:
    grp, (srv, _) = await _group(db_session, operator_view=False)
    zone = await _zone(db_session, grp)
    pool = await _pool(
        db_session,
        grp,
        zone,
        "www",
        [{"address": "10.1.0.1"}, {"address": "10.1.0.2", "cidrs": GEO_A}],
    )
    await db_session.commit()
    before = await render_bundle_body(db_session, srv)
    assert before.per_view_ops is True

    # A record-only change under a stable plan: etag moves, structural does not.
    db_session.add(
        DNSRecord(
            zone_id=zone.id, name="x", fqdn=f"x.{zone.name}", record_type="A", value="192.0.2.1"
        )
    )
    await db_session.flush()
    same = await render_bundle_body(db_session, srv)
    assert same.structural_etag == before.structural_etag

    # The default member takes the same scope: the views are unchanged, but the
    # pool is now all-geo, so its members are served into the catch-all too. No
    # record was written; only the plan moved.
    default = next(m for m in pool.members if not m.serving_cidrs)
    default.serving_cidrs = GEO_A
    await db_session.flush()
    moved = await render_bundle_body(db_session, srv)
    assert moved.structural_etag != same.structural_etag
