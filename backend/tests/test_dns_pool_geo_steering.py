"""Geo / topology-aware steering for DNS pools (issue #530).

DNS pools (GSLB-lite) historically steered on health only. This suite
covers the new client-location awareness:

* ``build_geo_steering`` resolves a member's serving scope from
  ``serving_cidrs`` and/or a linked Site's subnets, groups members by
  distinct scope into synthesized geo views, and maps each scoped
  member to its view.
* The live agent ConfigBundle (``agent_config.build_config_bundle``)
  renders the geo views into ``views`` with the right match_clients and
  scopes each geo-member's record into its own view while default
  members render as shared records in every view + the catch-all.
* The BIND9 driver (``config_bundle.build_config_bundle`` →
  ``BIND9Driver.render_server_config``) emits the geo ``view {
  match-clients … }`` ACL blocks with the geo member inside its view
  and only the default member in the catch-all.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.pool_router import PoolMemberUpdate, update_member
from app.core.agent_wake import dns_group_channel
from app.core.security import hash_password
from app.drivers.dns.base import ServerOptions
from app.drivers.dns.bind9 import BIND9Driver
from app.models.auth import User
from app.models.dns import (
    DNSPool,
    DNSPoolMember,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSView,
    DNSZone,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.ownership import Site
from app.services.dns.agent_config import build_config_bundle as build_agent_bundle
from app.services.dns.config_bundle import build_config_bundle as build_dataclass_bundle
from app.services.dns.pool_apply import apply_pool_state
from app.services.dns.pool_geo import GEO_DEFAULT_VIEW, build_geo_steering


async def _bind9_group(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone, DNSServer]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", is_recursive=True)
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="bind9.example.com",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    db.add(DNSServerOptions(group_id=grp.id, recursion_enabled=True))
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    return grp, zone, server


async def _pool_with_members(
    db: AsyncSession,
    grp: DNSServerGroup,
    zone: DNSZone,
    members: list[dict],
) -> DNSPool:
    """Create a ``www`` pool + members and materialise their records."""
    pool = DNSPool(
        group_id=grp.id,
        zone_id=zone.id,
        name="www",
        record_name="www",
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
                # Healthy so the reconciler renders the record.
                last_check_state="healthy",
                serving_cidrs=m.get("serving_cidrs", []),
                site_id=m.get("site_id"),
            )
        )
    await db.flush()
    await db.refresh(pool)
    # Materialise the DNSRecord rows the bundle renders from.
    await apply_pool_state(db, pool)
    await db.flush()
    return pool


# ── build_geo_steering ────────────────────────────────────────────────


async def test_geo_steering_cidr_scope_groups_and_maps(db_session: AsyncSession) -> None:
    grp, zone, _ = await _bind9_group(db_session)
    pool = await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},  # default — no scope
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},
            {"address": "10.0.0.3", "serving_cidrs": ["203.0.113.0/24"]},  # same scope
            {"address": "10.0.0.4", "serving_cidrs": ["198.51.100.0/24"]},
        ],
    )
    geo = await build_geo_steering(db_session, grp.id)

    # Two distinct scopes → two geo views; the default member has none.
    assert geo.active
    assert len(geo.views) == 2
    # Members with the SAME scope share one geo view.
    members = {m.address: m for m in pool.members}
    v_for = {addr: geo.member_view.get(str(m.id)) for addr, m in members.items()}
    assert v_for["10.0.0.1"] is None  # default target
    assert v_for["10.0.0.2"] is not None
    assert v_for["10.0.0.2"] == v_for["10.0.0.3"]
    assert v_for["10.0.0.4"] != v_for["10.0.0.2"]
    # Deterministic naming + the CIDR shows up as the view's match list.
    by_name = {gv.name: gv for gv in geo.views}
    assert "spatium-geo-1" in by_name
    assert "spatium-geo-2" in by_name
    all_cidrs = {c for gv in geo.views for c in gv.match_clients}
    assert "203.0.113.0/24" in all_cidrs
    assert "198.51.100.0/24" in all_cidrs


async def test_geo_steering_site_scope_resolves_subnets(db_session: AsyncSession) -> None:
    grp, zone, _ = await _bind9_group(db_session)

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    site = Site(name="DC-East")
    db_session.add(site)
    await db_session.flush()
    db_session.add(
        Subnet(
            space_id=space.id,
            block_id=block.id,
            network="10.20.30.0/24",
            name="east-lan",
            site_id=site.id,
        )
    )
    await db_session.flush()

    await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},  # default
            {"address": "10.20.30.9", "site_id": site.id},  # site-scoped
        ],
    )
    geo = await build_geo_steering(db_session, grp.id)
    assert geo.active
    # The site's subnet CIDR becomes the geo view's match list.
    all_cidrs = {c for gv in geo.views for c in gv.match_clients}
    assert "10.20.30.0/24" in all_cidrs


async def test_geo_steering_inactive_without_scopes(db_session: AsyncSession) -> None:
    grp, zone, _ = await _bind9_group(db_session)
    await _pool_with_members(
        db_session, grp, zone, [{"address": "10.0.0.1"}, {"address": "10.0.0.2"}]
    )
    geo = await build_geo_steering(db_session, grp.id)
    assert not geo.active
    assert geo.views == []
    assert geo.member_view == {}
    assert geo.default_fallback_members == set()


async def test_geo_steering_all_geo_pool_marks_fallback_members(
    db_session: AsyncSession,
) -> None:
    """A pool whose every member is geo-scoped (no default target) marks
    all its members as ``default_fallback_members`` so they're served
    into the non-geo views too — no NODATA for an unmatched client."""
    grp, zone, _ = await _bind9_group(db_session)
    pool = await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},
            {"address": "10.0.0.4", "serving_cidrs": ["198.51.100.0/24"]},
        ],
    )
    geo = await build_geo_steering(db_session, grp.id)
    assert geo.active
    ids = {str(m.id) for m in pool.members}
    # Every member is a fallback target (the pool has no unscoped member).
    assert geo.default_fallback_members == ids


async def test_geo_steering_pool_with_default_no_fallback(db_session: AsyncSession) -> None:
    """A pool that HAS an unscoped member keeps the strict behaviour —
    its geo members are NOT fallback targets (the default member is)."""
    grp, zone, _ = await _bind9_group(db_session)
    await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},  # default target
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},
        ],
    )
    geo = await build_geo_steering(db_session, grp.id)
    assert geo.active
    assert geo.default_fallback_members == set()


# ── live agent ConfigBundle rendering ─────────────────────────────────


async def test_agent_bundle_renders_geo_views_and_scoped_records(
    db_session: AsyncSession,
) -> None:
    grp, zone, server = await _bind9_group(db_session)
    await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},  # default — served everywhere
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},  # geo
        ],
    )
    bundle = await build_agent_bundle(db_session, server)

    # Geo view + catch-all present in the views block with match_clients.
    view_names = {v["name"] for v in bundle["views"]}
    assert "spatium-geo-1" in view_names
    assert GEO_DEFAULT_VIEW in view_names
    geo_view = next(v for v in bundle["views"] if v["name"] == "spatium-geo-1")
    assert "203.0.113.0/24" in geo_view["match_clients"]
    default_view = next(v for v in bundle["views"] if v["name"] == GEO_DEFAULT_VIEW)
    assert default_view["match_clients"] == ["any"]

    # Per-view zone record sets: the geo view serves the geo member + the
    # default member; the catch-all serves only the default member.
    def _addrs(view_name: str) -> set[str]:
        addrs: set[str] = set()
        for z in bundle["zones"]:
            if z["view_name"] == view_name and z["name"] == "example.com.":
                addrs |= {r["value"] for r in z["records"] if r["type"] == "A"}
        return addrs

    assert _addrs("spatium-geo-1") == {"10.0.0.1", "10.0.0.2"}
    assert _addrs(GEO_DEFAULT_VIEW) == {"10.0.0.1"}


async def test_agent_bundle_unhealthy_geo_member_not_served(
    db_session: AsyncSession,
) -> None:
    """Health gating composes with geo scope — an unhealthy geo member
    is never rendered into its view."""
    grp, zone, server = await _bind9_group(db_session)
    pool = await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},
        ],
    )
    # Flip the geo member unhealthy + reconcile → its record disappears.
    geo_member = next(m for m in pool.members if m.address == "10.0.0.2")
    geo_member.last_check_state = "unhealthy"
    await db_session.flush()
    await apply_pool_state(db_session, pool)
    await db_session.flush()

    bundle = await build_agent_bundle(db_session, server)
    for z in bundle["zones"]:
        if z["view_name"] == "spatium-geo-1" and z["name"] == "example.com.":
            assert "10.0.0.2" not in {r["value"] for r in z["records"]}


async def test_agent_bundle_geo_views_precede_operator_views(
    db_session: AsyncSession,
) -> None:
    """Finding #4a — with a coexisting operator split-horizon view, the
    synthesized geo views must render BEFORE the operator view so a
    geo-CIDR client hits its geo view first (BIND first-match-wins).
    Otherwise a broad operator view swallows the query and the geo
    member never gets served."""
    grp, zone, server = await _bind9_group(db_session)
    # Operator "internal" view — broad match that would otherwise swallow
    # any client (incl. the geo-CIDR client) if evaluated first.
    db_session.add(
        DNSView(
            group_id=grp.id,
            name="internal",
            match_clients=["10.0.0.0/8", "203.0.113.0/24"],
            order=0,
        )
    )
    await db_session.flush()
    await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},  # default — served everywhere
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},  # geo
        ],
    )
    bundle = await build_agent_bundle(db_session, server)

    names_in_order = [v["name"] for v in bundle["views"]]
    assert "spatium-geo-1" in names_in_order
    assert "internal" in names_in_order
    assert GEO_DEFAULT_VIEW in names_in_order
    # Geo view BEFORE the operator view; catch-all LAST.
    assert names_in_order.index("spatium-geo-1") < names_in_order.index("internal")
    assert names_in_order.index("internal") < names_in_order.index(GEO_DEFAULT_VIEW)

    # The geo-CIDR client reaches its geo view, which serves the geo
    # member (+ the shared default member).
    def _addrs(view_name: str) -> set[str]:
        addrs: set[str] = set()
        for z in bundle["zones"]:
            if z["view_name"] == view_name and z["name"] == "example.com.":
                addrs |= {r["value"] for r in z["records"] if r["type"] == "A"}
        return addrs

    assert _addrs("spatium-geo-1") == {"10.0.0.1", "10.0.0.2"}
    # The operator view still serves the default member (split-horizon
    # unchanged); the geo member is only reachable via the geo view.
    assert _addrs("internal") == {"10.0.0.1"}


async def test_agent_bundle_all_geo_pool_no_blackhole(
    db_session: AsyncSession,
) -> None:
    """Finding #4b — a pool where EVERY member is geo-scoped must not
    NODATA-blackhole a client matching no geo CIDR. The catch-all
    geo-default view falls back to the union of all healthy members."""
    grp, zone, server = await _bind9_group(db_session)
    await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},
            {"address": "10.0.0.4", "serving_cidrs": ["198.51.100.0/24"]},
        ],
    )
    bundle = await build_agent_bundle(db_session, server)

    def _addrs(view_name: str) -> set[str]:
        addrs: set[str] = set()
        for z in bundle["zones"]:
            if z["view_name"] == view_name and z["name"] == "example.com.":
                addrs |= {r["value"] for r in z["records"] if r["type"] == "A"}
        return addrs

    # Each geo view still serves only its own member (exclude the
    # catch-all, whose name also starts with ``spatium-geo-``).
    geo_views = sorted(
        v["name"]
        for v in bundle["views"]
        if v["name"].startswith("spatium-geo-") and v["name"] != GEO_DEFAULT_VIEW
    )
    assert len(geo_views) == 2
    per_view = {name: _addrs(name) for name in geo_views}
    assert {"10.0.0.2"} in per_view.values()
    assert {"10.0.0.4"} in per_view.values()
    # The catch-all serves the UNION of all healthy members instead of an
    # empty rrset — an unmatched client resolves rather than blackholes.
    assert _addrs(GEO_DEFAULT_VIEW) == {"10.0.0.2", "10.0.0.4"}


# ── BIND9 driver view / ACL output ────────────────────────────────────


async def test_bind9_driver_renders_geo_view_acl(db_session: AsyncSession) -> None:
    grp, zone, server = await _bind9_group(db_session)
    await _pool_with_members(
        db_session,
        grp,
        zone,
        [
            {"address": "10.0.0.1"},  # default
            {"address": "10.0.0.2", "serving_cidrs": ["203.0.113.0/24"]},  # geo
        ],
    )
    bundle = await build_dataclass_bundle(db_session, server)
    driver = BIND9Driver()
    out = driver.render_server_config(server, ServerOptions(), bundle=bundle)

    # named.conf renders the geo view block + its match-clients ACL, the
    # catch-all view, and the zone stanza inside each view.
    assert 'view "spatium-geo-1"' in out
    assert "match-clients { 203.0.113.0/24; }" in out
    assert f'view "{GEO_DEFAULT_VIEW}"' in out
    assert "match-clients { any; }" in out
    # The zone stanza materialises once per view.
    assert out.count('zone "example.com."') == 2

    # Record scoping lives in the per-view zone FILE, not named.conf.
    # The geo view serves geo member + default; the catch-all serves only
    # the default member.
    zones_by_view = {z.view_name: z for z in bundle.zones if z.name == "example.com."}
    geo_zone = zones_by_view["spatium-geo-1"]
    default_zone = zones_by_view[GEO_DEFAULT_VIEW]

    geo_file = driver.render_zone_file(geo_zone, list(geo_zone.records))
    default_file = driver.render_zone_file(default_zone, list(default_zone.records))

    assert "10.0.0.2" in geo_file  # geo member in its view
    assert "10.0.0.1" in geo_file  # default member shared into geo view too
    assert "10.0.0.1" in default_file
    assert "10.0.0.2" not in default_file


# ── Wake on geo-scope-only member edit (finding #10) ──────────────────


async def _superadmin(db: AsyncSession) -> User:
    user = User(
        username=f"pooladmin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="pool admin",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user


async def test_serving_scope_change_wakes_group(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A geo-scope-only member edit (``serving_cidrs`` / ``site_id``)
    doesn't touch the rendered records but DOES change which view they
    land in, so it must wake the pool's DNS group (cross-cutting #2) —
    otherwise the agent converges only on the ~12 s safety tick.

    Driven at the handler level with ``collect_wake`` monkeypatched so we
    assert the exact channel the ``wake_publishing`` dependency would
    flush after commit, without depending on Redis or the HTTP client."""
    user = await _superadmin(db_session)
    grp, zone, _ = await _bind9_group(db_session)
    pool = await _pool_with_members(
        db_session, grp, zone, [{"address": "10.0.0.1"}]  # unscoped to start
    )
    member = pool.members[0]

    woke: list[str] = []
    monkeypatch.setattr(
        "app.api.v1.dns.pool_router.collect_wake",
        lambda *channels: woke.extend(channels),
    )

    await update_member(
        member.id,
        PoolMemberUpdate(serving_cidrs=["203.0.113.0/24"]),
        db_session,
        user,
    )
    assert dns_group_channel(grp.id) in woke


async def test_noop_serving_scope_change_does_not_wake(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-submitting the SAME serving scope (order/dupes aside) is a
    no-op — it must NOT wake every agent in the group."""
    user = await _superadmin(db_session)
    grp, zone, _ = await _bind9_group(db_session)
    pool = await _pool_with_members(
        db_session,
        grp,
        zone,
        [{"address": "10.0.0.1", "serving_cidrs": ["203.0.113.0/24"]}],
    )
    member = pool.members[0]

    woke: list[str] = []
    monkeypatch.setattr(
        "app.api.v1.dns.pool_router.collect_wake",
        lambda *channels: woke.extend(channels),
    )

    # Same scope, re-ordered — the validator canonicalises and the
    # set-compare sees no change, so no wake fires.
    await update_member(
        member.id,
        PoolMemberUpdate(serving_cidrs=["203.0.113.0/24"]),
        db_session,
        user,
    )
    assert dns_group_channel(grp.id) not in woke


# ── #2292: site delete / emptied site scope must not become a default ──


async def _site_with_member(db: AsyncSession, with_subnet: bool):
    grp, zone, server = await _bind9_group(db)
    site = Site(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(site)
    await db.flush()
    if with_subnet:
        space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
        db.add(space)
        await db.flush()
        block = IPBlock(space_id=space.id, network="10.20.0.0/16", name="b")
        db.add(block)
        await db.flush()
        db.add(
            Subnet(
                space_id=space.id,
                block_id=block.id,
                network="10.20.30.0/24",
                name="n",
                site_id=site.id,
            )
        )
        await db.flush()
    await _pool_with_members(
        db,
        grp,
        zone,
        [{"address": "10.0.0.1"}, {"address": "10.0.0.2", "site_id": site.id}],
    )
    return grp, server, site


def _view_addrs(bundle: dict, view_name: str) -> set[str]:
    out: set[str] = set()
    for z in bundle["zones"]:
        if z["view_name"] == view_name and z["name"] == "example.com.":
            out |= {r["value"] for r in z["records"] if r["type"] == "A"}
    return out


async def test_site_scoped_member_with_no_subnets_serves_nobody(
    db_session: AsyncSession,
) -> None:
    _, server, _ = await _site_with_member(db_session, with_subnet=False)
    bundle = await build_agent_bundle(db_session, server)
    for v in bundle["views"]:
        assert "10.0.0.2" not in _view_addrs(bundle, v["name"])
    assert "10.0.0.2" not in {
        r["value"] for z in bundle["zones"] for r in z["records"] if r["type"] == "A"
    }
    # The default member is unaffected.
    assert "10.0.0.1" in {
        r["value"] for z in bundle["zones"] for r in z["records"] if r["type"] == "A"
    }


async def test_site_scoped_member_with_subnet_still_geo_served(
    db_session: AsyncSession,
) -> None:
    grp, _, _ = await _site_with_member(db_session, with_subnet=True)
    geo = await build_geo_steering(db_session, grp.id)
    assert geo.active and not geo.unreachable_members


async def test_unscoped_member_is_still_default(db_session: AsyncSession) -> None:
    grp, zone, server = await _bind9_group(db_session)
    await _pool_with_members(db_session, grp, zone, [{"address": "10.0.0.1"}])
    bundle = await build_agent_bundle(db_session, server)
    assert "10.0.0.1" in {
        r["value"] for z in bundle["zones"] for r in z["records"] if r["type"] == "A"
    }


async def test_site_delete_refused_while_pool_member_references_it(
    db_session: AsyncSession,
) -> None:
    from fastapi import HTTPException

    from app.api.v1.ownership.sites import SiteBulkDelete, bulk_delete_sites, delete_site

    _, _, site = await _site_with_member(db_session, with_subnet=True)
    user = User(
        username=f"u{uuid.uuid4().hex[:6]}",
        email="u@example.com",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()

    with pytest.raises(HTTPException) as ei:
        await delete_site(site.id, db_session, user)
    assert ei.value.status_code == 409
    assert "www" in ei.value.detail and "10.0.0.2" in ei.value.detail

    with pytest.raises(HTTPException) as ei:
        await bulk_delete_sites(SiteBulkDelete(ids=[site.id]), db_session, user)
    assert ei.value.status_code == 409
    assert await db_session.get(Site, site.id) is not None
