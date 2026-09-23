"""Geo / topology-aware steering view synthesis for DNS pools (issue #530).

DNS pools (GSLB-lite) historically steered on **health only** — every
client received the same healthy A/AAAA rrset. This module adds
client-location awareness: a pool member can carry a *serving scope*
(a list of client CIDRs and/or a Site whose linked subnets define
client CIDRs). A scoped member is served only to clients whose
resolver source IP matches that scope; a member with no scope stays a
**default** target served to everyone (the current behaviour).

Mechanism — synthesized BIND9 views
-----------------------------------
The natural BIND9 primitive is a ``view { match-clients … }`` block (a
"geo view" == a view with a client-subnet match list). This module
computes, per DNS server group, the set of geo views implied by the
group's pool members plus the mapping of each scoped member to its geo
view. The bundle builders (``agent_config`` live path + ``config_bundle``
dataclass path) consume this to:

* render one synthesized view per distinct scope,
* **place the geo views BEFORE the operator split-horizon views** in
  the rendered ``named.conf``. BIND evaluates ``view`` blocks
  top-to-bottom, first-match-wins, so a geo-CIDR client must reach its
  geo view *before* any broad/catch-all operator view (an "internal"
  view with ``match-clients 10.0.0.0/8``, or any ``any``/empty-match
  view) that would otherwise swallow the query first and strip the geo
  member. Geo scopes are the more-specific match, so geo-first is the
  most-specific-match-first ordering in the common case. (Full
  generality — sorting each geo view relative to each operator view by
  match-set breadth — is out of scope; the caveat is a narrow operator
  view (e.g. a single ``/32`` management host) that a broader geo view
  would now shadow. Split the geo scope or drop the overlap if that
  bites.)
* append a catch-all ``spatium-geo-default`` view (``match-clients {
  any; };``) LAST so a client matching no specific geo view *and* no
  operator view still resolves,
* scope each geo-member's rendered ``DNSRecord`` into its geo view
  only, while **default** members (and every non-pool record) render as
  *shared* records visible in every view — so a client from CIDR X gets
  ``{geo members for X} ∪ {default members}`` and a client matching no
  geo CIDR gets ``{default members}``.

No-blackhole fallback
---------------------
A pool where **every** member is geo-scoped (a natural "each site
serves its own region, no global fallback" config) has no default
members, so a client matching no geo CIDR would otherwise get an empty
rrset (NODATA) for a name that *does* have healthy targets. To avoid
that, an all-geo pool's members are ALSO rendered into the non-geo
views (the operator views + the ``spatium-geo-default`` catch-all) as a
union fallback — ``records_for_view`` treats them like default members
outside their own geo view. Pools that DO have at least one unscoped
member keep the strict behaviour (geo members only in their geo view).
Net: a healthy name never blackholes.

Health-check gating is unchanged and composes cleanly: the reconciler
(``pool_apply``) still only materialises records for healthy + enabled
members, so a geo view never advertises an unhealthy local target.

No ``DNSView`` / ``DNSAcl`` rows are persisted — geo views are a pure
render-time concern, kept out of the operator-managed split-horizon
view catalog so the two features don't collide in the admin UI.

Source-IP semantics (v1) and the ECS stretch goal
--------------------------------------------------
v1 keys purely on the **resolver source IP** — i.e. the address BIND
sees the query coming from. When a recursive resolver sits between the
end client and this authoritative server (the common public-internet
case), that source IP is the *resolver's*, not the end client's, so
steering follows the resolver's location. **EDNS Client Subnet (ECS,
RFC 7871)** is the future accuracy improvement: it carries a prefix of
the real client's address so the authoritative server can steer on the
client rather than the resolver. ECS is deliberately **not implemented
here** — wiring it needs match-clients driven off the ECS option
(``ecs-zones`` / a resolver that forwards ECS) rather than the TCP/UDP
source address, and is tracked as a stretch goal.

TTL-race caveat
---------------
As with all DNS-based steering this is subject to the pool TTL cache
window (see ``DNSPool`` docstring + the Pools UI banner): a client that
already cached an answer keeps using it until the TTL expires, even if
it later crosses into a different geo scope. Keep the pool TTL short.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSPool, DNSPoolMember, DNSRecord
from app.models.ipam import Subnet

# The catch-all view served to clients matching no specific geo scope
# and no operator view. Rendered LAST with ``match-clients { any; }`` so
# a specific geo view (rendered first) wins under BIND's first-match-wins
# view evaluation.
GEO_DEFAULT_VIEW = "spatium-geo-default"


@dataclass(frozen=True)
class GeoView:
    """One synthesized geo view — a name + the client CIDRs it matches."""

    name: str
    match_clients: tuple[str, ...]


@dataclass
class GeoSteering:
    """Result of resolving a group's pool-member serving scopes.

    ``views`` are the specific geo views (excluding the catch-all;
    consumers append that). ``member_view`` maps a scoped member's id
    (str) to its geo view name — members absent from the map are
    default targets (shared, served everywhere).

    ``default_fallback_members`` are the ids of geo-scoped members that
    belong to an **all-geo pool** (a pool with no unscoped/default
    member). They render in their own geo view AND in every non-geo
    view (operator views + the catch-all) so a client matching no geo
    CIDR still resolves to a healthy target instead of getting NODATA.
    """

    views: list[GeoView] = field(default_factory=list)
    member_view: dict[str, str] = field(default_factory=dict)
    default_fallback_members: set[str] = field(default_factory=set)

    @property
    def active(self) -> bool:
        return bool(self.views)


def _normalise_cidr(raw: str) -> str | None:
    """Return a canonical CIDR string, or None if unparseable."""
    s = (raw or "").strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        return None


async def _site_cidrs(db: AsyncSession, site_ids: set) -> dict[object, frozenset[str]]:
    """Map each Site id → the set of CIDRs of its linked (live) subnets."""
    if not site_ids:
        return {}
    # The default ORM query filter injects ``deleted_at IS NULL`` (see
    # ``SoftDeleteMixin``), so soft-deleted subnets are excluded here
    # without an explicit predicate.
    rows = (
        await db.execute(select(Subnet.site_id, Subnet.network).where(Subnet.site_id.in_(site_ids)))
    ).all()
    out: dict[object, set[str]] = {}
    for site_id, network in rows:
        norm = _normalise_cidr(str(network))
        if norm is not None:
            out.setdefault(site_id, set()).add(norm)
    return {k: frozenset(v) for k, v in out.items()}


def _member_scope(
    member: DNSPoolMember, site_cidrs: dict[object, frozenset[str]]
) -> frozenset[str]:
    """Resolve a member's effective serving scope (UNION of the two sources)."""
    cidrs: set[str] = set()
    for raw in member.serving_cidrs or []:
        norm = _normalise_cidr(str(raw))
        if norm is not None:
            cidrs.add(norm)
    if member.site_id is not None:
        cidrs |= set(site_cidrs.get(member.site_id, frozenset()))
    return frozenset(cidrs)


async def build_geo_steering(db: AsyncSession, group_id) -> GeoSteering:
    """Resolve the geo-steering plan for one DNS server group.

    Groups members by their resolved (canonical, sorted) CIDR scope so
    two members serving the same set of client subnets share one geo
    view. View names are ``spatium-geo-1 … spatium-geo-N``, assigned in
    a deterministic order (sorted by the scope's CIDR tuple) so the
    rendered config — and therefore the bundle ETag — is stable across
    rebuilds.
    """
    pools = (await db.execute(select(DNSPool).where(DNSPool.group_id == group_id))).scalars().all()

    site_ids: set = set()
    for p in pools:
        for m in p.members or []:
            if m.site_id is not None:
                site_ids.add(m.site_id)
    site_cidrs = await _site_cidrs(db, site_ids)

    # scope tuple -> member ids
    scope_to_members: dict[tuple[str, ...], list[str]] = {}
    # member ids of all-geo pools (no unscoped member) — served as a
    # union fallback into the non-geo views so a name never blackholes.
    fallback_members: set[str] = set()
    for p in pools:
        scoped_ids: list[str] = []
        has_default = False
        for m in p.members or []:
            scope = _member_scope(m, site_cidrs)
            if not scope:
                has_default = True  # unscoped → served everywhere already
                continue
            key = tuple(sorted(scope))
            scope_to_members.setdefault(key, []).append(str(m.id))
            scoped_ids.append(str(m.id))
        # A pool whose every member is geo-scoped has no default target;
        # its scoped members must also reach clients matching no geo CIDR.
        if scoped_ids and not has_default:
            fallback_members.update(scoped_ids)

    steering = GeoSteering(default_fallback_members=fallback_members)
    # Deterministic view numbering by sorted scope key.
    for idx, key in enumerate(sorted(scope_to_members.keys()), start=1):
        name = f"spatium-geo-{idx}"
        steering.views.append(GeoView(name=name, match_clients=key))
        for member_id in scope_to_members[key]:
            steering.member_view[member_id] = name
    return steering


def build_view_descriptors(ordered_views: list, geo: GeoSteering) -> list[dict[str, Any]]:
    """Unified, ordered view descriptor list for the bundle builders.

    Render order (== BIND first-match-wins evaluation order) is:

    1. synthesized geo views (issue #530) — FIRST, so a geo-CIDR client
       hits its geo view before any broad/catch-all operator view (an
       "internal" view matching ``10.0.0.0/8``, or any ``any``/empty
       match) that would otherwise swallow the query and strip the geo
       member (most-specific-match-first in the common case; see module
       docstring for the narrow-operator-view caveat),
    2. operator split-horizon views (issue #24), preserving their
       relative order,
    3. the ``spatium-geo-default`` catch-all (``match-clients { any; }``)
       LAST so a client matching no specific geo view *and* no operator
       view still resolves.

    ``order`` is assigned sequentially to reflect that render order (it
    is informational — the bundle builders render views in list order).
    Each descriptor carries ``kind`` ∈ {operator, geo, default}.
    Operator descriptors keep the ORM view's ``id`` (a UUID);
    synthesized ones carry ``id=None``.
    """
    descs: list[dict[str, Any]] = []
    order = 0
    # 1. Geo views first — most-specific client-CIDR match wins.
    if geo.active:
        for gv in geo.views:
            descs.append(
                {
                    "kind": "geo",
                    "id": None,
                    "name": gv.name,
                    "match_clients": tuple(gv.match_clients),
                    "match_destinations": (),
                    "recursion": True,
                    "order": order,
                    "allow_query": None,
                    "allow_query_cache": None,
                }
            )
            order += 1
    # 2. Operator split-horizon views, in their own relative order.
    for v in ordered_views:
        descs.append(
            {
                "kind": "operator",
                "id": v.id,
                "name": v.name,
                "match_clients": tuple(getattr(v, "match_clients", None) or ("any",)),
                "match_destinations": tuple(getattr(v, "match_destinations", None) or ()),
                "recursion": bool(getattr(v, "recursion", True)),
                "order": order,
                "allow_query": getattr(v, "allow_query", None),
                "allow_query_cache": getattr(v, "allow_query_cache", None),
            }
        )
        order += 1
    # 3. Catch-all geo-default LAST.
    if geo.active:
        descs.append(
            {
                "kind": "default",
                "id": None,
                "name": GEO_DEFAULT_VIEW,
                "match_clients": ("any",),
                "match_destinations": (),
                "recursion": True,
                "order": order,
                "allow_query": None,
                "allow_query_cache": None,
            }
        )
    return descs


def view_renders_zone(view_desc: dict[str, Any], operator_target_ids: set[Any]) -> bool:
    """True when ``view_desc`` carries a copy of a zone scoped to ``operator_target_ids``.

    ``operator_target_ids`` is the zone's own pinned ``view_id`` plus the view
    of every view-scoped record in it (issue #24). An operator view renders
    the zone unless that set is non-empty and names only OTHER operator
    views; geo views and the catch-all always render it (issue #530).

    The one rule both the bundle builder (which zone copies a view gets) and
    the transfer-key resolver (which view the control plane reads a zone
    from, #920) follow, so the view a transfer asks for always holds the zone.
    """
    return not (
        view_desc["kind"] == "operator"
        and bool(operator_target_ids)
        and view_desc["id"] not in operator_target_ids
    )


def records_for_view(
    rec_rows: list[DNSRecord], view_desc: dict[str, Any], geo: GeoSteering
) -> list[DNSRecord]:
    """Filter a zone's records to what one view should serve.

    Composes operator split-horizon scoping (``DNSRecord.view_id``;
    issue #24) with geo steering (issue #530):

    * a geo-scoped pool-member record renders in its own geo view; if
      its pool is **all-geo** (no unscoped member — see
      ``GeoSteering.default_fallback_members``) it ALSO renders in the
      non-geo views (operator views + catch-all) so a client matching
      no geo CIDR still gets a healthy answer instead of NODATA;
    * an operator-scoped record renders ONLY in its operator view;
    * everything else (``view_id IS NULL`` + not geo-scoped) is a
      *shared* / default record rendered in every view — so a geo view
      serves ``{geo members} ∪ {default members}`` and the catch-all
      serves ``{default members}`` (plus the all-geo fallback above).

    Health-check gating is already applied upstream: the reconciler only
    materialises records for healthy + enabled members, so this never
    surfaces an unhealthy target.
    """
    out: list[DNSRecord] = []
    for r in rec_rows:
        mid = str(r.pool_member_id) if r.pool_member_id else None
        gview = geo.member_view.get(mid) if mid else None
        if gview is not None:
            if view_desc["name"] == gview:
                out.append(r)  # its own geo view
            elif view_desc["kind"] != "geo" and mid in geo.default_fallback_members:
                # All-geo pool: serve into the operator + catch-all views
                # too so a no-geo-match client doesn't blackhole a name
                # that has healthy targets.
                out.append(r)
            continue
        if r.view_id is not None:
            if view_desc["kind"] == "operator" and r.view_id == view_desc["id"]:
                out.append(r)
            continue
        out.append(r)
    return out


__all__ = [
    "GEO_DEFAULT_VIEW",
    "GeoSteering",
    "GeoView",
    "build_geo_steering",
    "build_view_descriptors",
    "records_for_view",
]
