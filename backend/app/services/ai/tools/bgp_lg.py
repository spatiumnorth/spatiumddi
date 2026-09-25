"""Operator Copilot tools — BGP Looking Glass (issue #566).

Read-only surface over the ``bgp_lg_route`` / ``bgp_lg_peer`` /
``looking_glass_collector`` tables the collector daemon maintains via its
register/heartbeat/routes-push agent chain, plus one ``propose_*`` write to
create a new peer session. All tagged ``module="network.looking_glass"`` so
they disappear when the feature module is off.

Reads default-enabled — no secrets ever surface (``md5_password_encrypted``
is never returned, only implied by the peer row's own read surface); the
write proposal defaults OFF like every other ``propose_*`` tool, since
creating a peer is a config mutation that touches the operator's live BGP
sessions on the collector's next apply.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.bgp_looking_glass import BGPLGPeer, BGPLGRoute, LookingGlassCollector
from app.services.ai.tools.base import register_tool
from app.services.looking_glass.as_path_query import as_path_regexp_clause

_MODULE = "network.looking_glass"


def _route_dict(row: BGPLGRoute) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "peer_id": str(row.peer_id),
        "prefix": str(row.prefix),
        "origin_asn": int(row.origin_asn) if row.origin_asn is not None else None,
        "as_path": list(row.as_path or []),
        "next_hop": str(row.next_hop),
        "local_pref": row.local_pref,
        "med": row.med,
        "communities": list(row.communities or []),
        "large_communities": list(row.large_communities or []),
        "ext_communities": list(row.ext_communities or []),
        "route_distinguisher": row.route_distinguisher,
        "rpki_status": row.rpki_status,
        "is_best": row.is_best,
        "matched_block_id": str(row.matched_block_id) if row.matched_block_id else None,
        "matched_subnet_id": str(row.matched_subnet_id) if row.matched_subnet_id else None,
        "matched_space_id": str(row.matched_space_id) if row.matched_space_id else None,
        "matched_asn_id": str(row.matched_asn_id) if row.matched_asn_id else None,
        "matched_vrf_id": str(row.matched_vrf_id) if row.matched_vrf_id else None,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "withdrawn_at": row.withdrawn_at.isoformat() if row.withdrawn_at else None,
        "flap_count": row.flap_count,
    }


def _session_dict(peer: BGPLGPeer, collector_name: str | None) -> dict[str, Any]:
    return {
        "id": str(peer.id),
        "name": peer.name,
        "collector_id": str(peer.collector_id),
        "collector_name": collector_name,
        "peer_asn": int(peer.peer_asn),
        "peer_address": str(peer.peer_address),
        "session_state": peer.session_state,
        "uptime_started_at": (
            peer.uptime_started_at.isoformat() if peer.uptime_started_at else None
        ),
        "prefixes_received": peer.prefixes_received,
        "prefixes_accepted": peer.prefixes_accepted,
        "last_state_change": (
            peer.last_state_change.isoformat() if peer.last_state_change else None
        ),
        "last_flap_at": peer.last_flap_at.isoformat() if peer.last_flap_at else None,
        "rpki_invalid_count": peer.rpki_invalid_count,
        "enabled": peer.enabled,
    }


# ── find_bgp_routes ──────────────────────────────────────────────────


class FindBgpRoutesArgs(BaseModel):
    peer_id: UUID | None = Field(default=None, description="Restrict to one Looking Glass peer.")
    prefix: str | None = Field(
        default=None, description="Exact prefix match, e.g. '10.0.0.0/24' or '2001:db8::/32'."
    )
    origin_asn: int | None = Field(default=None, description="Filter to this origin AS number.")
    community: str | None = Field(
        default=None,
        description=(
            "Wire-form community string (e.g. '65000:100') to match against "
            "the route's standard/large/extended community lists."
        ),
    )
    as_path_regexp: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "AS-path regex (Cisco/Juniper '_' boundary convention) matched "
            "against the space-joined AS path, e.g. '_65001_'."
        ),
    )
    rpki_status: str | None = Field(
        default=None, description="'valid' | 'invalid' | 'unknown' (from ROA coverage at ingest)."
    )
    best_path_only: bool = Field(default=False, description="Only the best path per prefix.")
    include_withdrawn: bool = Field(
        default=False, description="Include routes that have been withdrawn from the RIB."
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_bgp_routes",
    description=(
        "List routes learned by a BGP Looking Glass collector — the live "
        "Adj-RIB-In mirrored from the operator's own routers (distinct from "
        "the public-table hijack monitor). Filter by peer, prefix, origin "
        "ASN, community, or RPKI status. Each row carries the AS path, "
        "next-hop, local-pref/MED, communities, and RPKI validity computed "
        "at ingest. Use for 'show ip bgp' style questions like 'what routes "
        "do we have for 10.0.0.0/8?' or 'any RPKI-invalid routes right now?'."
    ),
    args_model=FindBgpRoutesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_bgp_routes(db: AsyncSession, user: User, args: FindBgpRoutesArgs) -> dict[str, Any]:
    stmt = select(BGPLGRoute)
    if args.peer_id is not None:
        stmt = stmt.where(BGPLGRoute.peer_id == args.peer_id)
    if args.prefix:
        try:
            normalized = str(ipaddress.ip_network(args.prefix, strict=False))
        except ValueError:
            return {"routes": [], "count": 0, "note": f"invalid prefix {args.prefix!r}"}
        stmt = stmt.where(BGPLGRoute.prefix == normalized)
    if args.origin_asn is not None:
        stmt = stmt.where(BGPLGRoute.origin_asn == args.origin_asn)
    if args.community:
        stmt = stmt.where(
            or_(
                BGPLGRoute.communities.contains([args.community]),
                BGPLGRoute.large_communities.contains([args.community]),
                BGPLGRoute.ext_communities.contains([args.community]),
            )
        )
    if args.as_path_regexp:
        try:
            stmt = stmt.where(as_path_regexp_clause(args.as_path_regexp))
        except re.error:
            return {
                "routes": [],
                "count": 0,
                "note": f"invalid as_path_regexp {args.as_path_regexp!r}",
            }
    if args.rpki_status:
        stmt = stmt.where(BGPLGRoute.rpki_status == args.rpki_status)
    if args.best_path_only:
        stmt = stmt.where(BGPLGRoute.is_best.is_(True))
    if not args.include_withdrawn:
        stmt = stmt.where(BGPLGRoute.withdrawn_at.is_(None))
    stmt = stmt.order_by(BGPLGRoute.prefix).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"routes": [_route_dict(r) for r in rows], "count": len(rows)}


# ── count_bgp_routes ─────────────────────────────────────────────────


class CountBgpRoutesArgs(BaseModel):
    peer_id: UUID | None = Field(default=None, description="Restrict to one Looking Glass peer.")
    include_withdrawn: bool = Field(default=False)


@register_tool(
    name="count_bgp_routes",
    description=(
        "Count routes in the BGP Looking Glass RIB, broken down by RPKI "
        "status and by peer. Use for a quick 'how big is our learned "
        "routing table?' or 'how many invalid routes per peer?' health check."
    ),
    args_model=CountBgpRoutesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_bgp_routes(
    db: AsyncSession, user: User, args: CountBgpRoutesArgs
) -> dict[str, Any]:
    stmt = (
        select(BGPLGRoute.peer_id, BGPLGPeer.name, BGPLGRoute.rpki_status, func.count())
        .select_from(BGPLGRoute)
        .join(BGPLGPeer, BGPLGRoute.peer_id == BGPLGPeer.id)
        .group_by(BGPLGRoute.peer_id, BGPLGPeer.name, BGPLGRoute.rpki_status)
    )
    if args.peer_id is not None:
        stmt = stmt.where(BGPLGRoute.peer_id == args.peer_id)
    if not args.include_withdrawn:
        stmt = stmt.where(BGPLGRoute.withdrawn_at.is_(None))
    rows = (await db.execute(stmt)).all()
    total = 0
    by_rpki: dict[str, int] = {}
    by_peer: dict[str, dict[str, Any]] = {}
    for peer_id, peer_name, rpki_status, count in rows:
        total += count
        by_rpki[rpki_status] = by_rpki.get(rpki_status, 0) + count
        entry = by_peer.setdefault(str(peer_id), {"name": peer_name, "count": 0})
        entry["count"] += count
    return {"total": total, "by_rpki_status": by_rpki, "by_peer": by_peer}


# ── get_bgp_route ────────────────────────────────────────────────────


class GetBgpRouteArgs(BaseModel):
    prefix: str = Field(description="Exact prefix, e.g. '10.0.0.0/24' or '2001:db8::/32'.")
    include_withdrawn: bool = Field(
        default=False, description="Include paths that have since been withdrawn."
    )


@register_tool(
    name="get_bgp_route",
    description=(
        "Get every path a BGP Looking Glass collector has learned for one "
        "exact prefix — the 'show ip bgp <prefix>' detail view. Returns "
        "one entry per peer advertising the prefix, each with its own AS "
        "path, next-hop, and RPKI status."
    ),
    args_model=GetBgpRouteArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def get_bgp_route(db: AsyncSession, user: User, args: GetBgpRouteArgs) -> dict[str, Any]:
    try:
        normalized = str(ipaddress.ip_network(args.prefix, strict=False))
    except ValueError:
        return {"prefix": args.prefix, "paths": [], "count": 0, "note": "invalid prefix"}

    stmt = (
        select(BGPLGRoute, BGPLGPeer.name)
        .join(BGPLGPeer, BGPLGRoute.peer_id == BGPLGPeer.id)
        .where(BGPLGRoute.prefix == normalized)
    )
    if not args.include_withdrawn:
        stmt = stmt.where(BGPLGRoute.withdrawn_at.is_(None))
    stmt = stmt.order_by(BGPLGRoute.is_best.desc(), BGPLGRoute.last_seen_at.desc())
    rows = (await db.execute(stmt)).all()
    if not rows:
        return {
            "prefix": normalized,
            "paths": [],
            "count": 0,
            "note": "not found in the current RIB",
        }
    paths = []
    for route, peer_name in rows:
        d = _route_dict(route)
        d["peer_name"] = peer_name
        paths.append(d)
    return {"prefix": normalized, "paths": paths, "count": len(paths)}


# ── find_bgp_route_for_ip ────────────────────────────────────────────


class FindBgpRouteForIpArgs(BaseModel):
    ip: str = Field(description="A single IP address to reverse-lookup against the learned RIB.")


@register_tool(
    name="find_bgp_route_for_ip",
    description=(
        "Reverse longest-prefix-match lookup: given a single IP address, "
        "find the most-specific active BGP Looking Glass route that covers "
        "it, returning the covering prefix, origin ASN, and next-hop. Use "
        "for 'what route covers 8.8.8.8 in our table?' style questions."
    ),
    args_model=FindBgpRouteForIpArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_bgp_route_for_ip(
    db: AsyncSession, user: User, args: FindBgpRouteForIpArgs
) -> dict[str, Any]:
    from app.services.looking_glass.reachability import find_covering_routes  # noqa: PLC0415

    routes = await find_covering_routes(db, args.ip)
    if not routes:
        try:
            ipaddress.ip_address(args.ip)
            note = "no covering route in the current RIB"
        except ValueError:
            note = "not a valid IP address"
        return {"ip": args.ip, "found": False, "note": note}

    out = _route_dict(routes[0])
    out["ip"] = args.ip
    out["found"] = True
    out["alternate_paths_count"] = len(routes) - 1
    return out


# ── find_bgp_lg_sessions ─────────────────────────────────────────────


class FindLgSessionsArgs(BaseModel):
    collector_id: UUID | None = Field(default=None, description="Restrict to one collector.")
    session_state: str | None = Field(
        default=None,
        description="Filter by state: idle/connect/active/opensent/openconfirm/established.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_bgp_lg_sessions",
    description=(
        "List BGP Looking Glass peer sessions with their current state "
        "(established/idle/etc.), uptime, and received/accepted prefix "
        "counts — the Sessions-tab feed. Use for 'which BGP sessions are "
        "down?' or 'how many prefixes is each peer sending us?'."
    ),
    args_model=FindLgSessionsArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_bgp_lg_sessions(
    db: AsyncSession, user: User, args: FindLgSessionsArgs
) -> dict[str, Any]:
    stmt = select(BGPLGPeer, LookingGlassCollector.name).join(
        LookingGlassCollector, BGPLGPeer.collector_id == LookingGlassCollector.id
    )
    if args.collector_id is not None:
        stmt = stmt.where(BGPLGPeer.collector_id == args.collector_id)
    if args.session_state:
        stmt = stmt.where(BGPLGPeer.session_state == args.session_state)
    stmt = stmt.order_by(BGPLGPeer.name).limit(args.limit)
    rows = (await db.execute(stmt)).all()
    return {
        "sessions": [_session_dict(peer, collector_name) for peer, collector_name in rows],
        "count": len(rows),
    }


# ── find_vrf_learned_routes ──────────────────────────────────────────


class FindVrfLearnedRoutesArgs(BaseModel):
    vrf_id: UUID = Field(description="The VRF to find learned VPNv4/VPNv6 routes for.")
    include_withdrawn: bool = Field(default=False)
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_vrf_learned_routes",
    description=(
        "List BGP Looking Glass routes matched to a VRF by Route-Target "
        "cross-check — the routes whose "
        "extended-community route target fell in the VRF's import/export "
        "lists at ingest (falling back to whichever route just happens to "
        "fall under the VRF's IPAM block/space when there's no RT hit). "
        "Use for 'what routes has this VRF learned?' or 'is this VRF "
        "actually receiving any VPN routes?' questions."
    ),
    args_model=FindVrfLearnedRoutesArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_vrf_learned_routes(
    db: AsyncSession, user: User, args: FindVrfLearnedRoutesArgs
) -> dict[str, Any]:
    stmt = select(BGPLGRoute).where(BGPLGRoute.matched_vrf_id == args.vrf_id)
    if not args.include_withdrawn:
        stmt = stmt.where(BGPLGRoute.withdrawn_at.is_(None))
    stmt = stmt.order_by(BGPLGRoute.prefix).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"routes": [_route_dict(r) for r in rows], "count": len(rows)}


# ── find_multicast_bgp_reachability ───────────────────────────────────


class FindMulticastBgpReachabilityArgs(BaseModel):
    """No filters — the underlying tables (PIM domains, multicast groups)
    are small; this is a whole-fleet snapshot."""


@register_tool(
    name="find_multicast_bgp_reachability",
    description=(
        "Cross-reference multicast PIM domains' rendezvous-point addresses "
        "and multicast groups' producer source subnets against the BGP "
        "Looking Glass learned RIB — is the RP / "
        "source actually reachable per the current routing table? Use for "
        "'is our multicast RP reachable?' or 'is this source subnet "
        "actually being routed?' sanity checks."
    ),
    args_model=FindMulticastBgpReachabilityArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_multicast_bgp_reachability(
    db: AsyncSession, user: User, args: FindMulticastBgpReachabilityArgs
) -> dict[str, Any]:
    from app.services.looking_glass.reachability import multicast_bgp_reachability  # noqa: PLC0415

    result = await multicast_bgp_reachability(db)
    return {
        "domains": [
            {
                "domain_id": str(d.domain_id),
                "domain_name": d.domain_name,
                "rp_address": d.rp_address,
                "covering_route": _route_dict(d.covering_route) if d.covering_route else None,
                "reachable": d.covering_route is not None,
            }
            for d in result.domains
        ],
        "groups": [
            {
                "group_id": str(g.group_id),
                "group_name": g.group_name,
                "group_address": g.group_address,
                "source_subnet": g.source_subnet,
                "covering_route": _route_dict(g.covering_route) if g.covering_route else None,
                "reachable": g.covering_route is not None,
            }
            for g in result.groups
        ],
    }


# ── propose_create_lg_peer ───────────────────────────────────────────


class CreateLgPeerArgs(BaseModel):
    collector_id: UUID = Field(description="The looking_glass_collector this session runs on.")
    name: str = Field(description="Operator-facing label for the peer session.")
    local_asn: int = Field(description="The collector's own AS number for this session.")
    peer_asn: int = Field(description="The remote router's AS number.")
    peer_address: str = Field(description="The remote router's IP address (v4 or v6).")
    peer_router_id: UUID | None = Field(
        default=None, description="Optional link to an existing network_device row."
    )
    address_families: list[str] | None = Field(
        default=None,
        description="AFI/SAFIs to negotiate. Defaults to ['ipv4-unicast'].",
    )
    max_prefixes: int | None = Field(
        default=None, description="Hard prefix-limit safety cap. Defaults to 10000."
    )
    md5_password: str | None = Field(
        default=None, description="Optional TCP-MD5 session password (Fernet-encrypted at rest)."
    )
    import_filter: dict[str, Any] | None = Field(
        default=None, description="Route acceptance scope. Defaults to {'mode': 'accept_all'}."
    )
    enabled: bool = Field(default=True)
    description: str = Field(default="", description="Free-form note.")


@register_tool(
    name="propose_create_lg_peer",
    description=(
        "Prepare a proposal to create a new BGP Looking Glass peer session "
        "(a receive-only BGP session on a collector — SpatiumDDI never "
        "advertises routes back to the peer). The operator must click "
        "Apply in the chat drawer to commit. Returns a kind='proposal' "
        "payload — surface the preview and wait for their decision."
    ),
    args_model=CreateLgPeerArgs,
    writes=False,  # propose is read-only; the apply endpoint is the write.
    category="network",
    module=_MODULE,
    default_enabled=False,
)
async def propose_create_lg_peer(
    db: AsyncSession, user: User, args: CreateLgPeerArgs
) -> dict[str, Any]:
    from app.services.ai.tools.proposals import _propose_via  # noqa: PLC0415

    return await _propose_via(db=db, user=user, operation_name="create_lg_peer", args=args)
