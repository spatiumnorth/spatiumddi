"""Tier 1 network-modeling read tools for the Operator Copilot.

Surfaces the recently-shipped ASN / VRF / Domain / Circuit /
NetworkService / OverlayNetwork data model to the LLM. Each tool
returns operator-readable summaries (no UUID-only payloads).

All tools are read-only and respect ``deleted_at IS NULL`` for the
soft-deletable entities (Circuit / NetworkService / OverlayNetwork).
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asn import ASN, ASNRpkiRoa, BGPPeering
from app.models.auth import User
from app.models.circuit import Circuit
from app.models.domain import Domain
from app.models.network_service import NetworkService, NetworkServiceResource
from app.models.overlay import (
    ApplicationCategory,
    OverlayNetwork,
    OverlaySite,
    RoutingPolicy,
)
from app.models.ownership import Site
from app.models.vrf import VRF
from app.services.ai.tools.base import register_tool


def _try_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return None


# ── list_asns ─────────────────────────────────────────────────────────


class ListASNsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on ASN name, holder org, or description.",
    )
    kind: Literal["public", "private"] | None = Field(
        default=None,
        description="Filter by ASN kind (public 1-64511 / private 64512+).",
    )
    registry: str | None = Field(
        default=None,
        description="Filter by RIR: arin / ripe / apnic / lacnic / afrinic / iana.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_asns",
    permission=("read", "manage_asns"),
    module="network.asn",
    description=(
        "List Autonomous Systems tracked in SpatiumDDI. Use for "
        "questions about AS numbers, RDAP holder org, registry / RIR, "
        "or BGP peering relationships. Each row carries number, "
        "name, holder_org, kind, registry, whois_state, and customer "
        "/ provider linkage. Filterable by name / org substring, kind, "
        "or RIR."
    ),
    args_model=ListASNsArgs,
    category="network",
)
async def list_asns(db: AsyncSession, user: User, args: ListASNsArgs) -> list[dict[str, Any]]:
    stmt = select(ASN)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(ASN.name).like(like),
                func.lower(ASN.holder_org).like(like),
                func.lower(ASN.description).like(like),
            )
        )
    if args.kind:
        stmt = stmt.where(ASN.kind == args.kind)
    if args.registry:
        stmt = stmt.where(ASN.registry == args.registry.lower())
    stmt = stmt.order_by(ASN.number.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "number": r.number,
            "name": r.name,
            "description": r.description,
            "kind": r.kind,
            "registry": r.registry,
            "holder_org": r.holder_org,
            "whois_state": r.whois_state,
            "customer_id": str(r.customer_id) if r.customer_id else None,
            "provider_id": str(r.provider_id) if r.provider_id else None,
        }
        for r in rows
    ]


# ── get_asn ───────────────────────────────────────────────────────────


class GetASNArgs(BaseModel):
    asn_ref: str = Field(
        description=(
            "AS number (as a string, e.g. '15169') or the row UUID. "
            "Numeric input is matched against the ``number`` column "
            "first; falls back to UUID parse."
        ),
    )


@register_tool(
    name="get_asn",
    permission=("read", "manage_asns"),
    module="network.asn",
    description=(
        "Return full detail for one AS: number, name, holder_org, "
        "RPKI ROA count, BGP peering count, customer / provider "
        "ownership, latest WHOIS state. Use after ``list_asns`` "
        "narrows down to a candidate, or directly with the AS number."
    ),
    args_model=GetASNArgs,
    category="network",
)
async def get_asn(db: AsyncSession, user: User, args: GetASNArgs) -> dict[str, Any]:
    ref = args.asn_ref.strip()
    row: ASN | None = None
    # Try numeric AS number first; fall back to UUID.
    try:
        n = int(ref)
        row = (await db.execute(select(ASN).where(ASN.number == n))).scalar_one_or_none()
    except ValueError:
        pass
    if row is None:
        u = _try_uuid(ref)
        if u is not None:
            row = await db.get(ASN, u)
    if row is None:
        return {"error": f"No ASN matched {args.asn_ref!r}."}

    roa_count = int(
        await db.scalar(
            select(func.count()).select_from(ASNRpkiRoa).where(ASNRpkiRoa.asn_id == row.id)
        )
        or 0
    )
    peer_count = int(
        await db.scalar(
            select(func.count())
            .select_from(BGPPeering)
            .where(or_(BGPPeering.local_asn_id == row.id, BGPPeering.peer_asn_id == row.id))
        )
        or 0
    )
    return {
        "id": str(row.id),
        "number": row.number,
        "name": row.name,
        "description": row.description,
        "kind": row.kind,
        "registry": row.registry,
        "holder_org": row.holder_org,
        "whois_state": row.whois_state,
        "rpki_roa_count": roa_count,
        "bgp_peering_count": peer_count,
        "customer_id": str(row.customer_id) if row.customer_id else None,
        "provider_id": str(row.provider_id) if row.provider_id else None,
        "tags": row.tags or {},
    }


# ── list_domains ──────────────────────────────────────────────────────


class ListDomainsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on domain name or registrant org.",
    )
    expiring_within_days: int | None = Field(
        default=None,
        ge=1,
        le=730,
        description="Filter to domains whose ``expires_at`` is within this many days from now.",
    )
    nameserver_drift_only: bool | None = Field(
        default=None,
        description="When true, only return domains whose actual_nameservers differ from expected.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_domains",
    permission=("read", "manage_domains"),
    description=(
        "List domain-registration rows. Distinct from DNS zones — "
        "this is the *registry* side of a name (registrar, expiry, "
        "DNSSEC, nameserver drift). Filterable by name / registrant "
        "substring, expiring-soon window, or nameserver drift. Use "
        "for questions about who registered example.com, when it "
        "expires, or which domains are about to lapse."
    ),
    args_model=ListDomainsArgs,
    category="network",
)
async def list_domains(db: AsyncSession, user: User, args: ListDomainsArgs) -> list[dict[str, Any]]:
    stmt = select(Domain)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Domain.name).like(like),
                func.lower(Domain.registrant_org).like(like),
            )
        )
    if args.expiring_within_days is not None:
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        cutoff = now + timedelta(days=args.expiring_within_days)
        stmt = stmt.where(Domain.expires_at.isnot(None)).where(Domain.expires_at <= cutoff)
    if args.nameserver_drift_only:
        stmt = stmt.where(Domain.nameserver_drift.is_(True))
    stmt = stmt.order_by(Domain.expires_at.asc().nullslast()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "registrar": r.registrar,
            "registrant_org": r.registrant_org,
            "registered_at": r.registered_at.isoformat() if r.registered_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "last_renewed_at": r.last_renewed_at.isoformat() if r.last_renewed_at else None,
            "dnssec_signed": r.dnssec_signed,
            "nameserver_drift": r.nameserver_drift,
            "expected_nameservers": list(r.expected_nameservers or []),
            "actual_nameservers": list(r.actual_nameservers or []),
            "whois_state": r.whois_state,
            "customer_id": str(r.customer_id) if r.customer_id else None,
            "registrar_provider_id": (
                str(r.registrar_provider_id) if r.registrar_provider_id else None
            ),
        }
        for r in rows
    ]


# ── list_vrfs ─────────────────────────────────────────────────────────


class ListVRFsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on VRF name or description.",
    )
    asn_id: str | None = Field(
        default=None,
        description="Filter to VRFs linked to this ASN (UUID or number).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_vrfs",
    permission=("read", "vrf"),
    module="network.vrf",
    description=(
        "List VRFs (virtual routing/forwarding domains). Each row "
        "carries name, description, route_distinguisher, import / "
        "export route-targets, and optional ASN + customer linkage. "
        "Use for questions about RDs, RT lists, or which VRF a "
        "subnet belongs to."
    ),
    args_model=ListVRFsArgs,
    category="network",
)
async def list_vrfs(
    db: AsyncSession, user: User, args: ListVRFsArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    stmt = select(VRF)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(VRF.name).like(like),
                func.lower(VRF.description).like(like),
            )
        )
    if args.asn_id:
        u = _try_uuid(args.asn_id)
        if u is None:
            # Allow passing an AS number: resolve to UUID first.
            try:
                n = int(args.asn_id)
                row = (await db.execute(select(ASN).where(ASN.number == n))).scalar_one_or_none()
                u = row.id if row else None
            except ValueError:
                pass
        if u is None:
            return {
                "error": f"No ASN matched {args.asn_id!r}.",
                "hint": "Call list_asns or pass a valid AS number / UUID.",
            }
        stmt = stmt.where(VRF.asn_id == u)
    stmt = stmt.order_by(VRF.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "route_distinguisher": r.route_distinguisher,
            "import_targets": list(r.import_targets or []),
            "export_targets": list(r.export_targets or []),
            "asn_id": str(r.asn_id) if r.asn_id else None,
            "customer_id": str(r.customer_id) if r.customer_id else None,
        }
        for r in rows
    ]


# ── list_circuits ─────────────────────────────────────────────────────


class ListCircuitsArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on circuit name or carrier ckt_id.",
    )
    transport_class: (
        Literal[
            "mpls",
            "internet_broadband",
            "fiber_direct",
            "wavelength",
            "lte",
            "satellite",
            "direct_connect_aws",
            "express_route_azure",
            "interconnect_gcp",
        ]
        | None
    ) = Field(default=None, description="Filter by transport technology.")
    status: Literal["active", "pending", "suspended", "decom"] | None = Field(
        default=None,
        description="Filter by run state. ``decom`` is soft-deleted-but-restorable.",
    )
    customer_id: str | None = Field(default=None, description="Customer UUID filter.")
    provider_id: str | None = Field(default=None, description="Provider (carrier) UUID filter.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_circuits",
    permission=("read", "circuit"),
    module="network.circuit",
    description=(
        "List WAN circuits — carrier-supplied logical pipes. Each row "
        "includes name, carrier ckt_id, transport_class, "
        "asymmetric bandwidth (down/up Mbps), monthly_cost + currency, "
        "term dates, status, and a/z-end site + subnet endpoints. "
        "Use for questions about WAN topology, carrier inventory, "
        "term expiry, or cost roll-up."
    ),
    args_model=ListCircuitsArgs,
    category="network",
)
async def list_circuits(
    db: AsyncSession, user: User, args: ListCircuitsArgs
) -> list[dict[str, Any]]:
    stmt = select(Circuit).where(Circuit.deleted_at.is_(None))
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Circuit.name).like(like),
                func.lower(Circuit.ckt_id).like(like),
            )
        )
    if args.transport_class:
        stmt = stmt.where(Circuit.transport_class == args.transport_class)
    if args.status:
        stmt = stmt.where(Circuit.status == args.status)
    if args.customer_id:
        u = _try_uuid(args.customer_id)
        if u is not None:
            stmt = stmt.where(Circuit.customer_id == u)
    if args.provider_id:
        u = _try_uuid(args.provider_id)
        if u is not None:
            stmt = stmt.where(Circuit.provider_id == u)
    stmt = stmt.order_by(Circuit.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "ckt_id": r.ckt_id,
            "provider_id": str(r.provider_id) if r.provider_id else None,
            "customer_id": str(r.customer_id) if r.customer_id else None,
            "transport_class": r.transport_class,
            "bandwidth_mbps_down": r.bandwidth_mbps_down,
            "bandwidth_mbps_up": r.bandwidth_mbps_up,
            "monthly_cost": float(r.monthly_cost) if r.monthly_cost is not None else None,
            "currency": r.currency,
            "status": r.status,
            "term_start_date": r.term_start_date.isoformat() if r.term_start_date else None,
            "term_end_date": r.term_end_date.isoformat() if r.term_end_date else None,
            "a_end_site_id": str(r.a_end_site_id) if r.a_end_site_id else None,
            "z_end_site_id": str(r.z_end_site_id) if r.z_end_site_id else None,
            "a_end_subnet_id": str(r.a_end_subnet_id) if r.a_end_subnet_id else None,
            "z_end_subnet_id": str(r.z_end_subnet_id) if r.z_end_subnet_id else None,
        }
        for r in rows
    ]


# ── list_network_services ─────────────────────────────────────────────


class ListNetworkServicesArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on service name.",
    )
    kind: str | None = Field(
        default=None,
        description="Filter by kind: mpls_l3vpn / mpls_l2vpn / vpls / evpn / dia / hosted_dns / hosted_dhcp / sdwan / custom.",
    )
    customer_id: str | None = Field(default=None, description="Customer UUID filter.")
    status: Literal["active", "provisioning", "suspended", "decom"] | None = Field(
        default=None,
        description="Filter by service status.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_network_services",
    permission=("read", "network_service"),
    module="network.service",
    description=(
        "List service-catalog rows (issue #94). A NetworkService "
        "bundles VRF / Subnet / IPBlock / DNSZone / DHCPScope / "
        "Circuit / Site / OverlayNetwork into one customer "
        "deliverable. Each row carries name, kind, customer, status, "
        "term, monthly cost, and an attached-resource count. Use for "
        "operator questions like 'list MPLS services' or 'what's "
        "expiring in Q4'."
    ),
    args_model=ListNetworkServicesArgs,
    category="network",
)
async def list_network_services(
    db: AsyncSession, user: User, args: ListNetworkServicesArgs
) -> list[dict[str, Any]]:
    stmt = select(NetworkService).where(NetworkService.deleted_at.is_(None))
    if args.search:
        stmt = stmt.where(func.lower(NetworkService.name).like(f"%{args.search.lower()}%"))
    if args.kind:
        stmt = stmt.where(NetworkService.kind == args.kind)
    if args.customer_id:
        u = _try_uuid(args.customer_id)
        if u is not None:
            stmt = stmt.where(NetworkService.customer_id == u)
    if args.status:
        stmt = stmt.where(NetworkService.status == args.status)
    stmt = stmt.order_by(NetworkService.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()

    # Per-service resource count via a single grouped query.
    counts: dict[uuid.UUID, int] = {}
    if rows:
        cnt_rows = await db.execute(
            select(NetworkServiceResource.service_id, func.count())
            .where(NetworkServiceResource.service_id.in_([r.id for r in rows]))
            .group_by(NetworkServiceResource.service_id)
        )
        counts = {row[0]: row[1] for row in cnt_rows.all()}

    return [
        {
            "id": str(r.id),
            "name": r.name,
            "kind": r.kind,
            "customer_id": str(r.customer_id),
            "status": r.status,
            "sla_tier": r.sla_tier,
            "monthly_cost": float(r.monthly_cost_usd) if r.monthly_cost_usd is not None else None,
            "currency": r.currency,
            "term_start_date": r.term_start_date.isoformat() if r.term_start_date else None,
            "term_end_date": r.term_end_date.isoformat() if r.term_end_date else None,
            "resource_count": counts.get(r.id, 0),
        }
        for r in rows
    ]


# ── get_network_service_summary ───────────────────────────────────────


class GetServiceSummaryArgs(BaseModel):
    service_id: str = Field(description="UUID of the network service.")


@register_tool(
    name="get_network_service_summary",
    permission=("read", "network_service"),
    module="network.service",
    description=(
        "Full detail of a NetworkService: every attached resource by "
        "kind, plus the resource_count breakdown. Use after "
        "``list_network_services`` to drill into one row — answers "
        "'what's in the L3VPN' or 'which sites does service X cover'."
    ),
    args_model=GetServiceSummaryArgs,
    category="network",
)
async def get_network_service_summary(
    db: AsyncSession, user: User, args: GetServiceSummaryArgs
) -> dict[str, Any]:
    u = _try_uuid(args.service_id)
    if u is None:
        return {"error": f"service_id must be a UUID, got {args.service_id!r}."}
    svc = await db.get(NetworkService, u)
    if svc is None or svc.deleted_at is not None:
        return {"error": f"No active network service with id {args.service_id}."}
    res_rows = (
        (
            await db.execute(
                select(NetworkServiceResource).where(NetworkServiceResource.service_id == svc.id)
            )
        )
        .scalars()
        .all()
    )
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for r in res_rows:
        by_kind.setdefault(r.resource_kind, []).append(
            {"resource_id": str(r.resource_id), "role": r.role}
        )
    return {
        "id": str(svc.id),
        "name": svc.name,
        "kind": svc.kind,
        "customer_id": str(svc.customer_id),
        "status": svc.status,
        "sla_tier": svc.sla_tier,
        "monthly_cost": float(svc.monthly_cost_usd) if svc.monthly_cost_usd is not None else None,
        "currency": svc.currency,
        "term_start_date": svc.term_start_date.isoformat() if svc.term_start_date else None,
        "term_end_date": svc.term_end_date.isoformat() if svc.term_end_date else None,
        "resource_count": sum(len(v) for v in by_kind.values()),
        "resources_by_kind": by_kind,
    }


# ── list_overlay_networks ─────────────────────────────────────────────


class ListOverlayNetworksArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on overlay name.",
    )
    kind: str | None = Field(
        default=None,
        description="Filter by overlay kind: sdwan / ipsec_mesh / wireguard_mesh / dmvpn / vxlan_evpn / gre_mesh.",
    )
    status: Literal["active", "building", "suspended", "decom"] | None = Field(
        default=None,
        description="Filter by run state.",
    )
    customer_id: str | None = Field(default=None, description="Customer UUID filter.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_overlay_networks",
    permission=("read", "overlay_network"),
    module="network.overlay",
    description=(
        "List SD-WAN / IPsec / WireGuard / DMVPN / VXLAN / GRE "
        "overlay topologies (issue #95). Each row includes name, "
        "kind, vendor, encryption_profile, default_path_strategy, "
        "status, and per-overlay site / policy counts. Use for "
        "questions about overlay inventory or 'how many sites in "
        "the prod SD-WAN'."
    ),
    args_model=ListOverlayNetworksArgs,
    category="network",
)
async def list_overlay_networks(
    db: AsyncSession, user: User, args: ListOverlayNetworksArgs
) -> list[dict[str, Any]]:
    stmt = select(OverlayNetwork).where(OverlayNetwork.deleted_at.is_(None))
    if args.search:
        stmt = stmt.where(func.lower(OverlayNetwork.name).like(f"%{args.search.lower()}%"))
    if args.kind:
        stmt = stmt.where(OverlayNetwork.kind == args.kind)
    if args.status:
        stmt = stmt.where(OverlayNetwork.status == args.status)
    if args.customer_id:
        u = _try_uuid(args.customer_id)
        if u is not None:
            stmt = stmt.where(OverlayNetwork.customer_id == u)
    stmt = stmt.order_by(OverlayNetwork.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()

    site_counts: dict[uuid.UUID, int] = {}
    policy_counts: dict[uuid.UUID, int] = {}
    if rows:
        ids = [r.id for r in rows]
        sc = await db.execute(
            select(OverlaySite.overlay_network_id, func.count())
            .where(OverlaySite.overlay_network_id.in_(ids))
            .group_by(OverlaySite.overlay_network_id)
        )
        site_counts = {row[0]: row[1] for row in sc.all()}
        pc = await db.execute(
            select(RoutingPolicy.overlay_network_id, func.count())
            .where(RoutingPolicy.overlay_network_id.in_(ids))
            .group_by(RoutingPolicy.overlay_network_id)
        )
        policy_counts = {row[0]: row[1] for row in pc.all()}

    return [
        {
            "id": str(r.id),
            "name": r.name,
            "kind": r.kind,
            "vendor": r.vendor,
            "encryption_profile": r.encryption_profile,
            "default_path_strategy": r.default_path_strategy,
            "status": r.status,
            "customer_id": str(r.customer_id) if r.customer_id else None,
            "site_count": site_counts.get(r.id, 0),
            "policy_count": policy_counts.get(r.id, 0),
        }
        for r in rows
    ]


# ── get_overlay_topology ──────────────────────────────────────────────


class GetOverlayTopologyArgs(BaseModel):
    overlay_id: str = Field(description="UUID of the overlay network.")


@register_tool(
    name="get_overlay_topology",
    permission=("read", "overlay_network"),
    module="network.overlay",
    description=(
        "Return the membership + policy detail of one overlay "
        "network: every site (with role + edge device + ordered "
        "preferred_circuits) and every routing policy (priority, "
        "match_kind, match_value, action, action_target, enabled). "
        "Use after ``list_overlay_networks`` to drill in."
    ),
    args_model=GetOverlayTopologyArgs,
    category="network",
)
async def get_overlay_topology(
    db: AsyncSession, user: User, args: GetOverlayTopologyArgs
) -> dict[str, Any]:
    u = _try_uuid(args.overlay_id)
    if u is None:
        return {"error": f"overlay_id must be a UUID, got {args.overlay_id!r}."}
    ovl = await db.get(OverlayNetwork, u)
    if ovl is None or ovl.deleted_at is not None:
        return {"error": f"No active overlay network with id {args.overlay_id}."}

    sites = (
        (
            await db.execute(
                select(OverlaySite)
                .where(OverlaySite.overlay_network_id == ovl.id)
                .order_by(OverlaySite.role.asc())
            )
        )
        .scalars()
        .all()
    )
    policies = (
        (
            await db.execute(
                select(RoutingPolicy)
                .where(RoutingPolicy.overlay_network_id == ovl.id)
                .order_by(RoutingPolicy.priority.asc(), RoutingPolicy.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "id": str(ovl.id),
        "name": ovl.name,
        "kind": ovl.kind,
        "status": ovl.status,
        "default_path_strategy": ovl.default_path_strategy,
        "sites": [
            {
                "id": str(s.id),
                "site_id": str(s.site_id),
                "role": s.role,
                "device_id": str(s.device_id) if s.device_id else None,
                "loopback_subnet_id": (str(s.loopback_subnet_id) if s.loopback_subnet_id else None),
                "preferred_circuits": list(s.preferred_circuits or []),
            }
            for s in sites
        ],
        "policies": [
            {
                "id": str(p.id),
                "name": p.name,
                "priority": p.priority,
                "match_kind": p.match_kind,
                "match_value": p.match_value,
                "action": p.action,
                "action_target": p.action_target,
                "enabled": p.enabled,
            }
            for p in policies
        ],
    }


# ── list_application_categories ───────────────────────────────────────


class ListAppCategoriesArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Substring match on application name.",
    )
    builtin_only: bool | None = Field(
        default=None,
        description="When true, return only the curated built-in catalog rows.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_application_categories",
    permission=("read", "application_category"),
    module="network.overlay",
    description=(
        "List the SaaS application catalog used by overlay routing "
        "policies of match_kind=application. Each row is a curated "
        "(or operator-added) app: name, vendor, suggested DSCP per "
        "RFC 4594, hint domains/IPs. Use to answer 'what apps does "
        "the catalog know' or 'what DSCP does Office 365 ship with'."
    ),
    args_model=ListAppCategoriesArgs,
    category="network",
)
async def list_application_categories(
    db: AsyncSession, user: User, args: ListAppCategoriesArgs
) -> list[dict[str, Any]]:
    stmt = select(ApplicationCategory)
    if args.search:
        stmt = stmt.where(func.lower(ApplicationCategory.name).like(f"%{args.search.lower()}%"))
    if args.builtin_only:
        stmt = stmt.where(ApplicationCategory.is_builtin.is_(True))
    stmt = stmt.order_by(
        desc(ApplicationCategory.is_builtin), ApplicationCategory.name.asc()
    ).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "category": r.category,
            "default_dscp": r.default_dscp,
            "is_builtin": r.is_builtin,
        }
        for r in rows
    ]


# ── trace_circuit_impact ────────────────────────────────────────────


class TraceCircuitImpactArgs(BaseModel):
    circuit: str = Field(
        ...,
        description=(
            "Circuit UUID *or* exact circuit name. Name resolution is "
            "exact (no wildcards) so an ambiguous match returns an error."
        ),
    )


@register_tool(
    name="trace_circuit_impact",
    permission=("read", "circuit"),
    module="network.circuit",
    description=(
        "Walk every overlay site whose preferred-circuit chain references "
        "the given circuit, and report which sites would be primary / "
        "demoted / blackholed if it went down. This is the 'what's at "
        "stake?' query operators run mentally on incident calls — "
        "answers it without running the full /simulate engine."
    ),
    args_model=TraceCircuitImpactArgs,
    category="network",
)
async def trace_circuit_impact(
    db: AsyncSession,
    user: User,  # noqa: ARG001
    args: TraceCircuitImpactArgs,
) -> dict[str, Any]:
    target_uuid = _try_uuid(args.circuit)
    circuit_q = select(Circuit).where(Circuit.deleted_at.is_(None))
    if target_uuid is not None:
        circuit_q = circuit_q.where(Circuit.id == target_uuid)
    else:
        circuit_q = circuit_q.where(Circuit.name == args.circuit)
    circuit_rows = (await db.execute(circuit_q)).scalars().all()
    if not circuit_rows:
        return {"error": f"no circuit matched {args.circuit!r}"}
    if len(circuit_rows) > 1:
        return {
            "error": (
                f"{len(circuit_rows)} circuits match name {args.circuit!r}; "
                "pass the UUID to disambiguate."
            ),
            "candidates": [{"id": str(c.id), "name": c.name} for c in circuit_rows],
        }
    circuit = circuit_rows[0]

    # Walk every overlay site; ``preferred_circuits`` is a JSON list
    # of UUIDs in priority order. We don't filter at the SQL layer
    # because JSONB array containment requires the right operator
    # syntax — easier to load + filter in Python at the scale of
    # operator-managed overlays (typically <1k sites).
    overlay_sites = (
        await db.execute(
            select(OverlaySite, OverlayNetwork, Site)
            .join(OverlayNetwork, OverlaySite.overlay_network_id == OverlayNetwork.id)
            .outerjoin(Site, OverlaySite.site_id == Site.id)
            .where(OverlayNetwork.deleted_at.is_(None))
        )
    ).all()

    impacted: list[dict[str, Any]] = []
    overlays_seen: set[uuid.UUID] = set()
    for os_, overlay, site in overlay_sites:
        chain = [str(c) for c in (os_.preferred_circuits or []) if c]
        if str(circuit.id) not in chain:
            continue
        position = chain.index(str(circuit.id))
        survivors = [c for c in chain if c != str(circuit.id)]
        new_primary = survivors[0] if survivors else None
        impacted.append(
            {
                "overlay_id": str(overlay.id),
                "overlay_name": overlay.name,
                "site_name": site.name if site else "<deleted>",
                "circuit_position": position,
                "is_currently_primary": position == 0,
                "fallback_circuit_id": new_primary,
                "blackholed": new_primary is None,
            }
        )
        overlays_seen.add(overlay.id)

    return {
        "circuit_id": str(circuit.id),
        "circuit_name": circuit.name,
        "circuit_status": circuit.status,
        "transport_class": circuit.transport_class,
        "overlays_affected": len(overlays_seen),
        "sites_affected": len(impacted),
        "sites_blackholed_if_down": sum(1 for r in impacted if r["blackholed"]),
        "sites_currently_primary": sum(1 for r in impacted if r["is_currently_primary"]),
        "details": impacted,
    }


__all__ = [
    "list_asns",
    "get_asn",
    "list_domains",
    "list_vrfs",
    "list_circuits",
    "list_network_services",
    "get_network_service_summary",
    "list_overlay_networks",
    "get_overlay_topology",
    "list_application_categories",
    "trace_circuit_impact",
]
