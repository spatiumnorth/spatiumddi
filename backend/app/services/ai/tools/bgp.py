"""Operator Copilot tools — BGP enrichment (issue #122).

Backed by RIPEstat (origin / announced-prefixes / routing-history)
and PeeringDB (IXP presence + network record). All read-only,
default-enabled — the upstream data is public information and
operators benefit from the model being able to answer "who's
announcing 8.8.8.8?" or "what does AS15169 announce?" without
flipping anything in Settings first.

The tools surface the same normalised shapes returned by the REST
endpoints in :mod:`app.api.v1.bgp.router`. ``available: False``
results pass through cleanly so the model can tell the operator
"RIPEstat unreachable" instead of pretending the answer is empty.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.tools.base import register_tool
from app.services.bgp import (
    fetch_announced_prefixes,
    fetch_asn_ixps,
    fetch_asn_network,
    fetch_prefix_overview,
    fetch_routing_history,
)


def _validate_resource(resource: str) -> tuple[str, str | None]:
    s = resource.strip()
    if not s:
        return s, "resource is empty"
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
    except ValueError as exc:
        return s, f"'{s}' is not a valid IP or CIDR ({exc})"
    return s, None


# ── asn_announced_prefixes ────────────────────────────────────────────


class AnnouncedPrefixesArgs(BaseModel):
    asn: int = Field(..., ge=0, description="Autonomous system number.")


@register_tool(
    name="asn_announced_prefixes",
    permission=("read", "manage_asns"),
    description=(
        "Prefixes currently announced by an AS, sourced from "
        "RIPEstat. Returns a list of CIDRs with first-seen / "
        "last-seen timestamps plus a v4 / v6 split count. Use for "
        "'what does AS15169 advertise?' or 'how many /24s does this "
        "carrier originate?'."
    ),
    args_model=AnnouncedPrefixesArgs,
    category="network",
    module="network.asn",
)
async def asn_announced_prefixes(
    db: AsyncSession,
    user: User,
    args: AnnouncedPrefixesArgs,
) -> dict[str, Any]:
    return await fetch_announced_prefixes(args.asn)


# ── asn_ixp_presence ──────────────────────────────────────────────────


class IxpPresenceArgs(BaseModel):
    asn: int = Field(..., ge=0)


@register_tool(
    name="asn_ixp_presence",
    permission=("read", "manage_asns"),
    description=(
        "IXP membership rollup for an AS, sourced from PeeringDB. "
        "Each row is one peering port at one IX (IX name, city, "
        "speed in Mbps, the AS's IPv4 / IPv6 IPs at that IX, "
        "is_rs_peer, operational state). Use for 'where does "
        "AS15169 peer?' or 'what's their footprint at AMS-IX?'."
    ),
    args_model=IxpPresenceArgs,
    category="network",
    module="network.asn",
)
async def asn_ixp_presence(
    db: AsyncSession,
    user: User,
    args: IxpPresenceArgs,
) -> dict[str, Any]:
    return await fetch_asn_ixps(args.asn)


# ── asn_peering_profile ───────────────────────────────────────────────


class PeeringProfileArgs(BaseModel):
    asn: int = Field(..., ge=0)


@register_tool(
    name="asn_peering_profile",
    permission=("read", "manage_asns"),
    description=(
        "PeeringDB network record for an AS — registered org name, "
        "info_type (Content / NSP / Cable/DSL/ISP / Enterprise / "
        "Educational / Non-Profit), traffic estimate, scope (Global "
        "/ Regional / Local), peering policy (Open / Selective / "
        "Restrictive), IRR AS-set, looking-glass URL, public "
        "website. Use for 'is AS15169 open to peering?' or 'who do "
        "I email about peering with this carrier?'."
    ),
    args_model=PeeringProfileArgs,
    category="network",
    module="network.asn",
)
async def asn_peering_profile(
    db: AsyncSession,
    user: User,
    args: PeeringProfileArgs,
) -> dict[str, Any]:
    return await fetch_asn_network(args.asn)


# ── prefix_origin ─────────────────────────────────────────────────────


class PrefixOriginArgs(BaseModel):
    resource: str = Field(
        ...,
        description="IPv4 / IPv6 address or CIDR block.",
    )


@register_tool(
    name="prefix_origin",
    permission=("read", "manage_asns"),
    description=(
        "For a given IP or CIDR, return the originating AS(es) plus "
        "the enclosing prefix and announcement state, sourced from "
        "RIPEstat. Use for 'who's announcing 8.8.8.8?', 'is this "
        "address routed?', or 'what /24 covers 1.1.1.1?'. The "
        "returned ``asns`` list is usually a single entry but may be "
        "multi-origin if the prefix is intentionally announced from "
        "multiple ASes."
    ),
    args_model=PrefixOriginArgs,
    category="network",
    module="network.asn",
)
async def prefix_origin(
    db: AsyncSession,
    user: User,
    args: PrefixOriginArgs,
) -> dict[str, Any]:
    s, err = _validate_resource(args.resource)
    if err:
        return {"error": err}
    return await fetch_prefix_overview(s)


# ── prefix_routing_history ────────────────────────────────────────────


class RoutingHistoryArgs(BaseModel):
    resource: str = Field(
        ...,
        description="IPv4 / IPv6 address or CIDR block.",
    )


@register_tool(
    name="prefix_routing_history",
    permission=("read", "manage_asns"),
    description=(
        "Timeline of origin-AS changes for an IP or prefix, sourced "
        "from RIPEstat. Returns events ordered oldest → newest with "
        "starttime / endtime per origin AS. Use for 'has this prefix "
        "been re-homed recently?' or, in the worst case, 'is this "
        "looking like a hijack?'. Many prefixes show a single "
        "long-running event with no end-time — that's the steady "
        "state, the absence of churn."
    ),
    args_model=RoutingHistoryArgs,
    category="network",
    module="network.asn",
)
async def prefix_routing_history(
    db: AsyncSession,
    user: User,
    args: RoutingHistoryArgs,
) -> dict[str, Any]:
    s, err = _validate_resource(args.resource)
    if err:
        return {"error": err}
    return await fetch_routing_history(s)
