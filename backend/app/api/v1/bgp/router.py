"""REST surface for BGP enrichment (issue #122).

Public, free upstream sources (RIPEstat + PeeringDB) — no API key
required, in-process cache absorbs repeated queries. Endpoints are
authenticated but not RBAC-gated; the data is public information,
the only reason to gate is to avoid abuse of our cache by
unauthenticated callers.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import CurrentUser
from app.services.bgp import (
    fetch_announced_prefixes,
    fetch_as_overview,
    fetch_asn_ixps,
    fetch_asn_network,
    fetch_prefix_overview,
    fetch_routing_history,
)

router = APIRouter()


def _validate_asn(asn: int) -> int:
    if asn < 0 or asn > 4_294_967_295:
        raise HTTPException(
            status_code=422,
            detail="asn must be a 32-bit unsigned integer (0 .. 2^32 - 1)",
        )
    return asn


def _validate_resource(resource: str) -> str:
    """Accept a v4/v6 IP or a CIDR block. Reject obvious garbage so
    we don't waste an HTTP call on a malformed input.
    """
    s = resource.strip()
    if not s:
        raise HTTPException(status_code=422, detail="resource is empty")
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"resource '{s}' is not a valid IP or CIDR ({exc})",
        ) from exc
    return s


# ── Typed envelopes for the proxied intelligence sources (issue #917) ──
#
# These routes forward normalised RIPEstat / PeeringDB payloads. Each model
# declares the fields the service layer guarantees and sets
# ``extra="allow"``, which publishes ``additionalProperties: true``: a
# generated client gets typed access to the stable fields without the document
# claiming the upstream will never add another. Declaring these as closed
# models would silently drop whatever RIPEstat adds next.
#
# ``available`` is on every one of them and is load-bearing: an upstream
# outage returns ``available=false`` with ``error`` set, and a client that
# reads an empty ``prefixes`` list as "this AS announces nothing" would be
# reporting an outage as a fact about the network.


class _UpstreamEnvelope(BaseModel):
    model_config = {"extra": "allow"}

    available: bool
    #: Set when ``available`` is false — why the upstream could not answer.
    error: str | None = None


class ASNAnnouncedPrefixes(_UpstreamEnvelope):
    asn: int | None = None
    prefixes: list[dict[str, Any]] = []
    ipv4_count: int | None = None
    ipv6_count: int | None = None


class ASNOverview(_UpstreamEnvelope):
    asn: int | None = None
    holder: str | None = None
    type: str | None = None
    announced: bool | None = None
    block: dict[str, Any] | None = None


class ASNNetwork(_UpstreamEnvelope):
    asn: int | None = None
    #: False when PeeringDB simply has no record for this AS — distinct from
    #: ``available=false``, which means PeeringDB could not be reached.
    found: bool | None = None
    name: str | None = None
    aka: str | None = None
    info_type: str | None = None
    info_traffic: str | None = None
    info_scope: str | None = None
    policy_general: str | None = None
    policy_locations: str | None = None
    irr_as_set: str | None = None
    looking_glass: str | None = None
    website: str | None = None


class ASNIxpPresence(_UpstreamEnvelope):
    asn: int | None = None
    ixps: list[dict[str, Any]] = []
    #: Peering ports, not distinct IXPs — an AS with two ports at one IX
    #: counts twice, which is what the rows show.
    ixp_count: int | None = None


@router.get("/asn/{asn}/announced-prefixes", response_model=ASNAnnouncedPrefixes)
async def asn_announced_prefixes(
    asn: int,
    _: CurrentUser,
) -> ASNAnnouncedPrefixes:
    return ASNAnnouncedPrefixes.model_validate(await fetch_announced_prefixes(_validate_asn(asn)))


@router.get("/asn/{asn}/overview", response_model=ASNOverview)
async def asn_overview(
    asn: int,
    _: CurrentUser,
) -> ASNOverview:
    return ASNOverview.model_validate(await fetch_as_overview(_validate_asn(asn)))


@router.get("/asn/{asn}/network", response_model=ASNNetwork)
async def asn_network(
    asn: int,
    _: CurrentUser,
) -> ASNNetwork:
    """PeeringDB network record — org metadata + peering policy."""
    return ASNNetwork.model_validate(await fetch_asn_network(_validate_asn(asn)))


@router.get("/asn/{asn}/ixps", response_model=ASNIxpPresence)
async def asn_ixps(
    asn: int,
    _: CurrentUser,
) -> ASNIxpPresence:
    """IXP presence rollup from PeeringDB."""
    return ASNIxpPresence.model_validate(await fetch_asn_ixps(_validate_asn(asn)))


@router.get("/prefix/origin")
async def prefix_origin(
    _: CurrentUser,
    resource: str = Query(..., description="IPv4/v6 address or CIDR"),
) -> dict[str, Any]:
    """For a given IP or CIDR, who's announcing the enclosing
    prefix? Backed by RIPEstat ``prefix-overview``.
    """
    return await fetch_prefix_overview(_validate_resource(resource))


@router.get("/prefix/routing-history")
async def prefix_routing_history(
    _: CurrentUser,
    resource: str = Query(..., description="IPv4/v6 address or CIDR"),
) -> dict[str, Any]:
    """Timeline of origin-AS changes for the prefix. Catches
    re-homings and (in the worst case) hijack events.
    """
    return await fetch_routing_history(_validate_resource(resource))
