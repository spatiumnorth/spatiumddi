"""Public WHOIS / RDAP lookup tools for the Operator Copilot.

Three tools, all wrapping existing helpers:

* ``lookup_whois_ip`` — IANA RDAP bootstrap → RIR → prefix lookup.
* ``lookup_whois_asn`` — derive RIR from the IANA delegation snapshot,
  hit that RIR's RDAP autnum endpoint.
* ``lookup_whois_domain`` — IANA RDAP bootstrap → registry → domain
  lookup (same shape the WHOIS panel on the Domains page renders).

All three are ``default_enabled=False`` — they make outbound HTTP
requests to public RDAP servers, which some operators (air-gapped /
strict egress) want to opt into explicitly. Surfaces with a clear
``[disabled]`` annotation in the LLM's tool catalog when off.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.tools.base import register_tool
from app.services.rdap import lookup_domain
from app.services.rdap_asn import lookup_asn
from app.services.rdap_ip import lookup_ip

# ── lookup_whois_ip ─────────────────────────────────────────────────


class LookupWhoisIpArgs(BaseModel):
    address: str = Field(
        ...,
        description=(
            "IPv4 or IPv6 address. Returns the responsible RIR, the "
            "matched prefix, the holder org, and the abuse contact."
        ),
    )


@register_tool(
    name="lookup_whois_ip",
    permission=("read", "use_network_tools"),
    description=(
        "Look up the public WHOIS / RDAP record for an IP address — "
        "answers 'who owns this IP?'. Resolves the responsible RIR via "
        "the IANA RDAP bootstrap, then queries that RIR for the prefix "
        "this address lives in. Returns holder org, abuse contact, "
        "country, and the matched CIDR. Private (RFC 1918) and "
        "reserved ranges return a short note instead of a 404."
    ),
    args_model=LookupWhoisIpArgs,
    category="ops",
    default_enabled=False,
)
async def lookup_whois_ip(
    db: AsyncSession,  # noqa: ARG001 — RDAP is stateless
    user: User,  # noqa: ARG001
    args: LookupWhoisIpArgs,
) -> dict[str, Any]:
    result = await lookup_ip(args.address)
    if result is None:
        return {
            "address": args.address,
            "error": (
                "RDAP lookup failed (network error, bootstrap unreachable, "
                "or the responsible RIR returned a non-2xx). Try again or "
                "consult the live RIR WHOIS page directly."
            ),
        }
    return result


# ── lookup_whois_asn ────────────────────────────────────────────────


class LookupWhoisAsnArgs(BaseModel):
    number: int = Field(
        ...,
        ge=1,
        le=4294967295,
        description=(
            "AS number (1 – 4294967295). Both 16-bit and 32-bit ASNs "
            "are supported; the IANA delegation snapshot determines "
            "which RIR to query."
        ),
    )


@register_tool(
    name="lookup_whois_asn",
    permission=("read", "use_network_tools"),
    description=(
        "Look up the public WHOIS / RDAP record for an AS number — "
        "answers 'who runs this ASN?'. Returns the holder org, the "
        "responsible RIR, and the RDAP last-modified date. Same shape "
        "the SpatiumDDI ASN refresh task already uses; safe to call on "
        "any public ASN."
    ),
    args_model=LookupWhoisAsnArgs,
    category="ops",
    default_enabled=False,
)
async def lookup_whois_asn(
    db: AsyncSession,  # noqa: ARG001
    user: User,  # noqa: ARG001
    args: LookupWhoisAsnArgs,
) -> dict[str, Any]:
    result = await lookup_asn(args.number)
    if result is None:
        return {
            "asn": args.number,
            "error": (
                "RDAP lookup failed — the AS number may be private (RFC 6996 / 7300), "
                "in a region with no published RDAP base, or the responsible RIR "
                "returned a non-2xx."
            ),
        }
    # Drop the giant ``raw`` payload — the LLM doesn't need every
    # vCard array; the normalised top-level keys are enough.
    return {
        "asn": args.number,
        "holder_org": result.get("holder_org"),
        "registry": result.get("registry"),
        "name": result.get("name"),
        "last_modified_at": (
            result["last_modified_at"].isoformat() if result.get("last_modified_at") else None
        ),
    }


# ── lookup_whois_domain ─────────────────────────────────────────────


class LookupWhoisDomainArgs(BaseModel):
    name: str = Field(
        ...,
        description=(
            "Fully-qualified domain name without trailing dot, e.g. "
            "'example.com'. Subdomains are accepted but the lookup runs "
            "against the registered apex (TLD-aware bootstrap)."
        ),
    )


@register_tool(
    name="lookup_whois_domain",
    permission=("read", "use_network_tools"),
    description=(
        "Look up the public WHOIS / RDAP record for a domain name — "
        "answers 'who owns this domain?'. Returns the registrar, the "
        "registrant org, expiry / creation / updated dates, the "
        "DNSSEC status, and the published nameservers. Same path the "
        "Domains page already uses for refresh, so the result reflects "
        "what your registrar shows."
    ),
    args_model=LookupWhoisDomainArgs,
    category="ops",
    default_enabled=False,
)
async def lookup_whois_domain(
    db: AsyncSession,  # noqa: ARG001
    user: User,  # noqa: ARG001
    args: LookupWhoisDomainArgs,
) -> dict[str, Any]:
    result = await lookup_domain(args.name)
    if result is None:
        return {
            "name": args.name,
            "error": (
                "RDAP lookup failed — the TLD may not have an RDAP server, "
                "the domain may not exist, or the registry returned a non-2xx. "
                "Some legacy ccTLDs still only support port-43 WHOIS."
            ),
        }

    def _iso(key: str) -> str | None:
        val = result.get(key)
        return val.isoformat() if val else None

    return {
        "name": args.name,
        "registrar": result.get("registrar"),
        "registrant_org": result.get("registrant_org"),
        "registered_at": _iso("registered_at"),
        "expires_at": _iso("expires_at"),
        "last_renewed_at": _iso("last_renewed_at"),
        "nameservers": result.get("nameservers", []),
        "dnssec_signed": result.get("dnssec_signed", False),
    }


__all__ = [
    "LookupWhoisIpArgs",
    "LookupWhoisAsnArgs",
    "LookupWhoisDomainArgs",
    "lookup_whois_ip",
    "lookup_whois_asn",
    "lookup_whois_domain",
]
