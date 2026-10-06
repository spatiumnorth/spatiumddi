"""Operator Copilot tools for the built-in network tools (issue #58).

Seven read tools wrapping the same stateless runners the REST surface
uses. All ``module="tools.network"`` so disabling the feature module
strips them from the effective set (hard kill-switch, per
``effective_tool_names``).

Default-enabled state follows non-negotiable #13:

* On-prem tools (ping / traceroute / dig / port-test / tls-cert /
  mac-vendor) ship ``default_enabled=True`` — discoverable, no off-prem
  egress, no secrets.
* ``network_whois`` ships ``default_enabled=False`` — it makes outbound
  WHOIS queries to public registries, so air-gapped / strict-egress
  operators opt in explicitly (mirrors ``tools/whois.py``).

These are reads, not writes — they don't mutate state. Touching the
network is read-only here (a ping is observation, not a change), so no
``propose_*`` preview/apply contract is needed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool
from app.services.ipam.probe_policy import check_probe_target
from app.services.nettools import (
    inspect_tls_cert,
    run_dig,
    run_ping,
    run_traceroute,
    run_whois,
    test_port,
)
from app.services.nettools.runner import NetToolArgError
from app.services.nettools.schemas import DigRequest
from app.services.oui import bulk_lookup_vendors, is_voip_phone_vendor, normalize_mac_key

_MODULE = "tools.network"

# Trim subprocess stdout so a verbose traceroute / whois doesn't blow the
# model out of context.
_STDOUT_CHARS = 4000


def _trim(text: str) -> str:
    if len(text) <= _STDOUT_CHARS:
        return text
    return text[:_STDOUT_CHARS] + f"\n… (truncated, {len(text)} chars total)"


async def _probe_refusal(db: AsyncSession, host: str, *, action: str) -> dict[str, Any] | None:
    """Refusal payload when ``host`` is inside a do-not-probe scope (#722).

    These tools drive the runners directly rather than going through the
    ``/tools/*`` handlers, so they need the gate applied here or the
    copilot becomes the one surface that still probes flagged devices.

    Returns a plain error dict rather than raising: every other refusal
    in this module answers that way, and it puts the operator's own
    reason in front of the model so it can explain *why* instead of
    retrying. There is no override — clearing the flag is a deliberate
    superadmin action on the tools page, not something to talk a copilot
    into.
    """
    verdict = await check_probe_target(db, host)
    if not verdict.blocked:
        return None
    return {"host": host, "error": verdict.message(action=action)}


# ── network_ping ────────────────────────────────────────────────────


class NetworkPingArgs(BaseModel):
    host: str = Field(description="IPv4 / IPv6 address or hostname to ping from the server.")


@register_tool(
    name="network_ping",
    module=_MODULE,
    category="tools",
    description=(
        "Ping a host from the SpatiumDDI server (4 ICMP echoes). Returns "
        "the raw ping output plus exit code — use it to check basic "
        "reachability + round-trip latency. Server-perspective only."
    ),
    args_model=NetworkPingArgs,
)
async def network_ping(
    db: AsyncSession,
    user: User,  # noqa: ARG001
    args: NetworkPingArgs,
) -> dict[str, Any]:
    refusal = await _probe_refusal(db, args.host, action="Pinging")
    if refusal is not None:
        return refusal
    try:
        res = await run_ping(args.host)
    except NetToolArgError as exc:
        return {"error": str(exc)}
    return {
        "host": args.host,
        "available": res.available,
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "output": _trim(res.stdout or res.stderr),
        "error": res.error,
    }


# ── network_traceroute ──────────────────────────────────────────────


class NetworkTracerouteArgs(BaseModel):
    host: str = Field(description="IPv4 / IPv6 address or hostname to trace the path to.")


@register_tool(
    name="network_traceroute",
    module=_MODULE,
    category="tools",
    description=(
        "Trace the network path from the SpatiumDDI server to a host "
        "(max 20 hops, numeric output). Returns the per-hop list — use "
        "it to see where traffic exits / stalls. Server-perspective only."
    ),
    args_model=NetworkTracerouteArgs,
)
async def network_traceroute(
    db: AsyncSession,
    user: User,  # noqa: ARG001
    args: NetworkTracerouteArgs,
) -> dict[str, Any]:
    refusal = await _probe_refusal(db, args.host, action="Route tracing")
    if refusal is not None:
        return refusal
    try:
        res = await run_traceroute(args.host)
    except NetToolArgError as exc:
        return {"error": str(exc)}
    return {
        "host": args.host,
        "available": res.available,
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "output": _trim(res.stdout or res.stderr),
        "error": res.error,
    }


# ── network_dig ─────────────────────────────────────────────────────


class NetworkDigArgs(BaseModel):
    name: str = Field(description="DNS name to query (e.g. example.com).")
    record_type: str = Field(default="A", description="Record type — A, AAAA, MX, TXT, NS, …")
    server: str | None = Field(
        default=None,
        description="Optional resolver IP / hostname to query (@server). Defaults to the server's resolver.",
    )

    # Mirror the REST ``DigRequest`` validators — the MCP path historically
    # had no ``name`` validator, so a name like ``-froot`` flowed straight
    # into ``run_dig`` → ``build_dig_argv``. dig has no ``--`` terminator,
    # so a leading-dash name is parsed as a flag (``-f`` batch-mode reads
    # queries from a filesystem path). Delegate to the REST schema's
    # validators so the two surfaces stay in lockstep.
    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return DigRequest._v_name(v)

    @field_validator("server")
    @classmethod
    def _v_server(cls, v: str | None) -> str | None:
        return DigRequest._v_server(v)


@register_tool(
    name="network_dig",
    module=_MODULE,
    category="tools",
    description=(
        "Run a dig DNS query from the SpatiumDDI server. Returns the raw "
        "answer + authority sections — use it to resolve a name or check "
        "a specific record type against a specific resolver."
    ),
    args_model=NetworkDigArgs,
)
async def network_dig(
    db: AsyncSession,  # noqa: ARG001
    user: User,  # noqa: ARG001
    args: NetworkDigArgs,
) -> dict[str, Any]:
    try:
        res = await run_dig(args.name, args.record_type, args.server)
    except NetToolArgError as exc:
        return {"error": str(exc)}
    return {
        "name": args.name,
        "record_type": args.record_type.upper(),
        "server": args.server,
        "available": res.available,
        "exit_code": res.exit_code,
        "output": _trim(res.stdout or res.stderr),
        "error": res.error,
    }


# ── network_port_test ───────────────────────────────────────────────


class NetworkPortTestArgs(BaseModel):
    host: str = Field(description="IPv4 / IPv6 address or hostname.")
    port: int = Field(ge=1, le=65535, description="Port number 1–65535.")
    protocol: str = Field(default="tcp", description="'tcp' or 'udp'.")


@register_tool(
    name="network_port_test",
    module=_MODULE,
    category="tools",
    description=(
        "Test whether a TCP/UDP port is reachable from the SpatiumDDI "
        "server. TCP returns open / closed / filtered; UDP can only "
        "return open|filtered vs closed. Server-perspective only."
    ),
    args_model=NetworkPortTestArgs,
)
async def network_port_test(
    db: AsyncSession,
    user: User,  # noqa: ARG001
    args: NetworkPortTestArgs,
) -> dict[str, Any]:
    refusal = await _probe_refusal(db, args.host, action="Port testing")
    if refusal is not None:
        return refusal
    proto = args.protocol.strip().lower()
    if proto not in {"tcp", "udp"}:
        return {"error": "protocol must be 'tcp' or 'udp'"}
    res = await test_port(args.host, args.port, proto)
    return {
        "host": res.host,
        "port": res.port,
        "protocol": res.protocol,
        "state": res.state,
        "rtt_ms": res.rtt_ms,
        "error": res.error,
    }


# ── network_tls_cert ────────────────────────────────────────────────


class NetworkTlsCertArgs(BaseModel):
    host: str = Field(description="IPv4 / IPv6 address or hostname presenting TLS.")
    port: int = Field(default=443, ge=1, le=65535, description="TLS port (default 443).")
    server_name: str | None = Field(default=None, description="SNI override; defaults to host.")


@register_tool(
    name="network_tls_cert",
    module=_MODULE,
    category="tools",
    description=(
        "Inspect the TLS certificate a host presents (verification "
        "disabled so expired / self-signed certs are still readable). "
        "Returns subject, issuer, SAN list, validity window, days "
        "remaining, expired / self-signed / hostname-match flags."
    ),
    args_model=NetworkTlsCertArgs,
)
async def network_tls_cert(
    db: AsyncSession,
    user: User,  # noqa: ARG001
    args: NetworkTlsCertArgs,
) -> dict[str, Any]:
    refusal = await _probe_refusal(db, args.host, action="TLS probing")
    if refusal is not None:
        return refusal
    res = await inspect_tls_cert(args.host, args.port, args.server_name)
    return {
        "host": res.host,
        "port": res.port,
        "server_name": res.server_name,
        "ok": res.ok,
        "subject": res.subject,
        "issuer": res.issuer,
        "san": res.san,
        "not_before": res.not_before,
        "not_after": res.not_after,
        "days_remaining": res.days_remaining,
        "expired": res.expired,
        "self_signed": res.self_signed,
        "hostname_matches": res.hostname_matches,
        "error": res.error,
    }


# ── lookup_mac_vendor ───────────────────────────────────────────────


class LookupMacVendorArgs(BaseModel):
    macs: list[str] = Field(
        min_length=1,
        max_length=256,
        description="MAC addresses to resolve (any common delimiter form).",
    )


@register_tool(
    name="lookup_mac_vendor",
    module=_MODULE,
    category="tools",
    description=(
        "Resolve OUI vendor names for a batch of MAC addresses via the "
        "local OUI table. Also flags likely VoIP-phone vendors. Returns "
        "an ``oui_enabled`` flag — when False, OUI lookup is disabled in "
        "Settings → IPAM and vendors come back empty."
    ),
    args_model=LookupMacVendorArgs,
)
async def lookup_mac_vendor(
    db: AsyncSession,
    user: User,  # noqa: ARG001
    args: LookupMacVendorArgs,
) -> dict[str, Any]:
    ps = await db.get(PlatformSettings, 1)
    oui_enabled = bool(ps and ps.oui_lookup_enabled)
    vendors = await bulk_lookup_vendors(db, list(args.macs))
    entries = []
    for raw in args.macs:
        key = normalize_mac_key(raw)
        name = vendors.get(key) if key else None
        entries.append({"mac": raw, "vendor": name, "is_voip_phone": is_voip_phone_vendor(name)})
    return {"oui_enabled": oui_enabled, "entries": entries}


# ── network_whois (off-prem → default-disabled) ─────────────────────


class NetworkWhoisArgs(BaseModel):
    query: str = Field(description="IP, domain, or AS number to look up via WHOIS.")


@register_tool(
    name="network_whois",
    module=_MODULE,
    category="tools",
    description=(
        "Run a WHOIS query from the SpatiumDDI server against public "
        "registries — answers 'who owns this IP / domain / ASN?'. Makes "
        "an OUTBOUND connection to a WHOIS server, so it's disabled by "
        "default; an administrator enables it in Administration → AI Tool "
        "Catalog."
    ),
    args_model=NetworkWhoisArgs,
    default_enabled=False,
)
async def network_whois(
    db: AsyncSession,  # noqa: ARG001
    user: User,  # noqa: ARG001
    args: NetworkWhoisArgs,
) -> dict[str, Any]:
    try:
        res = await run_whois(args.query)
    except NetToolArgError as exc:
        return {"error": str(exc)}
    return {
        "query": args.query,
        "available": res.available,
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "output": _trim(res.stdout or res.stderr),
        "error": res.error,
    }


__all__ = [
    "lookup_mac_vendor",
    "network_dig",
    "network_ping",
    "network_port_test",
    "network_tls_cert",
    "network_traceroute",
    "network_whois",
]
