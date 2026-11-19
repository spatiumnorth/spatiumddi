"""Operator Copilot read tool for the appliance DNS resolver surface (#158).

Surfaces the singleton ``platform_settings`` resolver config so an operator
can ask the Copilot "is the appliance pinning its own DNS servers?", "which
upstream resolvers does it use?", "is DNSSEC / DNS-over-TLS on?". No redaction
— resolver IPs and search domains are not secrets (contrast with the SNMP
community / syslog CA PEM).

There is NO ``propose_*`` write tool — resolver config is changed through the
Appliance → DNS Resolver form, same as NTP / SNMP / SSH. The dedicated UI form
is the friendly path and there aren't compelling LLM-driven workflows yet.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool


class FindResolverSettingsArgs(BaseModel):
    """No arguments — there is exactly one resolver config row."""

    pass


@register_tool(
    name="find_resolver_settings",
    permission="authenticated",
    description=(
        "Return the appliance DNS resolver (systemd-resolved) configuration: "
        "the mode (``automatic`` — per-link NetworkManager / DHCP DNS, or "
        "``override`` — a pinned global server list), the configured upstream "
        "resolver IPs, the fallback resolver IPs, the DNS search domains, and "
        "the DNSSEC + DNS-over-TLS settings. systemd-resolved runs on every "
        "SpatiumDDI appliance host; the override drop-in pins the global DNS= "
        "servers so they win over the per-link resolvers. Use to answer 'is "
        "the appliance pinning its own DNS servers?', 'which upstream "
        "resolvers does it use?', 'is DNSSEC on?'. On docker / k8s deploys "
        "these settings still drive any registered appliance agents in a "
        "hybrid topology."
    ),
    args_model=FindResolverSettingsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets (resolver IPs /
    # domains are not secret), no off-prem calls. module=None: the resolver
    # is plain host-config (like SNMP / NTP / LLDP / syslog / SSH), not a
    # feature module.
    default_enabled=True,
    module=None,
)
async def find_resolver_settings(
    db: AsyncSession, user: User, args: FindResolverSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"note": "platform_settings row missing"}
    mode = (settings.resolver_mode or "automatic").strip()
    servers = list(settings.resolver_servers or [])
    return {
        "mode": mode,
        "servers": servers,
        "fallback_servers": list(settings.resolver_fallback_servers or []),
        "search_domains": list(settings.resolver_search_domains or []),
        "dnssec": settings.resolver_dnssec or "allow-downgrade",
        "dns_over_tls": settings.resolver_dns_over_tls or "no",
        # Aggregate signal for the LLM: is the appliance actually pinning
        # its own upstream DNS, or deferring to per-link DHCP/NM?
        "override_active": mode == "override" and bool(servers),
    }
