"""Operator Copilot read tools for DNS / DHCP config-import preview
(issues #128 / #129, MCP catch-up #280 / #304).

These are the read half of the import tools — they live-pull a source
(Windows DNS / PowerDNS / Windows DHCP) and return the would-import
summary WITHOUT persisting anything. The matching ``propose_commit_*``
write tools (in :mod:`proposals`) do the actual commit behind an
Approve gate.

Default-disabled + superadmin-gated: the pull makes off-prem calls
using stored credentials, so it's opt-in per CLAUDE.md non-negotiable
#13's "off-prem calls default to disabled" rule.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.services.ai.operations_writes import (
    CommitDHCPImportArgs,
    CommitDNSImportArgs,
    CommitNetboxImportArgs,
    _dhcp_import_pull,
    _dns_import_pull,
    _netbox_import_pull,
)
from app.services.ai.tools.base import register_tool


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {"error": "Config-import tools are restricted to superadmin users."}
    return None


@register_tool(
    name="find_dns_import_preview",
    permission="superadmin",
    description=(
        "Preview what a DNS config import from a live source would bring "
        "in, without importing anything. source='windows_dns' (pass "
        "server_id) or 'powerdns' (pass api_url + api_key). "
        "target_group_id scopes conflict detection. Returns zone/record "
        "counts + per-zone conflicts. Use this before "
        "propose_commit_dns_import. Superadmin; makes an off-prem pull."
    ),
    args_model=CommitDNSImportArgs,
    category="dns",
    default_enabled=False,
    module="dns.import",
)
async def find_dns_import_preview(
    db: AsyncSession, user: User, args: CommitDNSImportArgs
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate is not None:
        return gate
    try:
        preview = await _dns_import_pull(db, args)
    except ValueError as exc:
        return {"error": str(exc)}
    return {
        "source": preview.source,
        "zone_count": len(preview.zones),
        "total_records": preview.total_records,
        "conflict_count": len(preview.conflicts),
        "zones": [
            {
                "name": z.name,
                "kind": z.kind,
                "records": len(z.records),
            }
            for z in preview.zones[:100]
        ],
        "warnings": list(preview.warnings)[:20],
    }


@register_tool(
    name="find_dhcp_import_preview",
    permission="superadmin",
    description=(
        "Preview what a DHCP config import from a live Windows DHCP "
        "server would bring in, without importing. Pass "
        "source='windows_dhcp', server_id, target_group_id. Returns "
        "scope/pool/reservation counts + per-scope conflicts. Use before "
        "propose_commit_dhcp_import. Superadmin; makes an off-prem pull."
    ),
    args_model=CommitDHCPImportArgs,
    category="dhcp",
    default_enabled=False,
    module="dhcp.import",
)
async def find_dhcp_import_preview(
    db: AsyncSession, user: User, args: CommitDHCPImportArgs
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate is not None:
        return gate
    try:
        preview = await _dhcp_import_pull(db, args)
    except ValueError as exc:
        return {"error": str(exc)}
    return {
        "source": preview.source,
        "scope_count": len(preview.scopes),
        "total_pools": preview.total_pools,
        "total_reservations": preview.total_reservations,
        "conflict_count": len(preview.conflicts),
        "scopes": [
            {
                "subnet_cidr": s.subnet_cidr,
                "address_family": s.address_family,
                "pools": len(s.pools),
                "reservations": len(s.reservations),
            }
            for s in preview.scopes[:100]
        ],
        "warnings": list(preview.warnings)[:20],
    }


@register_tool(
    name="find_netbox_import_preview",
    permission="superadmin",
    description=(
        "Preview what a one-shot NetBox import would bring into IPAM "
        "without importing anything. Pass base_url + token (+ verify_tls, "
        "space_strategy 'per_vrf'/'single', optional target_space_id and "
        "scope filters vrf_id / tenant_id / status / family / "
        "within_include). Returns counts of spaces / VRFs / blocks / "
        "subnets / addresses / VLANs / customers / sites + per-entity "
        "conflicts. Use before propose_commit_netbox_import. Superadmin; "
        "makes an off-prem pull."
    ),
    args_model=CommitNetboxImportArgs,
    category="ipam",
    default_enabled=False,
    module="ipam.import.netbox",
)
async def find_netbox_import_preview(
    db: AsyncSession, user: User, args: CommitNetboxImportArgs
) -> dict[str, Any]:
    gate = _superadmin_gate(user)
    if gate is not None:
        return gate
    try:
        preview = await _netbox_import_pull(db, args)
    except ValueError as exc:
        return {"error": str(exc)}
    return {
        "source": preview.source,
        "customer_count": len(preview.customers),
        "site_count": len(preview.sites),
        "vrf_count": len(preview.vrfs),
        "space_count": len(preview.spaces),
        "vlan_count": len(preview.vlans),
        "block_count": len(preview.blocks),
        "subnet_count": len(preview.subnets),
        "address_count": len(preview.addresses),
        "conflict_count": len(preview.conflicts),
        "subnets": [
            {
                "network": s.network,
                "kind": s.kind,
                "space_name": s.space_name,
            }
            for s in preview.subnets[:100]
        ],
        "warnings": list(preview.warnings)[:20],
    }
