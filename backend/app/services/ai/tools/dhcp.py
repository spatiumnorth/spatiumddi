"""Read-only DHCP tools for the Operator Copilot (issue #90 Wave 2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dhcp import (
    DHCPClientClass,
    DHCPLease,
    DHCPMACBlock,
    DHCPOptionTemplate,
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPPool,
    DHCPPXEProfile,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.models.ipam import Subnet
from app.models.metrics import DHCPMetricSample
from app.services.ai.tools.base import register_tool
from app.services.dhcp.device_policy import compile_device_policy
from app.services.dhcp.stats import STATS_WINDOW_SECONDS, active_lease_count
from app.services.oui import bulk_lookup_vendors, is_voip_phone_vendor, normalize_mac_key


class ListDHCPServersArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DHCP server group UUID.")


@register_tool(
    name="list_dhcp_servers",
    description=(
        "List DHCP servers (Kea / Windows DHCP). Each summary "
        "includes name, group, driver, operational status, and HA state."
    ),
    args_model=ListDHCPServersArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_servers(
    db: AsyncSession, user: User, args: ListDHCPServersArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPServer)
    if args.group_id:
        # ``server_group_id`` — DHCPServer has no ``group_id`` column, so the
        # old spelling raised AttributeError and this tool 500'd whenever a
        # group filter was supplied (#923).
        stmt = stmt.where(DHCPServer.server_group_id == args.group_id)
    stmt = stmt.order_by(DHCPServer.name.asc())
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(s.id),
            "name": s.name,
            # #923: ``group_id`` / ``server_type`` / ``is_enabled`` are not
            # columns on DHCPServer, so building this row raised
            # AttributeError and the tool answered nothing for any input —
            # not just for the group filter. ``driver`` is what the old
            # "server_type" meant, and there is no enable flag; ``status`` is
            # the operational state a caller actually wants.
            "group_id": str(s.server_group_id) if s.server_group_id else None,
            "driver": s.driver,
            "status": s.status,
            "ha_state": s.ha_state,
        }
        for s in rows
    ]


class ListDHCPScopesArgs(BaseModel):
    group_id: str | None = None
    search: str | None = Field(
        default=None,
        description="Substring match on scope name or CIDR.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dhcp_scopes",
    description=(
        "List DHCP scopes (subnets where DHCP serves leases). Filter "
        "by server group or name / CIDR substring."
    ),
    args_model=ListDHCPScopesArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_scopes(
    db: AsyncSession, user: User, args: ListDHCPScopesArgs
) -> list[dict[str, Any]]:
    # The CIDR is NOT on DHCPScope — it has ``subnet_id`` and the prefix lives
    # on the related Subnet. The old code read ``DHCPScope.subnet`` for the
    # search, the sort AND the response, so this tool raised AttributeError on
    # the ``order_by`` alone and had never returned a scope (#923). Joining
    # Subnet makes all three work and keeps the CIDR filter in SQL.
    stmt = (
        select(DHCPScope, Subnet.network)
        .join(Subnet, Subnet.id == DHCPScope.subnet_id)
        .where(DHCPScope.deleted_at.is_(None))
    )
    if args.group_id:
        stmt = stmt.where(DHCPScope.group_id == args.group_id)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(DHCPScope.name).like(like),
                # ``network`` is a CIDR column; cast to text so LIKE applies.
                func.text(Subnet.network).like(like),
            )
        )
    stmt = stmt.order_by(Subnet.network.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).all()
    return [
        {
            "id": str(s.id),
            "group_id": str(s.group_id) if s.group_id else None,
            "subnet": str(network),
            "name": s.name,
            "address_family": s.address_family,
            "v6_address_mode": getattr(s, "v6_address_mode", "stateful"),
            # #637 — per-scope Kea lease-cache override; null = inherits the
            # group. Lets the copilot answer "why did this client's lease stop
            # refreshing / why is its DDNS record stale?" — a non-zero cache
            # threshold means Kea reuses the lease without a database write, so
            # no lease-event reaches DDNS or the IPAM mirror.
            "lease_cache_threshold": s.lease_cache_threshold,
            "lease_cache_max_age": s.lease_cache_max_age,
        }
        for s, network in rows
    ]


class FindDHCPLeasesArgs(BaseModel):
    server_id: str | None = None
    scope_id: str | None = None
    mac_address: str | None = Field(
        default=None,
        description="Filter by exact MAC address.",
    )
    ip_address: str | None = Field(
        default=None,
        description="Filter by exact IP address.",
    )
    hostname_search: str | None = Field(
        default=None,
        description="Substring match on the lease's reported client hostname.",
    )
    state: str | None = Field(
        default=None,
        description="Filter by lease state (active, expired, declined, released).",
    )
    device_class: str | None = Field(
        default=None,
        description=(
            "Filter by fingerbank device class (passive DHCP fingerprinting), "
            "e.g. 'Phone, Tablet or Wearable', 'Operating System', 'Hardware "
            "Manufacturer'. Only leases whose MAC has a matching fingerprint "
            "are returned."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_dhcp_leases",
    description=(
        "Find DHCP leases. Filterable by server, scope, MAC, IP, "
        "hostname substring, state, or fingerbank device class. Returns "
        "lease metadata (IP / MAC / mac_vendor / device_class / "
        "device_name / hostname / state / starts_at / ends_at). Use "
        "for questions like 'what's the lease for MAC X?', 'what's "
        "leased on subnet Y?', or 'show me the phones on this network'."
    ),
    args_model=FindDHCPLeasesArgs,
    category="dhcp",
    module="core.dhcp",
)
async def find_dhcp_leases(
    db: AsyncSession, user: User, args: FindDHCPLeasesArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPLease)
    if args.server_id:
        stmt = stmt.where(DHCPLease.server_id == args.server_id)
    if args.scope_id:
        stmt = stmt.where(DHCPLease.scope_id == args.scope_id)
    if args.mac_address:
        stmt = stmt.where(DHCPLease.mac_address == args.mac_address)
    if args.ip_address:
        stmt = stmt.where(
            func.host(DHCPLease.ip_address) == func.host(cast(literal(args.ip_address), INET))
        )
    if args.hostname_search:
        like = f"%{args.hostname_search.lower()}%"
        stmt = stmt.where(func.lower(DHCPLease.hostname).like(like))
    if args.state:
        stmt = stmt.where(DHCPLease.state == args.state)
    if args.device_class:
        stmt = stmt.join(
            DHCPFingerprint, DHCPFingerprint.mac_address == DHCPLease.mac_address
        ).where(DHCPFingerprint.fingerbank_device_class == args.device_class)
    stmt = stmt.order_by(DHCPLease.ends_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    vendors = await bulk_lookup_vendors(db, [str(le.mac_address) for le in rows])
    # Batch-fetch fingerprints for the result MACs (one query) so each lease
    # can report its fingerbank device class/name without a per-row lookup.
    macs = [str(le.mac_address) for le in rows if le.mac_address]
    fps: dict[str, DHCPFingerprint] = {}
    if macs:
        fp_rows = (
            await db.execute(select(DHCPFingerprint).where(DHCPFingerprint.mac_address.in_(macs)))
        ).scalars()
        for fp in fp_rows:
            fps[normalize_mac_key(str(fp.mac_address))] = fp
    out: list[dict[str, Any]] = []
    for le in rows:
        mac_key = normalize_mac_key(str(le.mac_address))
        vendor = vendors.get(mac_key) if mac_key else None
        fp = fps.get(mac_key) if mac_key else None
        out.append(
            {
                "id": str(le.id),
                "server_id": str(le.server_id),
                "scope_id": str(le.scope_id) if le.scope_id else None,
                "ip_address": str(le.ip_address),
                "mac_address": str(le.mac_address),
                "mac_vendor": vendor,
                "is_voip_phone": is_voip_phone_vendor(vendor),
                "device_class": fp.fingerbank_device_class if fp else None,
                "device_name": fp.fingerbank_device_name if fp else None,
                "device_manufacturer": fp.fingerbank_manufacturer if fp else None,
                "fingerbank_score": fp.fingerbank_score if fp else None,
                "hostname": le.hostname,
                "state": le.state,
                "starts_at": le.starts_at.isoformat() if le.starts_at else None,
                "ends_at": le.ends_at.isoformat() if le.ends_at else None,
            }
        )
    return out


class ListServerGroupsArgs(BaseModel):
    pass


@register_tool(
    name="list_dhcp_server_groups",
    description=(
        "List DHCP server groups (logical bundles of Kea servers, "
        "with HA implicit when the group has ≥ 2 members). Each "
        "summary includes name, member count, HA mode, "
        "dhcp_socket_mode ('direct' = raw sockets that hear broadcast "
        "DISCOVERs from on-LAN clients; 'relay' = udp, relay-only), and the "
        "group-wide Kea lease cache (lease_cache_threshold 0.0 = disabled / "
        "every renewal writes through; > 0 = Kea reuses a lease without a "
        "database write, which suppresses lease-events and can leave DDNS "
        "records and IPAM last-seen timestamps stale)."
    ),
    args_model=ListServerGroupsArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_server_groups(
    db: AsyncSession, user: User, args: ListServerGroupsArgs
) -> list[dict[str, Any]]:
    rows = (
        (await db.execute(select(DHCPServerGroup).order_by(DHCPServerGroup.name.asc())))
        .scalars()
        .all()
    )
    out: list[dict[str, Any]] = []
    for g in rows:
        member_count = await db.scalar(
            select(func.count(DHCPServer.id)).where(DHCPServer.server_group_id == g.id)
        )
        out.append(
            {
                "id": str(g.id),
                "name": g.name,
                # #923: DHCPServerGroup carries no ``ddns_enabled`` column —
                # DDNS is configured per scope and inherited down the IPAM
                # chain, not on the server group — so reading it raised
                # AttributeError and this tool answered nothing at all.
                # ``mode`` (the HA mode) is the group-level fact a caller
                # asking about a server group actually needs.
                "mode": g.mode,
                # #365 — "direct" (raw sockets, hears broadcast DISCOVERs) or
                # "relay" (udp sockets, relay-only). Helps the copilot answer
                # "why isn't this DHCP server replying to direct clients?".
                "dhcp_socket_mode": g.dhcp_socket_mode,
                # #637 — group-wide Kea lease cache. 0.0 = disabled (the Kea 2.6
                # write-through behaviour we default to); Kea 3.0's own default
                # would be 0.25. Scopes may override this individually.
                "lease_cache_threshold": g.lease_cache_threshold,
                "lease_cache_max_age": g.lease_cache_max_age,
                "member_count": int(member_count or 0),
            }
        )
    return out


# ── Tier 3 DHCP sub-resource depth (issue #101) ───────────────────────


# ── list_dhcp_pools ───────────────────────────────────────────────────


class ListDHCPPoolsArgs(BaseModel):
    scope_id: str | None = Field(default=None, description="Filter to one DHCP scope by UUID.")
    pool_type: str | None = Field(
        default=None,
        description="Filter by pool_type: dynamic / excluded / reserved / pd (v6 prefix delegation).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dhcp_pools",
    description=(
        "List DHCP pools — IP ranges within a scope, classified as "
        "dynamic (lease pool), excluded (skip during allocation), or "
        "reserved (operator-managed). Each row carries id, scope_id, "
        "name, start_ip + end_ip, pool_type, optional class_restriction, "
        "lease_time_override, and any options_override. Use for "
        "'what's the dynamic range in the corp scope?', 'show "
        "excluded ranges', or 'is the IoT pool restricted to a "
        "client class?'."
    ),
    args_model=ListDHCPPoolsArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_pools(
    db: AsyncSession, user: User, args: ListDHCPPoolsArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPPool)
    if args.scope_id:
        stmt = stmt.where(DHCPPool.scope_id == args.scope_id)
    if args.pool_type:
        stmt = stmt.where(DHCPPool.pool_type == args.pool_type.lower())
    stmt = stmt.order_by(DHCPPool.scope_id, DHCPPool.start_ip).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(p.id),
            "scope_id": str(p.scope_id),
            "name": p.name,
            "start_ip": str(p.start_ip),
            "end_ip": str(p.end_ip),
            "pool_type": p.pool_type,
            "class_restriction": p.class_restriction,
            "lease_time_override": p.lease_time_override,
            "options_override": p.options_override,
            # DHCPv6 prefix delegation (issue #368) — populated only on
            # pool_type == "pd" pools.
            "pd_prefix": getattr(p, "pd_prefix", None),
            "delegated_length": getattr(p, "delegated_length", None),
            "excluded_prefix": getattr(p, "excluded_prefix", None),
        }
        for p in rows
    ]


# ── list_dhcp_statics ─────────────────────────────────────────────────


class ListDHCPStaticsArgs(BaseModel):
    scope_id: str | None = Field(default=None, description="Filter to one DHCP scope by UUID.")
    mac_address: str | None = Field(default=None, description="Exact MAC address match.")
    ip_address: str | None = Field(default=None, description="Exact IP address match.")
    hostname_contains: str | None = Field(
        default=None, description="Substring match on the hostname."
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dhcp_statics",
    description=(
        "List DHCP static reservations (MAC → IP). Filterable by "
        "scope, MAC, IP, or hostname substring. Each row carries id, "
        "scope_id, ip_address, mac_address, client_id, hostname, "
        "description, options_override, and the linked IPAM "
        "ip_address_id when bound. Use for 'show statics for the "
        "voip scope', 'is 11:22:33:44:55:66 reserved?', or 'find "
        "every static for hostname matching printer*'."
    ),
    args_model=ListDHCPStaticsArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_statics(
    db: AsyncSession, user: User, args: ListDHCPStaticsArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPStaticAssignment)
    if args.scope_id:
        stmt = stmt.where(DHCPStaticAssignment.scope_id == args.scope_id)
    if args.mac_address:
        stmt = stmt.where(DHCPStaticAssignment.mac_address == args.mac_address.lower())
    if args.ip_address:
        stmt = stmt.where(DHCPStaticAssignment.ip_address == args.ip_address)
    if args.hostname_contains:
        stmt = stmt.where(
            func.lower(DHCPStaticAssignment.hostname).like(f"%{args.hostname_contains.lower()}%")
        )
    stmt = stmt.order_by(DHCPStaticAssignment.ip_address.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(s.id),
            "scope_id": str(s.scope_id),
            "ip_address": str(s.ip_address),
            "mac_address": str(s.mac_address),
            "client_id": s.client_id,
            "duid": getattr(s, "duid", None),
            "hostname": s.hostname,
            "description": s.description,
            "options_override": s.options_override,
            "ip_address_id": str(s.ip_address_id) if s.ip_address_id else None,
        }
        for s in rows
    ]


# ── list_dhcp_client_classes ──────────────────────────────────────────


class ListDHCPClientClassesArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DHCP server group UUID.")
    search: str | None = Field(default=None, description="Substring match on class name.")
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dhcp_client_classes",
    description=(
        "List DHCP client classes — group-scoped expressions used "
        "for conditional option delivery. Each row carries id, "
        "group_id, name, match_expression (the Kea expression), "
        "description, and the option overrides JSON. Use for 'what "
        "client classes are defined for corp?' or 'show me the "
        "match expression for the IoT class'."
    ),
    args_model=ListDHCPClientClassesArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_client_classes(
    db: AsyncSession, user: User, args: ListDHCPClientClassesArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPClientClass)
    if args.group_id:
        stmt = stmt.where(DHCPClientClass.group_id == args.group_id)
    if args.search:
        stmt = stmt.where(func.lower(DHCPClientClass.name).like(f"%{args.search.lower()}%"))
    stmt = stmt.order_by(DHCPClientClass.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(c.id),
            "group_id": str(c.group_id),
            "name": c.name,
            "match_expression": c.match_expression,
            "description": c.description,
            "options": c.options,
        }
        for c in rows
    ]


# ── list_dhcp_option_templates ────────────────────────────────────────


class ListDHCPOptionTemplatesArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DHCP server group UUID.")
    address_family: str | None = Field(
        default=None,
        description="Filter by address family: ``ipv4`` or ``ipv6``.",
    )
    search: str | None = Field(default=None, description="Substring match on template name.")
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dhcp_option_templates",
    description=(
        "List DHCP option templates — reusable named bundles of "
        "option-code → value pairs scoped per server group. Apply "
        "stamps the bundle into a scope's options dict at apply "
        "time (no runtime re-bind). Each row carries id, group_id, "
        "name, address_family (ipv4 / ipv6), description, and the "
        "options JSON. Use for 'what option templates exist?' or "
        "'show me the options in the corp template'."
    ),
    args_model=ListDHCPOptionTemplatesArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_option_templates(
    db: AsyncSession, user: User, args: ListDHCPOptionTemplatesArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPOptionTemplate)
    if args.group_id:
        stmt = stmt.where(DHCPOptionTemplate.group_id == args.group_id)
    if args.address_family:
        stmt = stmt.where(DHCPOptionTemplate.address_family == args.address_family.lower())
    if args.search:
        stmt = stmt.where(func.lower(DHCPOptionTemplate.name).like(f"%{args.search.lower()}%"))
    stmt = stmt.order_by(DHCPOptionTemplate.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(t.id),
            "group_id": str(t.group_id),
            "name": t.name,
            "address_family": t.address_family,
            "description": t.description,
            "options": t.options,
        }
        for t in rows
    ]


# ── list_pxe_profiles ─────────────────────────────────────────────────


class ListPXEProfilesArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DHCP server group UUID.")
    enabled: bool | None = Field(default=None, description="Filter by ``enabled`` flag.")
    search: str | None = Field(default=None, description="Substring match on profile name.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_pxe_profiles",
    description=(
        "List PXE / iPXE provisioning profiles — group-scoped, "
        "operator-pickable per scope via DHCPScope.pxe_profile_id. "
        "Each row carries id, group_id, name, description, "
        "next_server (TFTP/HTTP boot server IP), enabled flag, and "
        "the per-arch matches (vendor_class + arch_code → boot "
        "file). Use for 'what PXE profiles are configured?' or 'is "
        "the lab profile enabled?'."
    ),
    args_model=ListPXEProfilesArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_pxe_profiles(
    db: AsyncSession, user: User, args: ListPXEProfilesArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPPXEProfile)
    if args.group_id:
        stmt = stmt.where(DHCPPXEProfile.group_id == args.group_id)
    if args.enabled is not None:
        stmt = stmt.where(DHCPPXEProfile.enabled.is_(args.enabled))
    if args.search:
        stmt = stmt.where(func.lower(DHCPPXEProfile.name).like(f"%{args.search.lower()}%"))
    stmt = stmt.order_by(DHCPPXEProfile.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(p.id),
            "group_id": str(p.group_id),
            "name": p.name,
            "description": p.description,
            "next_server": p.next_server,
            "enabled": p.enabled,
            "match_count": len(p.matches or []),
            "matches": [
                {
                    "vendor_class": getattr(m, "vendor_class", None),
                    "arch_code": getattr(m, "arch_code", None),
                    "boot_file": getattr(m, "boot_file", None),
                    "priority": getattr(m, "priority", None),
                }
                for m in (p.matches or [])
            ],
        }
        for p in rows
    ]


# ── list_phone_profiles ──────────────────────────────────────────────


class ListPhoneProfilesArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DHCP server group UUID.")
    enabled: bool | None = Field(default=None, description="Filter by ``enabled`` flag.")
    vendor: str | None = Field(default=None, description="Filter by curated vendor label.")
    search: str | None = Field(default=None, description="Substring match on profile name.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="list_phone_profiles",
    description=(
        "List VoIP phone provisioning profiles — group-scoped, attached "
        "to scopes via the dhcp_phone_profile_scope join. Each row "
        "carries id, group_id, name, vendor (curated label like "
        "'Polycom' / 'Yealink' / 'Cisco SPA' or null for custom), "
        "vendor_class_match (option-60 substring fence), enabled "
        "flag, the option set delivered (DHCP option codes + values), "
        "and the count of attached scopes. Use for 'is the Polycom "
        "profile attached anywhere?' or 'which voice VLANs have phone "
        "profiles?'."
    ),
    args_model=ListPhoneProfilesArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_phone_profiles(
    db: AsyncSession, user: User, args: ListPhoneProfilesArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPPhoneProfile)
    if args.group_id:
        stmt = stmt.where(DHCPPhoneProfile.group_id == args.group_id)
    if args.enabled is not None:
        stmt = stmt.where(DHCPPhoneProfile.enabled.is_(args.enabled))
    if args.vendor:
        stmt = stmt.where(func.lower(DHCPPhoneProfile.vendor) == args.vendor.lower())
    if args.search:
        stmt = stmt.where(func.lower(DHCPPhoneProfile.name).like(f"%{args.search.lower()}%"))
    stmt = stmt.order_by(DHCPPhoneProfile.name.asc()).limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())

    if not rows:
        return []

    # Roll up scope-attachment counts in one query rather than per-row.
    counts_stmt = (
        select(
            DHCPPhoneProfileScope.profile_id,
            func.count(DHCPPhoneProfileScope.scope_id),
        )
        .where(DHCPPhoneProfileScope.profile_id.in_([p.id for p in rows]))
        .group_by(DHCPPhoneProfileScope.profile_id)
    )
    counts: dict[Any, int] = {}
    for pid, n in (await db.execute(counts_stmt)).all():
        counts[pid] = int(n)

    return [
        {
            "id": str(p.id),
            "group_id": str(p.group_id),
            "name": p.name,
            "description": p.description,
            "vendor": p.vendor,
            "vendor_class_match": p.vendor_class_match,
            "enabled": p.enabled,
            "option_count": len(p.option_set or []),
            "options": [
                {
                    "code": o.get("code"),
                    "name": o.get("name"),
                    "value": o.get("value"),
                }
                for o in (p.option_set or [])
            ],
            "scope_count": counts.get(p.id, 0),
        }
        for p in rows
    ]


# ── list_dhcp_mac_blocks ──────────────────────────────────────────────


class ListDHCPMACBlocksArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter by DHCP server group UUID.")
    mac_address: str | None = Field(default=None, description="Exact MAC match.")
    enabled: bool | None = Field(default=None, description="Filter by ``enabled`` flag.")
    reason: str | None = Field(
        default=None,
        description="Filter by reason: rogue / lost_stolen / quarantine / policy / other.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_dhcp_mac_blocks",
    description=(
        "List blocked MAC addresses — group-global, applies to "
        "every scope in the group. Each row carries id, group_id, "
        "mac_address, reason, description, enabled flag, and "
        "expires_at (when timed). Use for 'is the rogue MAC "
        "blocked?', 'list lost/stolen entries', or 'when does the "
        "quarantine expire?'."
    ),
    args_model=ListDHCPMACBlocksArgs,
    category="dhcp",
    module="core.dhcp",
)
async def list_dhcp_mac_blocks(
    db: AsyncSession, user: User, args: ListDHCPMACBlocksArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPMACBlock)
    if args.group_id:
        stmt = stmt.where(DHCPMACBlock.group_id == args.group_id)
    if args.mac_address:
        stmt = stmt.where(DHCPMACBlock.mac_address == args.mac_address.lower())
    if args.enabled is not None:
        stmt = stmt.where(DHCPMACBlock.enabled.is_(args.enabled))
    if args.reason:
        stmt = stmt.where(DHCPMACBlock.reason == args.reason.lower())
    stmt = stmt.order_by(DHCPMACBlock.mac_address.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(b.id),
            "group_id": str(b.group_id),
            "mac_address": str(b.mac_address),
            "reason": b.reason,
            "description": b.description,
            "enabled": b.enabled,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
        }
        for b in rows
    ]


class FindDHCPPoolOccupancyArgs(BaseModel):
    group_id: str | None = Field(default=None, description="Filter to one DHCP server group UUID.")
    scope_id: str | None = Field(default=None, description="Filter to one DHCP scope UUID.")
    min_percent: float = Field(
        default=0.0,
        description="Only return pools at or above this live occupancy percent (0-100).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_dhcp_pool_occupancy",
    description=(
        "Live occupancy of dynamic DHCP pools — assigned vs total addresses, "
        "free count, and occupancy percent, computed from active leases inside "
        "each pool range (works for Kea and Windows DHCP). Sorted most-full "
        "first. Use to answer 'which pools are near capacity / exhausted?'."
    ),
    args_model=FindDHCPPoolOccupancyArgs,
    category="dhcp",
    module="core.dhcp",
)
async def find_dhcp_pool_occupancy(
    db: AsyncSession, user: User, args: FindDHCPPoolOccupancyArgs
) -> list[dict[str, Any]]:
    from app.services.dhcp.pool_occupancy import compute_pool_occupancy_batch

    stmt = select(DHCPPool, DHCPScope).join(DHCPScope, DHCPScope.id == DHCPPool.scope_id)
    stmt = stmt.where(DHCPPool.pool_type == "dynamic")
    if args.scope_id:
        stmt = stmt.where(DHCPPool.scope_id == args.scope_id)
    if args.group_id:
        stmt = stmt.where(DHCPScope.group_id == args.group_id)
    # ``.unique()`` is a harmless leftover, not a requirement: DHCPScope's
    # collections are selectin-loaded as of #617, so no joined-collection rows
    # need de-duplicating.
    rows = (await db.execute(stmt)).unique().all()

    # One batched lease query for all pools rather than one per pool (N+1).
    occ_by_pool = await compute_pool_occupancy_batch(db, [pool for pool, _ in rows])

    out: list[dict[str, Any]] = []
    for pool, scope in rows:
        occ = occ_by_pool[pool.id]
        if occ.percent < args.min_percent:
            continue
        out.append(
            {
                "pool_id": str(pool.id),
                "pool_name": pool.name or None,
                "scope_id": str(pool.scope_id),
                "scope_name": scope.name or None,
                "group_id": str(scope.group_id),
                "start_ip": str(pool.start_ip),
                "end_ip": str(pool.end_ip),
                "assigned": occ.assigned,
                "total": occ.total,
                "free": occ.free,
                "occupancy_percent": round(occ.percent, 1),
            }
        )
    out.sort(key=lambda r: r["occupancy_percent"], reverse=True)
    return out[: args.limit]


# ── find_dhcp_failover_relationships (issue #1110) ────────────────────
#
# Deliberately no ``propose_*`` counterpart for the Phase 2 management routes
# (non-negotiable #13, explicit decision): creating, removing or re-scoping a
# relationship creates and DELETES scopes on the partner server, and creating
# one carries the relationship's shared secret — the broad-blast-radius,
# secret-bearing shape that guidance keeps off the copilot.


class FindDHCPFailoverRelationshipsArgs(BaseModel):
    group_id: str | None = Field(
        default=None,
        description=(
            "Limit to one DHCP server group (UUID). Omit to cover every group "
            "with a Windows DHCP member."
        ),
    )
    only_at_risk: bool = Field(
        default=False,
        description=(
            "Return only scopes that are NOT safely served — held by several "
            "Windows servers with no failover relationship, or whose "
            "coordination could not be read, or failover partners whose "
            "configuration has drifted."
        ),
    )


@register_tool(
    name="find_dhcp_failover_relationships",
    description=(
        "Windows DHCP failover relationships as each Windows server reports "
        "them (Get-DhcpServerv4Failover): name, mode (LoadBalance / "
        "HotStandby), per-side role, state and load-balance share, MCLT, and "
        "the scopes each covers — plus, per scope, which Windows servers of the "
        "group hold it and a verdict: single_server, failover, "
        "failover_one_sided (partner not in the group), split_scope, or "
        "uncoordinated (two servers can hand out the same address). Use for "
        "'are my Windows DHCP servers in failover?', 'which scopes could get "
        "duplicate addresses?', or 'are the partners' configs in sync?'. From "
        "the topology poll's stored observations, not a live read. Windows "
        "failover syncs leases between partners but NOT configuration. A group "
        "that also has Kea members lists them in kea_members; a scope both a Kea "
        "and a Windows member serve is reported uncoordinated. Read-only: "
        "relationships are created and changed from the group's Windows failover "
        "panel or its REST routes, never from chat."
    ),
    args_model=FindDHCPFailoverRelationshipsArgs,
    category="dhcp",
    module="core.dhcp",
)
async def find_dhcp_failover_relationships(
    db: AsyncSession, user: User, args: FindDHCPFailoverRelationshipsArgs
) -> list[dict[str, Any]]:
    # The same report the group view renders, run through the same response
    # model so timestamps and ids come out as the REST route emits them.
    from app.api.v1.dhcp._failover_schemas import GroupFailoverResponse  # noqa: PLC0415
    from app.services.dhcp.windows_failover_report import (  # noqa: PLC0415
        group_failover_report,
    )

    stmt = (
        select(DHCPServerGroup)
        .join(DHCPServer, DHCPServer.server_group_id == DHCPServerGroup.id)
        .where(DHCPServer.driver == "windows_dhcp")
        .distinct()
        .order_by(DHCPServerGroup.name)
    )
    if args.group_id:
        stmt = stmt.where(DHCPServerGroup.id == args.group_id)
    groups = (await db.execute(stmt)).scalars().all()
    out: list[dict[str, Any]] = []
    for group in groups:
        report = GroupFailoverResponse.model_validate(
            await group_failover_report(db, group)
        ).model_dump(mode="json")
        if args.only_at_risk:
            report["scopes"] = [s for s in report["scopes"] if not s["safe"] or s.get("drift")]
        report["group_name"] = group.name
        out.append(report)
    return out


# ── find_dhcp_responders (issue #370) ─────────────────────────────────


class FindDHCPRespondersArgs(BaseModel):
    group_id: str | None = Field(
        default=None, description="Filter to one DHCP server group by UUID."
    )
    classification: str | None = Field(
        default=None,
        description="Filter by classification: expected / acknowledged / rogue.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_dhcp_responders",
    description=(
        "List DHCP servers the active rogue-detection probe has observed "
        "answering on managed segments (issue #370). Each row carries the "
        "source IP / MAC, server-identifier, offered IP, classification "
        "(expected = a known group member, acknowledged = operator-allowlisted, "
        "rogue = unknown responder), and last-seen time. Filter "
        "classification='rogue' to answer 'is there a rogue DHCP server on my "
        "network?'. Read-only; only has data on segments running the probe."
    ),
    args_model=FindDHCPRespondersArgs,
    category="dhcp",
    module="core.dhcp",
)
async def find_dhcp_responders(
    db: AsyncSession, user: User, args: FindDHCPRespondersArgs
) -> list[dict[str, Any]]:
    from app.models.dhcp import DHCPObservedResponder  # noqa: PLC0415

    stmt = select(DHCPObservedResponder)
    if args.group_id:
        stmt = stmt.where(DHCPObservedResponder.group_id == args.group_id)
    if args.classification:
        stmt = stmt.where(DHCPObservedResponder.classification == args.classification.lower())
    stmt = stmt.order_by(DHCPObservedResponder.last_seen_at.desc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(r.id),
            "group_id": str(r.group_id),
            "server_identifier": r.server_identifier,
            "source_ip": str(r.source_ip),
            "source_mac": str(r.source_mac) if r.source_mac else None,
            "giaddr": str(r.giaddr) if r.giaddr else None,
            "offered_ip": str(r.offered_ip) if r.offered_ip else None,
            "classification": r.classification,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        }
        for r in rows
    ]


class FindDHCPServerStatsArgs(BaseModel):
    server_id: str = Field(description="DHCP server UUID to summarize.")
    range: str = Field(default="1h", description="Time window: 1h, 6h, 24h, or 7d.")


@register_tool(
    name="find_dhcp_server_stats",
    description=(
        "Summarize a DHCP server's recent traffic: active lease count and "
        "per-message-type totals (discover/offer/request/ack/nak/decline/"
        "release) over a 1h/6h/24h/7d window, plus packets LOST over that "
        "window. Use for 'how busy is server X?' and 'is server X dropping "
        "packets?'. socket_drop counts packets the kernel dropped before the "
        "server could read them (its receive buffer filled — the node is "
        "short of CPU); receive_drop counts packets the server read and then "
        "discarded. Either may be null, meaning the agent did not measure it "
        "(too old, or cannot read /proc/net/udp) — null is NOT zero, and must "
        "not be reported as 'no packets were dropped'."
    ),
    args_model=FindDHCPServerStatsArgs,
    category="dhcp",
    # Read-only summary of agent-reported counters; no secrets, no off-prem
    # calls, no writes -> default-enabled per non-negotiable #13.
    default_enabled=True,
    module="core.dhcp",
)
async def find_dhcp_server_stats(
    db: AsyncSession, user: User, args: FindDHCPServerStatsArgs
) -> dict[str, Any]:
    """Window totals (not per-bucket) — the AI wants a summary, not a chart."""
    if args.range not in STATS_WINDOW_SECONDS:
        return {
            "error": f"invalid range: {args.range!r}; "
            f"must be one of {sorted(STATS_WINDOW_SECONDS)}"
        }
    rng = args.range
    try:
        sid = uuid.UUID(args.server_id)
    except (ValueError, AttributeError):
        return {"error": f"invalid server_id: {args.server_id!r}"}

    server = await db.get(DHCPServer, sid)
    if server is None:
        return {"error": f"DHCP server {args.server_id} not found"}

    since = datetime.now(UTC) - timedelta(seconds=STATS_WINDOW_SECONDS[rng])

    leases_active = await active_lease_count(db, sid)

    totals_row = (
        await db.execute(
            select(
                func.coalesce(func.sum(DHCPMetricSample.discover), 0).label("discover"),
                func.coalesce(func.sum(DHCPMetricSample.offer), 0).label("offer"),
                func.coalesce(func.sum(DHCPMetricSample.request), 0).label("request"),
                func.coalesce(func.sum(DHCPMetricSample.ack), 0).label("ack"),
                func.coalesce(func.sum(DHCPMetricSample.nak), 0).label("nak"),
                func.coalesce(func.sum(DHCPMetricSample.decline), 0).label("decline"),
                func.coalesce(func.sum(DHCPMetricSample.release), 0).label("release"),
                # #980 — not coalesced: SUM over an all-NULL group is NULL,
                # which means "not measured" and must reach the model as
                # null rather than as a zero it would summarise as healthy.
                func.sum(DHCPMetricSample.receive_drop).label("receive_drop"),
                func.sum(DHCPMetricSample.socket_drop).label("socket_drop"),
            )
            .where(DHCPMetricSample.server_id == sid)
            .where(DHCPMetricSample.bucket_at >= since)
        )
    ).one()

    return {
        "server_id": str(sid),
        "server_name": server.name,
        "range": rng,
        "leases_active": int(leases_active),
        "totals": {
            "discover": int(totals_row.discover or 0),
            "offer": int(totals_row.offer or 0),
            "request": int(totals_row.request or 0),
            "ack": int(totals_row.ack or 0),
            "nak": int(totals_row.nak or 0),
            "decline": int(totals_row.decline or 0),
            "release": int(totals_row.release or 0),
        },
        # #980. Kept out of ``totals`` deliberately: those are messages
        # handled, these are messages not handled, and folding them into one
        # dict invites a model to add them up.
        #
        # ``measured`` keys on socket_drop ALONE. receive_drop always arrives
        # from a #980 agent, so testing the pair would report a server whose
        # kernel-side loss is unmeasurable as measured-and-clean — the exact
        # false reassurance the counters exist to remove.
        "packet_loss": {
            "socket_drop": (
                None if totals_row.socket_drop is None else int(totals_row.socket_drop)
            ),
            "receive_drop": (
                None if totals_row.receive_drop is None else int(totals_row.receive_drop)
            ),
            "measured": totals_row.socket_drop is not None,
            "note": (
                "socket_drop is lost traffic; receive_drop also counts deliberate "
                "drops (blocklisted MAC, HA out-of-scope) and is not by itself a fault"
            ),
        },
    }


# ── find_dhcp_lease_history (issue #917) ─────────────────────────────


class FindDHCPLeaseHistoryArgs(BaseModel):
    mac_address: str | None = Field(
        default=None, description="Substring match on MAC (any separator form)."
    )
    ip_address: str | None = Field(default=None, description="IP or CIDR.")
    hostname_search: str | None = Field(default=None, description="Hostname substring.")
    lease_state: str | None = Field(
        default=None, description="expired | released | removed | superseded."
    )
    server_id: str | None = Field(default=None, description="Filter to one DHCP server UUID.")
    days: int = Field(default=90, ge=1, le=3650, description="Trailing window in days.")
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_dhcp_lease_history",
    description=(
        "Expired / released DHCP leases across every server — 'has this MAC "
        "EVER had a lease here?', which find_dhcp_leases cannot answer "
        "because it only sees leases that are still active. Use it to place "
        "a device that is now offline, or to find which address a machine "
        "used to hold. Retention follows "
        "dhcp_lease_history_retention_days (default 90)."
    ),
    args_model=FindDHCPLeaseHistoryArgs,
    category="dhcp",
    module="core.dhcp",
)
async def find_dhcp_lease_history(
    db: AsyncSession, user: User, args: FindDHCPLeaseHistoryArgs
) -> list[dict[str, Any]]:
    from app.api.v1.dhcp.lease_history import (  # noqa: PLC0415
        VALID_LEASE_HISTORY_STATES,
        apply_lease_history_filters,
    )
    from app.models.dhcp import DHCPLeaseHistory  # noqa: PLC0415

    if args.lease_state and args.lease_state not in VALID_LEASE_HISTORY_STATES:
        return [
            {
                "result": (
                    f"{args.lease_state!r} is not a lease state; "
                    f"expected one of {sorted(VALID_LEASE_HISTORY_STATES)}"
                )
            }
        ]
    since = datetime.now(UTC) - timedelta(days=args.days)
    stmt = select(DHCPLeaseHistory).where(DHCPLeaseHistory.expired_at >= since)
    if args.server_id:
        try:
            stmt = stmt.where(DHCPLeaseHistory.server_id == str(uuid.UUID(args.server_id.strip())))
        except (ValueError, AttributeError):
            return [{"result": f"{args.server_id!r} is not a server UUID"}]
    # Shared with the REST route so the two cannot disagree about what a
    # filter means (#917).
    stmt = apply_lease_history_filters(
        stmt,
        mac=args.mac_address,
        ip=args.ip_address,
        hostname=args.hostname_search,
        lease_state=args.lease_state,
    )
    rows = (
        (await db.execute(stmt.order_by(DHCPLeaseHistory.expired_at.desc()).limit(args.limit)))
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "server_id": str(r.server_id),
            "scope_id": str(r.scope_id) if r.scope_id else None,
            "ip_address": str(r.ip_address),
            "mac_address": str(r.mac_address),
            "hostname": r.hostname,
            "lease_state": r.lease_state,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "expired_at": r.expired_at.isoformat() if r.expired_at else None,
        }
        for r in rows
    ]


# ── Fingerprint-driven device policies (#700) ──────────────────────────────


class ListDevicePoliciesArgs(BaseModel):
    group_id: uuid.UUID | None = Field(default=None, description="Filter to one DHCP server group.")
    enabled_only: bool = Field(default=False, description="Only policies that are switched on.")


@register_tool(
    name="find_dhcp_device_policies",
    description=(
        "List fingerprint-driven DHCP device policies (issue #700) — the rules "
        "that give devices of a given fingerbank class (Printer, IoT, game "
        "console, …) a specific option set, lease time and optionally a "
        "restricted pool. Each row reports the Kea client-class it compiles to "
        "and whether it currently matches anything."
    ),
    args_model=ListDevicePoliciesArgs,
    category="dhcp",
    default_enabled=True,
    module="core.dhcp",
)
async def find_dhcp_device_policies(
    db: AsyncSession, user: User, args: ListDevicePoliciesArgs
) -> list[dict[str, Any]]:
    stmt = select(DHCPDevicePolicy)
    if args.group_id:
        stmt = stmt.where(DHCPDevicePolicy.group_id == args.group_id)
    if args.enabled_only:
        stmt = stmt.where(DHCPDevicePolicy.enabled.is_(True))
    stmt = stmt.order_by(DHCPDevicePolicy.priority, DHCPDevicePolicy.name)
    rows = list((await db.execute(stmt)).scalars().all())
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "group_id": str(r.group_id),
            "enabled": r.enabled,
            "kea_client_class": r.class_name,
            "device_classes": list(r.device_classes or []),
            "lease_time": r.lease_time,
            "options": dict(r.options or {}),
            "has_manual_override": bool(r.match_override),
            "include_ambiguous": r.include_ambiguous,
            "priority": r.priority,
        }
        for r in rows
    ]


class PreviewDevicePolicyArgs(BaseModel):
    policy_id: uuid.UUID = Field(description="The device policy to compile.")


@register_tool(
    name="preview_dhcp_device_policy",
    description=(
        "Compile one fingerprint-driven DHCP device policy and report exactly "
        "what it matches: the Kea expression, how many observed signatures went "
        "into it, which devices it currently catches, and any signatures "
        "excluded because devices outside the selected classes emit them too. "
        "Read-only — it changes no configuration."
    ),
    args_model=PreviewDevicePolicyArgs,
    category="dhcp",
    default_enabled=True,
    module="core.dhcp",
)
async def preview_dhcp_device_policy(
    db: AsyncSession, user: User, args: PreviewDevicePolicyArgs
) -> dict[str, Any]:
    row = await db.get(DHCPDevicePolicy, args.policy_id)
    if row is None:
        return {"error": "Device policy not found", "policy_id": str(args.policy_id)}
    compiled = await compile_device_policy(db, row)
    return {
        "id": str(row.id),
        "name": row.name,
        "kea_client_class": row.class_name,
        "expression": compiled.expression,
        "source": compiled.source,
        "renders": bool(row.enabled and compiled.expression),
        "signature_count": len(compiled.signatures),
        "matched_device_count": len(compiled.matched_macs),
        "matched_macs": compiled.matched_macs[:50],
        "ambiguous_signature_count": len(compiled.ambiguous),
        "ambiguous_excluded": bool(compiled.ambiguous) and not row.include_ambiguous,
        "truncated_signatures": compiled.truncated,
        "unclassified_matches": compiled.unclassified_matches,
        "warnings": compiled.warnings,
        "note": (
            "Matching is over DHCP signatures already observed and classified. "
            "A device whose signature has never been seen does not match until "
            "it has leased once and been classified — policies apply from the "
            "next renewal, not instantly."
        ),
    }
