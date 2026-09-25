"""Read-only IPAM tools for the Operator Copilot (issue #90 Wave 2).

Each tool wraps a small, focused query against the existing IPAM
service / model layer and returns a JSON-serializable result. The
Pydantic args models double as JSON-Schema generators for the LLM
tool-call interface.

Tools deliberately return *summaries* — operator-readable subsets of
each row's columns, not the full ORM object. Keeps token cost down
and avoids leaking secrets / large blobs.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import Select, String, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address_set import AddressSet
from app.models.asn import ASN
from app.models.auth import User
from app.models.circuit import Circuit
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSZone
from app.models.domain import Domain
from app.models.ipam import (
    IPAddress,
    IPBlock,
    IPSpace,
    Subnet,
    SubnetUtilizationHistory,
)
from app.models.network import NetworkDevice
from app.models.network_service import NetworkService
from app.models.overlay import OverlayNetwork
from app.models.vrf import VRF
from app.services.ai.tools.base import register_tool
from app.services.ipam.probe_policy import resolve_probe_policy
from app.services.oui import bulk_lookup_vendors, is_voip_phone_vendor, normalize_mac_key
from app.services.tags import apply_tag_filter

# ── Reference resolution ──────────────────────────────────────────────
#
# The LLM frequently passes a *name* where the schema declares a UUID
# (e.g. ``space_id="home"`` because the operator said "the home space").
# Rather than make the model take a two-step "look up the UUID, then
# query" dance for every question, the IPAM read-tools accept either
# form and resolve names case-insensitively. Returns ``None`` when the
# name doesn't match any row — the caller raises a tool-level error
# pointing the model at the right list_* tool.


async def _resolve_space_ref(db: AsyncSession, value: str) -> uuid.UUID | None:
    """Translate an ``id-or-name`` reference into an ``IPSpace.id``.

    Tries UUID parse first, then case-insensitive name match. Returns
    ``None`` if neither hits — the tool wrapper turns that into an
    operator-readable error.
    """
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        pass
    row = (
        await db.execute(select(IPSpace.id).where(func.lower(IPSpace.name) == value.lower()))
    ).scalar_one_or_none()
    return row


async def _resolve_block_ref(db: AsyncSession, value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        pass
    row = (
        await db.execute(select(IPBlock.id).where(func.lower(IPBlock.name) == value.lower()))
    ).scalar_one_or_none()
    return row


# ── list_ip_spaces ────────────────────────────────────────────────────


class ListSpacesArgs(BaseModel):
    search: str | None = Field(
        default=None,
        description="Optional case-insensitive substring match on the space name or description.",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="list_ip_spaces",
    description=(
        "List IP spaces (top-level routing domains / VRFs). "
        "Returns each space's id, name, description, default flag, "
        "and tag count."
    ),
    args_model=ListSpacesArgs,
    category="ipam",
)
async def list_ip_spaces(
    db: AsyncSession, user: User, args: ListSpacesArgs
) -> list[dict[str, Any]]:
    stmt = select(IPSpace).where(IPSpace.deleted_at.is_(None))
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(IPSpace.name).like(like),
                func.lower(IPSpace.description).like(like),
            )
        )
    stmt = stmt.order_by(IPSpace.name.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "description": s.description,
            "is_default": s.is_default,
            "tag_count": len(s.tags or {}),
        }
        for s in rows
    ]


# ── list_ip_blocks ────────────────────────────────────────────────────


class ListBlocksArgs(BaseModel):
    space_id: str | None = Field(
        default=None,
        description=(
            "Filter by IP space — accepts either the UUID or the "
            "space name (case-insensitive). Omit to list across all spaces."
        ),
    )
    search: str | None = Field(
        default=None,
        description="Optional substring match on the block name or network CIDR.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_ip_blocks",
    description=(
        "List IP blocks (aggregate / supernet ranges). Each block "
        "summary includes its CIDR, name, parent block, space, and "
        "computed utilization percentage."
    ),
    args_model=ListBlocksArgs,
    category="ipam",
)
async def list_ip_blocks(
    db: AsyncSession, user: User, args: ListBlocksArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    stmt = select(IPBlock).where(IPBlock.deleted_at.is_(None))
    if args.space_id:
        space_uuid = await _resolve_space_ref(db, args.space_id)
        if space_uuid is None:
            return {
                "error": f"No IP space matched {args.space_id!r}.",
                "hint": "Call list_ip_spaces to see available space names + UUIDs.",
            }
        stmt = stmt.where(IPBlock.space_id == space_uuid)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(IPBlock.name).like(like),
                func.text(IPBlock.network).like(like),
            )
        )
    stmt = stmt.order_by(IPBlock.network.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(b.id),
            "network": str(b.network),
            "name": b.name,
            "description": b.description,
            "space_id": str(b.space_id),
            "parent_block_id": str(b.parent_block_id) if b.parent_block_id else None,
            "utilization_percent": float(b.utilization_percent or 0.0),
        }
        for b in rows
    ]


# ── list_subnets ──────────────────────────────────────────────────────


class ListSubnetsArgs(BaseModel):
    space_id: str | None = Field(
        default=None,
        description=(
            "Filter by IP space — accepts either the UUID or the "
            "space name (case-insensitive). Omit to search across all spaces."
        ),
    )
    block_id: str | None = Field(
        default=None,
        description=(
            "Filter by parent IP block — accepts either the UUID or the "
            "block name (case-insensitive)."
        ),
    )
    vlan_id: int | None = Field(default=None, description="Filter by VLAN tag (1–4094).")
    search: str | None = Field(
        default=None,
        description="Substring match on subnet name or CIDR.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="list_subnets",
    description=(
        "List subnets — the routable units that own IP addresses. "
        "Use this tool whenever the operator names a subnet by CIDR "
        "(e.g. '192.168.0.0/24') or by substring; pass it as the "
        "``search`` argument. The response carries ``total_ips``, "
        "``allocated_ips``, ``utilization_percent``, ``gateway``, "
        "and ``vlan_id`` for every match — one call answers most "
        "subnet questions without needing a follow-up. Also "
        "filterable by space, parent block, or VLAN tag."
    ),
    args_model=ListSubnetsArgs,
    category="ipam",
)
async def list_subnets(
    db: AsyncSession, user: User, args: ListSubnetsArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    stmt = select(Subnet).where(Subnet.deleted_at.is_(None))
    if args.space_id:
        space_uuid = await _resolve_space_ref(db, args.space_id)
        if space_uuid is None:
            return {
                "error": f"No IP space matched {args.space_id!r}.",
                "hint": "Call list_ip_spaces to see available space names + UUIDs.",
            }
        stmt = stmt.where(Subnet.space_id == space_uuid)
    if args.block_id:
        block_uuid = await _resolve_block_ref(db, args.block_id)
        if block_uuid is None:
            return {
                "error": f"No IP block matched {args.block_id!r}.",
                "hint": "Call list_ip_blocks to see available block names + UUIDs.",
            }
        stmt = stmt.where(Subnet.block_id == block_uuid)
    if args.vlan_id is not None:
        stmt = stmt.where(Subnet.vlan_id == args.vlan_id)
    if args.search:
        like = f"%{args.search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Subnet.name).like(like),
                func.text(Subnet.network).like(like),
            )
        )
    stmt = stmt.order_by(Subnet.network.asc()).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(s.id),
            "network": str(s.network),
            "name": s.name,
            "description": s.description,
            "space_id": str(s.space_id),
            "block_id": str(s.block_id) if s.block_id else None,
            "vlan_id": s.vlan_id,
            "vxlan_id": s.vxlan_id,
            "gateway": str(s.gateway) if s.gateway else None,
            "utilization_percent": float(s.utilization_percent or 0.0),
            "total_ips": int(s.total_ips or 0),
            "allocated_ips": int(s.allocated_ips or 0),
            "dns_zone_id": s.dns_zone_id,
            "dhcp_server_group_id": str(s.dhcp_server_group_id) if s.dhcp_server_group_id else None,
        }
        for s in rows
    ]


# ── find_subnets_decommissioning ──────────────────────────────────────


class FindSubnetsDecommissioningArgs(BaseModel):
    within_days: int = Field(
        default=30,
        ge=0,
        le=3650,
        description=(
            "Look-ahead window in days. Returns subnets whose scheduled "
            "``decom_date`` falls on or before today + this many days "
            "(default 30). Past-due decom dates (already overdue) are "
            "always included."
        ),
    )
    limit: int = Field(default=200, ge=1, le=500)


@register_tool(
    name="find_subnets_decommissioning",
    description=(
        "List subnets with a planned decommission date (issue #46) "
        "falling within the next N days (default 30) — plus any that "
        "are already past-due. Use this when the operator asks 'what's "
        "being retired soon?', 'which segments are scheduled for "
        "decommission?', or to sanity-check the decom_expiring alert. "
        "Each row carries ``decom_date`` and ``days_until_decom`` "
        "(negative = overdue)."
    ),
    args_model=FindSubnetsDecommissioningArgs,
    category="ipam",
    writes=False,
    default_enabled=True,
    module=None,
)
async def find_subnets_decommissioning(
    db: AsyncSession, user: User, args: FindSubnetsDecommissioningArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    from datetime import UTC, datetime, timedelta

    today = datetime.now(UTC).date()
    cutoff = today + timedelta(days=args.within_days)
    stmt = (
        select(Subnet)
        .where(Subnet.deleted_at.is_(None))
        .where(Subnet.decom_date.is_not(None))
        .where(Subnet.decom_date <= cutoff)
        .order_by(Subnet.decom_date.asc())
        .limit(args.limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": str(s.id),
            "network": str(s.network),
            "name": s.name,
            "space_id": str(s.space_id),
            "decom_date": s.decom_date.isoformat() if s.decom_date else None,
            "days_until_decom": (s.decom_date - today).days if s.decom_date else None,
            "utilization_percent": float(s.utilization_percent or 0.0),
            "allocated_ips": int(s.allocated_ips or 0),
        }
        for s in rows
    ]


# ── get_subnet_summary ────────────────────────────────────────────────


class SubnetSummaryArgs(BaseModel):
    subnet_id: str = Field(description="Subnet UUID.")


@register_tool(
    name="get_subnet_summary",
    description=(
        "Detailed summary for one subnet: status counts (allocated, "
        "free, reserved, dhcp, etc.), gateway, VLAN, recent allocation "
        "activity. Use this when the operator asks 'how full is X?' "
        "or 'what's in X?'."
    ),
    args_model=SubnetSummaryArgs,
    category="ipam",
)
async def get_subnet_summary(
    db: AsyncSession, user: User, args: SubnetSummaryArgs
) -> dict[str, Any]:
    subnet = await db.get(Subnet, args.subnet_id)
    if subnet is None or subnet.deleted_at is not None:
        return {"error": "subnet not found", "subnet_id": args.subnet_id}
    counts_stmt = (
        select(IPAddress.status, func.count(IPAddress.id))
        .where(IPAddress.subnet_id == subnet.id)
        .group_by(IPAddress.status)
    )
    counts_rows = (await db.execute(counts_stmt)).all()
    by_status = {row[0]: int(row[1]) for row in counts_rows}
    # Fragile-device probe suppression (#722). Surfaced here rather than
    # as its own tool because the flag is a *field*, not a resource
    # family — and because the copilot most needs it exactly when it is
    # about to suggest a scan of a subnet it just looked up.
    probe = await resolve_probe_policy(db, subnet)
    return {
        "id": str(subnet.id),
        "network": str(subnet.network),
        "name": subnet.name,
        "description": subnet.description,
        "vlan_id": subnet.vlan_id,
        "gateway": str(subnet.gateway) if subnet.gateway else None,
        "utilization_percent": float(subnet.utilization_percent or 0.0),
        "total_ips": int(subnet.total_ips or 0),
        "allocated_ips": int(subnet.allocated_ips or 0),
        "by_status": by_status,
        "do_not_probe": probe.blocked,
        "do_not_probe_reason": probe.reason,
        "do_not_probe_source": probe.source or None,
    }


# ── find_subnet_reconciliation ────────────────────────────────────────


class SubnetReconciliationArgs(BaseModel):
    subnet_id: str = Field(description="Subnet UUID.")
    stale_minutes: int = Field(
        default=1440,
        description=(
            "How old (minutes) a row's last-seen timestamp may be before it "
            "counts as stale. Default 1440 (24h)."
        ),
    )


@register_tool(
    name="find_subnet_reconciliation",
    description=(
        "IP-discovery reconciliation for one subnet (issue #23): which "
        "allocated IPs aren't answering on the wire, which live IPs were "
        "discovered but never formally allocated, and which IPs marked "
        "'available' are actually active right now (status mismatch). Use "
        "when the operator asks 'what's stale in X?', 'what did discovery "
        "find in X?', or 'is anything using IPs we think are free?'. "
        "Read-only — reflects the last sweep; trigger a fresh sweep from "
        "the subnet's Reconciliation panel."
    ),
    args_model=SubnetReconciliationArgs,
    category="ipam",
)
async def find_subnet_reconciliation(
    db: AsyncSession, user: User, args: SubnetReconciliationArgs
) -> dict[str, Any]:
    from app.services.ipam.discovery import build_reconciliation_report

    try:
        subnet_uuid = uuid.UUID(args.subnet_id)
    except (ValueError, TypeError):
        return {"error": "subnet_id must be a UUID", "subnet_id": args.subnet_id}
    subnet = await db.get(Subnet, subnet_uuid)
    if subnet is None or subnet.deleted_at is not None:
        return {"error": "subnet not found", "subnet_id": args.subnet_id}
    stale = max(1, min(args.stale_minutes, 525600))
    return await build_reconciliation_report(db, subnet, stale_minutes=stale)


# ── get_subnet_utilization_trend ──────────────────────────────────────


class SubnetUtilizationTrendArgs(BaseModel):
    subnet_id: str = Field(description="Subnet UUID.")
    days: int = Field(
        default=90,
        description="How many days of history to return (1–365, default 90).",
    )


@register_tool(
    name="get_subnet_utilization_trend",
    description=(
        "Daily IP-utilization history for one subnet (issue #44): a "
        "time-ordered series of allocated / total / percent snapshots plus "
        "first→last delta. Use when the operator asks 'is X filling up?', "
        "'how fast is X growing?', or 'what was utilization last month?'. "
        "Snapshots are recorded nightly and retained 90 days."
    ),
    args_model=SubnetUtilizationTrendArgs,
    category="ipam",
)
async def get_subnet_utilization_trend(
    db: AsyncSession, user: User, args: SubnetUtilizationTrendArgs
) -> dict[str, Any]:
    from datetime import UTC, datetime, timedelta

    try:
        subnet_uuid = uuid.UUID(args.subnet_id)
    except (ValueError, TypeError):
        return {"error": "subnet_id must be a UUID", "subnet_id": args.subnet_id}
    subnet = await db.get(Subnet, subnet_uuid)
    if subnet is None or subnet.deleted_at is not None:
        return {"error": "subnet not found", "subnet_id": args.subnet_id}
    days = max(1, min(args.days, 365))
    cutoff = datetime.now(UTC) - timedelta(days=days)
    rows = (
        (
            await db.execute(
                select(SubnetUtilizationHistory)
                .where(
                    SubnetUtilizationHistory.subnet_id == subnet_uuid,
                    SubnetUtilizationHistory.sampled_at >= cutoff,
                )
                .order_by(SubnetUtilizationHistory.sampled_at.asc())
            )
        )
        .scalars()
        .all()
    )
    points = [
        {
            "sampled_at": r.sampled_at.isoformat(),
            "allocated_ips": r.allocated_ips,
            "total_ips": r.total_ips,
            "utilization_percent": (
                round(r.allocated_ips / r.total_ips * 100, 2) if r.total_ips else 0.0
            ),
        }
        for r in rows
    ]
    delta = None
    if len(points) >= 2:
        delta = round(points[-1]["utilization_percent"] - points[0]["utilization_percent"], 2)
    return {
        "subnet_id": str(subnet.id),
        "network": str(subnet.network),
        "days": days,
        "points": points,
        "current_utilization_percent": float(subnet.utilization_percent or 0.0),
        "delta_percent_over_window": delta,
    }


# ── find_stale_ips ─────────────────────────────────────────────────────


class FindStaleIPsArgs(BaseModel):
    stale_days: int = Field(
        default=90,
        description="Allocated IPs not seen on the wire in this many days count as stale. Default 90.",
    )
    include_never_seen: bool = Field(
        default=False,
        description=(
            "Also include allocated IPs that were never seen on the wire "
            "(often in subnets where discovery was never enabled). Off by default."
        ),
    )
    space_id: str | None = Field(
        default=None, description="Optional IP-space UUID to scope the report to."
    )
    subnet_id: str | None = Field(
        default=None, description="Optional subnet UUID to scope the report to."
    )
    limit: int = Field(default=100, description="Max rows to return (1–500). Default 100.")


@register_tool(
    name="find_stale_ips",
    description=(
        "Address-space hygiene report (issue #45): allocated IPs that "
        "nothing has seen on the wire in N days (default 90), drawn from "
        "the discovery last-seen signal. Use when the operator asks "
        "'what's stale?', 'which IPs can I reclaim?', 'what allocations "
        "are dead?', or 'find addresses to clean up'. Read-only — to "
        "actually deprecate, point the operator at the Stale-IP report's "
        "bulk-deprecate action. Optionally scope by space or subnet."
    ),
    args_model=FindStaleIPsArgs,
    category="ipam",
)
async def find_stale_ips(db: AsyncSession, user: User, args: FindStaleIPsArgs) -> dict[str, Any]:
    from app.services.ipam.stale_ips import build_stale_ip_report

    space_uuid: uuid.UUID | None = None
    subnet_uuid: uuid.UUID | None = None
    if args.space_id:
        try:
            space_uuid = uuid.UUID(args.space_id)
        except (ValueError, TypeError):
            return {"error": "space_id must be a UUID", "space_id": args.space_id}
    if args.subnet_id:
        try:
            subnet_uuid = uuid.UUID(args.subnet_id)
        except (ValueError, TypeError):
            return {"error": "subnet_id must be a UUID", "subnet_id": args.subnet_id}
    return await build_stale_ip_report(
        db,
        stale_days=max(1, min(args.stale_days, 3650)),
        include_never_seen=args.include_never_seen,
        space_id=space_uuid,
        subnet_id=subnet_uuid,
        limit=max(1, min(args.limit, 500)),
    )


# ── find_ip ───────────────────────────────────────────────────────────


class FindIPArgs(BaseModel):
    address: str = Field(
        description=(
            "IPv4 or IPv6 address. Supports both bare host form "
            "('10.0.0.5') and host-with-prefix form ('10.0.0.5/32')."
        )
    )


@register_tool(
    name="find_ip",
    description=(
        "Look up a single IP address by its dotted-decimal value "
        "(e.g. ``192.168.0.4``) and return its full row: hostname, "
        "FQDN, **MAC address**, status, role, owner, tags, custom "
        "fields, and which subnet it belongs to. Use this for any "
        "question of the form 'what is the X of IP Y' — host name, "
        "MAC, owner, last-seen timestamp, custom field value, etc. "
        "Do NOT use ``query_dns_records`` for IP→MAC lookups; PTR "
        "records carry hostnames, not MACs."
    ),
    args_model=FindIPArgs,
    category="ipam",
)
async def find_ip(db: AsyncSession, user: User, args: FindIPArgs) -> dict[str, Any]:
    try:
        ipaddress.ip_address(args.address.split("/", 1)[0])
    except ValueError:
        return {"error": f"invalid IP address: {args.address!r}"}
    stmt = select(IPAddress).where(
        func.host(IPAddress.address) == func.host(cast(literal(args.address), INET))
    )
    rows = (await db.execute(stmt)).scalars().all()
    if not rows:
        return {"matches": []}
    # OUI vendor enrichment — bulk_lookup_vendors short-circuits to {}
    # when the lookup feature is disabled, so this is a no-op cost on
    # deployments that haven't seeded the OUI table.
    vendors = await bulk_lookup_vendors(
        db, [str(ip.mac_address) if ip.mac_address else None for ip in rows]
    )
    out: list[dict[str, Any]] = []
    for ip in rows:
        sub = await db.get(Subnet, ip.subnet_id)
        mac_key = normalize_mac_key(str(ip.mac_address)) if ip.mac_address else None
        vendor = vendors.get(mac_key) if mac_key else None
        out.append(
            {
                "id": str(ip.id),
                "address": str(ip.address),
                "subnet_id": str(ip.subnet_id),
                "subnet_network": str(sub.network) if sub else None,
                "subnet_name": sub.name if sub else None,
                "status": ip.status,
                "role": ip.role,
                "hostname": ip.hostname,
                "fqdn": ip.fqdn,
                "mac_address": str(ip.mac_address) if ip.mac_address else None,
                "mac_vendor": vendor,
                "is_voip_phone": is_voip_phone_vendor(vendor),
                "description": ip.description,
                "last_seen_at": ip.last_seen_at.isoformat() if ip.last_seen_at else None,
                "last_seen_method": ip.last_seen_method,
                "tags": ip.tags or {},
            }
        )
    return {"matches": out}


# ── find_ip_addresses (cross-subnet search) ───────────────────────────


class FindIPAddressesArgs(BaseModel):
    q: str | None = Field(
        default=None,
        description=(
            "Case-insensitive substring matched across the address, hostname, "
            "FQDN, description and MAC. Use for open-ended 'find any IP that "
            "mentions X' questions."
        ),
    )
    hostname: str | None = Field(default=None, description="Substring match on hostname only.")
    mac: str | None = Field(default=None, description="Substring match on the MAC address.")
    status: str | None = Field(
        default=None,
        description="Exact status filter (e.g. 'allocated', 'reserved', 'static_dhcp', 'orphan').",
    )
    space_id: str | None = Field(
        default=None, description="Restrict to one IP space — UUID or case-insensitive name."
    )
    subnet_id: str | None = Field(default=None, description="Restrict to one subnet UUID.")
    limit: int = Field(default=100, ge=1, le=500, description="Max rows to return (1–500).")


@register_tool(
    name="find_ip_addresses",
    description=(
        "Search IP addresses ACROSS every subnet by substring (``q``), "
        "hostname, MAC or status — the cross-subnet companion to ``find_ip`` "
        "(which needs an exact address). Returns each hit's address, "
        "hostname, MAC, status, and which subnet + space it lives in. Use "
        "for 'find all IPs named web-*', 'which IPs have MAC prefix aa:bb', "
        "'list reserved IPs in the DMZ space', etc. Only returns IPs in "
        "subnets you can read."
    ),
    args_model=FindIPAddressesArgs,
    category="ipam",
)
async def find_ip_addresses(
    db: AsyncSession, user: User, args: FindIPAddressesArgs
) -> dict[str, Any]:
    from app.core.permissions import (  # noqa: PLC0415 — avoid import cycle
        is_effective_superadmin,
        user_has_permission,
    )

    structural: list[Any] = []
    if args.space_id:
        space_uuid = await _resolve_space_ref(db, args.space_id)
        if space_uuid is None:
            return {"error": f"no IP space matches {args.space_id!r}."}
        structural.append(Subnet.space_id == space_uuid)
    if args.subnet_id:
        try:
            structural.append(Subnet.id == uuid.UUID(args.subnet_id))
        except ValueError:
            return {"error": f"subnet_id {args.subnet_id!r} is not a valid UUID."}

    # Read-permission scope pushed into SQL so the capped page is drawn from
    # only the readable set (never a post-limit slice). Superadmin skips it.
    readable: list[uuid.UUID] | None = None
    if not is_effective_superadmin(user):
        idq = select(Subnet.id)
        for cond in structural:
            idq = idq.where(cond)
        cand = [r[0] for r in (await db.execute(idq)).all()]
        readable = [s for s in cand if user_has_permission(user, "read", "subnet", s)]

    stmt = (
        select(IPAddress, Subnet.network, Subnet.name, IPSpace.name)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .join(IPSpace, IPSpace.id == Subnet.space_id)
    )
    for cond in structural:
        stmt = stmt.where(cond)
    if args.status:
        stmt = stmt.where(IPAddress.status == args.status)
    if args.hostname:
        stmt = stmt.where(IPAddress.hostname.ilike(f"%{args.hostname}%"))
    if args.mac:
        stmt = stmt.where(cast(IPAddress.mac_address, String).ilike(f"%{args.mac}%"))
    if args.q:
        pat = f"%{args.q}%"
        stmt = stmt.where(
            or_(
                func.host(IPAddress.address).ilike(pat),
                IPAddress.hostname.ilike(pat),
                IPAddress.fqdn.ilike(pat),
                IPAddress.description.ilike(pat),
                cast(IPAddress.mac_address, String).ilike(pat),
            )
        )
    if readable is not None:
        stmt = stmt.where(Subnet.id.in_(readable))
    stmt = stmt.order_by(IPAddress.address).limit(args.limit)

    rows = (await db.execute(stmt)).all()
    ip_objs = [r[0] for r in rows]
    vendors = await bulk_lookup_vendors(
        db, [str(ip.mac_address) if ip.mac_address else None for ip in ip_objs]
    )
    matches: list[dict[str, Any]] = []
    for ip, net, sub_name, sp_name in rows:
        mac_key = normalize_mac_key(str(ip.mac_address)) if ip.mac_address else None
        vendor = vendors.get(mac_key) if mac_key else None
        matches.append(
            {
                "id": str(ip.id),
                "address": str(ip.address),
                "hostname": ip.hostname,
                "fqdn": ip.fqdn,
                "mac_address": str(ip.mac_address) if ip.mac_address else None,
                "mac_vendor": vendor,
                "is_voip_phone": is_voip_phone_vendor(vendor),
                "status": ip.status,
                "role": ip.role,
                "description": ip.description,
                "subnet_id": str(ip.subnet_id),
                "subnet_cidr": str(net),
                "subnet_name": sub_name or None,
                "space_name": sp_name or None,
                "tags": ip.tags or {},
            }
        )
    return {"matches": matches, "returned": len(matches), "capped": len(matches) >= args.limit}


# ── find_by_tag ───────────────────────────────────────────────────────


# Per-kind dispatch table for find_by_tag. Each entry: (model class,
# whether the model has SoftDeleteMixin so we should hide tombstoned
# rows, response-row renderer). Kept as data so adding a new tagged
# resource kind in the future is one line, not a new branch.
_TAG_KIND_TABLE: dict[str, tuple[type, bool, Any]] = {
    "ip_space": (
        IPSpace,
        True,
        lambda r: {"id": str(r.id), "name": r.name, "tags": r.tags or {}},
    ),
    "ip_block": (
        IPBlock,
        True,
        lambda r: {
            "id": str(r.id),
            "network": str(r.network),
            "name": r.name,
            "tags": r.tags or {},
        },
    ),
    "subnet": (
        Subnet,
        True,
        lambda r: {
            "id": str(r.id),
            "network": str(r.network),
            "name": r.name,
            "tags": r.tags or {},
        },
    ),
    "ip_address": (
        IPAddress,
        False,
        lambda r: {
            "id": str(r.id),
            "address": str(r.address),
            "hostname": r.hostname,
            "status": r.status,
            "tags": r.tags or {},
        },
    ),
    "asn": (
        ASN,
        False,
        lambda r: {
            "id": str(r.id),
            "number": r.number,
            "name": r.name,
            "tags": r.tags or {},
        },
    ),
    "vrf": (
        VRF,
        False,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "route_distinguisher": r.route_distinguisher,
            "tags": r.tags or {},
        },
    ),
    "network_device": (
        NetworkDevice,
        False,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "device_type": r.device_type,
            "tags": r.tags or {},
        },
    ),
    "domain": (
        Domain,
        False,
        lambda r: {"id": str(r.id), "name": r.name, "tags": r.tags or {}},
    ),
    "circuit": (
        Circuit,
        True,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "ckt_id": r.ckt_id,
            "tags": r.tags or {},
        },
    ),
    "network_service": (
        NetworkService,
        True,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "kind": r.kind,
            "tags": r.tags or {},
        },
    ),
    "overlay_network": (
        OverlayNetwork,
        True,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "kind": r.kind,
            "tags": r.tags or {},
        },
    ),
    "dns_zone": (
        DNSZone,
        True,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "zone_type": r.zone_type,
            "tags": r.tags or {},
        },
    ),
    "dns_record": (
        DNSRecord,
        True,
        lambda r: {
            "id": str(r.id),
            "fqdn": r.fqdn,
            "record_type": r.record_type,
            "value": r.value,
            "tags": r.tags or {},
        },
    ),
    "dhcp_scope": (
        DHCPScope,
        True,
        lambda r: {
            "id": str(r.id),
            "name": r.name,
            "tags": r.tags or {},
        },
    ),
    "dhcp_static_assignment": (
        DHCPStaticAssignment,
        False,
        lambda r: {
            "id": str(r.id),
            "ip_address": str(r.ip_address),
            "mac_address": str(r.mac_address),
            "hostname": r.hostname,
            "tags": r.tags or {},
        },
    ),
}

_TAG_KIND_DEFAULT = ["subnet", "ip_block", "ip_address", "ip_space"]


class FindByTagArgs(BaseModel):
    key: str = Field(description="Tag key — case-sensitive.")
    value: str | None = Field(
        default=None,
        description=(
            "Optional tag value. If omitted, matches any row where "
            "the key is present regardless of value."
        ),
    )
    resource_kinds: list[str] = Field(
        default_factory=lambda: list(_TAG_KIND_DEFAULT),
        description=(
            "Which resource kinds to search. Default is the four IPAM "
            "kinds (preserves prior behaviour). Pass an extended list "
            "to also search ASNs, VRFs, network devices, domains, "
            "circuits, network services, or overlay networks. "
            "Recognised values: " + ", ".join(_TAG_KIND_TABLE) + "."
        ),
    )
    limit_per_kind: int = Field(default=25, ge=1, le=100)


@register_tool(
    name="find_by_tag",
    description=(
        "Find tagged resources across IPAM, network modeling, DNS / "
        "DHCP scopes, etc. — every resource type that carries a "
        "JSONB ``tags`` column. Filters at the database with the "
        "JSONB ``?`` / ``@>`` operators (Postgres GIN-indexed). "
        "Useful for questions like 'what's tagged owner=alice?', "
        "'which subnets have env=prod?', or (with extended "
        "resource_kinds) 'find every ASN tagged carrier=lumen'."
    ),
    args_model=FindByTagArgs,
    category="ipam",
)
async def find_by_tag(db: AsyncSession, user: User, args: FindByTagArgs) -> dict[str, Any]:
    # Collapse (key, value) → the wire-level ``key:value`` form so the
    # AI tool and the REST endpoints route through the *same* helper —
    # any future change to the operator-facing tag syntax (case
    # folding, glob support, etc.) lands in one place.
    tag_param = f"{args.key}:{args.value}" if args.value is not None else args.key

    out: dict[str, list[dict[str, Any]]] = {}
    for kind in args.resource_kinds:
        entry = _TAG_KIND_TABLE.get(kind)
        if entry is None:
            out[kind] = [
                {"error": f"unknown resource kind {kind!r}; recognised: {sorted(_TAG_KIND_TABLE)}"}
            ]
            continue
        model, has_soft_delete, render = entry
        # ``model`` carries ``type`` from the dispatch table, so mypy
        # can't infer the select's column type — annotate it as one
        # column of ``Any``.
        stmt: Select[Any] = select(model)
        if has_soft_delete:
            stmt = stmt.where(model.deleted_at.is_(None))
        stmt = apply_tag_filter(stmt, model.tags, [tag_param])
        stmt = stmt.limit(args.limit_per_kind)
        rows = (await db.execute(stmt)).scalars().all()
        out[kind] = [render(r) for r in rows]
    return {"key": args.key, "value": args.value, "results": out}


# ── count_resources ───────────────────────────────────────────────────


class CountResourcesArgs(BaseModel):
    pass


@register_tool(
    name="count_ipam_resources",
    description=(
        "Total counts of IPAM resources — spaces, blocks, subnets, IP "
        "addresses, plus a breakdown of IP addresses by status. "
        "Equivalent to the dashboard's KPI ribbon. Use this when the "
        "operator asks 'how big is my deployment?' or 'how many "
        "subnets do I have?'."
    ),
    args_model=CountResourcesArgs,
    category="ipam",
)
async def count_ipam_resources(
    db: AsyncSession, user: User, args: CountResourcesArgs
) -> dict[str, Any]:
    space_count = await db.scalar(
        select(func.count(IPSpace.id)).where(IPSpace.deleted_at.is_(None))
    )
    block_count = await db.scalar(
        select(func.count(IPBlock.id)).where(IPBlock.deleted_at.is_(None))
    )
    subnet_count = await db.scalar(select(func.count(Subnet.id)).where(Subnet.deleted_at.is_(None)))
    ip_count = await db.scalar(select(func.count(IPAddress.id)))
    by_status_rows = (
        await db.execute(
            select(IPAddress.status, func.count(IPAddress.id)).group_by(IPAddress.status)
        )
    ).all()
    return {
        "ip_spaces": int(space_count or 0),
        "ip_blocks": int(block_count or 0),
        "subnets": int(subnet_count or 0),
        "ip_addresses": int(ip_count or 0),
        "ip_addresses_by_status": {row[0]: int(row[1]) for row in by_status_rows},
    }


# ── address sets (#103) ───────────────────────────────────────────────


class FindAddressSetsArgs(BaseModel):
    subnet_id: str | None = Field(
        default=None,
        description="Filter by subnet UUID — omit to search across all subnets.",
    )
    search: str | None = Field(default=None, description="Substring match on the address-set name.")
    limit: int = Field(default=200, ge=1, le=1000)


@register_tool(
    name="find_address_sets",
    description=(
        "List address sets — named, RBAC-scoped slices of a subnet's "
        "address space (a contiguous range like .50–.99 or an explicit "
        "list of hosts) used to delegate edit of just that slice without "
        "subnet-wide write. Filterable by subnet and name substring."
    ),
    args_model=FindAddressSetsArgs,
    category="ipam",
    module="ipam.address_sets",
)
async def find_address_sets(
    db: AsyncSession, user: User, args: FindAddressSetsArgs
) -> list[dict[str, Any]] | dict[str, Any]:
    from app.core.permissions import user_has_permission  # noqa: PLC0415 — avoid cycle

    stmt = select(AddressSet)
    if args.subnet_id:
        try:
            stmt = stmt.where(AddressSet.subnet_id == uuid.UUID(args.subnet_id))
        except ValueError:
            return {"error": f"subnet_id {args.subnet_id!r} is not a valid UUID."}
    if args.search:
        stmt = stmt.where(AddressSet.name.ilike(f"%{args.search}%"))
    stmt = stmt.order_by(AddressSet.name).limit(args.limit)
    rows = (await db.execute(stmt)).scalars().all()
    # Read-model (#103, finding #4): an MCP caller may see a set only if they can
    # READ its parent subnet — otherwise any authenticated copilot user could
    # enumerate the whole fleet's delegation slices. Superadmin / IPAM-reader
    # pass for all; a zero-subnet-read caller gets nothing.
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "subnet_id": str(s.subnet_id),
            "range_kind": s.range_kind,
            "start_address": str(s.start_address) if s.start_address is not None else None,
            "end_address": str(s.end_address) if s.end_address is not None else None,
            "explicit_addresses": list(s.explicit_addresses or []),
            "customer_id": str(s.customer_id) if s.customer_id else None,
            "site_id": str(s.site_id) if s.site_id else None,
        }
        for s in rows
        if user_has_permission(user, "read", "subnet", s.subnet_id)
    ]


class CountAddressSetsArgs(BaseModel):
    pass


@register_tool(
    name="count_address_sets",
    description=(
        "Total count of address sets plus a breakdown by range kind "
        "(contiguous vs explicit). Use to answer 'how many address sets "
        "do I have?'."
    ),
    args_model=CountAddressSetsArgs,
    category="ipam",
    module="ipam.address_sets",
)
async def count_address_sets(
    db: AsyncSession, user: User, args: CountAddressSetsArgs
) -> dict[str, Any]:
    from app.core.permissions import user_has_permission  # noqa: PLC0415 — avoid cycle

    # Count only sets whose parent subnet the caller can READ (#103, finding #4).
    # The per-row subnet check is synchronous Python, so the SQL can't group it
    # in-DB; pull just (subnet_id, range_kind) and aggregate the visible rows.
    rows = (await db.execute(select(AddressSet.subnet_id, AddressSet.range_kind))).all()
    total = 0
    by_kind: dict[str, int] = {}
    for subnet_id, range_kind in rows:
        if not user_has_permission(user, "read", "subnet", subnet_id):
            continue
        total += 1
        by_kind[range_kind] = by_kind.get(range_kind, 0) + 1
    return {
        "address_sets": total,
        "by_range_kind": by_kind,
    }


class FindIPHygieneFindingsArgs(BaseModel):
    free_responding_days: int = Field(
        default=1,
        ge=1,
        le=365,
        description="Recency window for 'free but responding' (answered within N days).",
    )
    stale_reservation_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Staleness window for reservations not seen in N days.",
    )
    squat_days: int = Field(
        default=7,
        ge=1,
        le=365,
        description="Recency window for an observed MAC differing from the recorded one.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_ip_hygiene_findings",
    description=(
        "Fleet-wide IPAM hygiene findings (issue #369), in three buckets: "
        "'free_but_responding' (IPs marked available that answered on the "
        "wire), 'stale_reservations' (reserved/static IPs not seen in N "
        "days), and 'unknown_mac_in_static_range' (an IP answered by a MAC "
        "differing from the recorded one — a squat). Mirrors the IP-hygiene "
        "alert rules but on demand. Use to answer 'any IP hygiene issues?', "
        "'is anything squatting in my static ranges?', or 'which reservations "
        "are dead?'. Read-only; depends on subnet discovery (ping/ARP/SNMP)."
    ),
    args_model=FindIPHygieneFindingsArgs,
    category="ipam",
)
async def find_ip_hygiene_findings(
    db: AsyncSession, user: User, args: FindIPHygieneFindingsArgs
) -> dict[str, Any]:
    # Shared with ``GET /ipam/reports/hygiene`` (#917) so the copilot answer
    # and the REST answer cannot disagree; that helper in turn calls the alert
    # matchers, so a tuning change to a detection reaches all three surfaces.
    from app.services.ipam.hygiene import build_hygiene_report  # noqa: PLC0415

    return await build_hygiene_report(
        db,
        free_responding_days=args.free_responding_days,
        stale_reservation_days=args.stale_reservation_days,
        squat_days=args.squat_days,
        limit=args.limit,
    )
