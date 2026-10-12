"""Operator-Copilot read tools for new-device (arpwatch) detection — #459.

All three reads are gated on the ``security.new_device_watch`` feature module so
they disappear from the registry in lock-step with the sidebar surface when the
feature is off. MACs are OUI-vendor-enriched inline (the established pattern).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.ipam import IPAddress, IpMacHistory, MACAllowlist, Subnet
from app.services.ai.tools.base import register_tool
from app.services.ipam.new_device import new_device_counts
from app.services.oui import bulk_lookup_vendors, normalize_mac_key

_MODULE = "security.new_device_watch"


class FindNewDevicesArgs(BaseModel):
    since_hours: int = Field(
        default=168,
        ge=1,
        le=24 * 365,
        description="Only sightings first seen within this many hours (default 7 days).",
    )
    classification: str = Field(
        default="new",
        description="'new' (default, the review queue), 'acknowledged', or 'known'.",
    )
    subnet_id: UUID | None = Field(default=None, description="Restrict to one subnet.")
    include_randomized: bool = Field(
        default=False,
        description="Include locally-administered (privacy-randomised) MACs.",
    )
    limit: int = Field(default=50, ge=1, le=500)


@register_tool(
    name="find_new_devices",
    permission=("read", "ip_address"),
    description=(
        "List recently first-seen MAC addresses (new-device / arpwatch review "
        "queue). Each row has the IP, subnet, MAC, OUI vendor, source (dhcp_lease "
        "/ snmp / sweep / l2_sniff), classification, randomised flag, and "
        "first/last-seen times. Defaults to unacknowledged new devices in the "
        "last 7 days. Use this to answer 'what new devices showed up?'."
    ),
    args_model=FindNewDevicesArgs,
    category="ipam",
    module=_MODULE,
)
async def find_new_devices(
    db: AsyncSession, user: User, args: FindNewDevicesArgs
) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC) - timedelta(hours=args.since_hours)
    stmt = (
        select(IpMacHistory, IPAddress, Subnet)
        .join(IPAddress, IPAddress.id == IpMacHistory.ip_address_id)
        .outerjoin(Subnet, Subnet.id == IPAddress.subnet_id)
        .where(
            IpMacHistory.classification == args.classification,
            IpMacHistory.first_seen >= cutoff,
        )
        .order_by(IpMacHistory.first_seen.desc())
        .limit(args.limit)
    )
    if args.subnet_id is not None:
        stmt = stmt.where(IPAddress.subnet_id == args.subnet_id)
    if not args.include_randomized:
        stmt = stmt.where(IpMacHistory.is_randomized.is_(False))
    rows = (await db.execute(stmt)).all()
    macs: list[str | None] = [str(h.mac_address) for h, _ip, _s in rows]
    vendors = await bulk_lookup_vendors(db, macs)
    return [
        {
            "sighting_id": str(h.id),
            "ip_address_id": str(h.ip_address_id),
            "ip_address": str(ip.address),
            "subnet_id": str(s.id) if s else None,
            "subnet": str(s.network) if s else None,
            "mac_address": str(h.mac_address),
            "oui_vendor": vendors.get(normalize_mac_key(str(h.mac_address)) or ""),
            "source": h.source,
            "classification": h.classification,
            "is_randomized": h.is_randomized,
            "first_seen": h.first_seen.isoformat(),
            "last_seen": h.last_seen.isoformat(),
        }
        for h, ip, s in rows
    ]


class CountNewDevicesArgs(BaseModel):
    pass


@register_tool(
    name="count_new_devices",
    permission=("read", "ip_address"),
    description=(
        "Count new-device sightings by classification (new / acknowledged / "
        "known), plus how many new ones appeared in the last 24h and the "
        "allowlist size. Use for 'how many new devices are waiting for review?'."
    ),
    args_model=CountNewDevicesArgs,
    category="ipam",
    module=_MODULE,
)
async def count_new_devices(
    db: AsyncSession, user: User, args: CountNewDevicesArgs
) -> dict[str, Any]:
    # Single source of truth shared with the dashboard summary endpoint so the
    # two can't drift (one aggregate query under the hood).
    c = await new_device_counts(db)
    return {
        "new": c["new"],
        "new_randomized": c["new_randomized"],
        "new_last_24h": c["new_last_24h"],
        "acknowledged": c["acknowledged"],
        "known": c["known"],
        "allowlist_entries": c["allowlist"],
    }


class FindMacAllowlistArgs(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)


@register_tool(
    name="find_mac_allowlist",
    permission=("read", "ip_address"),
    description=(
        "List the trusted-MAC allowlist entries (exact MAC or OUI prefix) that "
        "suppress new-device alerts. Use to check whether a MAC/vendor is already "
        "trusted before alerting on it."
    ),
    args_model=FindMacAllowlistArgs,
    category="ipam",
    module=_MODULE,
)
async def find_mac_allowlist(
    db: AsyncSession, user: User, args: FindMacAllowlistArgs
) -> list[dict[str, Any]]:
    rows = (
        (
            await db.execute(
                select(MACAllowlist).order_by(MACAllowlist.created_at.desc()).limit(args.limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "mac_address": str(r.mac_address) if r.mac_address else None,
            "oui_prefix": r.oui_prefix,
            "note": r.note,
            "is_builtin": r.is_builtin,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
