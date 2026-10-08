"""Vendor-rollup tools for the Operator Copilot.

These answer questions like 'how many Apple devices are on my
network?', 'do I have any Raspberry Pis?', or 'breakdown of devices
by manufacturer'. They aggregate MAC addresses across IPAM rows and
/ or active DHCP leases through the existing OUI table populated by
``app.tasks.oui_update``.

Both tools short-circuit cleanly when ``PlatformSettings.oui_lookup_enabled``
is False — :func:`bulk_lookup_vendors` returns ``{}`` in that case, so
the rollup just shows zero matches with the same shape and the LLM
can naturally surface 'OUI lookup is disabled' to the operator.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.tools.base import register_tool
from app.services.ipam.vendor_rollup import count_by_vendor, find_devices


class CountDevicesByVendorArgs(BaseModel):
    vendor_search: str | None = Field(
        default=None,
        description=(
            "Optional case-insensitive substring filter on the vendor "
            "name (e.g. 'apple', 'raspberry', 'sonos'). Leave empty "
            "for the full breakdown."
        ),
    )
    source: Literal["ipam", "dhcp_active", "all"] = Field(
        default="ipam",
        description=(
            "Where to draw MACs from. 'ipam' = managed IPAddress rows; "
            "'dhcp_active' = currently-active DHCP leases; 'all' = the "
            "deduplicated union. Defaults to 'ipam' (stable, "
            "operator-curated view)."
        ),
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum vendor buckets to return.",
    )


@register_tool(
    name="count_devices_by_vendor",
    permission=("read", ("ip_space", "ip_block", "subnet", "ip_address")),
    description=(
        "Roll up MAC addresses by vendor (OUI lookup). Use for "
        "questions like 'how many Apple devices are on my "
        "network?', 'do I have any Raspberry Pis?', or 'breakdown of "
        "devices by manufacturer'. Returns vendor → count buckets "
        "sorted by count descending. Optional vendor_search narrows "
        "to a specific vendor substring. Set source='ipam' for "
        "managed rows, 'dhcp_active' for currently-leased devices, "
        "or 'all' for the union. Requires OUI lookup to be enabled "
        "in Settings → IPAM (admin) — when off, the rollup is empty."
    ),
    args_model=CountDevicesByVendorArgs,
    category="ipam",
)
async def count_devices_by_vendor(
    db: AsyncSession, user: User, args: CountDevicesByVendorArgs
) -> dict[str, Any]:
    # Shared with ``GET /ipam/reports/vendors`` (#917) so the copilot and the
    # REST rollup cannot disagree about what counts as a device.
    return await count_by_vendor(
        db, source=args.source, vendor_search=args.vendor_search, limit=args.limit
    )


class FindDevicesByVendorArgs(BaseModel):
    vendor_search: str = Field(
        description=(
            "Case-insensitive substring match on the OUI vendor name. "
            "Examples: 'apple', 'raspberry', 'sonos', 'cisco'."
        ),
    )
    source: Literal["ipam", "dhcp_active", "all"] = Field(
        default="ipam",
        description=(
            "Where to look. 'ipam' = managed IPAddress rows (stable); "
            "'dhcp_active' = currently-active DHCP leases (transient); "
            "'all' = both, deduplicated by MAC."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_devices_by_vendor",
    permission=("read", ("ip_space", "ip_block", "subnet", "ip_address")),
    description=(
        "List specific devices whose MAC OUI matches a vendor "
        "substring. Use after count_devices_by_vendor when the "
        "operator wants to see the actual rows ('show me my "
        "Raspberry Pis', 'what are all my Apple devices?'). Returns "
        "IP, MAC, vendor, hostname, and source per match. Sourced "
        "from IPAM, active DHCP leases, or both."
    ),
    args_model=FindDevicesByVendorArgs,
    category="ipam",
)
async def find_devices_by_vendor(
    db: AsyncSession, user: User, args: FindDevicesByVendorArgs
) -> dict[str, Any]:
    # Shared with ``GET /ipam/reports/vendors/devices`` (#917).
    return await find_devices(
        db, vendor_search=args.vendor_search, source=args.source, limit=args.limit
    )
