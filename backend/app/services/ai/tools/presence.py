"""Operator-Copilot read tool for device presence by MAC — #2147.

Same service and wire shape as ``POST /api/v1/presence`` so the two cannot
disagree. Default-enabled: it reads nothing the already-enabled
``find_dhcp_leases`` / ``find_new_devices`` do not, and the rows are narrowed to
subnets the caller may read.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services.ai.tools.base import register_tool
from app.services.ipam.presence import PresenceRequest, presence_for


class FindDevicePresenceArgs(PresenceRequest):
    """Same body as the REST route (cap, MAC forms, window)."""


@register_tool(
    name="find_device_presence",
    permission=("read", "subnet"),
    description=(
        "Are these devices on the network right now? Takes up to 500 MAC "
        "addresses (any separator form) and returns one row each: present (an "
        "active lease AND activity within window_seconds, default 600), the "
        "lease IP / hostname / expiry, last_seen_at and its source "
        "(dhcp / arp / ping / snmp), a randomized-MAC flag, and freshness_s "
        "when the lease comes from a polled Windows DHCP server. A lease alone "
        "is not presence. Only subnets the caller may read are considered."
    ),
    args_model=FindDevicePresenceArgs,
    category="ipam",
)
async def find_device_presence(
    db: AsyncSession, user: User, args: FindDevicePresenceArgs
) -> dict[str, Any]:
    try:
        req = PresenceRequest.model_validate(args.model_dump())
    except ValidationError as exc:  # unreachable via the registry; defensive
        return {"error": str(exc)}
    return (await presence_for(db, user, req)).model_dump(mode="json")
