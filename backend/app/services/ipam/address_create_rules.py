"""The refusals the REST address create makes before it writes a row.

One home so the REST ``create_address`` handler and the request portal's
submit-time check (#2903, #2905) apply the same rules, statuses and wording
instead of two copies. Each function raises a 4xx ``HTTPException``.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet


def assert_subnet_takes_addresses(subnet: Subnet) -> None:
    """Multicast subnets hold stream identities, not endpoint rows (422)."""
    if subnet.kind == "multicast":
        raise HTTPException(
            status_code=422,
            detail=(
                "This is a multicast subnet — addresses are stream identities. "
                "Create a multicast group under /multicast/groups instead of an "
                "IPAM address row."
            ),
        )


def assert_static_dhcp_has_mac(addr_status: str | None, mac_address: str | None) -> None:
    """``static_dhcp`` needs a MAC to reserve (422)."""
    if addr_status == "static_dhcp" and not mac_address:
        raise HTTPException(
            status_code=422,
            detail="mac_address is required when status is 'static_dhcp'",
        )


async def assert_address_unallocated(db: AsyncSession, subnet_id: uuid.UUID, address: str) -> None:
    """The address must not already be held in the subnet (409)."""
    existing = await db.scalar(
        select(func.count())
        .select_from(IPAddress)
        .where(IPAddress.subnet_id == subnet_id)
        .where(IPAddress.address == address)
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Address {address} is already allocated in this subnet",
        )
