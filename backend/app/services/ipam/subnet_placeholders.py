"""The network / broadcast / gateway rows a new subnet holds (#2979).

One home so every path that creates a subnet (``POST /ipam/subnets``, plan
apply, the subnet import) leaves it with the same rows, and therefore the same
counters and the same "Next available" answer: the stored gateway is never
offered as a free host.
"""

from __future__ import annotations

import ipaddress
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet


def takes_placeholder_rows(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Version-aware: a v4 /31+/32 has no network/broadcast concept (RFC 3021)
    and the v6 analogue is /127+/128 (#506)."""
    return net.prefixlen < (127 if isinstance(net, ipaddress.IPv6Network) else 31)


async def create_placeholder_rows(
    db: AsyncSession,
    subnet: Subnet,
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    *,
    gateway: str | None,
    created_by_user_id: uuid.UUID | None,
) -> tuple[list[str], IPAddress | None]:
    """Add the network, broadcast (IPv4 only) and gateway rows and stamp
    ``subnet.gateway``. The caller decides whether the subnet takes them
    (multicast / ``skip_auto_addresses`` / ``takes_placeholder_rows``).
    Returns ``(addresses created, gateway row)``. Does not flush."""
    created: list[str] = []
    db.add(
        IPAddress(
            subnet_id=subnet.id,
            address=str(net.network_address),
            status="network",
            description="Network address",
            created_by_user_id=created_by_user_id,
        )
    )
    created.append(str(net.network_address))
    if not isinstance(net, ipaddress.IPv6Network):
        db.add(
            IPAddress(
                subnet_id=subnet.id,
                address=str(net.broadcast_address),
                status="broadcast",
                description="Broadcast address",
                created_by_user_id=created_by_user_id,
            )
        )
        created.append(str(net.broadcast_address))
    gw_addr = gateway or str(net.network_address + 1)
    gw_row = IPAddress(
        subnet_id=subnet.id,
        address=gw_addr,
        status="reserved",
        description="Gateway",
        hostname="gateway",
        created_by_user_id=created_by_user_id,
    )
    db.add(gw_row)
    subnet.gateway = gw_addr
    created.append(gw_addr)
    return created, gw_row
