"""The network / broadcast / gateway rows a new subnet holds (#2979).

One home so every path that creates a subnet (``POST /ipam/subnets``, plan
apply, the subnet import) leaves it with the same rows, and therefore the same
counters and the same "Next available" answer: the stored gateway is never
offered as a free host.

The rule (``create_subnet``, #506): a subnet gets a ``network`` row, and for
IPv4 a ``broadcast`` one, only when its prefix is short enough to have them:
below /31 for IPv4 (RFC 3021) and below /127 for IPv6. IPv6 has no broadcast.
A multicast subnet gets none: its addresses are stream identities, not
endpoint slots. ``has_boundary_rows`` / ``boundary_rows`` are that rule and
nothing else, so the operations that rebuild a subnet at a new prefix (Split,
Merge, Resize) can share it with the create paths rather than carry a copy.
"""

from __future__ import annotations

import ipaddress
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_V4_MULTICAST = ipaddress.IPv4Network("224.0.0.0/4")
_V6_MULTICAST = ipaddress.IPv6Network("ff00::/8")


def subnet_kind_for(net: IPNetwork) -> str:
    """``multicast`` for a subnet inside the IANA multicast ranges, else
    ``unicast`` (#126) — the kind ``create_subnet`` stamps."""
    if isinstance(net, ipaddress.IPv4Network):
        return "multicast" if net.subnet_of(_V4_MULTICAST) else "unicast"
    return "multicast" if net.subnet_of(_V6_MULTICAST) else "unicast"


def has_boundary_rows(net: IPNetwork, kind: str | None = "unicast") -> bool:
    """True when a subnet at this prefix (and kind) gets network / broadcast
    rows (and, on create, a gateway row)."""
    if kind == "multicast":
        return False
    return net.prefixlen < (127 if isinstance(net, ipaddress.IPv6Network) else 31)


def boundary_rows(net: IPNetwork, kind: str | None = "unicast") -> list[tuple[str, str, str]]:
    """``(address, status, description)`` for the boundary rows create_subnet seeds."""
    if not has_boundary_rows(net, kind):
        return []
    rows = [(str(net.network_address), "network", "Network address")]
    if isinstance(net, ipaddress.IPv4Network):
        rows.append((str(net.broadcast_address), "broadcast", "Broadcast address"))
    return rows


async def create_placeholder_rows(
    db: AsyncSession,
    subnet: Subnet,
    net: IPNetwork,
    *,
    gateway: str | None,
    created_by_user_id: uuid.UUID | None,
) -> tuple[list[str], IPAddress | None]:
    """Add the network, broadcast (IPv4 only) and gateway rows and stamp
    ``subnet.gateway``. The gateway defaults to the first host, as on New
    Subnet. The caller decides whether the subnet takes them
    (``has_boundary_rows``, and ``skip_auto_addresses`` on New Subnet).
    Returns ``(addresses created, gateway row)``. Does not flush."""
    created: list[str] = []
    for addr, row_status, desc in boundary_rows(net):
        db.add(
            IPAddress(
                subnet_id=subnet.id,
                address=addr,
                status=row_status,
                description=desc,
                created_by_user_id=created_by_user_id,
            )
        )
        created.append(addr)
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
