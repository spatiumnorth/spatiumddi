"""The gateway rules New Subnet and Subnet Planner share (#2984)."""

from __future__ import annotations

import ipaddress


def gateway_problem(
    gateway: str | None,
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    *,
    reject_reserved: bool = False,
) -> str | None:
    """Why ``gateway`` cannot be a subnet's gateway, or None.

    ``reject_reserved`` also refuses the network and (IPv4) broadcast address,
    which the subnet's own placeholder rows already hold; callers pass it only
    for a subnet that gets those rows.
    """
    if not gateway:
        return None
    try:
        gw = ipaddress.ip_address(gateway)
    except ValueError:
        return f"Invalid gateway {gateway!r} on {net}"
    if gw.version != net.version or gw not in net:
        return f"Gateway {gateway} is not within subnet {net}"
    if reject_reserved:
        if gw == net.network_address:
            return f"Gateway {gateway} is the network address of subnet {net}"
        if isinstance(net, ipaddress.IPv4Network) and gw == net.broadcast_address:
            return f"Gateway {gateway} is the broadcast address of subnet {net}"
    return None
