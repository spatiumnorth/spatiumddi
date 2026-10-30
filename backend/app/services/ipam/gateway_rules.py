"""The gateway rule New Subnet, subnet edit and Subnet Planner share (#2984).

One rule and one wording, so the planner's validation and ``POST
/ipam/subnets`` can never disagree about the same gateway.
"""

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
    which the subnet's own placeholder rows already hold (the gateway row would
    meet them on ``uq_ip_address_subnet_address``); callers pass it only for a
    subnet that gets those rows.
    """
    if gateway is None:
        return None
    try:
        gw = ipaddress.ip_address(gateway)
    except ValueError:
        return f"Invalid gateway IP: {gateway}"
    if gw.version != net.version or gw not in net:
        return f"Gateway {gateway} is not within subnet {net}"
    if reject_reserved:
        if gw == net.network_address:
            return f"Gateway {gateway} is the network address of subnet {net}"
        if isinstance(net, ipaddress.IPv4Network) and gw == net.broadcast_address:
            return f"Gateway {gateway} is the broadcast address of subnet {net}"
    return None
