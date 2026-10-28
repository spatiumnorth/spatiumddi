"""One definition of which address rows count toward a subnet's
``allocated_ips`` (#2411).

``Subnet.total_ips`` is the *usable* size: an IPv4 subnet leaves its
network and broadcast addresses out. The auto-created ``network`` /
``broadcast`` placeholder rows therefore must not be counted as
allocated, or a full /29 reads 8 / 6 (133 %). An IPv6 ``network`` row is
inside ``total_ips`` (v6 keeps the whole range), so it still counts.

Every writer of the cached counters (the router, the integration
reconcilers, the hourly recount) goes through this so they agree.
"""

from __future__ import annotations

import ipaddress

from sqlalchemy import ColumnElement, and_, func, not_

from app.models.ipam import IPAddress

# Raw-SQL twin of ``counts_toward_utilization`` for the recount task,
# which groups over the whole ``ip_address`` table with ``text()``.
COUNTS_TOWARD_UTILIZATION_SQL = (
    "status != 'available' AND status != 'broadcast' "
    "AND NOT (status = 'network' AND family(address) = 4)"
)


def counts_toward_utilization() -> ColumnElement[bool]:
    return and_(
        IPAddress.status != "available",
        IPAddress.status != "broadcast",
        not_(and_(IPAddress.status == "network", func.family(IPAddress.address) == 4)),
    )


def utilization_percent(allocated: int, total: int) -> float:
    """``allocated / total`` as a percent rounded to 2 places; 0.0 for an
    empty denominator."""
    return round(float(allocated) / total * 100, 2) if total > 0 else 0.0


def block_utilization_percent(allocated: int, network: object) -> float:
    """A block's utilization: allocated addresses over the block CIDR's
    *whole* size (network and broadcast included — a block is address
    space, not a host pool). The one definition shared by the router's
    cached ``IPBlock.utilization_percent`` and the tree PDF's Summary
    (#2982), so the two cannot print different figures for one block.
    """
    total = ipaddress.ip_network(str(network), strict=False).num_addresses
    return utilization_percent(allocated, total)
