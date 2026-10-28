"""One definition of which address rows count toward a subnet's
``allocated_ips`` (#2411).

``Subnet.total_ips`` is the *usable* size: an IPv4 subnet leaves its
network and broadcast addresses out. The auto-created ``network`` /
``broadcast`` placeholder rows therefore must not be counted as
allocated, or a full /29 reads 8 / 6 (133 %). An IPv6 ``network`` row is
inside ``total_ips`` (v6 keeps the whole range), so it still counts.

Every writer of the cached counters (the router, the integration
reconcilers, the hourly recount) goes through this so they agree.

A *block* counts differently: its utilization is the share of its whole
CIDR in use, so each subnet's network/broadcast addresses count as used
in the block's rollup (#2982) — see ``block_subnet_contribution_sql``.
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


def _counting_row_at(alias: str, address_sql: str) -> str:
    """SQL: a row of subnet ``alias`` sits on ``address_sql`` and counts
    toward that subnet's ``allocated_ips``. Hits the
    ``uq_ip_address_subnet_address`` index."""
    return (
        "EXISTS (SELECT 1 FROM ip_address a "
        f"WHERE a.subnet_id = {alias}.id AND a.address = {address_sql} "
        "AND a.status != 'available' AND a.status != 'broadcast' "
        "AND NOT (a.status = 'network' AND family(a.address) = 4))"
    )


def block_subnet_contribution_sql(alias: str = "s") -> str:
    """SQL expression: what one subnet adds to its blocks' ``allocated_ips``.

    A block's utilization is the share of its CIDR in use (#2982,
    maintainer decision 2026-10-28), so a subnet's non-usable addresses
    count as used there even though the subnet's own count leaves them
    out (#2411 — the subnet's total is its *usable* size, and its count
    must stay over the same set). The non-usable addresses are the
    network + broadcast of an IPv4 subnet shorter than /31, and the
    network address (subnet-router anycast) of an IPv6 subnet shorter
    than /127 (#506); /31, /32, /127 and /128 have none.

    Each is added only when no counting row already sits on it. An IPv6
    ``network`` placeholder row already counts toward the subnet (its
    total keeps the whole range), and a v4 subnet created without
    placeholders can hold an ordinary row on .0; counting those twice
    would push a full block past 100%.
    """
    net = f"{alias}.network"
    network_addr = f"host(network({net}))::inet"
    broadcast_addr = f"host(broadcast({net}))::inet"
    return (
        f"({alias}.allocated_ips"
        f" + CASE WHEN family({net}) = 4 AND masklen({net}) < 31 THEN"
        f" (CASE WHEN {_counting_row_at(alias, network_addr)} THEN 0 ELSE 1 END)"
        f" + (CASE WHEN {_counting_row_at(alias, broadcast_addr)} THEN 0 ELSE 1 END)"
        f" WHEN family({net}) = 6 AND masklen({net}) < 127 THEN"
        f" (CASE WHEN {_counting_row_at(alias, network_addr)} THEN 0 ELSE 1 END)"
        " ELSE 0 END)"
    )


def block_allocated(allocated: int, network: object) -> int:
    """Clamp a block's rolled-up allocated count to its CIDR size, so a
    block never reads over 100% even if a subnet's cached counter has
    drifted high."""
    total = ipaddress.ip_network(str(network), strict=False).num_addresses
    return max(0, min(int(allocated), total))


def block_utilization_percent(allocated: int, network: object) -> float:
    """A block's utilization: allocated addresses over the block CIDR's
    *whole* size (network and broadcast included — a block is address
    space, not a host pool). ``allocated`` is the rollup built from
    :func:`block_subnet_contribution_sql`, which counts each subnet's
    network/broadcast addresses as used, so a block fully carved into
    full subnets reads 100%. Shared by the router's cached
    ``IPBlock.utilization_percent`` and the hourly recount, so the two
    cannot disagree; the tree PDF reads that cached figure (#2982).
    """
    total = ipaddress.ip_network(str(network), strict=False).num_addresses
    return utilization_percent(block_allocated(allocated, network), total)
