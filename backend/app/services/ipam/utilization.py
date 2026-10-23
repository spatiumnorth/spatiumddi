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
