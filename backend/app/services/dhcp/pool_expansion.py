"""Free ranges to extend or add to a nearly-full DHCP pool (issue #4489).

Read-only. When ``dhcp_pool_exhaustion`` fires the operator still has to work
out which addresses of the subnet are free of IPAM allocations, reservations,
other pools and the gateway before widening anything. This does that
arithmetic and proposes ranges; applying one stays the ordinary pool create /
update path, so overlap checks, audit and the agent wake are unchanged.

IPv4 only. A DHCPv6 pool is a slice of a /64 whose "free" space is not
meaningfully enumerable (and SLAAC hosts never register), so v6 is refused with
the reason by the caller rather than answered with a range that would look
authoritative.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPPool, DHCPScope, DHCPStaticAssignment
from app.models.ipam import IPAddress, Subnet

#: How many discovery-seen addresses a candidate lists before truncating.
SEEN_SAMPLE = 10


@dataclass
class Suggestion:
    start_ip: str
    end_ip: str
    size: int
    #: ``extends_after`` / ``extends_before`` touch the pool; ``separate`` does not.
    kind: str
    #: The pool's range if this candidate were merged into it (extend kinds only).
    resulting_start: str | None = None
    resulting_end: str | None = None
    #: Addresses in the candidate that discovery has seen answering.
    seen_answering: list[str] = field(default_factory=list)
    seen_answering_count: int = 0


def usable_bounds(net: ipaddress.IPv4Network) -> tuple[int, int]:
    """First and last host address. /31 (RFC 3021) and /32 have no network or
    broadcast address to hold back."""
    first, last = int(net.network_address), int(net.broadcast_address)
    if net.prefixlen >= 31:
        return first, last
    return first + 1, last - 1


def free_runs(lo: int, hi: int, blocked: Iterable[int], ranges: Iterable[tuple[int, int]]):
    """Maximal ``(start, end)`` integer runs inside ``[lo, hi]`` containing no
    blocked address and no blocked range."""
    spans = sorted(
        [(b, b) for b in blocked if lo <= b <= hi]
        + [(max(s, lo), min(e, hi)) for s, e in ranges if e >= lo and s <= hi]
    )
    runs: list[tuple[int, int]] = []
    cursor = lo
    for s, e in spans:
        if s > cursor:
            runs.append((cursor, s - 1))
        cursor = max(cursor, e + 1)
    if cursor <= hi:
        runs.append((cursor, hi))
    return runs


def _ints(values: Iterable[object], net: ipaddress.IPv4Network) -> set[int]:
    out: set[int] = set()
    for v in values:
        try:
            a = ipaddress.ip_address(str(v))
        except ValueError:
            continue
        if a.version == 4 and a in net:
            out.add(int(a))
    return out


async def suggest_pool_expansion(
    db: AsyncSession,
    pool: DHCPPool,
    scope: DHCPScope,
    subnet: Subnet,
    *,
    limit: int = 5,
    min_size: int = 1,
) -> list[Suggestion]:
    """Candidate ranges for ``pool``: those touching it first, then the other
    free runs, largest first. Caller guarantees an IPv4 dynamic pool."""
    net = ipaddress.ip_network(str(subnet.network), strict=False)
    assert isinstance(net, ipaddress.IPv4Network)
    lo, hi = usable_bounds(net)

    blocked: set[int] = set()
    if subnet.gateway:
        blocked |= _ints([subnet.gateway], net)

    ip_rows = (
        await db.execute(
            select(IPAddress.address, IPAddress.status, IPAddress.last_seen_at).where(
                IPAddress.subnet_id == subnet.id
            )
        )
    ).all()
    # Anything IPAM holds that is not plainly free: allocated, reserved, dhcp,
    # static_dhcp, discovered, orphan, deprecated, network, broadcast.
    blocked |= _ints([a for a, st, _ in ip_rows if st != "available"], net)
    seen_all = _ints([a for a, _, seen in ip_rows if seen is not None], net)

    scope_ids = (
        (await db.execute(select(DHCPScope.id).where(DHCPScope.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    blocked |= _ints(
        (
            await db.execute(
                select(DHCPStaticAssignment.ip_address).where(
                    DHCPStaticAssignment.scope_id.in_(scope_ids)
                )
            )
        )
        .scalars()
        .all(),
        net,
    )
    # A live lease outside any pool (a client that kept its address after the
    # pool shrank) still owns the address.
    blocked |= _ints(
        (
            await db.execute(
                select(DHCPLease.ip_address)
                .where(DHCPLease.scope_id.in_(scope_ids))
                .where(DHCPLease.state == "active")
            )
        )
        .scalars()
        .all(),
        net,
    )

    ranges: list[tuple[int, int]] = []
    for p in (await db.execute(select(DHCPPool).where(DHCPPool.scope_id.in_(scope_ids)))).scalars():
        if p.pool_type == "pd":
            continue
        try:
            s, e = int(ipaddress.ip_address(str(p.start_ip))), int(
                ipaddress.ip_address(str(p.end_ip))
            )
        except ValueError:
            continue
        ranges.append((s, e))

    p_start, p_end = int(ipaddress.ip_address(str(pool.start_ip))), int(
        ipaddress.ip_address(str(pool.end_ip))
    )
    ip = ipaddress.IPv4Address

    adjacent: list[Suggestion] = []
    other: list[Suggestion] = []
    for s, e in free_runs(lo, hi, blocked, ranges):
        size = e - s + 1
        if size < min_size:
            continue
        seen = sorted(x for x in seen_all if s <= x <= e)
        sug = Suggestion(
            start_ip=str(ip(s)),
            end_ip=str(ip(e)),
            size=size,
            kind="separate",
            seen_answering=[str(ip(x)) for x in seen[:SEEN_SAMPLE]],
            seen_answering_count=len(seen),
        )
        if s == p_end + 1:
            sug.kind = "extends_after"
            sug.resulting_start, sug.resulting_end = str(ip(p_start)), str(ip(e))
            adjacent.append(sug)
        elif e == p_start - 1:
            sug.kind = "extends_before"
            sug.resulting_start, sug.resulting_end = str(ip(s)), str(ip(p_end))
            adjacent.append(sug)
        else:
            other.append(sug)
    adjacent.sort(key=lambda x: x.kind != "extends_after")  # stable: growing upward first
    other.sort(key=lambda x: (-x.size, int(ip(x.start_ip))))
    return (adjacent + other)[:limit]


__all__ = ["Suggestion", "suggest_pool_expansion", "usable_bounds", "free_runs"]
