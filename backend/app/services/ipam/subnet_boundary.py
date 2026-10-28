"""The network / broadcast rule shared by Split, Merge and Resize (#2976).

A subnet created at a prefix (``create_subnet``, #506) gets a ``network``
pseudo-row, and for IPv4 a ``broadcast`` one, only when the prefix is short
enough to have them: below /31 for IPv4 (RFC 3021) and below /127 for IPv6.
IPv6 has no broadcast. Split, Merge and Resize build subnets at new prefixes,
so they all ask this module instead of each carrying its own threshold (the
old flat ``prefixlen < 31`` was IPv4 logic and left every IPv6 result without
its network row).

A host on one of those addresses is a conflict: no client can use it, and it
would count against a total that excludes it.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def has_boundary_rows(net: IPNetwork) -> bool:
    """True when a subnet at this prefix gets network / broadcast rows."""
    return net.prefixlen < (127 if isinstance(net, ipaddress.IPv6Network) else 31)


def boundary_rows(net: IPNetwork) -> list[tuple[str, str, str]]:
    """``(address, status, description)`` for the rows create_subnet seeds."""
    if not has_boundary_rows(net):
        return []
    rows = [(str(net.network_address), "network", "Network address")]
    if isinstance(net, ipaddress.IPv4Network):
        rows.append((str(net.broadcast_address), "broadcast", "Broadcast address"))
    return rows


def boundary_addresses(net: IPNetwork) -> set[str]:
    return {a for a, _s, _d in boundary_rows(net)}


def boundary_host_conflicts(rows: Iterable[Any], nets: Iterable[IPNetwork]) -> list[str]:
    """Details for every host row sitting on a result's network / broadcast.

    ``network`` / ``broadcast`` rows are the placeholders themselves (or an
    operator's renamed one, which survives by design); only another status
    is a host.
    """
    where: dict[str, str] = {}
    for net in nets:
        for addr, status, _d in boundary_rows(net):
            where[addr] = f"the {status} address of {net}"
    out: list[str] = []
    for row in rows:
        if row.status in ("network", "broadcast"):
            continue
        label = where.get(str(row.address))
        if label is not None:
            out.append(
                f"{row.address} ({row.status}"
                f"{', ' + row.hostname if row.hostname else ''}) would sit on "
                f"{label}, which no client can use. Move or delete it first."
            )
    return out


async def ensure_boundary_rows(
    db: AsyncSession,
    subnet_id: uuid.UUID,
    net: IPNetwork,
    created_by_user_id: uuid.UUID | None,
) -> int:
    """Add the network / broadcast rows a subnet at ``net`` is missing."""
    spec = boundary_rows(net)
    if not spec:
        return 0
    existing = {
        str(a)
        for a in (
            await db.execute(select(IPAddress.address).where(IPAddress.subnet_id == subnet_id))
        )
        .scalars()
        .all()
    }
    created = 0
    for addr, status, desc in spec:
        if addr in existing:
            continue
        db.add(
            IPAddress(
                subnet_id=subnet_id,
                address=addr,
                status=status,
                description=desc,
                created_by_user_id=created_by_user_id,
            )
        )
        created += 1
    return created
