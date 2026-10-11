"""Single-signer rule for DNSSEC on a multi-server group (#1762).

Every engine (BIND9 inline-signing, PowerDNS, Technitium) signs a zone
*independently on each server* with keys that server generated and holds.
SpatiumDDI has no shared key custody, so a signed zone on a group with two
enabled servers is served with two different DNSKEY sets: a validating
resolver that lands on server B holds a DS (published at the parent from
server A's report) that does not match B's keys, and gets SERVFAIL.

Until keys are shared (out of scope for 1.0), a zone may only be signed
when exactly one enabled server in its group would sign it, and a group
holding signed zones may not gain a second enabled server. Zones already
signed on such a group are never unsigned automatically; they are flagged
(``ZoneResponse.dnssec_multi_signer``) so the operator sees the hazard.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSZone

WORKAROUND = (
    "Keep a single enabled server in the group (disable or move the others), "
    "or wait for shared DNSSEC keys."
)


async def enabled_server_count(
    db: AsyncSession, group_id: uuid.UUID, *, exclude_server_id: uuid.UUID | None = None
) -> int:
    q = (
        select(func.count())
        .select_from(DNSServer)
        .where(DNSServer.group_id == group_id, DNSServer.is_enabled.is_(True))
    )
    if exclude_server_id is not None:
        q = q.where(DNSServer.id != exclude_server_id)
    return int((await db.execute(q)).scalar_one())


async def signed_zone_count(db: AsyncSession, group_id: uuid.UUID) -> int:
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(DNSZone)
                .where(DNSZone.group_id == group_id, DNSZone.dnssec_enabled.is_(True))
            )
        ).scalar_one()
    )


async def multi_signer_group_ids(
    db: AsyncSession, group_ids: Iterable[uuid.UUID]
) -> set[uuid.UUID]:
    """Of ``group_ids``, those with more than one enabled server."""
    ids = set(group_ids)
    if not ids:
        return set()
    res = await db.execute(
        select(DNSServer.group_id)
        .where(DNSServer.group_id.in_(ids), DNSServer.is_enabled.is_(True))
        .group_by(DNSServer.group_id)
        .having(func.count() > 1)
    )
    return set(res.scalars().all())


def sign_refusal_message(group_name_or_id: object, servers: int) -> str:
    return (
        f"Refusing to enable DNSSEC: group {group_name_or_id} has {servers} enabled DNS "
        f"servers and each would sign the zone with its own keys, so resolvers would "
        f"see mismatched DNSKEYs against the published DS (SERVFAIL). {WORKAROUND}"
    )


def add_server_refusal_message(group_name: str, signed: int) -> str:
    return (
        f"Group {group_name!r} has {signed} DNSSEC-signed zone(s) and already has an "
        f"enabled server. A second enabled server would sign them with its own keys, "
        f"so the DS published at the parent would not match it. Unsign the zones, "
        f"add/move the server disabled, or wait for shared DNSSEC keys."
    )
