"""Single-signer rule for DNSSEC on a multi-server group (#1762).

Every agent engine (BIND9 inline-signing, PowerDNS, Technitium) signs a zone
*independently on each server* with keys that server generated and holds.
SpatiumDDI has no shared key custody, so a signed zone on a group with two
agent servers is served with two different DNSKEY sets: a validating
resolver that lands on server B holds a DS (published at the parent from
server A's report) that does not match B's keys, and gets SERVFAIL.

**Every agent server in the group counts, enabled or not.** ``is_enabled``
only pauses the record-op fan-out (``record_ops``); a disabled agent still
long-polls and receives the full bundle (nothing in the bundle path reads
``is_enabled``), so a disabled BIND9 server renders ``inline-signing`` and
serves the zone signed with ITS OWN keys, and a disabled PowerDNS /
Technitium server serves it unsigned under the parent's DS (no sign op
reaches it) — bogus either way. A ``pending_approval`` server counts too:
approving it hands it the bundle.

Agentless drivers (``technitium_api``, Windows, cloud) are outside the rule:
the cloud providers hold one key set per hosted zone whatever the number of
server rows, and the others cannot sign at all (the router's
``_DRIVER_GATED_OPERATIONS["dnssec_sign"]`` refuses them).

Until keys are shared (out of scope for 1.0), a zone may only be signed when
at most one agent server would serve it, and a group holding signed zones
may not gain a second agent server through any operator path. A row the
control plane cannot refuse (an agent auto-registering into the group via
``AGENT_GROUP``; refusing would break its bootstrap) is recorded and
surfaced instead: the zone response's ``dnssec_multi_signer``, the zone
detail badge + DNSSEC card, and the default-on ``dnssec_multi_signer``
alert rule. Zones already signed on such a group are never unsigned
automatically.

The checks that refuse take a ``FOR NO KEY UPDATE`` lock on the group row
(:func:`lock_group`) so two concurrent "add a server" / "sign a zone"
requests serialise: the second re-reads after the first commits. The
``NO KEY`` strength does not block the FK ``KEY SHARE`` lock an ordinary
server insert takes, so agent registration is never stalled by it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSZone

#: Agent drivers that sign per server. Pinned equal to the router's
#: ``_DRIVER_GATED_OPERATIONS["dnssec_sign"]`` by a test (not imported here:
#: the router imports this module).
SIGNING_DRIVERS: frozenset[str] = frozenset({"bind9", "powerdns", "technitium"})

WORKAROUND = (
    "Keep a single DNS server in the group (delete it or move the others to "
    "another group; disabling a server does not stop it serving the zone), "
    "or wait for shared DNSSEC keys."
)


async def lock_group(db: AsyncSession, group_id: uuid.UUID) -> None:
    """Serialise signer-count decisions for ``group_id`` until commit."""
    await db.execute(
        select(DNSServerGroup.id)
        .where(DNSServerGroup.id == group_id)
        .with_for_update(key_share=True)
    )


async def signing_server_count(
    db: AsyncSession, group_id: uuid.UUID, *, exclude_server_id: uuid.UUID | None = None
) -> int:
    """Agent servers in the group that would sign (or serve) its zones."""
    q = (
        select(func.count())
        .select_from(DNSServer)
        .where(DNSServer.group_id == group_id, DNSServer.driver.in_(sorted(SIGNING_DRIVERS)))
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
    """Of ``group_ids``, those with more than one signing agent server."""
    ids = set(group_ids)
    if not ids:
        return set()
    res = await db.execute(
        select(DNSServer.group_id)
        .where(DNSServer.group_id.in_(ids), DNSServer.driver.in_(sorted(SIGNING_DRIVERS)))
        .group_by(DNSServer.group_id)
        .having(func.count() > 1)
    )
    return set(res.scalars().all())


async def multi_signer_zones(db: AsyncSession) -> list[tuple[DNSZone, int]]:
    """Every signed zone on a multi-signer group, with that group's signer count."""
    counts = (
        select(DNSServer.group_id.label("gid"), func.count().label("n"))
        .where(DNSServer.driver.in_(sorted(SIGNING_DRIVERS)))
        .group_by(DNSServer.group_id)
        .having(func.count() > 1)
        .subquery()
    )
    rows = (
        await db.execute(
            select(DNSZone, counts.c.n)
            .join(counts, counts.c.gid == DNSZone.group_id)
            .where(DNSZone.dnssec_enabled.is_(True))
            .order_by(DNSZone.name)
        )
    ).all()
    return [(z, int(n)) for z, n in rows]


async def sign_refusal(db: AsyncSession, group_id: uuid.UUID, *, lock: bool = True) -> str | None:
    """Why a zone in ``group_id`` may not be signed, or None. Locks the group
    unless ``lock=False`` (a read-only preview)."""
    if lock:
        await lock_group(db, group_id)
    n = await signing_server_count(db, group_id)
    if n <= 1:
        return None
    group = await db.get(DNSServerGroup, group_id)
    return sign_refusal_message(repr(group.name) if group else group_id, n)


async def second_signer_refusal(
    db: AsyncSession,
    group: DNSServerGroup,
    *,
    driver: str | None,
    exclude_server_id: uuid.UUID | None = None,
    lock: bool = True,
) -> str | None:
    """Why a ``driver`` server may not join ``group``, or None. Locks the
    group unless ``lock=False`` (a read-only preview).

    ``driver=None`` means "an agent of a not-yet-known engine" and is
    treated as a signer.
    """
    if driver is not None and driver not in SIGNING_DRIVERS:
        return None
    if lock:
        await lock_group(db, group.id)
    if await signing_server_count(db, group.id, exclude_server_id=exclude_server_id) < 1:
        return None
    signed = await signed_zone_count(db, group.id)
    if not signed:
        return None
    return add_server_refusal_message(group.name, signed)


async def is_ds_reporter(db: AsyncSession, server: DNSServer) -> bool:
    """Whether ``server``'s DNSSEC state report is the one the group keeps.

    One signer: always. Several (zones signed before the rule, or an agent
    that auto-registered in): the group's primary; with no primary among the
    signers (the primary was deleted — nothing re-elects on delete), the
    oldest signer, so the report never stops landing. Deterministic either
    way, which ends the last-writer-wins flapping. Going back to one server
    re-opens it to whoever remains.
    """
    if server.driver not in SIGNING_DRIVERS:
        return True
    gid = server.group_id
    if await signing_server_count(db, gid) <= 1:
        return True
    if server.is_primary:
        return True
    signers = (DNSServer.group_id == gid, DNSServer.driver.in_(sorted(SIGNING_DRIVERS)))
    has_primary = (
        await db.execute(
            select(func.count())
            .select_from(DNSServer)
            .where(*signers, DNSServer.is_primary.is_(True))
        )
    ).scalar_one()
    if has_primary:
        return False
    oldest = (
        (
            await db.execute(
                select(DNSServer.id).where(*signers).order_by(DNSServer.created_at, DNSServer.id)
            )
        )
        .scalars()
        .first()
    )
    return bool(oldest == server.id)


def sign_refusal_message(group_name_or_id: object, servers: int) -> str:
    return (
        f"Refusing to enable DNSSEC: group {group_name_or_id} has {servers} DNS servers "
        f"and each would sign the zone with its own keys, so resolvers would see "
        f"mismatched DNSKEYs against the published DS (SERVFAIL). {WORKAROUND}"
    )


def add_server_refusal_message(group_name: str, signed: int) -> str:
    return (
        f"Group {group_name!r} has {signed} DNSSEC-signed zone(s) and already has a DNS "
        f"server. A second server would sign them with its own keys (a disabled server "
        f"still serves them), so the DS published at the parent would not match it. "
        f"Unsign the zones first, use another group, or wait for shared DNSSEC keys."
    )


def register_warning_message(group_name: str, server_name: str, signed: int, n: int) -> str:
    return (
        f"DNS agent {server_name!r} registered into group {group_name!r}, which holds "
        f"{signed} DNSSEC-signed zone(s); the group now has {n} servers each signing with "
        f"its own keys, so resolvers that reach a server whose keys the published DS does "
        f"not match will SERVFAIL. Move the agent to another group (or unsign the zones)."
    )
