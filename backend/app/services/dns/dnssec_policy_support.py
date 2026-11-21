"""A custom DNSSEC policy on a PowerDNS group (#4567, #4623).

The PowerDNS agent signs every zone with its own fixed settings (ECDSA P-256,
plain NSEC, no scheduled rollover) and never reads the zone's
``DNSSECPolicy``, so a stored custom policy claims an algorithm / NSEC3 /
lifetimes the zone is not signed with. #4567 refused it on the zone update and
on Sign; every other way a zone and a PowerDNS server meet is checked here too,
from this one module: the Copilot ``sign_zone_dnssec`` proposal, a zone move
into the group, and a server joining the group. A backup restore is not
refused (a restore must not fail on stored data); the zone's DNSSEC info
reports :func:`stored_policy_warning` instead.

Only a *change* to a custom policy is refused. The built-in default matches
what PowerDNS does and is always accepted, and a value already stored passes
an untouched save (transition-only, so a zone that held one before the
upgrade stays editable).
"""

from __future__ import annotations

import uuid
from collections.abc import Collection

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSSECPolicy, DNSServer, DNSZone

#: Drivers that sign with fixed settings and ignore the zone's policy.
POLICY_IGNORING_DRIVERS: frozenset[str] = frozenset({"powerdns"})


def policy_refusal(policy_name: str) -> str:
    return (
        "PowerDNS does not apply a custom DNSSEC policy: it signs zones with ECDSA "
        "P-256 and plain NSEC and does no scheduled key rollover, so the policy "
        f"{policy_name!r} would be stored but not honoured. Use the built-in default "
        "policy, or put the zone in a BIND9 group."
    )


async def group_ignores_policy(db: AsyncSession, group_id: uuid.UUID) -> bool:
    """True when any server of the group runs a driver that ignores policies."""
    row = await db.execute(
        select(DNSServer.id)
        .where(DNSServer.group_id == group_id, DNSServer.driver.in_(POLICY_IGNORING_DRIVERS))
        .limit(1)
    )
    return row.first() is not None


async def custom_policy(db: AsyncSession, policy_id: uuid.UUID | None) -> DNSSECPolicy | None:
    """The policy row when it is a custom (non built-in) one, else None."""
    if policy_id is None:
        return None
    pol = await db.get(DNSSECPolicy, policy_id)
    if pol is None or pol.is_builtin:
        return None
    return pol


async def set_policy_refusal(
    db: AsyncSession, group_id: uuid.UUID, zone: DNSZone, policy_id: uuid.UUID | None
) -> str | None:
    """Why setting *policy_id* on *zone* (in *group_id*) is refused, or None."""
    if policy_id is None or policy_id == zone.dnssec_policy_id:
        return None
    pol = await custom_policy(db, policy_id)
    if pol is None or not await group_ignores_policy(db, group_id):
        return None
    return policy_refusal(pol.name)


async def move_refusal(
    db: AsyncSession,
    zone: DNSZone,
    source_drivers: Collection[str],
    target_drivers: Collection[str],
) -> str | None:
    """Why moving *zone* into a group running *target_drivers* is refused.

    A zone already on a PowerDNS group keeps its stored policy across a move
    to another one (nothing new is lost), so only a move from a group that
    honoured it is refused.
    """
    if not POLICY_IGNORING_DRIVERS & set(target_drivers):
        return None
    if POLICY_IGNORING_DRIVERS & set(source_drivers):
        return None
    pol = await custom_policy(db, zone.dnssec_policy_id)
    if pol is None:
        return None
    return policy_refusal(pol.name)


async def group_policy_zone_refusal(
    db: AsyncSession, group_id: uuid.UUID, group_name: str, driver: str
) -> str | None:
    """Why a *driver* server joining *group_id* is refused: the group holds a
    zone with a custom policy the driver would silently stop honouring.

    A group already served by such a driver passes: the zone is already on it.
    """
    if driver not in POLICY_IGNORING_DRIVERS or await group_ignores_policy(db, group_id):
        return None
    row = (
        await db.execute(
            select(DNSZone.name, DNSSECPolicy.name)
            .join(DNSSECPolicy, DNSSECPolicy.id == DNSZone.dnssec_policy_id)
            .where(
                DNSZone.group_id == group_id,
                DNSZone.deleted_at.is_(None),
                DNSSECPolicy.is_builtin.is_(False),
            )
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    return (
        f"Group {group_name!r} holds zone {row[0].rstrip('.')!r} with the custom DNSSEC "
        f"policy {row[1]!r}, which a {driver} server would not apply (it signs with ECDSA "
        "P-256 and plain NSEC). Switch the zone to the built-in default policy first."
    )


async def stored_policy_warning(db: AsyncSession, zone: DNSZone) -> str | None:
    """Text for a zone that holds a custom policy while its group runs
    PowerDNS (stored before #4567, or by a restore), or None."""
    pol = await custom_policy(db, zone.dnssec_policy_id)
    if pol is None or not await group_ignores_policy(db, zone.group_id):
        return None
    return (
        f"The custom DNSSEC policy {pol.name!r} is stored but not applied: PowerDNS signs "
        "this zone with ECDSA P-256 and plain NSEC and ignores the policy. Switch the zone "
        "to the built-in default policy, or move it to a BIND9 group."
    )
