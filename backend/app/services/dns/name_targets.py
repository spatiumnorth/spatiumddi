"""Name targets a PowerDNS group cannot take without a trailing dot (#2060).

A record whose value is, or ends in, a domain name (CNAME, PTR, MX, SRV, …)
may be stored without its trailing dot. A zone-file driver reads such a
target relative to the zone (``db1.example.com`` in ``example.com`` is
``db1.example.com.example.com.``), and that is the reading the rest of the
control plane applies to a PowerDNS group too (``targets_are_relative``,
``zone_target_readings``).

PowerDNS itself has no such reading: its API refuses the dot-less spelling
(``422 Not in expected format (parsed as 'db1.example.com.')``, verified
against pdns-auth 5.0.7). Its agent now qualifies a dot-less target against
the zone, so a row that already exists — an importer's, or one written
before this check — is served as a BIND9 agent would serve it. But an
operator on a PowerDNS group is used to absolute names, so ``db1.example.com``
typed there almost certainly means ``db1.example.com.``, and silently
serving ``db1.example.com.example.com.`` instead would be a wrong answer
nobody asked for. The record API and the Copilot therefore refuse a new
dot-less target on a group that runs PowerDNS, naming both spellings it
could have meant, rather than guessing.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer

#: Drivers whose API refuses a name target without its trailing dot.
ABSOLUTE_TARGET_DRIVERS = frozenset({"powerdns"})

# Types whose whole value is the target name.
_BARE_TARGET_TYPES = frozenset({"CNAME", "DNAME", "NS", "PTR", "ALIAS"})
# Types whose target is the value's last token (an MX / SRV value may carry
# its priority / weight / port inline; a NAPTR replacement is its last field).
_LAST_TOKEN_TARGET_TYPES = frozenset({"MX", "SRV", "NAPTR"})
# SVCB / HTTPS: ``priority target params…``.
_SVCB_TARGET = re.compile(r"^\s*\d+\s+([^\s\"=]+)(?=\s|$)")


def record_target(record_type: str, value: str) -> str | None:
    """The domain name in a record's value, or None if its type carries none
    (or the value is not in a shape that carries one)."""
    rtype = record_type.upper()
    text = (value or "").strip()
    if not text:
        return None
    if rtype in _BARE_TARGET_TYPES:
        return text
    if rtype in _LAST_TOKEN_TARGET_TYPES:
        last = text.split()[-1]
        return None if last.startswith('"') else last
    if rtype in ("SVCB", "HTTPS"):
        m = _SVCB_TARGET.match(text)
        return m.group(1) if m else None
    return None


def dotless_target(record_type: str, value: str) -> str | None:
    """The record's target name when it lacks its trailing dot, else None.

    The root (``.``: a null MX, an SVCB pointing at its owner, a NAPTR with
    no replacement) is absolute.
    """
    target = record_target(record_type, value)
    if target is None or target.endswith("."):
        return None
    return target


def dotless_target_error(record_type: str, value: str, zone_name: str) -> str | None:
    """The refusal for a dot-less target on a PowerDNS group, or None."""
    target = dotless_target(record_type, value)
    if target is None:
        return None
    zone = zone_name.rstrip(".") + "."
    rtype = record_type.upper()
    if target == "@":
        return (
            f"{rtype} record value: the target '@' needs to be written as an absolute "
            f"name on this group's PowerDNS servers: use '{zone}'."
        )
    return (
        f"{rtype} record value: the target '{target}' has no trailing dot. This group's "
        "PowerDNS servers take record targets as absolute names, so end it with a dot: "
        f"'{target}.' for that name, or '{target}.{zone}' for a name in {zone}"
    )


async def group_needs_absolute_targets(db: AsyncSession, group_id: uuid.UUID | None) -> bool:
    """True when any server in ``group_id`` runs a driver that refuses a
    dot-less name target. A group with no servers yet does not: there is no
    server to refuse it, and the agent qualifies the row if one joins."""
    if group_id is None:
        return False
    drivers = (
        (await db.execute(select(DNSServer.driver).where(DNSServer.group_id == group_id)))
        .scalars()
        .all()
    )
    return any(d in ABSOLUTE_TARGET_DRIVERS for d in drivers)


async def absolute_target_error(
    db: AsyncSession,
    group_id: uuid.UUID | None,
    record_type: str,
    value: str,
    zone_name: str,
) -> str | None:
    """:func:`dotless_target_error`, only on a group that needs it. The
    group is looked up only when the value has a dot-less target at all."""
    if dotless_target(record_type, value) is None:
        return None
    if not await group_needs_absolute_targets(db, group_id):
        return None
    return dotless_target_error(record_type, value, zone_name)
