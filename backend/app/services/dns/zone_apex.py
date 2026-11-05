"""The SOA and apex NS a primary zone actually serves (#3518).

The agent-managed BIND9 driver builds a zone file's opening lines from the
zone's settings, not from stored records (``_zone_apex`` in
``agent/dns/spatium_dns_agent/drivers/bind9.py``, #1153): the zone's own apex NS
records when it has any, else ``primary_ns`` when that can resolve, else the
placeholder ``ns1.<zone>`` glued to 127.0.0.1. This module is the control
plane's one copy of that rule, so the records list, the ingest mirror and the
copilot cannot disagree with what is served. The agent image cannot import
``app``, so the rule is duplicated there; ``tests/test_zone_apex_parity_3518.py``
feeds both the same zones and fails when they drift. Keep the two in step.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import admin_email_error, primary_ns_error
from app.models.dns import DNSRecord, DNSServer, DNSZone

ApexSource = Literal["declared", "primary_ns", "placeholder"]

PLACEHOLDER_NS_LABEL = "ns1"
PLACEHOLDER_NS_ADDRESS = "127.0.0.1"
_PLACEHOLDER_RNAME_LABEL = "admin"
# A zone whose own name holds a label that is not a host name (``_msdcs.…``)
# cannot hold a name BIND's check-names accepts, so its placeholder lives
# outside it (#3003).
_PLACEHOLDER_OUTSIDE = "invalid."
_PLACEHOLDER_OUTSIDE_RNAME = "invalid."

_ZONEFILE_UNSAFE_RE = re.compile(r'[\s;$()"@\\]|[\x00-\x1f\x7f]')
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class ServedApex:
    soa_mname: str
    soa_rname: str
    # The NS set the zone serves at its apex, absolute names.
    ns: tuple[str, ...]
    source: ApexSource
    # The agent writes ``ns1 IN A 127.0.0.1`` beside the placeholder NS.
    placeholder_glue: bool


def _absolute_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if (
        not name
        or name == "."
        or not name.isascii()
        or name.startswith(".")
        or ".." in name
        or _ZONEFILE_UNSAFE_RE.search(name)
    ):
        return None
    return name if name.endswith(".") else name + "."


def _is_host_name(absolute: str) -> bool:
    return primary_ns_error(absolute) is None


def _is_mailbox_name(absolute: str) -> bool:
    return admin_email_error(absolute) is None


def _zone_file_name(value: str, origin: str) -> str:
    v = (value or "").strip()
    if v in ("", "@"):
        return origin
    return v if v.endswith(".") else f"{v}.{origin}"


def _inside(name: str, origin: str) -> bool:
    n, o = name.lower(), origin.lower()
    return n == o or n.endswith("." + o)


def _labels_are_host_names(origin: str) -> bool:
    body = origin.removesuffix(".")
    return not body or all(_HOST_LABEL_RE.match(label) for label in body.split("."))


def compute_served_apex(
    zone_name: str,
    primary_ns: str | None,
    admin_email: str | None,
    records: Iterable[tuple[str, str, str]],
) -> ServedApex:
    """What the BIND9 agent renders at the apex of primary zone ``zone_name``.

    ``records`` are ``(name, record_type, value)`` for every record that
    reaches the agent's bundle (name as stored: relative, ``@`` for the apex).
    Mirrors ``_zone_apex``; see its docstring for the order of the NS rules.
    """
    raw = str(zone_name or "")
    origin = raw if raw.endswith(".") else raw + "."

    addressed: set[str] = set()
    declared_ns: list[str] = []
    for name, rtype_raw, value in records:
        rtype = str(rtype_raw or "").upper()
        owner = _zone_file_name(str(name or ""), origin)
        if rtype in ("A", "AAAA"):
            addressed.add(owner.lower())
        elif rtype == "NS" and owner.lower() == origin.lower():
            declared_ns.append(_zone_file_name(str(value or ""), origin))

    primary = _absolute_name(primary_ns)
    if primary is not None and not _is_host_name(primary):
        primary = None
    admin = _absolute_name(admin_email)
    if admin is not None and not _is_mailbox_name(admin):
        admin = None

    if _labels_are_host_names(origin):
        placeholder = f"{PLACEHOLDER_NS_LABEL}.{origin}"
        rname_fallback = f"{_PLACEHOLDER_RNAME_LABEL}.{origin}"
    else:
        placeholder = _PLACEHOLDER_OUTSIDE
        rname_fallback = _PLACEHOLDER_OUTSIDE_RNAME

    source: ApexSource
    if declared_ns:
        source = "declared"
        ns_set = declared_ns
    elif primary is not None and (not _inside(primary, origin) or primary.lower() in addressed):
        source = "primary_ns"
        ns_set = [primary]
    else:
        source = "placeholder"
        ns_set = [placeholder]

    placeholder_glue = (
        _inside(placeholder, origin)
        and placeholder.lower() in {n.lower() for n in ns_set}
        and placeholder.lower() not in addressed
    )
    mname = primary or (declared_ns[0] if declared_ns else placeholder)
    rname = admin or rname_fallback
    return ServedApex(mname, rname, tuple(ns_set), source, placeholder_glue)


@dataclass(frozen=True)
class ZoneApexView:
    """A primary zone's :class:`ServedApex` plus whether the BIND9 rule is the
    one its group's driver follows."""

    apex: ServedApex
    driver_applies: bool


async def served_apex_for_zones(
    db: AsyncSession, zones: Iterable[DNSZone]
) -> dict[uuid.UUID, ZoneApexView]:
    """:class:`ZoneApexView` for each primary zone of ``zones``, in two queries
    however many zones there are. Other zone types are absent from the result:
    a secondary, stub or forward zone has no apex of ours."""
    # Lazy: ``app.services.dns.ingest`` imports this module.
    from app.services.dns.ingest import EXTERNAL_IMPORT_SOURCE  # noqa: PLC0415

    primaries = [z for z in zones if z.zone_type == "primary"]
    if not primaries:
        return {}
    by_zone: dict[uuid.UUID, list[tuple[str, str, str]]] = {z.id: [] for z in primaries}
    rows = await db.execute(
        select(DNSRecord.zone_id, DNSRecord.name, DNSRecord.record_type, DNSRecord.value).where(
            DNSRecord.zone_id.in_(list(by_zone)),
            DNSRecord.deleted_at.is_(None),
            # ddns_external mirrors never reach the agent's bundle.
            DNSRecord.import_source.is_distinct_from(EXTERNAL_IMPORT_SOURCE),
        )
    )
    for zone_id, name, rtype, value in rows.all():
        by_zone[zone_id].append((name, rtype, value))
    group_ids = {z.group_id for z in primaries}
    drivers: dict[uuid.UUID, set[str]] = {g: set() for g in group_ids}
    for group_id, driver in (
        await db.execute(
            select(DNSServer.group_id, DNSServer.driver).where(DNSServer.group_id.in_(group_ids))
        )
    ).all():
        drivers[group_id].add(driver)
    out: dict[uuid.UUID, ZoneApexView] = {}
    for z in primaries:
        # A group with no servers yet defaults to bind9, the flagship driver.
        names = drivers[z.group_id] or {"bind9"}
        out[z.id] = ZoneApexView(
            compute_served_apex(z.name, z.primary_ns, z.admin_email, by_zone[z.id]),
            names == {"bind9"},
        )
    return out
