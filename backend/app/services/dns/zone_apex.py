"""The SOA and apex NS a primary zone actually serves (#3518).

The agent-managed BIND9 driver builds a zone file's opening lines from the
zone's settings, not from stored records (``_zone_apex`` in
``agent/dns/spatium_dns_agent/drivers/bind9.py``, #1153): the zone's own apex NS
records when it has any, else ``primary_ns`` when that can resolve, else the
placeholder ``ns1.<zone>`` glued to 127.0.0.1. This module is the control
plane's one copy of that rule, so the records list, the ingest mirror and the
copilot cannot disagree with what is served. The agent image cannot import
``app``, so the rule is duplicated there; ``tests/test_zone_apex_parity_3518.py``
feeds both the same zones and ``tests/test_zone_apex_bundle_parity_3518.py``
runs the agent's copy on a real config bundle; both fail when they drift.
Keep the two in step.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import MAX_NAME_LEN, admin_email_error, primary_ns_error
from app.models.dns import DNSRecord, DNSServer, DNSView, DNSZone
from app.services.dns.pool_geo import (
    build_geo_steering,
    build_view_descriptors,
    records_for_view,
    views_rendering_zone,
)

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


def apex_name_length_error(
    zone_name: str,
    primary_ns: str | None,
    admin_email: str | None,
    records: Iterable[tuple[str, str, str]] = (),
) -> str | None:
    """Why primary zone ``zone_name`` cannot be served with the apex names it
    would get, or None (#3672).

    A zone name may be 253 characters, but with no Primary NS its SOA names
    the placeholder ``ns1.<zone>``, and with no Admin Email the mailbox
    ``admin.<zone>``: four and six characters more. Past 253 those are not DNS
    names at all, so BIND refuses the zone and it is never served. The names
    an operator types are held to 253 by their own validators; this catches
    the ones the zone is given in their absence. ``records`` are the zone's
    as for :func:`compute_served_apex`: an apex NS record replaces the
    placeholder name server.
    """
    apex = compute_served_apex(zone_name, primary_ns, admin_email, records)
    zone = str(zone_name or "").rstrip(".")
    unset: list[str] = []
    served_as: list[str] = []
    room = MAX_NAME_LEN
    for served, field, what in (
        (apex.soa_mname, "Primary NS (primary_ns)", "name server"),
        (apex.soa_rname, "Admin Email (admin_email)", "mailbox"),
    ):
        body = served.rstrip(".")
        if len(body) <= MAX_NAME_LEN:
            continue
        label = body[: -len(zone) - 1] if zone else body
        unset.append(field)
        served_as.append(f"the {what} '{label}.<zone name>' ({len(body)} characters)")
        room = min(room, MAX_NAME_LEN - len(label) - 1)
    if not unset:
        return None
    return (
        f"zone name is {len(zone)} characters, so with no {' and no '.join(unset)} "
        f"set the zone would be served with {' and '.join(served_as)}, over the "
        f"{MAX_NAME_LEN}-character limit of a DNS name, and the DNS server would "
        f"refuse the zone. Set the {' and the '.join(unset)}, or shorten the zone "
        f"name to at most {room} characters"
    )


@dataclass(frozen=True)
class ZoneApexView:
    """A primary zone's :class:`ServedApex` plus whether the BIND9 rule is the
    one its group's driver follows.

    Under split-horizon the agent renders the apex once per view, from that
    view's records, so a zone whose apex NS is declared in one view only is
    served the placeholder in the others. ``by_view`` then lists every view's
    apex in render order, and ``apex`` is the worst of them (the loopback glue
    first, then any placeholder), so a summary never hides it. ``by_view`` is
    empty when every view serves the same apex, or the group has no views.
    """

    apex: ServedApex
    driver_applies: bool
    by_view: tuple[tuple[str, ServedApex], ...] = ()


def _address_candidates(zone: DNSZone) -> set[str]:
    """Lowercased stored owner spellings whose A/AAAA can change ``zone``'s
    apex: the placeholder and an in-zone Primary NS, each relative or
    absolute. A superset is harmless: other owners never decide the apex."""
    raw = str(zone.name or "")
    origin = raw if raw.endswith(".") else raw + "."
    targets = {f"{PLACEHOLDER_NS_LABEL}.{origin}".lower()}
    if (primary := _absolute_name(zone.primary_ns)) is not None:
        targets.add(primary.lower())
    out: set[str] = set()
    for t in targets:
        if not _inside(t, origin):
            continue
        out.add(t)
        if t == origin.lower():
            out.update({"@", ""})
        else:
            out.add(t[: -(len(origin) + 1)])
    return out


def _worst(apexes: list[ServedApex]) -> ServedApex:
    for a in apexes:
        if a.placeholder_glue:
            return a
    for a in apexes:
        if a.source == "placeholder":
            return a
    return apexes[0]


async def served_apex_for_zones(
    db: AsyncSession, zones: Iterable[DNSZone]
) -> dict[uuid.UUID, ZoneApexView]:
    """:class:`ZoneApexView` for each primary zone of ``zones``. Other zone
    types are absent from the result: a secondary, stub or forward zone has
    no apex of ours.

    The inputs are the ones the agent's bundle carries (``agent_config``):
    every live record, ingest mirrors included (#2850), in the bundle's order,
    split per view by the bundle's own ``views_rendering_zone`` /
    ``records_for_view``. Only the rows that can decide an apex are read
    (apex-candidate NS rows and the A/AAAA of the placeholder and the Primary
    NS), so a zone's size does not set the cost of a records-list page.
    """
    primaries = [z for z in zones if z.zone_type == "primary"]
    if not primaries:
        return {}
    by_zone: dict[uuid.UUID, list[Any]] = {z.id: [] for z in primaries}
    addr_names: set[str] = set()
    for z in primaries:
        addr_names |= _address_candidates(z)
    rtype = func.upper(DNSRecord.record_type)
    rows = await db.execute(
        select(
            DNSRecord.zone_id,
            DNSRecord.name,
            DNSRecord.record_type,
            DNSRecord.value,
            DNSRecord.view_id,
            DNSRecord.pool_member_id,
        ).where(
            DNSRecord.zone_id.in_(list(by_zone)),
            DNSRecord.deleted_at.is_(None),
            or_(
                rtype == "NS",
                and_(rtype.in_(("A", "AAAA")), func.lower(DNSRecord.name).in_(addr_names)),
            ),
        )
        # The bundle's record order (``_records_query``): the first declared
        # NS is the SOA MNAME when no Primary NS is set.
        .order_by(DNSRecord.zone_id, DNSRecord.name, DNSRecord.record_type, DNSRecord.value)
    )
    for row in rows.all():
        by_zone[row.zone_id].append(row)

    group_ids = {z.group_id for z in primaries}
    drivers: dict[uuid.UUID, set[str]] = {g: set() for g in group_ids}
    for group_id, driver in (
        await db.execute(
            select(DNSServer.group_id, DNSServer.driver).where(DNSServer.group_id.in_(group_ids))
        )
    ).all():
        drivers[group_id].add(driver)
    views_by_group: dict[uuid.UUID, list[DNSView]] = {g: [] for g in group_ids}
    for v in (
        (await db.execute(select(DNSView).where(DNSView.group_id.in_(group_ids)))).scalars().all()
    ):
        views_by_group[v.group_id].append(v)
    geo_by_group = {g: await build_geo_steering(db, g) for g in group_ids}
    descs_by_group = {
        g: (
            build_view_descriptors(
                sorted(views_by_group[g], key=lambda v: (v.order, v.name)), geo_by_group[g]
            )
            if views_by_group[g] or geo_by_group[g].active
            else []
        )
        for g in group_ids
    }
    # Which views a zone lands in turns on every view-scoped record it holds,
    # not only the apex rows read above.
    viewed = [z.id for z in primaries if descs_by_group[z.group_id]]
    scoped_views: dict[uuid.UUID, set[uuid.UUID]] = {zid: set() for zid in viewed}
    if viewed:
        for zone_id, view_id in (
            await db.execute(
                select(DNSRecord.zone_id, DNSRecord.view_id)
                .where(
                    DNSRecord.zone_id.in_(viewed),
                    DNSRecord.deleted_at.is_(None),
                    DNSRecord.view_id.is_not(None),
                )
                .distinct()
            )
        ).all():
            scoped_views[zone_id].add(view_id)

    def _apex(z: DNSZone, recs: list[Any]) -> ServedApex:
        return compute_served_apex(
            z.name, z.primary_ns, z.admin_email, ((r.name, r.record_type, r.value) for r in recs)
        )

    out: dict[uuid.UUID, ZoneApexView] = {}
    for z in primaries:
        # A group with no servers yet defaults to bind9, the flagship driver.
        names = drivers[z.group_id] or {"bind9"}
        applies = names == {"bind9"}
        geo = geo_by_group[z.group_id]
        recs = by_zone[z.id]
        descs = descs_by_group[z.group_id]
        if not descs:
            flat = [
                r
                for r in recs
                if r.pool_member_id is None or str(r.pool_member_id) not in geo.unreachable_members
            ]
            out[z.id] = ZoneApexView(_apex(z, flat), applies)
            continue
        per_view = [
            (vd["name"], _apex(z, records_for_view(recs, vd, geo)))
            for vd in views_rendering_zone(descs, z.view_id, scoped_views[z.id])
        ]
        if not per_view:
            # Rendered in no view, so served nowhere; describe the shared rows.
            out[z.id] = ZoneApexView(_apex(z, [r for r in recs if r.view_id is None]), applies)
            continue
        apexes = [a for _, a in per_view]
        if all(a == apexes[0] for a in apexes):
            out[z.id] = ZoneApexView(apexes[0], applies)
        else:
            out[z.id] = ZoneApexView(_worst(apexes), applies, tuple(per_view))
    return out
