"""Render a DNSZone + its DNSRecords back to RFC 1035 zone-file text."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns._txt import quote_txt
from app.models.dns import DNSRecord, DNSZone
from app.services.dns.zone_apex import (
    PLACEHOLDER_NS_ADDRESS,
    PLACEHOLDER_NS_LABEL,
    ServedApex,
    ZoneApexView,
    compute_served_apex,
    served_apex_for_zones,
)

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _fqdn(name: str) -> str:
    """Ensure a name is a FQDN with trailing dot."""
    return name if name.endswith(".") else name + "."


def _format_record(zone_name: str, r: DNSRecord) -> str:
    """Render a single DNSRecord in zone-file presentation format."""
    label = r.name if r.name else "@"
    ttl_part = f"{r.ttl}\t" if r.ttl is not None else ""

    rdata: str
    rtype = r.record_type.upper()
    if rtype == "MX":
        pri = r.priority if r.priority is not None else 10
        rdata = f"{pri} {r.value}"
    elif rtype == "SRV":
        pri = r.priority if r.priority is not None else 0
        wgt = r.weight if r.weight is not None else 0
        prt = r.port if r.port is not None else 0
        rdata = f"{pri} {wgt} {prt} {r.value}"
    elif rtype in {"CNAME", "NS", "PTR", "DNAME"}:
        # #2187: a name target is written exactly as stored. A stored
        # target without a trailing dot is relative to the zone (that is how
        # BIND and the record API read it), and ``$ORIGIN`` makes the file
        # read it the same way; forcing a dot on it turned ``mail`` into the
        # absolute ``mail.`` (a different name, outside the zone). DNAME
        # (RFC 6672) is a single redirection target like the others.
        # SVCB/HTTPS rdata falls through to verbatim passthrough.
        rdata = r.value
    elif rtype == "TXT":
        # Quoted, escaped and split into <=255-octet strings as the drivers
        # do; an already-quoted value is kept as is.
        rdata = quote_txt(r.value)
    else:
        rdata = r.value

    return f"{label}\t{ttl_part}IN\t{rtype}\t{rdata}"


def _comment_safe(text: str) -> str:
    """``text`` on one comment line: a control character would end the comment
    and start a record line."""
    return _CONTROL_RE.sub("?", text)


def _apex_notes(apex: ServedApex) -> list[str]:
    if apex.source == "declared":
        return []
    # The served NS set is not a stored record. Written as one it would
    # re-import as a created record (and break "an export re-imports as no
    # change", #2187), so it is only noted for whoever restores the file.
    notes = [f"; apex NS served from zone settings: {' '.join(apex.ns)}"]
    if apex.placeholder_glue:
        notes.append(
            f"; {PLACEHOLDER_NS_LABEL} is served glued to {PLACEHOLDER_NS_ADDRESS}"
            " by the BIND9 agent; declare your own NS before relying on it"
        )
    return notes


def write_zone_file(
    zone: DNSZone, records: Iterable[DNSRecord], served: ZoneApexView | None = None
) -> str:
    """Return the zone as a BIND-style RFC 1035 zone file.

    The SOA is the one the zone is served with (#3533), not a second guess at
    it: ``served`` is :func:`served_apex_for_zones`'s answer (what the agent
    renders). A caller with none (a zone that is not primary, or no database)
    gets the same rule applied to the records being written, and no notes.

    The served apex NS set, when the zone declares none of its own, is noted in
    a comment rather than written as records, and so is each split-horizon
    view's apex when the views disagree (the SOA line is then the worst of
    them, as the records list shows it). A group whose driver does not follow
    the BIND9 rule gets a note saying the SOA is that rule's, not a claim.
    """
    records = list(records)
    origin = _fqdn(zone.name)
    notes: list[str] = []
    if served is None:
        apex = compute_served_apex(
            zone.name,
            zone.primary_ns,
            zone.admin_email,
            ((r.name, r.record_type, r.value) for r in records),
        )
    else:
        apex = served.apex
        if not served.driver_applies:
            notes.append(
                "; SOA by the BIND9 agent's rule; this group's driver serves"
                " its own apex, so check it against the server"
            )
        elif served.by_view:
            for view_name, a in served.by_view:
                ns = " ".join(a.ns)
                notes.append(
                    _comment_safe(
                        f"; view {view_name}: SOA {a.soa_mname} {a.soa_rname}, apex NS {ns}"
                    )
                )
            notes.extend(_apex_notes(apex))
        else:
            notes.extend(_apex_notes(apex))
    serial = zone.last_serial or 1

    lines: list[str] = []
    lines.append(f"$ORIGIN {origin}")
    lines.append(f"$TTL {zone.ttl}")
    lines.append(
        f"@\tIN\tSOA\t{apex.soa_mname} {apex.soa_rname} ("
        f" {serial} {zone.refresh} {zone.retry} {zone.expire} {zone.minimum} )"
    )
    lines.extend(notes)

    # Group by name for readability.
    sorted_records = sorted(
        records,
        key=lambda r: (r.name != "@", r.name.lower(), r.record_type, r.value),
    )
    for r in sorted_records:
        # Skip SOA records if any slipped into DNSRecord — zone-level SOA above is the source of truth.
        if r.record_type.upper() == "SOA":
            continue
        lines.append(_format_record(zone.name, r))

    return "\n".join(lines) + "\n"


async def write_zone_file_served(
    db: AsyncSession, zone: DNSZone, records: Iterable[DNSRecord]
) -> str:
    """:func:`write_zone_file` with the apex the zone's group actually serves."""
    view = (await served_apex_for_zones(db, [zone])).get(zone.id)
    return write_zone_file(zone, records, view)
