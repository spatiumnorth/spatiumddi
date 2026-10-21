"""Render a DNSZone + its DNSRecords back to RFC 1035 zone-file text."""

from __future__ import annotations

from collections.abc import Iterable

from app.drivers.dns._txt import quote_txt
from app.models.dns import DNSRecord, DNSZone


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


def write_zone_file(zone: DNSZone, records: Iterable[DNSRecord]) -> str:
    """Return the zone as a BIND-style RFC 1035 zone file."""
    origin = _fqdn(zone.name)
    primary = _fqdn(zone.primary_ns) if zone.primary_ns else origin
    admin = zone.admin_email or f"hostmaster.{origin}"
    admin = _fqdn(admin)
    serial = zone.last_serial or 1

    lines: list[str] = []
    lines.append(f"$ORIGIN {origin}")
    lines.append(f"$TTL {zone.ttl}")
    lines.append(
        f"@\tIN\tSOA\t{primary} {admin} ("
        f" {serial} {zone.refresh} {zone.retry} {zone.expire} {zone.minimum} )"
    )

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
