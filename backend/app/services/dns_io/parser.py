"""RFC 1035 zone-file parser using dnspython."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone

from app.models.dns import servable_ttl

# Record types SpatiumDDI stores in DNSRecord (matches VALID_RECORD_TYPES in router).
SUPPORTED_RECORD_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "NS",
    "PTR",
    "SRV",
    "CAA",
    "TLSA",
    "SSHFP",
    "NAPTR",
    "LOC",
    "SOA",
    "SVCB",
    "HTTPS",
    "DNAME",
}


class ZoneParseError(ValueError):
    """Raised when a zone file cannot be parsed."""


@dataclass(frozen=True)
class ParsedRecord:
    """Normalized representation of one DNS resource record.

    `name` is the label relative to the zone (``@`` means the apex).
    `value` is the rdata in presentation format, without any trailing dot
    where dnspython would omit one — matching how records are stored in
    the DNSRecord table.
    """

    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None

    def key(self) -> tuple[str, str, str]:
        """Identity tuple used for diffing (name, type, value)."""
        return (self.name.lower(), self.record_type.upper(), self.value)


@dataclass(frozen=True)
class ParsedSOA:
    """SOA fields extracted from a zone file."""

    primary_ns: str
    admin_email: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    ttl: int


@dataclass(frozen=True)
class ParsedZone:
    """Full parsing result for a zone file.

    ``skipped_types`` is a histogram of rdtypes the parser saw but
    chose not to surface as ``ParsedRecord`` rows because they're
    not in :data:`SUPPORTED_RECORD_TYPES` (DNSKEY, RRSIG, NSEC, …).
    Callers like the DNS import pipeline use this to warn the
    operator about DNSSEC + experimental record types that won't
    survive the round trip into SpatiumDDI's record table.
    """

    soa: ParsedSOA | None
    records: list[ParsedRecord]
    skipped_types: dict[str, int] = field(default_factory=dict)


def _normalize_zone_name(name: str) -> str:
    """Ensure name has a trailing dot."""
    return name if name.endswith(".") else name + "."


def _rel_name(rdata_name: dns.name.Name, origin: dns.name.Name) -> str:
    """Return the relative label for a record (``@`` for the apex)."""
    if rdata_name == origin:
        return "@"
    rel = rdata_name.relativize(origin)
    return rel.to_text()


def _format_rdata(rdtype: int, rdata: object) -> tuple[str, int | None, int | None, int | None]:
    """Return (value, priority, weight, port) for DB storage.

    ``value`` is the rdata in presentation format stripped of the priority
    (for MX) or priority/weight/port (for SRV) so those are stored in
    dedicated columns — matching how the DNSRecord create endpoint treats
    them today.
    """
    priority: int | None = None
    weight: int | None = None
    port: int | None = None

    if rdtype == dns.rdatatype.MX:
        priority = int(rdata.preference)  # type: ignore[attr-defined]
        value = rdata.exchange.to_text()  # type: ignore[attr-defined]
    elif rdtype == dns.rdatatype.SRV:
        priority = int(rdata.priority)  # type: ignore[attr-defined]
        weight = int(rdata.weight)  # type: ignore[attr-defined]
        port = int(rdata.port)  # type: ignore[attr-defined]
        value = rdata.target.to_text()  # type: ignore[attr-defined]
    else:
        value = rdata.to_text()  # type: ignore[attr-defined]

    return value, priority, weight, port


def parse_zone_file(text: str, zone_name: str) -> ParsedZone:
    """Parse an RFC 1035 zone file.

    ``zone_name`` is used as the $ORIGIN if the file does not provide one.
    Raises :class:`ZoneParseError` with a readable message on malformed input.
    """
    origin_str = _normalize_zone_name(zone_name)
    try:
        zone = dns.zone.from_text(
            text,
            origin=origin_str,
            relativize=False,
            check_origin=False,
        )
    except dns.exception.DNSException as exc:
        raise ZoneParseError(f"Failed to parse zone file: {exc}") from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise ZoneParseError(f"Unexpected error parsing zone file: {exc}") from exc

    origin = dns.name.from_text(origin_str)
    soa: ParsedSOA | None = None
    records: list[ParsedRecord] = []
    skipped_types: dict[str, int] = {}

    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            rtype_text = dns.rdatatype.to_text(rdataset.rdtype)
            rel = _rel_name(name, origin)

            if rdataset.rdtype == dns.rdatatype.SOA:
                # Only one SOA per zone.
                rdata = list(rdataset)[0]
                soa = ParsedSOA(
                    primary_ns=rdata.mname.to_text(),  # type: ignore[attr-defined]
                    admin_email=rdata.rname.to_text(),  # type: ignore[attr-defined]
                    serial=int(rdata.serial),  # type: ignore[attr-defined]
                    refresh=int(rdata.refresh),  # type: ignore[attr-defined]
                    retry=int(rdata.retry),  # type: ignore[attr-defined]
                    expire=int(rdata.expire),  # type: ignore[attr-defined]
                    minimum=int(rdata.minimum),  # type: ignore[attr-defined]
                    ttl=int(rdataset.ttl),
                )
                continue

            if rtype_text not in SUPPORTED_RECORD_TYPES:
                # Skip unsupported record types rather than fail the whole
                # import. Record the count by type so callers (e.g. the
                # DNS configuration importer, issue #128) can warn the
                # operator that DNSSEC / experimental rdtypes were
                # dropped on the way in.
                skipped_types[rtype_text] = skipped_types.get(rtype_text, 0) + len(rdataset)
                continue

            for rdata in rdataset:
                value, pri, wgt, prt = _format_rdata(rdataset.rdtype, rdata)
                records.append(
                    ParsedRecord(
                        name=rel,
                        record_type=rtype_text,
                        value=value,
                        # #2073 — dnspython accepts up to 2^32-1; past RFC
                        # 2181's 2^31-1 (and int4) the record inherits $TTL.
                        ttl=servable_ttl(int(rdataset.ttl)) if rdataset.ttl else None,
                        priority=pri,
                        weight=wgt,
                        port=prt,
                    )
                )

    return ParsedZone(soa=soa, records=records, skipped_types=skipped_types)
