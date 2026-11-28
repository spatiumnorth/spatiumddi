"""Canonical IR shared by all DNS importers (issue #128).

Every source — BIND9 archive, Windows DNS live-pull, PowerDNS REST —
parses upstream config into the same neutral shape so the commit
endpoint can stay source-agnostic. The shape is deliberately a
strict subset of what ``DNSZone`` + ``DNSRecord`` carry: enough to
recreate a zone faithfully, no source-specific extensions. Anything
the source carries that we can't model lands in
``ImportedZone.parse_warnings`` so the UI can surface it on the
preview.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

# Stable enum the importer stamps on every row it creates. Keep in
# sync with the values the migration writes into ``import_source``.
# The cloud-hosted DNS sources (issue #37, Part B) stamp the provider
# name directly so provenance stays queryable per provider; all four
# fit the ``import_source`` String(20) column.
ImportSource = Literal[
    "bind9",
    "windows_dns",
    "powerdns",
    "technitium",
    "cloudflare",
    "route53",
    "azure_dns",
    "google_dns",
    "digitalocean",
    "hetzner",
    "linode",
    "vultr",
]

# Per-zone conflict resolution. ``rename`` requires ``rename_to`` to
# carry the new FQDN; the commit endpoint validates that.
ConflictAction = Literal["skip", "overwrite", "rename"]


@dataclass
class ImportedRecord:
    """One DNS record in the canonical shape.

    Mirrors the columns the DNSRecord table needs at create-time. MX /
    SRV split priority + weight + port out of ``value`` so the table's
    dedicated columns stay populated — same convention
    :func:`app.services.dns_io.parser.parse_zone_file` already uses.
    """

    name: str  # relative label, "@" for apex
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


@dataclass
class ImportedSOA:
    """SOA fields. NULL on a forward / stub zone."""

    primary_ns: str
    admin_email: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    ttl: int


@dataclass
class ImportedZone:
    """One zone in the canonical shape.

    ``name`` is FQDN with trailing dot. ``view_name`` is the BIND9
    view the zone lived in (if any) — Phase 1 collapses everything
    to the default view and emits a warning per multi-view source.

    ``skipped_record_types`` lists rdtypes we can't model (DNSKEY,
    RRSIG, NSEC, …) so the UI can show "stripped 47 DNSSEC records"
    on the preview without diving into per-record detail.
    """

    name: str
    zone_type: str  # primary | secondary | stub | forward
    kind: str  # forward | reverse
    soa: ImportedSOA | None
    records: list[ImportedRecord]
    view_name: str | None = None
    forwarders: list[str] = field(default_factory=list)
    # #4259: the primaries a secondary / stub zone transfers from, as the
    # zone API stores them (``ip`` or ``ip@port``). Empty for other types.
    masters: list[str] = field(default_factory=list)
    skipped_record_types: dict[str, int] = field(default_factory=dict)
    parse_warnings: list[str] = field(default_factory=list)
    # #1892: set by the commit when ``apex_ns_policy="replace"`` rewrote the
    # apex NS set; recorded in the zone's audit row. Never round-tripped.
    apex_ns_replaced: dict[str, Any] | None = None
    # #1892: apex NS targets naming no server of the target group, set by the
    # preview so the UI can offer ``apex_ns_policy="replace"``. Derived.
    foreign_apex_ns: list[str] = field(default_factory=list)

    @property
    def record_type_histogram(self) -> dict[str, int]:
        """Per-record-type count for the preview UI."""
        out: dict[str, int] = {}
        for r in self.records:
            out[r.record_type] = out.get(r.record_type, 0) + 1
        return out


@dataclass
class ZoneConflict:
    """A zone whose name already exists in the target group + view.

    Operator picks ``action`` per row; default is ``skip`` so a fat-
    fingered "Commit" doesn't trample existing zones. ``rename``
    expects ``rename_to`` to carry the operator-typed replacement
    name (FQDN with trailing dot — the commit endpoint validates).
    """

    zone_name: str
    existing_zone_id: str  # uuid as str
    existing_record_count: int
    action: ConflictAction = "skip"
    rename_to: str | None = None


@dataclass
class ImportPreview:
    """What ``POST /dns/import/{source}/preview`` returns.

    ``zones`` is the full canonical IR — the commit endpoint
    re-receives it from the operator (the UI passes it back) so we
    don't need to store it server-side between the two calls.
    """

    source: ImportSource
    zones: list[ImportedZone]
    conflicts: list[ZoneConflict]
    warnings: list[str]
    total_records: int
    record_type_histogram: dict[str, int]
    # The server the records were live-pulled from (cloud / Windows DNS),
    # ``None`` for file-based and API-endpoint sources. The commit uses it
    # to not push the records back to the server they came from (#1456).
    source_server_id: uuid.UUID | None = None


REPLICA_ZONE_TYPES = frozenset({"secondary", "stub"})


def settle_replica_zone(zone: ImportedZone) -> str | None:
    """Hold a secondary / stub zone to the rule the zone API holds it to (#4259).

    A secondary or stub zone takes its data from its masters, so it imports
    with no records (#3838 refuses them there: nothing serves them), and it
    needs at least one master (the zone API 422s without one). Drops the
    records in place with a note on the zone. Returns the reason the zone
    cannot be imported (no master), or None when it can.
    """

    if zone.zone_type not in REPLICA_ZONE_TYPES:
        return None
    if not zone.masters:
        return (
            f"Zone {zone.name!r} skipped: it is a {zone.zone_type} zone and the source "
            "names no primary server (masters / primaries) to transfer it from, "
            f"which a {zone.zone_type} zone needs. Add it by hand once you know its masters."
        )
    if zone.records:
        zone.parse_warnings.append(
            f"Zone {zone.name!r}: records come from the masters; "
            f"{len(zone.records)} record(s) in the file were not imported"
        )
        zone.records = []
    return None


def settle_replica_zones(zones: list[ImportedZone], warnings: list[str]) -> list[ImportedZone]:
    """:func:`settle_replica_zone` over a source's zones; the zones that cannot
    be imported are left out and named in ``warnings``."""

    kept: list[ImportedZone] = []
    for z in zones:
        reason = settle_replica_zone(z)
        if reason is None:
            kept.append(z)
        else:
            warnings.append(reason)
    return kept
