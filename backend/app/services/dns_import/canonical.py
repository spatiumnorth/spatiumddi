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
from typing import Literal

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
    skipped_record_types: dict[str, int] = field(default_factory=dict)
    parse_warnings: list[str] = field(default_factory=list)

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
