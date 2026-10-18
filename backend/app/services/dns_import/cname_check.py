"""CNAME-beside-other-data check for the DNS importers (#2089).

The record API refuses a CNAME at a name that holds other data, and a CNAME
at the zone apex (#1381, ``app.services.dns.cname_conflict``); the importers
stored such rows anyway, and the server then refused the zone (BIND's
"CNAME and other data", PowerDNS's "Conflicts with pre-existing RRset").

Every importer creates its zone fresh (an overwrite deletes and recreates),
so the only clashes to find are inside the imported set itself. They are
resolved with the shared rule: the non-CNAME data is kept and the CNAME is
skipped; of several CNAMEs at one name the first is kept; an apex CNAME is
skipped. The preview reports each such record (``annotate_cname_conflicts``)
and the commit drops it, saying why (``cname_skips``). The commit never
trusts the preview's report: the plan round-trips through the client.
"""

from __future__ import annotations

from app.core.dns_names import contains_control_chars
from app.services.dns.cname_conflict import NameRow, refused_by_cname_rule

from .canonical import ImportedZone, ImportPreview

_PREFIX = "CNAME rule: "


def cname_skips(zone: ImportedZone) -> dict[int, str]:
    """``{index into zone.records: reason}`` for each record that cannot be
    stored under the CNAME rule. The SOA is not stored as a record, and nor
    is a record the commit drops for a control character (#597): a row that
    never lands must not cost another row its place."""
    idx = [
        i
        for i, r in enumerate(zone.records)
        if r.record_type != "SOA"
        and not contains_control_chars(r.name)
        and not contains_control_chars(r.value)
    ]
    rows = [
        NameRow(zone.records[i].name, zone.records[i].record_type, zone.records[i].value)
        for i in idx
    ]
    return {idx[j]: why for j, why in refused_by_cname_rule(rows).items()}


def describe_skip(zone: ImportedZone, index: int, reason: str) -> str:
    r = zone.records[index]
    return f"{r.name or '@'} {r.record_type} {r.value}: skipped - {reason}"


def is_cname_warning(warning: str) -> bool:
    """Whether a preview warning is one :func:`annotate_cname_conflicts` added."""
    return warning.startswith(_PREFIX)


def zone_warnings(zone: ImportedZone) -> list[str]:
    return [
        f"{_PREFIX}zone {zone.name!r}: {describe_skip(zone, i, why)}"
        for i, why in sorted(cname_skips(zone).items())
    ]


def annotate_cname_conflicts(preview: ImportPreview) -> None:
    """Add one preview warning per record the commit will skip."""
    for z in preview.zones:
        preview.warnings.extend(zone_warnings(z))


def count_cname_warnings(warnings: list[str]) -> int:
    """How many records a preview says the commit will skip under the rule."""
    return sum(1 for w in warnings if is_cname_warning(w))
