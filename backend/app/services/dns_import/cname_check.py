"""CNAME-beside-other-data check for the DNS importers (#2089), plus the
BIND ``check-names`` check (#4155) that rides the same preview-warning and
commit-skip plumbing.

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

from app.core.dns_names import bind_check_names_error, contains_control_chars
from app.services.dns.cname_conflict import NameRow, refused_by_cname_rule

from .canonical import ImportedZone, ImportPreview

_PREFIX = "CNAME rule: "
_NAMES_PREFIX = "Name rule: "


def _owner_fqdn(zone: ImportedZone, rel: str) -> str:
    """The owner name the commit stores for relative owner *rel*."""
    zone_fqdn = zone.name.rstrip(".") + "."
    if rel in ("@", ""):
        return zone_fqdn
    return rel.rstrip(".") + "." + zone_fqdn


def names_skips(zone: ImportedZone) -> dict[int, str]:
    """``{index into zone.records: reason}`` for each record BIND's
    ``check-names`` would refuse (#4155) — the rule the record API applies
    (``bind_check_names_error``). One such row makes ``named-checkzone``
    reject the whole zone, so it is skipped and reported, not stored."""
    out: dict[int, str] = {}
    for i, r in enumerate(zone.records):
        if (
            r.record_type == "SOA"
            or contains_control_chars(r.name)
            or contains_control_chars(r.value)
        ):
            continue
        err = bind_check_names_error(
            r.record_type, _owner_fqdn(zone, r.name), r.value, origin=zone.name
        )
        if err is not None:
            out[i] = err
    return out


def cname_skips(zone: ImportedZone) -> dict[int, str]:
    """``{index into zone.records: reason}`` for each record that cannot be
    stored under the CNAME rule. The SOA is not stored as a record, and nor
    is a record the commit drops for a control character (#597): a row that
    never lands must not cost another row its place."""
    refused_names = names_skips(zone)
    idx = [
        i
        for i, r in enumerate(zone.records)
        if r.record_type != "SOA"
        and not contains_control_chars(r.name)
        and not contains_control_chars(r.value)
        and i not in refused_names  # never stored, so it costs no CNAME its place (#4155)
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
    """Whether a preview warning is one :func:`annotate_cname_conflicts` added
    (a CNAME-rule skip, or a check-names skip, #4155)."""
    return warning.startswith((_PREFIX, _NAMES_PREFIX))


def zone_warnings(zone: ImportedZone) -> list[str]:
    return [
        f"{_PREFIX}zone {zone.name!r}: {describe_skip(zone, i, why)}"
        for i, why in sorted(cname_skips(zone).items())
    ] + [
        f"{_NAMES_PREFIX}zone {zone.name!r}: {describe_skip(zone, i, why)}"
        for i, why in sorted(names_skips(zone).items())
    ]


def annotate_cname_conflicts(preview: ImportPreview) -> None:
    """Add one preview warning per record the commit will skip."""
    for z in preview.zones:
        preview.warnings.extend(zone_warnings(z))


def count_cname_warnings(warnings: list[str]) -> int:
    """How many records a preview says the commit will skip under the rule."""
    return sum(1 for w in warnings if is_cname_warning(w))
