"""Diff parsed zone-file records against existing DNSRecord rows."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.drivers.dns._txt import quote_txt
from app.models.dns import DNSRecord
from app.services.dns.cname_conflict import NameRow, refused_by_cname_rule
from app.services.dns_io.parser import ParsedRecord
from app.services.dns_io.spreadsheet import managed_reason
from app.services.technitium.rdata import svcb_canonical

# Types whose whole value ends in a domain name (SRV / MX: the priority,
# weight and port live in their own columns, so the value is the target).
_NAME_VALUED_TYPES = frozenset({"CNAME", "DNAME", "NS", "PTR", "MX", "SRV"})


@dataclass
class RecordChange:
    """A single record add / update / delete."""

    op: str  # "create" | "update" | "delete" | "unchanged"
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None
    existing_id: str | None = None
    # The record's view: the import's scope for a create, the row's own
    # view otherwise (#2167).
    view_id: uuid.UUID | None = None


@dataclass
class ZoneDiff:
    """Result of comparing parsed records to the existing zone."""

    to_create: list[RecordChange] = field(default_factory=list)
    to_update: list[RecordChange] = field(default_factory=list)
    to_delete: list[RecordChange] = field(default_factory=list)
    unchanged: list[RecordChange] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _abs_name(v: str, zone: str) -> str:
    """``v`` as a lower-case absolute name. A zone file reads a name without
    a trailing dot relative to the zone origin, and ``@`` is the origin."""
    v = v.strip().lower()
    if v in ("", "@"):
        return zone
    return v if v.endswith(".") else f"{v}.{zone}"


def _canonical_value(rtype: str, value: str, zone: str | None) -> str:
    """The one comparison form of a record value (#2187).

    The export writes a stored value as it is, and the parser reads the file
    back with every name absolute, so ``mail`` (relative, as the record API
    stores it), ``mail.example.com.`` and ``MAIL.example.com`` are one name;
    a TXT value is the same record bare or quoted. With no ``zone`` the value
    compares as written.
    """
    if zone is None:
        return value
    if rtype == "TXT":
        return quote_txt(value or "")
    if rtype in _NAME_VALUED_TYPES:
        return _abs_name(value, zone)
    if rtype == "NAPTR":
        head, sep, replacement = (value or "").strip().rpartition(" ")
        return f"{head.lower()} {_abs_name(replacement, zone)}" if sep else value
    if rtype in ("SVCB", "HTTPS"):
        return svcb_canonical((value or "").strip(), zone)
    return value


def _record_key(name: str, rtype: str, value: str, zone: str | None = None) -> tuple[str, str, str]:
    rtype = rtype.upper()
    return (name.lower(), rtype, _canonical_value(rtype, value, zone))


def _label(name: str, rtype: str, value: str) -> str:
    return f"{name} {rtype} {value}"


def _scope_name(view_id: uuid.UUID | None, view_names: dict[uuid.UUID, str]) -> str:
    if view_id is None:
        return "shared (no view)"
    return f"view {view_names.get(view_id, str(view_id))}"


def diff_records(
    parsed: Iterable[ParsedRecord],
    existing: Iterable[DNSRecord],
    zone_default_ttl: int | None = None,
    *,
    view_id: uuid.UUID | None = None,
    view_names: dict[uuid.UUID, str] | None = None,
    replace: bool = False,
    zone_name: str | None = None,
) -> ZoneDiff:
    """Compare ``parsed`` records against ``existing`` DB rows.

    Identity is (name, record_type, value) within the import's view scope.
    With ``zone_name`` the value is compared in its canonical form (#2187):
    names absolute against the zone, case folded, TXT quoted - so a
    relative target the record API stored matches the absolute one the
    parser reads back from our own export.
    When that key matches but TTL or priority/weight/port differ, the change
    becomes an ``update``.

    **Scope (#2167).** A zone file carries no view, so the import targets ONE
    scope: ``view_id`` when the caller names a view, else the shared records
    (``view_id IS NULL``). Only rows in that scope are matched, updated or
    deleted; rows in any other scope are never touched. A shared row renders
    in every view, so a view-scoped replace must not delete it (that would
    take it out of every OTHER view too), and a view-scoped import that
    names a record a shared row already serves leaves that row alone rather
    than creating a view twin. In the other direction, a shared import does
    not create a shared copy of a record that exists only in views: a shared
    row renders in every view, so it would widen the record into views that
    deliberately lack it (#935's lesson). That row is skipped with the reason.
    New records are created in the import's scope.

    **Ownership (#2167).** A record IPAM or an integration owns (``managed_by``
    — shared with the spreadsheet import, #2139) is never updated or deleted:
    a changed row for one is skipped with the reason, and under ``replace`` an
    owned record the file lacks is kept and reported. ``to_update`` and
    ``to_delete`` therefore only ever name operator-owned rows.

    TTLs are compared as *effective* TTLs (#1727). A row whose ``ttl`` is NULL
    inherits ``zone_default_ttl``; the parser cannot tell an inherited TTL from
    an explicit one (``$TTL`` fills it in), and our own export omits the column
    for such rows, so a re-import hands back the zone default. Comparing that
    against NULL read every inherited record as changed, and committing it
    pinned the TTL. A foreign file's explicit TTL that differs from the zone
    default still differs and updates as before.

    The parser also reports one TTL per RRset: dnspython collapses members
    of one (name, type) to the lowest TTL among them, as RFC 2181 §5.2
    requires of an RRset. So an RRset whose members carry different TTLs
    (an inherited member beside an explicit ``300``, say) parses back with
    every member at that minimum. The minimum is also what the RRset is
    served with (``services.dns.rrset``), so a member whose parsed TTL
    equals the RRset's existing effective minimum is unchanged too.
    Otherwise the round trip would pin the inherited member, and lower an
    explicit higher one, to a value the file never stated for it.
    """
    names = view_names or {}
    zone = zone_name.lower().rstrip(".") + "." if zone_name else None
    existing_list = list(existing)
    parsed_list = list(parsed)
    # Every row per key: legacy twins (#1230) share a key, and a dict keeping
    # one of them left the others neither matched nor deleted.
    in_scope: dict[tuple[str, str, str], list[DNSRecord]] = {}
    shared: dict[tuple[str, str, str], list[DNSRecord]] = {}
    in_views: dict[tuple[str, str, str], list[DNSRecord]] = {}
    out_of_scope: list[DNSRecord] = []
    for r in existing_list:
        key = _record_key(r.name, r.record_type, r.value, zone)
        if r.view_id == view_id:
            in_scope.setdefault(key, []).append(r)
            continue
        out_of_scope.append(r)
        if r.view_id is None:
            shared.setdefault(key, []).append(r)
        else:
            in_views.setdefault(key, []).append(r)

    def _effective(row: DNSRecord) -> int | None:
        if row.ttl is None:
            return zone_default_ttl
        return row.ttl

    # Lowest effective TTL among the existing rows the file names, per RRset:
    # what the file's collapsed TTL reads back as when nothing changed. A
    # shared row serves the view too, so it counts towards a view's RRset.
    rrset_min: dict[tuple[str, str], int] = {}
    for p in parsed_list:
        key = _record_key(p.name, p.record_type, p.value, zone)
        for row in in_scope.get(key) or shared.get(key) or []:
            eff = _effective(row)
            if eff is None:
                continue
            rk = (p.name.lower(), p.record_type.upper())
            rrset_min[rk] = min(eff, rrset_min.get(rk, eff))

    def _changes(p: ParsedRecord, row: DNSRecord) -> tuple[bool, bool]:
        if row.ttl is None and zone_default_ttl is not None:
            ttl_changed = p.ttl is not None and p.ttl != zone_default_ttl
        else:
            ttl_changed = (p.ttl or 0) != (row.ttl or 0)
        if ttl_changed and p.ttl == rrset_min.get((p.name.lower(), p.record_type.upper())):
            ttl_changed = False
        meta_changed = p.priority != row.priority or p.weight != row.weight or p.port != row.port
        return ttl_changed, meta_changed

    def _unchanged(p: ParsedRecord, row: DNSRecord) -> RecordChange:
        return RecordChange(
            op="unchanged",
            name=p.name,
            record_type=p.record_type,
            value=p.value,
            ttl=p.ttl,
            priority=p.priority,
            weight=p.weight,
            port=p.port,
            existing_id=str(row.id),
            view_id=row.view_id,
        )

    diff = ZoneDiff()
    seen_keys: set[tuple[str, str, str]] = set()

    for p in parsed_list:
        key = _record_key(p.name, p.record_type, p.value, zone)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        label = _label(p.name, p.record_type, p.value)
        rows = in_scope.get(key)
        if not rows:
            if view_id is not None and key in shared:
                # Already served in this view by a shared row: never a view
                # twin, and never an edit of a row every other view serves.
                row = shared[key][0]
                if any(_changes(p, row)):
                    diff.skipped.append(
                        f"{label}: not changed - this record is shared by every view; "
                        "import it without a view to change it"
                    )
                else:
                    diff.unchanged.append(_unchanged(p, row))
                continue
            if view_id is None and key in in_views:
                where = ", ".join(sorted({_scope_name(r.view_id, names) for r in in_views[key]}))
                diff.skipped.append(
                    f"{label}: not created - it exists only in {where}; a shared copy "
                    "would render in every view. Import into a view to manage view records"
                )
                continue
            diff.to_create.append(
                RecordChange(
                    op="create",
                    name=p.name,
                    record_type=p.record_type,
                    value=p.value,
                    ttl=p.ttl,
                    priority=p.priority,
                    weight=p.weight,
                    port=p.port,
                    view_id=view_id,
                )
            )
            continue

        for row in rows:
            ttl_changed, meta_changed = _changes(p, row)
            if not (ttl_changed or meta_changed):
                diff.unchanged.append(_unchanged(p, row))
                continue
            reason = managed_reason(row)
            if reason is not None:
                diff.skipped.append(f"{label}: not changed - this record is {reason}")
                continue
            # An update that is only about priority/weight/port must not touch
            # the TTL: the commit writes ``change.ttl`` verbatim, so it would
            # pin a TTL the row inherits, or collapse an explicit one to the
            # RRset minimum.
            diff.to_update.append(
                RecordChange(
                    op="update",
                    name=p.name,
                    record_type=p.record_type,
                    value=p.value,
                    ttl=p.ttl if ttl_changed else row.ttl,
                    priority=p.priority,
                    weight=p.weight,
                    port=p.port,
                    existing_id=str(row.id),
                    view_id=row.view_id,
                )
            )

    for key, rows in in_scope.items():
        if key in seen_keys:
            continue
        for row in rows:
            reason = managed_reason(row)
            if reason is not None:
                if replace:
                    diff.skipped.append(
                        f"{_label(row.name, row.record_type, row.value)}: "
                        f"not deleted - this record is {reason}"
                    )
                continue
            diff.to_delete.append(
                RecordChange(
                    op="delete",
                    name=row.name,
                    record_type=row.record_type,
                    value=row.value,
                    ttl=row.ttl,
                    priority=row.priority,
                    weight=row.weight,
                    port=row.port,
                    existing_id=str(row.id),
                    view_id=row.view_id,
                )
            )

    if replace and out_of_scope:
        counts: dict[str, int] = {}
        for row in out_of_scope:
            scope = _scope_name(row.view_id, names)
            counts[scope] = counts.get(scope, 0) + 1
        parts = ", ".join(f"{n} {scope}" for scope, n in sorted(counts.items()))
        diff.skipped.append(
            f"not deleted: {len(out_of_scope)} record(s) outside this import's scope "
            f"({_scope_name(view_id, names)}) were left in place - {parts}"
        )

    return diff


def apply_cname_rule(diff: ZoneDiff, existing: Iterable[DNSRecord], *, replace: bool) -> ZoneDiff:
    """Move every ``to_create`` row the CNAME rule refuses into ``diff.skipped``
    with its reason (#2089), so neither the preview nor the commit offers it.

    Standing rows are the zone's existing records that survive the import: all
    of them, except the ones a ``replace`` deletes. They win over the file; the
    file's own rows resolve among themselves as the importers do (non-CNAME
    data beats a CNAME, first CNAME wins, no apex CNAME). The check shares its
    rule with the record API through ``services.dns.cname_conflict``.
    """
    dropped = {c.existing_id for c in diff.to_delete} if replace else set()
    standing = [
        NameRow(r.name, r.record_type, r.value, r.view_id)
        for r in existing
        if str(r.id) not in dropped
    ]
    # Rows the file leaves in place count too: they are in ``existing`` already.
    rows = [NameRow(c.name, c.record_type, c.value, c.view_id) for c in diff.to_create]
    refused = refused_by_cname_rule(rows, standing)
    if not refused:
        return diff
    keep: list[RecordChange] = []
    for i, c in enumerate(diff.to_create):
        if i in refused:
            diff.skipped.append(f"{c.name} {c.record_type} {c.value}: skipped - {refused[i]}")
        else:
            keep.append(c)
    diff.to_create = keep
    return diff
