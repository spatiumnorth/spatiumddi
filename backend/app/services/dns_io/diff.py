"""Diff parsed zone-file records against existing DNSRecord rows."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from app.models.dns import DNSRecord
from app.services.dns_io.parser import ParsedRecord


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


@dataclass
class ZoneDiff:
    """Result of comparing parsed records to the existing zone."""

    to_create: list[RecordChange] = field(default_factory=list)
    to_update: list[RecordChange] = field(default_factory=list)
    to_delete: list[RecordChange] = field(default_factory=list)
    unchanged: list[RecordChange] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _record_key(name: str, rtype: str, value: str) -> tuple[str, str, str]:
    return (name.lower(), rtype.upper(), value)


def diff_records(
    parsed: Iterable[ParsedRecord],
    existing: Iterable[DNSRecord],
    zone_default_ttl: int | None = None,
) -> ZoneDiff:
    """Compare ``parsed`` records against ``existing`` DB rows.

    Identity is (name, record_type, value). When that key matches but TTL
    or priority/weight/port differ, the change becomes an ``update``.

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
    existing_list = list(existing)
    parsed_list = list(parsed)
    existing_by_key: dict[tuple[str, str, str], DNSRecord] = {
        _record_key(r.name, r.record_type, r.value): r for r in existing_list
    }

    def _effective(row: DNSRecord) -> int | None:
        if row.ttl is None:
            return zone_default_ttl
        return row.ttl

    # Lowest effective TTL among the existing rows the file names, per RRset:
    # what the file's collapsed TTL reads back as when nothing changed.
    rrset_min: dict[tuple[str, str], int] = {}
    for p in parsed_list:
        row = existing_by_key.get(_record_key(p.name, p.record_type, p.value))
        eff = _effective(row) if row is not None else None
        if eff is None:
            continue
        rk = (p.name.lower(), p.record_type.upper())
        rrset_min[rk] = min(eff, rrset_min.get(rk, eff))

    diff = ZoneDiff()
    seen_keys: set[tuple[str, str, str]] = set()

    for p in parsed_list:
        key = _record_key(p.name, p.record_type, p.value)
        seen_keys.add(key)
        existing_row = existing_by_key.get(key)
        if existing_row is None:
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
                )
            )
            continue

        if existing_row.ttl is None and zone_default_ttl is not None:
            ttl_changed = p.ttl is not None and p.ttl != zone_default_ttl
        else:
            ttl_changed = (p.ttl or 0) != (existing_row.ttl or 0)
        if ttl_changed and p.ttl == rrset_min.get((p.name.lower(), p.record_type.upper())):
            ttl_changed = False
        meta_changed = (
            p.priority != existing_row.priority
            or p.weight != existing_row.weight
            or p.port != existing_row.port
        )
        # An update that is only about priority/weight/port must not touch the
        # TTL: the commit writes ``change.ttl`` verbatim, so it would pin a TTL
        # the row inherits, or collapse an explicit one to the RRset minimum.
        if ttl_changed or meta_changed:
            diff.to_update.append(
                RecordChange(
                    op="update",
                    name=p.name,
                    record_type=p.record_type,
                    value=p.value,
                    ttl=p.ttl if ttl_changed else existing_row.ttl,
                    priority=p.priority,
                    weight=p.weight,
                    port=p.port,
                    existing_id=str(existing_row.id),
                )
            )
        else:
            diff.unchanged.append(
                RecordChange(
                    op="unchanged",
                    name=p.name,
                    record_type=p.record_type,
                    value=p.value,
                    ttl=p.ttl,
                    priority=p.priority,
                    weight=p.weight,
                    port=p.port,
                    existing_id=str(existing_row.id),
                )
            )

    for key, row in existing_by_key.items():
        if key in seen_keys:
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
            )
        )

    return diff
