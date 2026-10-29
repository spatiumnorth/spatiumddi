"""Zone delegation wizard helpers.

When operators create a sub-zone of a zone they already host (e.g.
``dev.example.com`` under ``example.com``) the parent must carry NS records
for the sub-zone's label, plus glue (A / AAAA) for any in-bailiwick NS
hostnames. Without that, recursive resolvers never learn the sub-zone exists
and queries for it NXDOMAIN at the parent. This module computes the records
needed, surfaces them to the UI for confirmation, then applies them through
the normal record-op pipeline so DDNS / agent push fires uniformly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone


def _norm(name: str) -> str:
    """Lower-case + ensure exactly one trailing dot."""
    n = name.strip().lower()
    if not n.endswith("."):
        n += "."
    return n


async def find_parent_zone(
    db: AsyncSession, group_id: uuid.UUID, child_name: str
) -> DNSZone | None:
    """Return the longest-suffix-matching zone in the same group.

    Compares against every zone whose name is a strict suffix of ``child_name``
    (excluding the child itself). Returns the zone with the longest name when
    multiple suffixes match — that's the immediate parent. Forward zones are
    not eligible parents (they don't carry records).
    """
    child = _norm(child_name)
    res = await db.execute(select(DNSZone).where(DNSZone.group_id == group_id))
    candidates: list[DNSZone] = []
    for z in res.scalars().all():
        if z.zone_type == "forward":
            continue
        zname = _norm(z.name)
        if zname == child:
            continue
        # Strict suffix: parent.example.com. is a parent of host.parent.example.com.
        # Match must be on a label boundary, not a trailing-substring coincidence.
        if child.endswith("." + zname):
            candidates.append(z)
    if not candidates:
        return None
    candidates.sort(key=lambda z: len(z.name), reverse=True)
    return candidates[0]


def child_label_in_parent(parent: DNSZone, child: DNSZone) -> str:
    """Return the relative label that names the child inside the parent.

    For child ``dev.example.com.`` and parent ``example.com.`` returns
    ``dev``. For deeper nesting (``a.b.example.com.`` under ``example.com.``)
    returns ``a.b``. Empty string is impossible — the child must be strictly
    deeper than the parent.
    """
    p = _norm(parent.name)
    c = _norm(child.name)
    assert c.endswith("." + p), "caller must verify parent/child relationship"
    return c[: -len(p) - 1]  # strip trailing ".parent." (with the dot)


def is_in_bailiwick(child_name: str, ns_hostname: str) -> bool:
    """True when ``ns_hostname`` falls under ``child_name`` (needs glue)."""
    c = _norm(child_name)
    n = _norm(ns_hostname)
    return n == c or n.endswith("." + c)


@dataclass
class _PendingRecord:
    name: str
    record_type: str
    value: str
    ttl: int


@dataclass
class DelegationPreview:
    parent_zone_id: uuid.UUID
    parent_zone_name: str
    child_zone_id: uuid.UUID
    child_zone_name: str
    child_label: str
    # Records that would be created in the parent zone:
    ns_records_to_create: list[_PendingRecord] = field(default_factory=list)
    glue_records_to_create: list[_PendingRecord] = field(default_factory=list)
    # Records already present in the parent zone — left alone:
    existing_ns_records: list[_PendingRecord] = field(default_factory=list)
    existing_glue_records: list[_PendingRecord] = field(default_factory=list)
    # Operator-facing diagnostics surfaced even though apply still works.
    warnings: list[str] = field(default_factory=list)
    child_apex_ns_count: int = 0


async def _load_records(db: AsyncSession, zone_id: uuid.UUID) -> list[DNSRecord]:
    res = await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone_id))
    return list(res.scalars().all())


async def compute_delegation(
    db: AsyncSession, parent: DNSZone, child: DNSZone
) -> DelegationPreview:
    """Compute the NS + glue records needed to delegate ``child`` from ``parent``.

    Source of truth is the child zone's own apex NS records — that's what the
    delegation has to mirror so the parent's NS RRset matches what the child
    serves authoritatively. Glue is only needed for in-bailiwick NS names.
    """
    label = child_label_in_parent(parent, child)
    preview = DelegationPreview(
        parent_zone_id=parent.id,
        parent_zone_name=parent.name,
        child_zone_id=child.id,
        child_zone_name=child.name,
        child_label=label,
    )

    child_records = await _load_records(db, child.id)
    parent_records = await _load_records(db, parent.id)

    apex_ns = [r for r in child_records if r.record_type == "NS" and r.name == "@"]
    preview.child_apex_ns_count = len(apex_ns)
    if not apex_ns:
        preview.warnings.append(
            f"{child.name.rstrip('.')} has no NS records at the apex — add at least "
            "one (e.g. ``@ NS ns1.example.com.``) before delegating."
        )

    parent_ns_at_label = {
        r.value.rstrip(".").lower()
        for r in parent_records
        if r.record_type == "NS" and r.name == label
    }

    for ns in apex_ns:
        ns_value = ns.value.rstrip(".") + "."
        rec = _PendingRecord(
            name=label,
            record_type="NS",
            value=ns_value,
            ttl=ns.ttl if ns.ttl is not None else child.ttl,
        )
        if ns_value.rstrip(".").lower() in parent_ns_at_label:
            preview.existing_ns_records.append(rec)
        else:
            preview.ns_records_to_create.append(rec)

    glue_seen: set[tuple[str, str, str]] = set()
    for ns in apex_ns:
        ns_value = _norm(ns.value)
        if not is_in_bailiwick(child.name, ns_value):
            continue
        rel = ns_value[: -len(_norm(child.name)) - 1] if ns_value != _norm(child.name) else "@"
        # Find the matching A/AAAA records in the child zone:
        matching = [
            r
            for r in child_records
            if r.record_type in ("A", "AAAA") and (r.name == rel or (rel == "@" and r.name == "@"))
        ]
        if not matching:
            preview.warnings.append(
                f"{ns.value.rstrip('.')} is in-bailiwick but has no A/AAAA record in "
                f"{child.name.rstrip('.')} — recursive resolvers won't be able to reach it."
            )
            continue
        # Glue name in the *parent* is the in-bailiwick NS hostname's label
        # relative to the parent zone — i.e., its full name minus the parent
        # zone, no trailing dot.
        glue_label = ns_value[: -len(_norm(parent.name)) - 1]
        for ar in matching:
            key = (glue_label, ar.record_type, ar.value)
            if key in glue_seen:
                continue
            glue_seen.add(key)
            existing = any(
                r.name == glue_label and r.record_type == ar.record_type and r.value == ar.value
                for r in parent_records
            )
            rec = _PendingRecord(
                name=glue_label,
                record_type=ar.record_type,
                value=ar.value,
                ttl=ar.ttl if ar.ttl is not None else child.ttl,
            )
            if existing:
                preview.existing_glue_records.append(rec)
            else:
                preview.glue_records_to_create.append(rec)

    return preview


def preview_to_dict(p: DelegationPreview) -> dict[str, Any]:
    """JSON-friendly dict for the API response."""

    def _list(rs: list[_PendingRecord]) -> list[dict[str, Any]]:
        return [
            {"name": r.name, "record_type": r.record_type, "value": r.value, "ttl": r.ttl}
            for r in rs
        ]

    return {
        "parent_zone_id": str(p.parent_zone_id),
        "parent_zone_name": p.parent_zone_name,
        "child_zone_id": str(p.child_zone_id),
        "child_zone_name": p.child_zone_name,
        "child_label": p.child_label,
        "ns_records_to_create": _list(p.ns_records_to_create),
        "glue_records_to_create": _list(p.glue_records_to_create),
        "existing_ns_records": _list(p.existing_ns_records),
        "existing_glue_records": _list(p.existing_glue_records),
        "warnings": p.warnings,
        "child_apex_ns_count": p.child_apex_ns_count,
    }
