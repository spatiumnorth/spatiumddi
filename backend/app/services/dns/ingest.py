"""Ingest-back for externally-injected DDNS records (issue #641, Alt.1).

When an operator enables dynamic updates on a zone, a third-party writer
(an AD domain controller, a DHCP server registering A/PTR) can inject
records straight into the running daemon over RFC 2136. Those records live
only in the daemon's journal — the control plane, which treats the DB as
the source of truth, doesn't know about them, so a full re-render (cold
boot, from-scratch re-seed, zone-file path change) would drop them.

The agent closes the loop: it AXFRs each dynamic zone from loopback, diffs
the live records against the set the control plane shipped in the bundle,
and POSTs the *unknown* records here. We persist them as ordinary
``DNSRecord`` rows stamped ``import_source="ddns_external"`` so they become
UI/IPAM-visible and survive a re-render.

Conflict rule: **control-plane-managed names win.** An incoming record
whose ``(name, record_type)`` collides with a control-plane-managed row
(anything not itself an ``ddns_external`` mirror) is skipped — the operator's
declared state is authoritative. External-only names are preserved.

The agent sends the *complete* current external set for the zone each
cycle, so this reconciles: rows that vanished upstream are removed, new
ones are added. Zone-management + DNSSEC RRs (SOA, apex NS, RRSIG, NSEC*,
DNSKEY, CDS/CDNSKEY, private-type 65534) are never ingested — BIND owns them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone

# Provenance marker for a record the agent read back off the live zone.
EXTERNAL_IMPORT_SOURCE = "ddns_external"

# RR types the daemon manages itself — never ingested as "external writer"
# data even though they show up in an AXFR.
_IGNORED_TYPES = frozenset(
    {
        "SOA",
        "RRSIG",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "DNSKEY",
        "CDS",
        "CDNSKEY",
        "TYPE65534",  # BIND9 private-type signing marker
    }
)


@dataclass(frozen=True)
class IncomingRecord:
    """One record the agent read back off the live zone (relative name)."""

    name: str  # relative label, "@" = apex
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


@dataclass
class IngestResult:
    added: int = 0
    removed: int = 0
    skipped_managed: int = 0
    skipped_ignored: int = 0
    # What was added / removed, as ``{name, fqdn, record_type, value, ttl}``
    # dicts, so the caller can audit the batch by name (#2302). Uncapped here;
    # the audit writer caps what it persists.
    added_records: list[dict[str, object]] = field(default_factory=list)
    removed_records: list[dict[str, object]] = field(default_factory=list)


def _key(name: str, rtype: str, value: str) -> tuple[str, str, str]:
    return (name.lower(), rtype.upper(), value.strip())


def _describe(fqdn: str, name: str, rtype: str, value: str, ttl: int | None) -> dict[str, object]:
    return {"name": name, "fqdn": fqdn, "record_type": rtype, "value": value, "ttl": ttl}


# The glue the BIND9 agent renders beside its placeholder apex NS, for a zone
# that names no name server of its own (#2841). It is the renderer's own
# data, not an external writer's, so it is never mirrored.
_PLACEHOLDER_LABEL = "ns1"
_PLACEHOLDER_ADDRESS = "127.0.0.1"


def _placeholder_glue_in_use(zone: DNSZone, managed: list[DNSRecord]) -> bool:
    """True when the agent's renderer falls back to ``ns1.<zone>`` + glue.

    Mirrors ``_zone_apex`` in the agent's BIND9 driver: no managed NS record
    at the apex, and no usable ``primary_ns`` (empty, or inside the zone
    with no managed address of its own). ``managed`` is every live row that
    is not an external mirror, since only those reach the agent's bundle.
    """
    if any(r.record_type.upper() == "NS" and r.name in ("@", "") for r in managed):
        return False
    origin = zone.name.rstrip(".").lower()
    primary = (zone.primary_ns or "").strip().rstrip(".").lower()
    if not primary:
        return True
    if not primary.endswith("." + origin):
        return False  # resolves wherever it lives; no placeholder
    label = primary[: -(len(origin) + 1)]
    return not any(
        r.record_type.upper() in ("A", "AAAA") and r.name.lower() == label for r in managed
    )


def _is_placeholder_glue(name: str, rtype: str, value: str) -> bool:
    return (
        name.lower() == _PLACEHOLDER_LABEL
        and rtype.upper() == "A"
        and value.strip() == _PLACEHOLDER_ADDRESS
    )


def _is_apex_ns(name: str, rtype: str) -> bool:
    # The zone's own delegation NS at the apex is zone-management data, not
    # an external writer's record. Sub-label NS (delegations) are kept.
    return rtype.upper() == "NS" and name in ("@", "")


async def reconcile_external_records(
    db: AsyncSession,
    zone: DNSZone,
    incoming: list[IncomingRecord],
) -> IngestResult:
    """Reconcile the ``ddns_external`` mirror rows for one zone.

    Adds newly-seen external records, removes ones that vanished upstream,
    and skips anything shadowed by a control-plane-managed record (managed
    names win) or owned by the daemon (SOA/NS-apex/DNSSEC). Idempotent —
    re-running with the same input is a no-op.

    The caller is responsible for gating on ``zone.dynamic_update_enabled``
    and for committing the session.
    """
    result = IngestResult()

    # Exclude soft-deleted rows: a soft-deleted managed record must not keep
    # shadowing an incoming external one, and a soft-deleted mirror must not be
    # treated as "already present" (which would strand a still-live external
    # record as permanently invisible).
    existing = (
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zone.id, DNSRecord.deleted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    # (name, type) owned by the control plane — anything that isn't our own
    # external mirror. These win over an incoming external record.
    managed_nt: set[tuple[str, str]] = {
        (r.name.lower(), r.record_type.upper())
        for r in existing
        if r.import_source != EXTERNAL_IMPORT_SOURCE
    }
    # Current external mirror rows, keyed for diff.
    external_by_key: dict[tuple[str, str, str], DNSRecord] = {
        _key(r.name, r.record_type, r.value): r
        for r in existing
        if r.import_source == EXTERNAL_IMPORT_SOURCE
    }

    # An earlier build mirrored the placeholder glue as an external row. It is
    # simply never "desired" here, so the vanished-row sweep below removes it.
    placeholder_in_use = _placeholder_glue_in_use(
        zone, [r for r in existing if r.import_source != EXTERNAL_IMPORT_SOURCE]
    )

    zone_name_no_dot = zone.name.rstrip(".")
    desired_keys: set[tuple[str, str, str]] = set()

    for rec in incoming:
        rtype = rec.record_type.upper()
        if rtype in _IGNORED_TYPES or _is_apex_ns(rec.name, rtype):
            result.skipped_ignored += 1
            continue
        if placeholder_in_use and _is_placeholder_glue(rec.name, rtype, rec.value):
            result.skipped_ignored += 1
            continue
        if (rec.name.lower(), rtype) in managed_nt:
            result.skipped_managed += 1
            continue
        k = _key(rec.name, rtype, rec.value)
        desired_keys.add(k)
        if k in external_by_key:
            continue  # already mirrored
        fqdn = zone_name_no_dot if rec.name == "@" else f"{rec.name}.{zone_name_no_dot}"
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=rec.name,
                fqdn=fqdn,
                record_type=rtype,
                value=rec.value,
                ttl=rec.ttl,
                priority=rec.priority,
                weight=rec.weight,
                port=rec.port,
                auto_generated=False,
                import_source=EXTERNAL_IMPORT_SOURCE,
            )
        )
        result.added += 1
        result.added_records.append(_describe(fqdn, rec.name, rtype, rec.value, rec.ttl))

    # Remove mirrors that vanished upstream (present in DB, absent from the
    # agent's current external set). Hard-delete — a stale mirror would
    # otherwise re-render a record the writer already withdrew. Not
    # soft-deleted: the row is a cache of what the external writer holds, so
    # "restoring" it would resurrect a record the writer withdrew, and a
    # churning writer would pile up soft-deleted rows. The trail is the audit
    # row the caller writes from ``removed_records`` (#2302).
    for k, row in external_by_key.items():
        if k not in desired_keys:
            result.removed_records.append(
                _describe(row.fqdn, row.name, row.record_type, row.value, row.ttl)
            )
            await db.delete(row)
            result.removed += 1

    return result


def to_summary(result: IngestResult) -> dict[str, int]:
    return {
        "added": result.added,
        "removed": result.removed,
        "skipped_managed": result.skipped_managed,
        "skipped_ignored": result.skipped_ignored,
    }


__all__ = [
    "EXTERNAL_IMPORT_SOURCE",
    "IncomingRecord",
    "IngestResult",
    "reconcile_external_records",
    "to_summary",
]
