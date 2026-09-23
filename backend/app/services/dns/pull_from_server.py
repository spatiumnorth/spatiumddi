"""Bi-directional DNS zone sync between SpatiumDDI's DB and the zone's
authoritative server.

Two phases, both additive:

1. **Pull** — AXFR the server and create ``DNSRecord`` rows for anything
   on the wire that's missing from our DB.
2. **Push** — for every record in our DB (after the pull) that isn't on
   the wire, send an RFC 2136 update via the driver's
   ``apply_record_change`` so it lands on the server.

Neither phase deletes anything. Delete intent flows through the normal
record-deletion UI (which already pushes a ``delete`` op through the
driver). Destructive reconciliation (three-way diff + confirmation UI)
is a later iteration.

Driver-agnostic via ``DNSDriver.pull_zone_records`` + the existing
``apply_record_change``. BIND9, Technitium, Windows DNS and the cloud
providers all implement the pull side; the agent-managed ones read over
a TSIG-signed AXFR (#734), the rest over their own authenticated API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import get_driver
from app.drivers.dns.base import RecordChange, RecordData, TsigKey
from app.models.dns import DNSRecord, DNSZone
from app.services.dns.record_ops import resolve_primary_server
from app.services.dns.serial import bump_zone_serial
from app.services.dns.tsig import (
    pull_zone_records_signed,
    resolve_group_transfer_key,
    resolve_view_transfer_key,
    transfer_needs_tsig,
)

logger = structlog.get_logger(__name__)


@dataclass
class PullResult:
    """What happened during a pull-from-server operation."""

    server_records: int  # count read from the wire
    existing_in_db: int  # count already in DB that matched
    imported: int  # count of rows we created
    imported_records: list[dict[str, Any]]  # user-visible list for UI
    skipped_unsupported: int  # count filtered because record_type not imported


@dataclass
class PushResult:
    """What happened during a push-to-server operation."""

    candidates: int  # DB rows considered (in DB but not on wire)
    pushed: int  # successfully applied on the wire
    pushed_records: list[dict[str, Any]]  # user-visible list for UI
    push_errors: list[str]  # one entry per failed push (first ~10)


@dataclass
class SyncResult:
    """Combined pull + push result returned by ``sync_zone_with_server``."""

    pull: PullResult
    push: PushResult


# Record types we import — matches the IP/host model. Excludes zone-level
# metadata (SOA/apex NS), security-heavy types that need their own editor
# (DNSKEY, DS, RRSIG), and IDN puns.
_IMPORTABLE_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "SRV",
    "PTR",
    "NS",  # non-apex NS only; the driver filters apex NS already
    "TLSA",
}


# Record types whose value is a DNS name. Same-zone targets are sometimes
# stored relative ("aaa") and sometimes absolute ("aaa.zone.example."). A
# naive string compare would treat those as distinct and import a duplicate.
# ``_normalize_value`` folds both forms into a single canonical shape before
# we key on them.
_NAME_VALUED_TYPES = frozenset({"CNAME", "NS", "PTR", "MX", "SRV"})


def _normalize_value(rtype: str, value: str, zone_name: str) -> str:
    """Canonicalise a record value for dedup.

    * Name-valued types: lowercase, ensure trailing dot, and expand bare
      labels against the zone origin. "aaa", "aaa.", "AAA.ZONE.LOCAL." and
      "aaa.zone.local" all collapse to "aaa.zone.local." once the zone is
      "zone.local.".
    * Everything else: stripped + lowercased (fine for A/AAAA/IP literals
      where case doesn't matter either).
    """
    v = (value or "").strip().lower()
    if rtype not in _NAME_VALUED_TYPES:
        return v
    # "@" means the zone apex.
    if v == "@" or v == "":
        return zone_name.lower()
    # Already absolute.
    if v.endswith("."):
        return v
    # Bare label (no dot or not fully qualified) → append zone.
    if "." not in v:
        return f"{v}.{zone_name}".lower()
    # Qualified but missing trailing dot → add it.
    return f"{v}.".lower()


def _key(r: RecordData | DNSRecord, zone_name: str) -> tuple[str, str, str]:
    """Identity key for dedup: (name, type, canonical-value). TTL-only
    differences don't count — neither does relative-vs-FQDN storage for
    name-valued records."""
    name = (r.name or "").strip().lower()
    rtype = r.record_type.upper()
    return (name, rtype, _normalize_value(rtype, r.value, zone_name))


#: The address record the BIND9 agent writes into every primary zone file,
#: beside the apex ``NS ns1.<zone>`` it also writes, so BIND will load a zone
#: whose NS names an in-zone host (``_write_zone_file`` in
#: agent/dns/spatium_dns_agent/drivers/bind9.py). Keep the two in step.
_AGENT_NS_GLUE = RecordData(name="ns1", record_type="A", value="127.0.0.1")


def without_agent_ns_glue(
    on_wire: list[RecordData],
    server: Any,
    zone_name: str,
    db_keys: set[tuple[str, str, str]],
) -> list[RecordData]:
    """``on_wire`` minus the agent's own NS glue, when ``server`` is agent-managed BIND9.

    The glue is render apparatus, the same class as the apex SOA and NS the
    AXFR helper already drops: nobody created it, and SpatiumDDI puts it on
    every zone the agent serves. Left in, every drift report on an
    agent-managed BIND9 zone lists ``ns1 A 127.0.0.1`` as extra on the
    server forever, so no zone ever reads in sync, and every sync-with-servers
    imports it into the DB as a record an operator never made — which the
    agent then renders a second time. Found once #920 let the transfer
    through on the QA seed. A zone whose DB really holds that exact record
    keeps it, and it is compared like any other. An operator-run BIND9, or any
    other driver, never had it added, so its records pass through untouched.
    """
    if getattr(server, "driver", None) != "bind9" or getattr(server, "agent_id", None) is None:
        return on_wire
    glue = _key(_AGENT_NS_GLUE, zone_name)
    if glue in db_keys:
        return on_wire
    return [r for r in on_wire if _key(r, zone_name) != glue]


async def _resolve_primary_and_driver(
    db: AsyncSession, zone: DNSZone
) -> tuple[Any, Any, list[TsigKey | None], str | None]:
    """Shared preamble for both pull and sync: find the zone's primary,
    sanity-check the driver supports pulling records, and resolve the TSIG
    key(s) its transfers have to be signed with.

    The third element is the keys to try, in order, through
    :func:`~app.services.dns.tsig.pull_zone_records_signed`: ``[None]``
    unless :func:`transfer_needs_tsig` says this server's agent granted one.
    Windows Path A, the cloud providers and an operator's own BIND9 all
    authorise the read some other way, and signing for them would break a
    working pull rather than fix a broken one (#734). For an agent-managed
    BIND9 whose group renders views, the key of the view holding this zone's
    copy goes first (#920) — without it the transfer matches no view, or the
    wrong one — and the group key follows for an agent that predates it. The
    fourth element is that view's name, or None.
    """
    primary = await resolve_primary_server(db, zone)
    if primary is None:
        raise ValueError(
            "No primary DNS server is configured in this zone's group. "
            "Mark one of the group's servers as primary first."
        )
    driver = get_driver(primary.driver)
    if not hasattr(driver, "pull_zone_records"):
        raise ValueError(
            f"Driver {primary.driver!r} does not support syncing with the authoritative server."
        )
    if not transfer_needs_tsig(primary):
        return primary, driver, [None], None

    # #734 — the agent grants allow-transfer to the group key, so an
    # unsigned read is REFUSED. No key means the sync cannot work at all;
    # say so up front instead of surfacing a REFUSED that points the
    # operator at a named.conf the agent owns and they cannot edit.
    tsig = await resolve_group_transfer_key(db, primary.group_id)
    if tsig is None:
        raise ValueError(
            f"This zone's group has no TSIG key, so the zone transfer that "
            f"syncing reads from {primary.name!r} cannot be authenticated. "
            "Create a TSIG key on the group and let the agent apply the new "
            "config, then try again."
        )
    view_transfer = await resolve_view_transfer_key(db, zone) if primary.driver == "bind9" else None
    if view_transfer is None:
        return primary, driver, [tsig], None
    view_key, view_name = view_transfer
    return primary, driver, [view_key, tsig], view_name


def _additive_import(
    db: AsyncSession,
    zone: DNSZone,
    on_wire: list[RecordData],
    db_keys: set[tuple[str, str, str]],
    *,
    apply: bool,
) -> PullResult:
    """Create DNSRecord rows for on-wire entries that are missing from DB."""
    zone_name = zone.name
    zone_name_no_dot = zone.name.rstrip(".")
    imported_records: list[dict[str, Any]] = []
    skipped_unsupported = 0
    existing = 0
    imported = 0

    for rec in on_wire:
        rtype = rec.record_type.upper()
        if rtype not in _IMPORTABLE_TYPES:
            skipped_unsupported += 1
            continue
        if _key(rec, zone_name) in db_keys:
            existing += 1
            continue

        fqdn = zone_name_no_dot if rec.name == "@" else f"{rec.name}.{zone_name_no_dot}"
        row = DNSRecord(
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
            ip_address_id=None,
        )
        if apply:
            db.add(row)
        imported += 1
        imported_records.append(
            {
                "name": rec.name,
                "fqdn": fqdn,
                "record_type": rtype,
                "value": rec.value,
                "ttl": rec.ttl,
            }
        )

    return PullResult(
        server_records=len(on_wire),
        existing_in_db=existing,
        imported=imported,
        imported_records=imported_records,
        skipped_unsupported=skipped_unsupported,
    )


async def pull_zone_from_server(
    db: AsyncSession,
    zone: DNSZone,
    *,
    apply: bool = True,
) -> PullResult:
    """One-way pull: read the zone from the primary server, additively
    import anything missing from DB. No push phase. Used by the scheduled
    task when the admin wants read-only sync; for the UI "Sync with server"
    button see ``sync_zone_with_server``.
    """
    primary, driver, keys, view_name = await _resolve_primary_and_driver(db, zone)

    on_wire, _key_used = await pull_zone_records_signed(
        driver, primary, zone.name, keys, view_name=view_name
    )

    db_rows_res = await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))
    db_rows = list(db_rows_res.scalars().all())
    db_keys = {_key(r, zone.name) for r in db_rows}
    on_wire = without_agent_ns_glue(on_wire, primary, zone.name, db_keys)

    result = _additive_import(db, zone, on_wire, db_keys, apply=apply)
    if apply and result.imported:
        await db.flush()

    logger.info(
        "dns.pull_from_server",
        zone=zone.name,
        server=str(primary.id),
        driver=primary.driver,
        on_wire=len(on_wire),
        existing=result.existing_in_db,
        imported=result.imported,
        skipped=result.skipped_unsupported,
        mode="apply" if apply else "preview",
    )
    return result


# Record types the push phase will send to the server via apply_record_change.
# Mirrors the Windows driver's _SUPPORTED_RECORD_TYPES but importing that
# would couple us to the driver module — keep a copy here and let drivers
# raise if they really don't support something at call time.
_PUSHABLE_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV", "NS", "TLSA"})


async def _additive_push(
    db: AsyncSession,
    primary: Any,
    driver: Any,
    zone: DNSZone,
    on_wire: list[RecordData],
    db_rows: list[DNSRecord],
    *,
    apply: bool,
) -> PushResult:
    """For every DB row whose key isn't on the wire, send a create op via
    the driver. Errors are collected, not raised, so one bad record
    doesn't abort the whole sync.

    Dispatch uses ``apply_record_changes`` (plural) so agentless drivers
    (Windows DNS) can ship the whole batch in one WinRM round trip
    instead of one per record. The ABC default falls back to a
    sequential loop for agent-based drivers (BIND9) where the control
    plane never calls the record writer anyway.
    """
    on_wire_keys = {_key(r, zone.name) for r in on_wire}

    pushed_records: list[dict[str, Any]] = []
    push_errors: list[str] = []

    target_serial = bump_zone_serial(zone) if apply else 0

    # Build the candidate list — DB rows whose (name, type, value) isn't
    # already on the wire. Keeping this as a list (not a generator) so we
    # can zip the driver's per-op results back onto the source rows by
    # index after dispatch.
    candidate_rows: list[DNSRecord] = []
    for row in db_rows:
        rtype = row.record_type.upper()
        if rtype not in _PUSHABLE_TYPES:
            continue
        if _key(row, zone.name) in on_wire_keys:
            continue
        candidate_rows.append(row)

    candidates = len(candidate_rows)

    if not apply:
        for row in candidate_rows:
            pushed_records.append(
                {
                    "name": row.name,
                    "fqdn": row.fqdn,
                    "record_type": row.record_type.upper(),
                    "value": row.value,
                    "ttl": row.ttl,
                }
            )
        return PushResult(
            candidates=candidates,
            pushed=candidates,
            pushed_records=pushed_records,
            push_errors=push_errors,
        )

    changes: list[RecordChange] = [
        RecordChange(
            op="create",
            zone_name=zone.name,
            record=RecordData(
                name=row.name,
                record_type=row.record_type.upper(),
                value=row.value,
                ttl=row.ttl,
                priority=row.priority,
                weight=row.weight,
                port=row.port,
            ),
            target_serial=target_serial,
        )
        for row in candidate_rows
    ]

    if not changes:
        return PushResult(
            candidates=0, pushed=0, pushed_records=pushed_records, push_errors=push_errors
        )

    try:
        results = await driver.apply_record_changes(primary, changes)
    except Exception as exc:  # noqa: BLE001 — whole-batch failure, surface once
        logger.warning(
            "dns.push_drift_batch_failed",
            zone=zone.name,
            server=str(primary.id),
            count=len(changes),
            error=str(exc),
        )
        return PushResult(
            candidates=candidates,
            pushed=0,
            pushed_records=pushed_records,
            push_errors=[f"batch failed: {exc}"],
        )

    pushed = 0
    for row, result in zip(candidate_rows, results, strict=True):
        rtype = row.record_type.upper()
        if result.ok:
            pushed += 1
            pushed_records.append(
                {
                    "name": row.name,
                    "fqdn": row.fqdn,
                    "record_type": rtype,
                    "value": row.value,
                    "ttl": row.ttl,
                }
            )
            continue
        err = f"{row.name} {rtype}: {result.error}"
        logger.warning(
            "dns.push_drift_failed",
            zone=zone.name,
            server=str(primary.id),
            name=row.name,
            record_type=rtype,
            error=result.error,
        )
        if len(push_errors) < 10:
            push_errors.append(err)

    return PushResult(
        candidates=candidates,
        pushed=pushed,
        pushed_records=pushed_records,
        push_errors=push_errors,
    )


async def sync_zone_with_server(
    db: AsyncSession,
    zone: DNSZone,
    *,
    apply: bool = True,
) -> SyncResult:
    """Bi-directional additive sync between DB and the zone's primary server.

    1. AXFR the server once.
    2. Pull phase: import on-wire records missing from DB.
    3. Push phase: for every DB row not on the wire, send an RFC 2136 add.

    Never deletes. Returns counts for both phases so the UI can surface
    them in one pass.
    """
    primary, driver, keys, view_name = await _resolve_primary_and_driver(db, zone)

    on_wire, _key_used = await pull_zone_records_signed(
        driver, primary, zone.name, keys, view_name=view_name
    )

    # Snapshot DB state BEFORE the pull so we can compute the push set
    # against the "old" DB. We still import new rows from the pull into
    # the DB first; those obviously live on the wire so they never need
    # pushing — they'd be no-ops on the server anyway, but filtering them
    # out keeps the push count honest.
    db_rows_res = await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))
    db_rows = list(db_rows_res.scalars().all())
    db_keys = {_key(r, zone.name) for r in db_rows}
    on_wire = without_agent_ns_glue(on_wire, primary, zone.name, db_keys)

    pull_result = _additive_import(db, zone, on_wire, db_keys, apply=apply)
    if apply and pull_result.imported:
        await db.flush()

    push_result = await _additive_push(db, primary, driver, zone, on_wire, db_rows, apply=apply)

    logger.info(
        "dns.sync_with_server",
        zone=zone.name,
        server=str(primary.id),
        driver=primary.driver,
        on_wire=len(on_wire),
        imported=pull_result.imported,
        pushed=push_result.pushed,
        push_errors=len(push_result.push_errors),
        mode="apply" if apply else "preview",
    )
    return SyncResult(pull=pull_result, push=push_result)
