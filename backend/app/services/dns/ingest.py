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
cycle. Zone-management + DNSSEC RRs (SOA, apex NS, RRSIG, NSEC*, DNSKEY,
CDS/CDNSKEY, private-type 65534) are never ingested — BIND owns them.

**One agent server in the group** (the only case before #2654 was fixed):
the report is the truth. Rows that vanished upstream are removed, new ones
are added. Unchanged since #641.

**Two or more enabled agent servers** (#2654). Each one is an independent
primary with its own journal, and an RFC 2136 writer usually talks to only
one of them (the SOA MNAME). Treating every report as the whole truth made
the mirror flap: ns1 reports ``dc01``, the row is added; ns2 never had it,
reports nothing, the row is deleted; repeat. And the row, added with no
record op, never reached ns2 at all. So the reconcile works on CHANGE, using
each server's previous report (``DNSIngestSnapshot``):

* a record that APPEARED on a server since its last report, with no mirror
  row, is a writer's add: mirror it and queue a ``create`` op to every OTHER
  enabled agent server in the group;
* a record that VANISHED from a server since its last report, with a mirror
  row, is a writer's delete: drop the mirror and queue a ``delete`` op to the
  others. A record missing from a server that never had it is not a delete;
* a server that lacks a mirrored record it never reported, or still holds
  one whose mirror is gone, is behind (it was disabled when the op went out,
  joined the group later, or predates this fix): it alone is sent an op for
  that value, unless one is already queued for it or failed recently;
* a change on a server that one of OUR ops explains (an op for that value
  still queued for it, or applied since its last report) is not acted on
  this cycle, because it is most likely our own write landing rather than
  the writer's, and is looked at again on the next report;
* a mirror whose (name, type) a managed record now owns is dropped, with no
  wire op, as in the one-server path.

Every op this sends is PER VALUE (``rrset_action`` add / delete_value), not
the whole-RRset replace an operator's edit sends: the database only knows the
values that have been reported, and a replace would wipe any other value the
target server holds at that name.

The server a record came from is never sent an op for it: it already holds
the record. A disabled server's report is ignored and its snapshot is kept
as it was when it was paused, so on re-enable the changes a writer made on it
meanwhile read as changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import is_agentless
from app.models.dns import DNSIngestSnapshot, DNSRecord, DNSRecordOp, DNSServer, DNSZone

logger = structlog.get_logger(__name__)

# Provenance marker for a record the agent read back off the live zone.
EXTERNAL_IMPORT_SOURCE = "ddns_external"

# A correction that failed permanently (``MAX_OP_ATTEMPTS``) is not queued
# again for this long, so a value one server will not accept is retried a few
# times a day rather than on every 180 s report.
FAILED_OP_BACKOFF = timedelta(hours=6)

# An op applied this long before a server's previous report still counts as
# an explanation for a change in its next one. The agent reads the zone a few
# seconds before it posts, so an op applied in that gap shows up in the NEXT
# report even though it was applied before the previous one was stored. The
# gap is bounded by the agent's 20 s transfer and 20 s POST timeouts; kept
# well under the 180 s sweep so one landed op defers at most one report.
OP_ATTRIBUTION_SLACK = timedelta(seconds=60)

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
    # #2654, multi-server groups only.
    mode: str = "single"  # "single" | "multi" | "disabled_reporter"
    peer_ops: int = 0  # record ops queued to the reporter's peers
    corrections: int = 0  # record ops queued to the reporter itself
    deferred: int = 0  # changes left for the next report (explained by our ops)


def _key(name: str, rtype: str, value: str) -> tuple[str, str, str]:
    return (name.lower(), rtype.upper(), value.strip())


def _describe(fqdn: str, name: str, rtype: str, value: str, ttl: int | None) -> dict[str, object]:
    return {"name": name, "fqdn": fqdn, "record_type": rtype, "value": value, "ttl": ttl}


def _is_apex_ns(name: str, rtype: str) -> bool:
    # The zone's own delegation NS at the apex is zone-management data, not
    # an external writer's record. Sub-label NS (delegations) are kept.
    return rtype.upper() == "NS" and name in ("@", "")


def _nt(k: tuple[str, str, str]) -> tuple[str, str]:
    return (k[0] or "@", k[1])


async def reconcile_external_records(
    db: AsyncSession,
    zone: DNSZone,
    incoming: list[IncomingRecord],
    *,
    server: DNSServer | None = None,
) -> IngestResult:
    """Reconcile the ``ddns_external`` mirror rows for one zone.

    Adds newly-seen external records, removes ones that vanished upstream,
    and skips anything shadowed by a control-plane-managed record (managed
    names win) or owned by the daemon (SOA/NS-apex/DNSSEC). Idempotent —
    re-running with the same input is a no-op.

    ``server`` is the agent the report came from. Without it, or when it has
    no enabled agent peers in its group, the report is the whole truth (the
    #641 behaviour). With peers, see the module docstring (#2654).

    The caller is responsible for gating on ``zone.dynamic_update_enabled``
    and for committing the session.
    """
    result = IngestResult()
    if server is not None:
        # Serialise reports for one zone: two servers posting the same new
        # record at once must create ONE mirror, not two.
        await db.execute(select(DNSZone.id).where(DNSZone.id == zone.id).with_for_update())

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

    # What the server holds, after the daemon-owned and managed-name filters.
    desired: dict[tuple[str, str, str], IncomingRecord] = {}
    for rec in incoming:
        rtype = rec.record_type.upper()
        if rtype in _IGNORED_TYPES or _is_apex_ns(rec.name, rtype):
            result.skipped_ignored += 1
            continue
        if (rec.name.lower(), rtype) in managed_nt:
            result.skipped_managed += 1
            continue
        desired.setdefault(_key(rec.name, rtype, rec.value), rec)

    if server is None:
        await _full_reconcile(db, zone, desired, external_by_key, result)
        return result

    if not await _enabled_agent_peers(db, zone, server):
        await _full_reconcile(db, zone, desired, external_by_key, result)
        await _save_snapshot(db, server, zone, set(desired))
        return result

    if not server.is_enabled:
        # A paused server is sent no ops, so what it holds says nothing about
        # what its peers should serve: it does not drive the mirror. Its
        # snapshot is deliberately NOT updated. When it is enabled again its
        # first report is compared against what it held when it was paused,
        # so a writer's add or delete made on it during the pause reads as a
        # change (and is mirrored and fanned out) instead of as drift to
        # correct away.
        result.mode = "disabled_reporter"
        return result

    result.mode = "multi"
    await _transition_reconcile(db, zone, server, desired, external_by_key, managed_nt, result)
    return result


async def _full_reconcile(
    db: AsyncSession,
    zone: DNSZone,
    desired: dict[tuple[str, str, str], IncomingRecord],
    external_by_key: dict[tuple[str, str, str], DNSRecord],
    result: IngestResult,
) -> None:
    """The report is the whole truth: one agent server in the group (#641)."""
    for k, rec in desired.items():
        if k in external_by_key:
            continue  # already mirrored
        _add_mirror(db, zone, rec, result)

    # Remove mirrors that vanished upstream (present in DB, absent from the
    # agent's current external set). Hard-delete — a stale mirror would
    # otherwise re-render a record the writer already withdrew. Not
    # soft-deleted: the row is a cache of what the external writer holds, so
    # "restoring" it would resurrect a record the writer withdrew, and a
    # churning writer would pile up soft-deleted rows. The trail is the audit
    # row the caller writes from ``removed_records`` (#2302).
    for k, row in external_by_key.items():
        if k not in desired:
            await _drop_mirror(db, row, result)


def learned_record_op(op: str, rec: IncomingRecord | DNSRecord) -> dict[str, Any]:
    """A PER-VALUE record op for a learned record (#2654 review).

    ``rrset_action`` makes the agent add or remove exactly this value
    (BIND9 ``update add`` / ``update delete <rdata>``, PowerDNS splice,
    Technitium ``overwrite=false`` / value delete), and keeps
    ``stamp_rrsets_for_ops`` from turning the op into a whole-RRset replace.
    A replace would carry only what the DATABASE holds at that name, and wipe
    every value the target server holds that is not mirrored yet: a writer's
    value on that server that has not been reported, or one whose report was
    deferred.
    """
    rtype = rec.record_type.upper()
    record: dict[str, Any] = {
        "name": rec.name,
        "type": rtype,
        "value": rec.value,
        "ttl": rec.ttl,
        "priority": rec.priority,
        "weight": rec.weight,
        "port": rec.port,
        "rrset_action": "add" if op == "create" else "delete_value",
    }
    if isinstance(rec, DNSRecord) and rec.id is not None:
        record["record_id"] = str(rec.id)
    return {"op": op, "record": record}


async def _transition_reconcile(
    db: AsyncSession,
    zone: DNSZone,
    server: DNSServer,
    desired: dict[tuple[str, str, str], IncomingRecord],
    external_by_key: dict[tuple[str, str, str], DNSRecord],
    managed_nt: set[tuple[str, str]],
    result: IngestResult,
) -> None:
    """Several agent servers: act on what changed on ``server`` (#2654)."""
    from app.services.dns.record_ops import (  # noqa: PLC0415 — record_ops imports models heavily
        enqueue_agent_record_ops,
    )
    from app.services.dns.serial import bump_zone_serial  # noqa: PLC0415

    snap = await db.get(DNSIngestSnapshot, (server.id, zone.id))
    previous: set[tuple[str, str, str]] = set()
    since: datetime | None = None
    if snap is not None:
        previous = {(str(a), str(b), str(c)) for a, b, c in snap.record_keys}
        since = snap.reported_at - OP_ATTRIBUTION_SLACK
    ops = await server_ops_touching(db, zone, server, since)

    current = set(desired)
    carried = set(current)  # becomes the stored snapshot
    added_rows: list[DNSRecord] = []
    peer_ops: list[dict[str, Any]] = []
    self_ops: list[dict[str, Any]] = []

    # Appeared on this server since its last report.
    for k in current - previous:
        if k in external_by_key:
            continue
        if ops.explains(k):
            carried.discard(k)  # look again next report
            result.deferred += 1
            continue
        added_rows.append(_add_mirror(db, zone, desired[k], result))

    # Vanished from this server since its last report.
    for k in previous - current:
        row = external_by_key.get(k)
        if row is None or _nt(k) in managed_nt:
            continue  # shadowed mirrors are dropped below
        if ops.explains(k):
            carried.add(k)  # still "held" until the next report decides
            result.deferred += 1
            continue
        peer_ops.append(learned_record_op("delete", row))
        await _drop_mirror(db, row, result)
        del external_by_key[k]

    # A managed record now owns a mirror's (name, type): the operator's
    # declared state wins, exactly as in the single-server path. Drop the row
    # and send nothing: the managed (name, type) is often an import of what
    # the servers really serve (Sync with servers, the scheduled pull), so a
    # wire delete here would remove a writer's live record everywhere.
    for k, row in list(external_by_key.items()):
        if _nt(k) in managed_nt:
            await _drop_mirror(db, row, result)
            del external_by_key[k]

    # This server is behind: corrections to it alone, unless one is queued
    # or recently failed for that value.
    for k, row in external_by_key.items():
        if k not in current and k not in previous and not ops.blocks_correction(k):
            self_ops.append(learned_record_op("create", row))
    for k in (current & previous) - set(external_by_key):
        if ops.blocks_correction(k):
            continue
        self_ops.append(learned_record_op("delete", desired[k]))

    if added_rows:
        await db.flush()  # ids for the op payloads
        peer_ops.extend(learned_record_op("create", r) for r in added_rows)
    await db.flush()

    if peer_ops or self_ops:
        serial = bump_zone_serial(zone)
        for o in (*peer_ops, *self_ops):
            o["target_serial"] = serial
    if peer_ops:
        result.peer_ops = await enqueue_agent_record_ops(
            db, zone, peer_ops, exclude_server_ids={server.id}
        )
    if self_ops:
        result.corrections = await enqueue_agent_record_ops(
            db, zone, self_ops, only_server_ids={server.id}
        )
    await _save_snapshot(db, server, zone, carried)
    if result.peer_ops or result.corrections or result.deferred:
        logger.info(
            "dns_ingest_multi_server",
            zone=zone.name,
            server=str(server.id),
            added=result.added,
            removed=result.removed,
            peer_ops=result.peer_ops,
            corrections=result.corrections,
            deferred=result.deferred,
        )


def _add_mirror(
    db: AsyncSession, zone: DNSZone, rec: IncomingRecord, result: IngestResult
) -> DNSRecord:
    rtype = rec.record_type.upper()
    zone_name_no_dot = zone.name.rstrip(".")
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
        import_source=EXTERNAL_IMPORT_SOURCE,
    )
    db.add(row)
    result.added += 1
    result.added_records.append(_describe(fqdn, rec.name, rtype, rec.value, rec.ttl))
    return row


async def _drop_mirror(db: AsyncSession, row: DNSRecord, result: IngestResult) -> None:
    result.removed_records.append(
        _describe(row.fqdn, row.name, row.record_type, row.value, row.ttl)
    )
    await db.delete(row)
    result.removed += 1


async def _enabled_agent_peers(
    db: AsyncSession, zone: DNSZone, server: DNSServer
) -> list[DNSServer]:
    """The OTHER enabled agent-based servers in the zone's group."""
    rows = (
        (
            await db.execute(
                select(DNSServer).where(
                    DNSServer.group_id == zone.group_id,
                    DNSServer.is_enabled.is_(True),
                    DNSServer.id != server.id,
                )
            )
        )
        .scalars()
        .all()
    )
    return [s for s in rows if not is_agentless(s.driver)]


@dataclass
class ServerOps:
    """What record ops say about one server's RRsets in one zone.

    Keys are ``(name_lower, TYPE)`` for a whole-RRset op (it rewrites every
    value at that name) and ``(name_lower, TYPE, value)`` for a per-value op.
    """

    explained_nt: set[tuple[str, str]] = field(default_factory=set)
    explained_v: set[tuple[str, str, str]] = field(default_factory=set)
    blocked_nt: set[tuple[str, str]] = field(default_factory=set)
    blocked_v: set[tuple[str, str, str]] = field(default_factory=set)
    queued_nt: set[tuple[str, str]] = field(default_factory=set)

    def explains(self, k: tuple[str, str, str]) -> bool:
        """An op queued, or applied since the server's last report, could be
        what changed ``k`` on it."""
        return _nt(k) in self.explained_nt or (_nt(k) + (k[2],)) in self.explained_v

    def blocks_correction(self, k: tuple[str, str, str]) -> bool:
        """An op for ``k`` is queued, or failed recently, so do not queue
        another correction for it."""
        return _nt(k) in self.blocked_nt or (_nt(k) + (k[2],)) in self.blocked_v

    def queued_at(self, name: str, rtype: str) -> bool:
        """Any op (whole-RRset or per-value) for this name and type is still
        pending or in flight to the server."""
        return ((name or "@").lower(), rtype.upper()) in self.queued_nt


async def server_ops_touching(
    db: AsyncSession, zone: DNSZone, server: Any, since: datetime | None
) -> ServerOps:
    """Classify ``server``'s record ops for ``zone`` (#2654).

    ``explains``: the op is still queued, or was applied after ``since`` (the
    previous report, less the slack). ``blocks_correction``: still queued, or
    failed within ``FAILED_OP_BACKOFF``, so a correction that keeps failing is
    not re-queued on every report.
    """
    from app.services.dns.record_ops import (  # noqa: PLC0415
        QUEUED_OP_STATES,
        _op_name_sql,
        _op_type_sql,
    )

    now = datetime.now(UTC)
    conds = [
        DNSRecordOp.state.in_(QUEUED_OP_STATES),
        (DNSRecordOp.state == "failed") & (DNSRecordOp.updated_at >= now - FAILED_OP_BACKOFF),
    ]
    if since is not None:
        conds.append((DNSRecordOp.state == "applied") & (DNSRecordOp.applied_at >= since))
    rows = (
        await db.execute(
            select(
                _op_name_sql(),
                _op_type_sql(),
                DNSRecordOp.record["value"].astext,
                DNSRecordOp.record.has_key("rrset"),
                DNSRecordOp.state,
            ).where(
                DNSRecordOp.server_id == server.id,
                DNSRecordOp.zone_id == zone.id,
                or_(*conds),
            )
        )
    ).all()
    out = ServerOps()
    for name, rtype, value, whole_rrset, state in rows:
        nt = (str(name or "@"), str(rtype or ""))
        vk = (*nt, str(value or "").strip())
        if state != "failed":
            if whole_rrset:
                out.explained_nt.add(nt)
            else:
                out.explained_v.add(vk)
        if state in QUEUED_OP_STATES:
            out.queued_nt.add(nt)
        if state != "applied":
            if whole_rrset:
                out.blocked_nt.add(nt)
            else:
                out.blocked_v.add(vk)
    return out


async def _save_snapshot(
    db: AsyncSession, server: DNSServer, zone: DNSZone, keys: set[tuple[str, str, str]]
) -> None:
    """Replace ``server``'s stored report for ``zone``. The caller holds the
    zone row lock, so two reports for one (server, zone) cannot race."""
    payload = [list(k) for k in sorted(keys)]
    snap = await db.get(DNSIngestSnapshot, (server.id, zone.id))
    if snap is None:
        db.add(
            DNSIngestSnapshot(
                server_id=server.id,
                zone_id=zone.id,
                record_keys=payload,
                reported_at=datetime.now(UTC),
            )
        )
    else:
        snap.record_keys = payload
        snap.reported_at = datetime.now(UTC)
    await db.flush()


def to_summary(result: IngestResult) -> dict[str, int]:
    return {
        "added": result.added,
        "removed": result.removed,
        "skipped_managed": result.skipped_managed,
        "skipped_ignored": result.skipped_ignored,
        "peer_ops": result.peer_ops,
        "corrections": result.corrections,
        "deferred": result.deferred,
    }


__all__ = [
    "EXTERNAL_IMPORT_SOURCE",
    "FAILED_OP_BACKOFF",
    "OP_ATTRIBUTION_SLACK",
    "ServerOps",
    "learned_record_op",
    "server_ops_touching",
    "IncomingRecord",
    "IngestResult",
    "reconcile_external_records",
    "to_summary",
]
