"""Enqueue and resolve RecordOps for DNS agents.

Per docs/deployment/DNS_AGENT.md §5: when a record is mutated, compute the
delta and write RecordOp rows targeting the primary server for that zone.
Secondaries pick up the changes via native AXFR/IXFR from the primary.

Agentless drivers (Windows DNS today) don't follow this queue — the control
plane applies the change directly at enqueue time and writes the row as
``applied`` / ``failed`` so operators still see a per-op audit trail.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.agent_wake import collect_wake, dns_group_channel
from app.drivers.dns import get_driver, is_agentless
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember
from app.models.dns import DNSKey, DNSRecord, DNSRecordOp, DNSServer, DNSZone
from app.models.ipam import IPAddress
from app.services.dns.rrset import stamp_rrsets_for_ops
from app.services.dns.serial import bump_zone_serial

logger = structlog.get_logger(__name__)


# Queued-op states. ``in_flight`` is queued work too: an op already shipped is
# not finished with — ``ack_op`` returns a NACKed one to ``pending`` — so any
# sweep of a zone's queue must cover both (the #934 review finding).
QUEUED_OP_STATES: tuple[str, ...] = ("pending", "in_flight")


def queued_zone_ops_where(zone: DNSZone, group_id: uuid.UUID) -> list[Any]:
    """WHERE clauses selecting the live (queued) ops for ``zone`` on the servers
    of ``group_id`` — every server, as a correlated subquery, so no caller has
    to prefetch an id list (and none can pass a partial one: a sweep that
    reaches only the primary leaves secondaries' queues behind, the fan-out
    bug #934 fixed).

    **This predicate is name-scoped, and that is a decision, not an accident
    of the schema (#964).** ``DNSRecordOp`` carries ``server_id`` +
    ``zone_name`` and no view discriminator, while ``DNSZone`` is unique on
    ``(group_id, view_id, name)`` — so under split-horizon (#24) the same name
    legitimately exists twice in one group, and a sweep for ``internal``'s
    ``example.com.`` also discards ``external``'s queued ops on the same
    servers.

    Why that is accepted rather than fixed with a view column: under
    split-horizon the incremental op path does not run at all. When a group
    has views (or geo steering) ``agent_config.build_config_bundle`` folds
    records INTO the structural fingerprint, so every record change is a full
    view-correct re-render from the database — and it ships no
    ``pending_record_ops``, retiring every queued op for the server as
    ``applied`` on each bundle build instead. A sibling view's op the sweep
    discards was therefore never going to reach ``nsupdate``: the over-sweep
    costs nothing. In a flat group the same name cannot exist twice (the
    create route 409s it), so the predicate is exact there. A ``zone_id``
    column would need a migration plus a name-scoped fallback for every
    pre-upgrade row, i.e. this predicate again, to guard a path that is
    already bypassed.

    Every zone-scoped sweep and count goes through here so the decision lives
    in one place; ``tests/test_dns_record_ops_sweep.py`` pins both the
    behaviour and that no other module carries its own copy.
    """
    return [
        DNSRecordOp.server_id.in_(select(DNSServer.id).where(DNSServer.group_id == group_id)),
        DNSRecordOp.zone_name == zone.name,
        DNSRecordOp.state.in_(QUEUED_OP_STATES),
    ]


async def count_queued_zone_ops(db: AsyncSession, zone: DNSZone, group_id: uuid.UUID) -> int:
    """How many queued ops :func:`sweep_zone_ops` would discard. See its caveat."""
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(DNSRecordOp)
                .where(*queued_zone_ops_where(zone, group_id))
            )
        ).scalar_one()
    )


async def sweep_zone_ops(db: AsyncSession, zone: DNSZone, group_id: uuid.UUID) -> int:
    """Discard the queued ops for ``zone`` on ``group_id``'s servers; returns the count.

    Used when the ops can no longer apply: the zone is being permanently
    deleted, or moved out of the group whose servers they target (pass the
    OLD group). Applied / failed rows are history, not queued work, and are
    kept. Name-scoped — see :func:`queued_zone_ops_where` for the
    split-horizon caveat (#964).
    """
    res = await db.execute(sa_delete(DNSRecordOp).where(*queued_zone_ops_where(zone, group_id)))
    return int(res.rowcount or 0)


async def resolve_primary_server(db: AsyncSession, zone: DNSZone) -> DNSServer | None:
    """Find the `is_primary=True` server in the zone's group."""
    res = await db.execute(
        select(DNSServer)
        .where(DNSServer.group_id == zone.group_id, DNSServer.is_primary.is_(True))
        .limit(1)
    )
    return res.scalar_one_or_none()


def _rrset_from_payload(record: dict[str, Any]) -> RRsetData | None:
    """Lift the stamped ``record["rrset"]`` payload into the neutral type.

    #783 — the agentless drivers consume dataclasses, not the wire dict the
    agent bundle ships, so the two representations meet here. Returns
    ``None`` when the op carries no set (an ``rrset_action`` caller opted
    out), which every driver reads as "keep your previous per-value
    behaviour".
    """
    raw = record.get("rrset")
    if not isinstance(raw, dict):
        return None
    members = raw.get("members")
    if not isinstance(members, list):
        return None
    return RRsetData(
        ttl=raw.get("ttl"),
        members=tuple(
            RRsetMember(
                value=m.get("value", ""),
                priority=m.get("priority"),
                weight=m.get("weight"),
                port=m.get("port"),
            )
            for m in members
            if isinstance(m, dict)
        ),
    )


async def _apply_agentless(
    db: AsyncSession,
    server: DNSServer,
    zone: DNSZone,
    op: str,
    record: dict[str, Any],
    target_serial: int | None,
) -> DNSRecordOp:
    """Apply a record op synchronously via the server's driver.

    Writes a DNSRecordOp row marked ``applied`` on success or ``failed`` on
    error. The request path continues either way — a failure is visible in
    the record-ops dashboard and via the existing IPAM↔DNS sync-check.

    #783 — the op is stamped with its complete desired RRset first, the same
    way the agent path is (#773). This used to be deliberately skipped here,
    on the reasoning that an agentless op row must not claim an RRset write
    nobody performed; that reasoning was sound and the conclusion was the
    bug, because the agentless drivers were performing whole-RRset writes
    anyway — just with one value in them, which is what silently retired the
    siblings. Now they perform the write the row describes.
    """
    if "rrset" not in record:
        record = dict(record)
        await stamp_rrsets_for_ops(db, zone, [{"op": op, "record": record}])

    op_row = DNSRecordOp(
        server_id=server.id,
        zone_name=zone.name,
        op=op,
        record=record,
        target_serial=target_serial,
        state="pending",
    )
    db.add(op_row)
    await db.flush()

    change = RecordChange(
        op=op,  # type: ignore[arg-type]
        zone_name=zone.name,
        record=RecordData(
            name=record["name"],
            record_type=record["type"],
            value=record["value"],
            ttl=record.get("ttl"),
            priority=record.get("priority"),
            weight=record.get("weight"),
            port=record.get("port"),
        ),
        target_serial=target_serial or 0,
        rrset=_rrset_from_payload(record),
    )

    try:
        driver = get_driver(server.driver)
        await driver.apply_record_change(server, change)
        op_row.state = "applied"
        op_row.applied_at = datetime.now(UTC)
        op_row.attempts = 1
        op_row.last_error = None
        logger.info(
            "record_op_applied_agentless",
            server=str(server.id),
            driver=server.driver,
            zone=zone.name,
            op=op,
            name=record["name"],
            type=record["type"],
        )
    except Exception as exc:  # noqa: BLE001 — surface any wire / config error
        op_row.state = "failed"
        op_row.attempts = 1
        op_row.last_error = str(exc)[:500]
        logger.warning(
            "record_op_failed_agentless",
            server=str(server.id),
            driver=server.driver,
            zone=zone.name,
            op=op,
            error=str(exc),
        )

    await db.flush()
    return op_row


async def enqueue_dnssec_op(db: AsyncSession, zone: DNSZone, op: str) -> None:
    """Queue the driver-side half of a DNSSEC state change.

    ``op`` is ``dnssec_sign`` or ``dnssec_unsign``. The synthetic "record"
    is the DNSSEC_OP sentinel: BIND9 ignores it (it signs inline from the
    rendered config bundle); PowerDNS and Technitium consume it to drive
    their online sign/unsign. One chokepoint for every path that flips
    ``zone.dnssec_enabled`` — the sign/unsign endpoints (REST + Copilot),
    zone create (REST + Copilot) and the update-zone flag flip — so they
    cannot drift apart again (#811: create set the flag and never enqueued,
    leaving PowerDNS / Technitium zones flagged-but-unsigned until a manual
    Sign). Nothing here reads ``zone.id`` — ops key the zone by name — so a
    freshly-added, not-yet-flushed zone row is fine.
    """
    await enqueue_record_op(db, zone, op, {"name": "@", "type": "DNSSEC_OP"})


async def clear_dnssec_key_state(db: AsyncSession, zone: DNSZone) -> None:
    """Clear the cached DS records + per-key mirror rows for a zone.

    Companion to ``enqueue_dnssec_op("dnssec_unsign")`` — every flag-off
    path (the unsign endpoints, the update-zone flip) must do this, because
    the BIND9 agent only reports *signed* zones and will never send a
    ``keys=[]`` report to clear them.
    """
    zone.dnssec_ds_records = None
    await db.execute(sa_delete(DNSKey).where(DNSKey.zone_id == zone.id))


async def enqueue_record_op(
    db: AsyncSession,
    zone: DNSZone,
    op: str,
    record: dict[str, Any],
    target_serial: int | None = None,
) -> DNSRecordOp | None:
    """Queue a record operation against every applicable server in
    the zone's group.

    Driver semantics:

    * **Agentless** (Windows DNS): exactly one server in the group
      writes — the one marked ``is_primary=True``. Apply immediately
      via the driver from the control plane; the row lands as
      ``applied`` or ``failed``.
    * **Agent-based** (BIND9 / PowerDNS): every enabled, agent-based
      server in the group runs an independent authoritative copy of
      the zone (each renders ``type master`` in its named.conf). A
      record change therefore needs to land on *every* server, not
      just the one with ``is_primary=True``. Enqueue one
      ``pending`` op row per server; each agent picks up its own row
      on its next long-poll and applies via loopback nsupdate.
      Pre-#170 the queue only went to the primary, which silently
      broke any multi-server (or supervised-appliance) group — the
      secondaries' on-disk zone files stayed frozen at the bundle
      they received on initial register.

    Returns the op for the primary server (or ``None`` if no primary
    + agent-based path didn't run either). Callers that need to ack
    every server's apply outcome should query ``DNSRecordOp`` directly
    by ``server_id``; the singular return preserves the prior
    contract for the typed-event audit path.
    """
    primary = await resolve_primary_server(db, zone)
    if primary is None:
        # Silent drop was a footgun: frontend got a 200, nothing landed. Log
        # it loudly so the symptom shows up in `docker compose logs -f api`
        # and in the audit log via the caller.
        logger.warning(
            "record_op_dropped_no_primary",
            zone=zone.name,
            group_id=str(zone.group_id),
            op=op,
            name=record.get("name"),
            type=record.get("type"),
            hint=(
                "No DNS server in this zone's group has is_primary=True. "
                "Edit the server in DNS → Server Groups and mark one as primary."
            ),
        )
        return None

    if is_agentless(primary.driver):
        # User flipped the primary off — for agentless, drop the op with a
        # warning rather than hang on a dead WinRM / nsupdate socket at a paused
        # server. (Agent-based groups fall through to the fan-out below, which
        # queues to whatever agent-based servers ARE enabled.)
        if not primary.is_enabled:
            logger.warning(
                "record_op_dropped_server_disabled",
                zone=zone.name,
                server=str(primary.id),
                driver=primary.driver,
                op=op,
                name=record.get("name"),
                type=record.get("type"),
            )
            return None
        return await _apply_agentless(db, primary, zone, op, record, target_serial)

    # Agent-based group: fan out to every ENABLED, agent-based server in the
    # group, independent of whether the designated primary is currently
    # disabled. Gating the whole group on the primary's is_enabled (as we used
    # to) dropped the op for healthy secondaries too — and because the agent's
    # structural_etag excludes records in a no-views group, re-enabling the
    # primary later does NOT flush the missed op, so the edit could strand on
    # every agent (#481). The query mirrors ``resolve_primary_server`` minus the
    # is_primary filter; agentless servers are excluded because their write path
    # is single-server immediate-apply.
    agent_rows = (
        (
            await db.execute(
                select(DNSServer)
                .where(
                    DNSServer.group_id == zone.group_id,
                    DNSServer.is_enabled.is_(True),
                )
                .order_by(DNSServer.is_primary.desc(), DNSServer.created_at)
            )
        )
        .scalars()
        .all()
    )
    agent_servers = [s for s in agent_rows if not is_agentless(s.driver)]
    if not agent_servers:
        # Every agent-based server in the group is disabled (incl. the primary).
        # Nothing can converge right now; log it rather than drop silently.
        logger.warning(
            "record_op_dropped_no_enabled_agent",
            zone=zone.name,
            group_id=str(zone.group_id),
            op=op,
            name=record.get("name"),
            type=record.get("type"),
        )
        return None

    # #773 — ship the complete desired RRset alongside the op. Every agent
    # driver has to apply a record change as a whole-RRset write, so without
    # this a second value at an existing (name, type) silently retired the
    # first. Skipped when the payload already carries one, because the batch
    # path folds and stamps its whole list in a single query before delegating
    # here — restamping per op would undo the fold. (An op carrying an explicit
    # ``rrset_action`` opts out entirely; ``stamp_rrsets_for_ops`` handles it.)
    if "rrset" not in record:
        record = dict(record)
        await stamp_rrsets_for_ops(db, zone, [{"op": op, "record": record}])

    primary_op: DNSRecordOp | None = None
    first_op: DNSRecordOp | None = None
    for srv in agent_servers:
        row = DNSRecordOp(
            server_id=srv.id,
            zone_name=zone.name,
            op=op,
            record=record,
            target_serial=target_serial,
            state="pending",
        )
        db.add(row)
        if first_op is None:
            first_op = row
        if srv.id == primary.id:
            primary_op = row
    await db.flush()
    # #358 — wake every agent in this group so they re-poll + apply the
    # queued op immediately instead of waiting for the belt-and-braces
    # tick. Collected here (no commit yet); the request's
    # ``wake_publishing`` dependency flushes it after the outer commit.
    collect_wake(dns_group_channel(zone.group_id))
    # Return the primary's op when the primary is among the enabled servers,
    # else the first enabled agent's op. The return must be truthy whenever we
    # actually enqueued something — a disabled primary + enabled secondary still
    # dispatches a wire op (#481) — so a caller that gates a DB delete on "was a
    # wire op dispatched?" (e.g. dns bulk-delete) doesn't keep a row whose
    # record was already removed on-wire.
    return primary_op or first_op


def record_op_payload(record: DNSRecord) -> dict[str, Any]:
    """The neutral RecordOp payload (``name``/``type``/``value``/``ttl``/
    ``priority``/``weight``/``port``) ``enqueue_record_op`` + the agentless
    drivers consume, built from a ``DNSRecord`` row. One place to add a field so
    a new one can't be silently dropped from a provider push (#632)."""
    return {
        "name": record.name,
        "type": record.record_type,
        "value": record.value,
        "ttl": record.ttl,
        "priority": record.priority,
        "weight": record.weight,
        "port": record.port,
    }


async def push_record_restore(db: AsyncSession, record: DNSRecord) -> DNSRecordOp | None:
    """Re-assert a restored record at its provider by pushing ``create``.

    The inverse of the ``delete`` push ``delete_record`` fires on soft-delete
    (#632). Call **after** the row's ``deleted_at`` has been cleared — the
    record must be live for the zone lookup + field snapshot to be correct.
    ``enqueue_record_op`` re-creates it at agentless providers and enqueues an
    idempotent create for agent-based servers (the next bundle also covers it).
    Returns ``None`` when the zone can't be resolved (nothing to push).
    """
    zone = await db.get(DNSZone, record.zone_id)
    if zone is None:
        return None
    target_serial = bump_zone_serial(zone)
    return await enqueue_record_op(
        db, zone, "create", record_op_payload(record), target_serial=target_serial
    )


async def push_records_restore(
    db: AsyncSession, zone_id: uuid.UUID, records: list[DNSRecord]
) -> list[DNSRecordOp | None]:
    """Batch form of :func:`push_record_restore`: one serial bump and one
    :func:`enqueue_record_ops_batch` call for every restored record of a zone.
    Same ``[]`` outcome when the zone cannot be resolved."""
    if not records:
        return []
    zone = await db.get(DNSZone, zone_id)
    if zone is None:
        return []
    target_serial = bump_zone_serial(zone)
    ops = [
        {"op": "create", "record": record_op_payload(r), "target_serial": target_serial}
        for r in records
    ]
    return await enqueue_record_ops_batch(db, zone, ops)


async def _fanout_agent_ops(
    db: AsyncSession,
    zone: DNSZone,
    primary: DNSServer,
    ops: list[dict[str, Any]],
) -> list[DNSRecordOp | None]:
    """Queue ``ops`` for every ENABLED agent-based server in the zone's group.

    The one fan-out both batch entry points share. Resolves the server set
    ONCE, stamps the RRsets ONCE (#773), inserts every row in one ``add_all``
    + one flush, wakes the group once. Returns, per input op, the row created
    for ``primary`` when it is among the enabled servers, else the first
    enabled agent's row — the same truthy-when-dispatched contract as
    :func:`enqueue_record_op` (#481), which is what lets a caller gate a DB
    delete on "was a wire op dispatched?". ``[None] * len(ops)`` when every
    agent-based server is disabled.

    Before this helper ``enqueue_record_ops_batch`` looped the singular path
    per op: two identical server SELECTs and a flush for EVERY record, i.e.
    ~4,000 round trips for a 2,000-record bulk delete on a two-agent group,
    all inside one transaction holding the zone's serial-bump row lock.
    """
    if not ops:
        return []
    agent_rows = (
        (
            await db.execute(
                select(DNSServer)
                .where(
                    DNSServer.group_id == zone.group_id,
                    DNSServer.is_enabled.is_(True),
                )
                .order_by(DNSServer.is_primary.desc(), DNSServer.created_at)
            )
        )
        .scalars()
        .all()
    )
    agent_servers = [s for s in agent_rows if not is_agentless(s.driver)]
    if not agent_servers:
        logger.warning(
            "record_op_batch_dropped_no_enabled_agent",
            zone=zone.name,
            group_id=str(zone.group_id),
            count=len(ops),
        )
        return [None] * len(ops)
    ops = [{**o, "record": dict(o["record"])} for o in ops]
    await stamp_rrsets_for_ops(db, zone, ops)
    # The row we hand back per op: the primary's if enabled, else the first
    # enabled agent's (``agent_servers`` is ordered is_primary DESC).
    returned = next((s for s in agent_servers if s.id == primary.id), agent_servers[0])
    result: list[DNSRecordOp | None] = []
    rows: list[DNSRecordOp] = []
    for srv in agent_servers:
        for o in ops:
            row = DNSRecordOp(
                server_id=srv.id,
                zone_name=zone.name,
                op=o["op"],
                record=o["record"],
                target_serial=o.get("target_serial"),
                state="pending",
            )
            rows.append(row)
            if srv.id == returned.id:
                result.append(row)
    db.add_all(rows)
    await db.flush()
    # #358 — wake every agent in the group so they drain the queued ops on the
    # next poll instead of the belt-and-braces tick. Flushed after the outer
    # commit by the request's ``wake_publishing`` dependency.
    collect_wake(dns_group_channel(zone.group_id))
    return result


async def enqueue_record_ops_batch(
    db: AsyncSession,
    zone: DNSZone,
    ops: list[dict[str, Any]],
) -> list[DNSRecordOp | None]:
    """Batch counterpart to :func:`enqueue_record_op`.

    Groups all ops for a single zone into one driver call when the zone's
    primary is agentless — cuts an N-record sync from N WinRM round trips
    to one. Agent-based groups fan out in one ``add_all`` + flush via
    :func:`_fanout_agent_ops`, and the agent batches at poll time.

    ``ops`` is a list of ``{op, record, target_serial?}`` dicts matching
    the singular ``enqueue_record_op`` arg shape.

    Returns one ``DNSRecordOp`` (or None on drop) per input op, in the
    same order as ``ops``.
    """
    if not ops:
        return []

    primary = await resolve_primary_server(db, zone)
    if primary is None:
        logger.warning(
            "record_op_batch_dropped_no_primary",
            zone=zone.name,
            group_id=str(zone.group_id),
            count=len(ops),
        )
        return [None] * len(ops)

    if is_agentless(primary.driver):
        # Agentless: drop at a paused server rather than hang on a dead socket.
        if not primary.is_enabled:
            logger.warning(
                "record_op_batch_dropped_server_disabled",
                zone=zone.name,
                server=str(primary.id),
                driver=primary.driver,
                count=len(ops),
            )
            return [None] * len(ops)
        return await _apply_agentless_batch(db, primary, zone, ops)

    # Agent-based: DB rows only; the agent batches at poll time. One fan-out
    # to every ENABLED agent-based server regardless of whether the designated
    # primary is disabled (#481), with the RRsets resolved for the whole batch
    # first (#773) so every op at a shared (name, type) carries the same
    # complete set whatever order the agent drains them in.
    return await _fanout_agent_ops(db, zone, primary, ops)


async def enqueue_record_ops_bulk(
    db: AsyncSession,
    zone: DNSZone,
    ops: list[dict[str, Any]],
) -> int:
    """Enqueue many ops for a SINGLE zone with one server-set resolution.

    The seeding / bulk-import fast-path: the same fan-out as
    :func:`enqueue_record_ops_batch` but returning a count rather than per-op
    rows, for callers that own idempotency and write one summary audit row.

    Returns the number of ops dispatched (0 if no enabled primary).
    """
    if not ops:
        return 0

    primary = await resolve_primary_server(db, zone)
    if primary is None:
        logger.warning(
            "record_op_bulk_dropped",
            zone=zone.name,
            group_id=str(zone.group_id),
            count=len(ops),
            reason="no primary configured for zone",
        )
        return 0

    if is_agentless(primary.driver):
        # Agentless: drop at a paused server rather than hang on a dead socket.
        if not primary.is_enabled:
            logger.warning(
                "record_op_bulk_dropped",
                zone=zone.name,
                group_id=str(zone.group_id),
                count=len(ops),
                reason="agentless primary is disabled",
            )
            return 0
        rows = await _apply_agentless_batch(db, primary, zone, ops)
        return sum(1 for r in rows if r is not None)
    # Agent-based: same fan-out as the batch path — every enabled agent-based
    # server, resolved once, one add_all + flush (#481 semantics included).
    rows = await _fanout_agent_ops(db, zone, primary, ops)
    return sum(1 for r in rows if r is not None)


# Ids per ``IN`` clause: asyncpg refuses a statement with more than 32 767 bind
# parameters, and a purge sweep can hand over many subnets / many records.
_RETRACT_CHUNK = 5000


async def retract_address_records(
    db: AsyncSession, subnet_ids: Collection[uuid.UUID]
) -> tuple[int, set[uuid.UUID]]:
    """Withdraw every auto-generated DNS record IPAM published for the
    addresses of ``subnet_ids``, before those subnets are hard-deleted
    (spatiumddi#1151). Returns ``(records_retracted, dns_group_ids)`` — the
    groups to wake once the caller has committed.

    A subnet's hard delete cascades its ``ip_address`` rows, but
    ``dns_record.ip_address_id`` is ON DELETE SET NULL: left to the database,
    every A / AAAA / PTR / alias IPAM generated for those addresses survives
    as an ownerless row in a live zone — and on the wire, because in a group
    without views the agents never re-render records from the bundle, so only
    a queued delete op takes one out of BIND.

    What is withdrawn, and what is not:

    * ``auto_generated`` records only. A record an operator made by hand is
      theirs; it keeps its place with ``ip_address_id`` null, as before.
    * live records only. One already in the trash — the PTRs of an
      auto-created reverse zone that went to the trash with its subnet
      (#1066) — is not being served, and keeps riding its own batch.
    * records bound to these subnets' addresses only. The caller passes the
      subnets it is about to hard-delete, so every address concerned is
      really going; a sibling subnet's records in a shared zone are untouched.

    Ops go out per zone in one batch (one serial bump, one RRset resolution),
    so every op carries the zone's final RRset: a round-robin name losing two
    of its three members to the purge keeps exactly the third, whatever order
    the agent drains them in. Agent ops are rows in the caller's transaction,
    so a rolled-back purge queues nothing; an agentless primary (Windows DNS)
    is written immediately, as every record op to it is.
    """
    ids = list(subnet_ids)
    if not ids:
        return 0, set()
    records: list[DNSRecord] = []
    for start in range(0, len(ids), _RETRACT_CHUNK):
        chunk = ids[start : start + _RETRACT_CHUNK]
        records.extend(
            (
                await db.execute(
                    select(DNSRecord)
                    .where(
                        DNSRecord.auto_generated.is_(True),
                        DNSRecord.ip_address_id.in_(
                            select(IPAddress.id).where(IPAddress.subnet_id.in_(chunk))
                        ),
                    )
                    .options(selectinload(DNSRecord.zone))
                )
            )
            .scalars()
            .all()
        )
    if not records:
        return 0, set()

    by_zone: dict[uuid.UUID, tuple[DNSZone, list[DNSRecord]]] = {}
    for rec in records:
        zone = rec.zone
        if zone is None or zone.deleted_at is not None:
            continue  # a zone in the trash is not served: nothing on the wire
        by_zone.setdefault(zone.id, (zone, []))[1].append(rec)
    wake: set[uuid.UUID] = set()
    for zone, recs in by_zone.values():
        target_serial = bump_zone_serial(zone)
        await enqueue_record_ops_batch(
            db,
            zone,
            [
                {"op": "delete", "record": record_op_payload(r), "target_serial": target_serial}
                for r in recs
            ],
        )
        wake.add(zone.group_id)

    # After the enqueue: the RRset stamp reads the zone's live members and
    # removes each op's own value (rrset._fold), so the victims are still rows.
    record_ids = [r.id for r in records]
    for start in range(0, len(record_ids), _RETRACT_CHUNK):
        await db.execute(
            sa_delete(DNSRecord).where(DNSRecord.id.in_(record_ids[start : start + _RETRACT_CHUNK]))
        )
    logger.info(
        "ipam_address_records_retracted",
        subnets=len(ids),
        records=len(records),
        zones=len(by_zone),
    )
    return len(records), wake


async def _apply_agentless_batch(
    db: AsyncSession,
    server: DNSServer,
    zone: DNSZone,
    ops: list[dict[str, Any]],
) -> list[DNSRecordOp | None]:
    """Apply many record ops against an agentless server in one driver call.

    Writes per-op DNSRecordOp rows (applied / failed) so the audit trail
    matches what the singular path produces. A whole-batch exception
    (WinRM auth failure, PS parse error in the generated script) marks
    every row failed with the same error — per-op failures (a bad
    record type for example) only mark their own row.

    #783 — the whole batch is folded and stamped with its desired RRsets in
    ONE query before any row is written, exactly as the agent batch path
    does. Folding matters here for the same reason it does there: a bulk
    delete of two of three values at one name resolves both ops against the
    same pre-delete snapshot, so reconciling each in isolation would ship
    two contradictory sets and whichever landed last would reinstate a value
    the operator deleted.
    """
    ops = [{**o, "record": dict(o["record"])} for o in ops]
    await stamp_rrsets_for_ops(db, zone, ops)

    op_rows: list[DNSRecordOp] = []
    for o in ops:
        row = DNSRecordOp(
            server_id=server.id,
            zone_name=zone.name,
            op=o["op"],
            record=o["record"],
            target_serial=o.get("target_serial"),
            state="pending",
        )
        db.add(row)
        op_rows.append(row)
    await db.flush()

    changes = [
        RecordChange(
            op=o["op"],  # type: ignore[arg-type]
            zone_name=zone.name,
            record=RecordData(
                name=o["record"]["name"],
                record_type=o["record"]["type"],
                value=o["record"]["value"],
                ttl=o["record"].get("ttl"),
                priority=o["record"].get("priority"),
                weight=o["record"].get("weight"),
                port=o["record"].get("port"),
            ),
            target_serial=o.get("target_serial") or 0,
            rrset=_rrset_from_payload(o["record"]),
        )
        for o in ops
    ]

    driver = get_driver(server.driver)
    try:
        results = await driver.apply_record_changes(server, changes)
    except Exception as exc:  # noqa: BLE001 — whole-batch wire/auth failure
        logger.warning(
            "record_op_batch_failed",
            server=str(server.id),
            driver=server.driver,
            zone=zone.name,
            count=len(op_rows),
            error=str(exc),
        )
        err = str(exc)[:500]
        for row in op_rows:
            row.state = "failed"
            row.attempts = 1
            row.last_error = err
        await db.flush()
        return list(op_rows)

    applied_count = 0
    for row, result in zip(op_rows, results, strict=True):
        row.attempts = 1
        if result.ok:
            row.state = "applied"
            row.applied_at = datetime.now(UTC)
            row.last_error = None
            applied_count += 1
        else:
            row.state = "failed"
            row.last_error = (result.error or "unknown")[:500]
    await db.flush()

    logger.info(
        "record_op_batch_applied_agentless",
        server=str(server.id),
        driver=server.driver,
        zone=zone.name,
        total=len(results),
        applied=applied_count,
        failed=len(results) - applied_count,
    )
    return list(op_rows)


async def ack_op(db: AsyncSession, op_id: str, result: str, message: str | None = None) -> None:
    """Mark an op applied (ok) or failed."""
    from datetime import UTC, datetime

    op = await db.get(DNSRecordOp, op_id)
    if op is None:
        return
    op.attempts += 1
    if result == "ok":
        op.state = "applied"
        op.applied_at = datetime.now(UTC)
        op.last_error = None
    else:
        op.last_error = message
        if op.attempts >= 5:
            op.state = "failed"
        else:
            # Reset to pending so it gets re-shipped in the next bundle.
            op.state = "pending"
    await db.flush()
