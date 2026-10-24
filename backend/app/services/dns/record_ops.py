"""Enqueue and resolve RecordOps for DNS agents.

Per docs/deployment/DNS_AGENT.md §5: when a record is mutated, compute the
delta and write RecordOp rows targeting the primary server for that zone.
Secondaries pick up the changes via native AXFR/IXFR from the primary.

Agentless drivers (Windows DNS, cloud providers, technitium_api) don't follow
this queue — the control plane applies the change itself, but only AFTER the
request's transaction commits (#1539): the op row is written ``pending``
inside the transaction and dispatched from an after-commit hook, which marks
it ``applied`` or reschedules it so operators still see a per-op audit trail.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, event, func, or_, select, tuple_, update
from sqlalchemy import delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload
from sqlalchemy.orm.attributes import set_committed_value
from sqlalchemy.util import await_only

from app.core.agent_wake import collect_wake, dns_group_channel
from app.drivers.dns import AGENTLESS_DRIVERS, get_driver, is_agentless
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember
from app.models.audit import AuditLog
from app.models.dns import DNSKey, DNSRecord, DNSRecordOp, DNSServer, DNSZone, servable_ttl
from app.models.ipam import IPAddress
from app.services.dns.bundle_dirty import mark_bundles_dirty
from app.services.dns.row_locks import ids_in, lock_op_ids, lock_ops
from app.services.dns.rrset import rrset_key as record_rrset_key
from app.services.dns.rrset import stamp_rrsets_for_ops
from app.services.dns.serial import bump_zone_serial

logger = structlog.get_logger(__name__)


# Queued-op states. ``in_flight`` is queued work too: an op already shipped is
# not finished with — ``ack_op`` returns a NACKed one to ``pending`` — so any
# sweep of a zone's queue must cover both (the #934 review finding). The
# terminal states are ``applied``, ``failed`` and ``superseded`` (#1232).
QUEUED_OP_STATES: tuple[str, ...] = ("pending", "in_flight")


# #1232 — retry policy for an op the agent failed to apply. Exponential,
# 30 s doubling to a 15 min cap: 30 s, 1 m, 2 m, 4 m, 8 m, 15 m, 15 m, i.e.
# about 45 minutes before the op is given up on. Retries used to go out on
# every heartbeat, so five attempts were spent inside a ~2.5 minute daemon
# restart or upgrade — exactly the outage a retry exists to ride out.
MAX_OP_ATTEMPTS = 8
OP_RETRY_BASE_SECONDS = 30
OP_RETRY_MAX_SECONDS = 15 * 60
# An op shipped and never acknowledged — the agent restarted before its next
# heartbeat (it keeps its acks in memory), or the long-poll response was lost
# after its commit — used to stay ``in_flight`` forever. The agent acks on its
# next heartbeat (~30 s) and keeps an unsent ack across failed heartbeats, so
# five minutes is several missed heartbeats, not a slow one.
IN_FLIGHT_ACK_TIMEOUT = timedelta(minutes=5)
# Keys per ``IN`` list when matching RRsets in SQL: three bind parameters a
# key, well under asyncpg's 32767.
RRSET_KEY_CHUNK = 3000


def retry_delay(attempts: int) -> timedelta:
    """Backoff after the ``attempts``-th failed attempt (1-based)."""
    exp = max(0, attempts - 1)
    return timedelta(seconds=min(OP_RETRY_BASE_SECONDS * (2 ** min(exp, 16)), OP_RETRY_MAX_SECONDS))


def op_rrset_key(op: DNSRecordOp) -> tuple[str, str, str] | None:
    """``(zone, name, type)`` of the RRset an op rewrites, or None when the op
    carries no whole-RRset state.

    Only an op with an ``rrset`` (#773) is a complete statement of what the
    RRset should be; one that opted out via ``rrset_action`` (DNS pools) or
    carries none (the DNSSEC signal op) says nothing about a sibling op, so it
    neither supersedes nor is superseded. Name and type are normalised by the
    same ``rrset.rrset_key`` the RRset stamping uses (an empty name is ``@``).
    """
    record = op.record or {}
    if "rrset" not in record:
        return None
    key = record_rrset_key(record)
    return None if key is None else (op.zone_name, key[0], key[1])


def _op_name_sql() -> Any:
    """``op_rrset_key``'s name, in SQL."""
    return func.lower(func.coalesce(func.nullif(DNSRecordOp.record["name"].astext, ""), "@"))


def _op_type_sql() -> Any:
    return func.upper(DNSRecordOp.record["type"].astext)


def rrset_match_where(keys: Collection[tuple[str, str, str]]) -> Any:
    """WHERE clause matching ops whose RRset is one of ``keys``."""
    return and_(
        DNSRecordOp.record.has_key("rrset"),
        tuple_(DNSRecordOp.zone_name, _op_name_sql(), _op_type_sql()).in_(list(keys)),
    )


def queued_after(
    created: datetime, seq: int | None, other_created: datetime, other_seq: int | None
) -> bool:
    """Whether an op queued at ``(created, seq)`` came after one queued at
    ``(other_created, other_seq)`` (#1489).

    ``created_at`` is the transaction START, so ops of different transactions
    compare by it as before. Ops one transaction queued tie on it and are
    ordered by ``seq``, the order they were queued in. A row queued before
    ``seq`` existed (NULL) says nothing about order within its transaction.
    """
    if created != other_created:
        return created > other_created
    return seq is not None and other_seq is not None and seq > other_seq


async def _successors(db: AsyncSession, ops: Collection[DNSRecordOp]) -> dict[uuid.UUID, uuid.UUID]:
    """For each op, the newest op queued STRICTLY after it for the same server
    and RRset, if any (#1232). One query per server per key chunk.

    That newer op carries the whole desired RRset as of a later moment, so it
    already delivers the older op's change; retrying the older one after it
    would put the old state back. Strictly after, by ``queued_after``: within
    one transaction that is the queue order (#1489), so a failed delete is
    superseded by the create queued after it instead of retrying and removing
    the record again. A ``failed`` or ``superseded`` op is not a successor.
    """
    out: dict[uuid.UUID, uuid.UUID] = {}
    by_server: dict[uuid.UUID, list[tuple[DNSRecordOp, tuple[str, str, str]]]] = {}
    for op in ops:
        key = op_rrset_key(op)
        if key is not None:
            by_server.setdefault(op.server_id, []).append((op, key))
    for server_id, keyed in by_server.items():
        earliest = min(op.created_at for op, _ in keyed)
        keys = sorted({k for _, k in keyed})
        newest: dict[tuple[str, str, str], list[tuple[datetime, int | None, uuid.UUID]]] = {}
        for i in range(0, len(keys), RRSET_KEY_CHUNK):
            rows = (
                await db.execute(
                    select(
                        DNSRecordOp.id,
                        DNSRecordOp.zone_name,
                        _op_name_sql(),
                        _op_type_sql(),
                        DNSRecordOp.created_at,
                        DNSRecordOp.seq,
                    ).where(
                        DNSRecordOp.server_id == server_id,
                        # ``>=``: an op of the earliest op's own transaction
                        # can follow it (#1489).
                        DNSRecordOp.created_at >= earliest,
                        DNSRecordOp.state.in_(("pending", "in_flight", "applied")),
                        rrset_match_where(keys[i : i + RRSET_KEY_CHUNK]),
                    )
                )
            ).all()
            for row_id, zone, name, rtype, created, seq in rows:
                newest.setdefault((zone, name, rtype), []).append((created, seq, row_id))
        for op, key in keyed:
            later = [
                (c, s, i)
                for c, s, i in newest.get(key, ())
                if queued_after(c, s, op.created_at, op.seq)
            ]
            if later:
                # Newest by queue order; ``seq`` is NULL only on rows from
                # before the column, which cannot share a transaction with
                # one that has it.
                out[op.id] = max(later, key=lambda t: (t[0], t[1] or 0))[2]
    return out


def supersede(op: DNSRecordOp, successor_id: uuid.UUID, now: datetime) -> None:
    op.state = "superseded"
    op.superseded_by = successor_id
    op.next_attempt_at = None
    op.updated_at = now


async def fail_attempts(
    db: AsyncSession, failures: Collection[tuple[DNSRecordOp, str]], *, now: datetime
) -> None:
    """Account for one failed or unacknowledged attempt at each op (#1232).

    Superseded when a newer op for its RRset exists; otherwise back to
    ``pending`` with a backoff, or ``failed`` once the budget is spent.
    """
    successors = await _successors(db, [op for op, _ in failures])
    for op, message in failures:
        op.attempts += 1
        op.last_error = message
        op.updated_at = now
        successor = successors.get(op.id)
        if successor is not None:
            supersede(op, successor, now)
        elif op.attempts >= MAX_OP_ATTEMPTS:
            op.state = "failed"
            op.next_attempt_at = None
            logger.warning(
                "dns_record_op_failed",
                op_id=str(op.id),
                server_id=str(op.server_id),
                zone=op.zone_name,
                name=(op.record or {}).get("name"),
                type=(op.record or {}).get("type"),
                attempts=op.attempts,
                error=message,
            )
        else:
            op.state = "pending"
            op.next_attempt_at = now + retry_delay(op.attempts)


async def reset_unacknowledged_ops(
    db: AsyncSession, server_id: uuid.UUID, *, now: datetime | None = None
) -> int:
    """Return ops shipped and never acknowledged to the retry path (#1232).

    The agent keeps its acks in memory until a heartbeat succeeds, so a
    restart in between, or a long-poll response lost after its commit, left
    the op ``in_flight`` forever: never re-shipped, never failed, and anything
    waiting for ``applied`` (the ACME DNS-01 wait) timed out. Counted as a
    failed attempt, so an op that crashes the agent cannot loop forever.

    Called from the heartbeat, after that heartbeat's own acks: a live agent
    is exactly when re-shipping can help, and the heartbeat always commits.
    (The long-poll does not — a 304 rolls its transaction back — which is why
    this is not done there.)

    ``now`` is the heartbeat's own, so the rows it locked up front
    (``lock_heartbeat_ops``) are exactly the ones selected here.
    """
    now = now or datetime.now(UTC)
    stale = (
        (
            await db.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.server_id == server_id,
                    DNSRecordOp.state == "in_flight",
                    DNSRecordOp.updated_at < now - IN_FLIGHT_ACK_TIMEOUT,
                )
            )
        )
        .scalars()
        .all()
    )
    if not stale:
        return 0
    minutes = int(IN_FLIGHT_ACK_TIMEOUT.total_seconds() // 60)
    message = (
        f"no acknowledgement from the agent within {minutes} minutes "
        "(it restarted, or the response was lost); retrying"
    )
    await fail_attempts(db, [(op, message) for op in stale], now=now)
    logger.warning(
        "dns_record_ops_unacknowledged_reset", server_id=str(server_id), count=len(stale)
    )
    await db.flush()
    return len(stale)


async def return_ops_dispatched_elsewhere(
    db: AsyncSession,
    server_id: uuid.UUID,
    instance: str,
    *,
    poll_started_at: datetime,
    now: datetime | None = None,
) -> int:
    """Return this server's ops shipped to another agent process to ``pending``
    (#2042). Returns the count; flushes, the caller commits.

    When an agent is replaced (a pod roll, a container restart), the API can
    still be holding a long-poll for the agent that went away. A record change
    committed in the next few seconds is paged into that poll, marked
    ``in_flight`` and written to a connection nobody reads, and the
    replacement never receives it. Each op records the instance it was shipped
    to (``dispatched_to``); a poll from instance ``instance`` therefore knows
    any op still ``in_flight`` to a DIFFERENT instance cannot be one it holds,
    and sends it back to be shipped on this poll. ``reset_unacknowledged_ops``
    did the same, but only after five minutes.

    Counted as an attempt, like the 5-minute reset: the departed agent may have
    applied the op and died before acking it, and an op that crashes the agent
    on every start must still exhaust its retries. But no backoff: nothing
    failed here, the op was delivered to the wrong place. Record ops are
    whole-RRset replaces (#773), so re-applying one the old agent did apply is
    a no-op, and its late ``ok`` ack still marks the op applied.

    Only an op shipped by a poll that STARTED BEFORE this one
    (``dispatched_poll_at < poll_started_at``). The departed agent's leftover
    poll runs at the same time as its replacement's and also passes through
    here; without the ranking it would take back ops the replacement has
    received and not yet acked (acks ride the ~30 s heartbeat), re-send them to
    nobody, and the replacement would get them a second time — one more
    attempt each, and a second ``rndc dnssec -rollover`` for a rollover op. The
    leftover poll always started first, so it never qualifies; the
    replacement's polls always started after it, so they always do.

    An op with no ``dispatched_to`` (shipped by an older control plane, or to
    an agent too old to send an instance id) is left to the 5-minute reset.
    """
    now = now or datetime.now(UTC)
    stale = await lock_ops(
        db,
        DNSRecordOp.server_id == server_id,
        DNSRecordOp.state == "in_flight",
        DNSRecordOp.dispatched_to.is_not(None),
        DNSRecordOp.dispatched_to != instance,
        DNSRecordOp.dispatched_poll_at < poll_started_at,
    )
    if not stale:
        return 0
    message = "shipped to an agent instance that has since been replaced; re-sending"
    await fail_attempts(db, [(op, message) for op in stale], now=now)
    for op in stale:
        if op.state == "pending":
            op.next_attempt_at = None
    logger.info(
        "dns_record_ops_returned_from_replaced_agent",
        server_id=str(server_id),
        count=len(stale),
    )
    await db.flush()
    return len(stale)


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
    create route 409s it), so the predicate is exact there. Ops now carry
    ``zone_id`` too (set on every enqueue path, used where per-view
    attribution matters: the pending-ops list narrowed to a token's zones),
    but rows queued before that column existed have it NULL, so keying this
    predicate on it would need this name-scoped fallback anyway, to guard a
    path the incremental op flow never takes under split-horizon.

    Every zone-scoped sweep and count goes through here so the decision lives
    in one place; ``tests/test_dns_record_ops_sweep.py`` pins both the
    behaviour and that no other module carries its own copy.
    """
    return [
        DNSRecordOp.server_id.in_(select(DNSServer.id).where(DNSServer.group_id == group_id)),
        DNSRecordOp.zone_name == zone.name,
        DNSRecordOp.state.in_(QUEUED_OP_STATES),
    ]


async def queued_op_counts(
    db: AsyncSession,
    *,
    server_ids: Collection[uuid.UUID],
    zone_names: Collection[str] | None = None,
) -> dict[tuple[uuid.UUID, str], int]:
    """How many ops each ``(server, zone name)`` pair still has unacknowledged
    — ``pending`` or ``in_flight`` (#2042). Pairs with none are absent.
    ``zone_names`` None counts every zone the servers have ops for.

    A zone's server-state compares the serial a server reported with the
    zone's target serial, and a serial is not proof a record arrived: an agent
    that starts from its cached bundle reports what it serves, which can match
    or pass the target while a record op is still undelivered. Until the op is
    acknowledged the server is not in sync for that zone, whatever its serial
    says. Name-scoped like :func:`queued_zone_ops_where`, for the same reason.
    """
    if not server_ids or (zone_names is not None and not zone_names):
        return {}
    conds: list[Any] = [
        DNSRecordOp.server_id.in_(list(server_ids)),
        DNSRecordOp.state.in_(QUEUED_OP_STATES),
    ]
    if zone_names is not None:
        conds.append(DNSRecordOp.zone_name.in_(list(zone_names)))
    rows = await db.execute(
        select(DNSRecordOp.server_id, DNSRecordOp.zone_name, func.count())
        .where(*conds)
        .group_by(DNSRecordOp.server_id, DNSRecordOp.zone_name)
    )
    return {(sid, name): int(n) for sid, name, n in rows.all()}


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
    # Locked ascending first (``row_locks``): a DELETE alone takes its rows in
    # scan order, which can cross a server move or a poll locking the same
    # server's ops in id order.
    await lock_op_ids(db, *queued_zone_ops_where(zone, group_id))
    res = await db.execute(sa_delete(DNSRecordOp).where(*queued_zone_ops_where(zone, group_id)))
    return int(res.rowcount or 0)


async def primary_candidate(
    db: AsyncSession, group_id: uuid.UUID, *, exclude_id: uuid.UUID | None = None
) -> DNSServer | None:
    """The server a group that has no primary should treat as one (#2276).

    Read-only: picks, never writes. The one ordering every election uses —
    :func:`app.services.dns.server_move.elect_primary` (a move or a delete
    taking the primary out), the beat self-heal, and the write path below
    when a group has no primary at all — so all three name the same server.

    Prefers a server that can actually accept writes: enabled, not paused,
    oldest first so the choice is deterministic. Falls back to any member when
    every one is disabled or paused, because a paused primary still beats none:
    a disabled one is visible in the UI, a missing one is not.
    ``exclude_id`` names a server still in the group in this session that is
    on its way out (see ``elect_primary``).
    """
    conditions = [DNSServer.group_id == group_id]
    if exclude_id is not None:
        conditions.append(DNSServer.id != exclude_id)
    base = select(DNSServer).where(*conditions).order_by(DNSServer.created_at, DNSServer.id)
    candidate = (
        await db.execute(
            base.where(
                DNSServer.is_enabled.is_(True),
                DNSServer.maintenance_mode.is_(False),
            ).limit(1)
        )
    ).scalar_one_or_none()
    if candidate is None:
        candidate = (await db.execute(base.limit(1))).scalar_one_or_none()
    return candidate


async def resolve_primary_server(db: AsyncSession, zone: DNSZone) -> DNSServer | None:
    """The server that stands for the zone's group on the write path.

    The ``is_primary=True`` server when the group has one. When it has none —
    the group's primary was deleted on a build that did not re-elect, or the
    flag was cleared some other way — the server the election would pick
    (:func:`primary_candidate`) rather than ``None`` (#2276). ``None`` used to
    make every record write to the group's zones a logged no-op behind a 200,
    and it did so BEFORE the agent fan-out, so the surviving agents got
    nothing either. The beat self-heal stamps the flag on that same server
    within a minute; until then this keeps writes flowing to it.

    ``None`` now means the group has no servers at all, where nothing is lost:
    a server added later receives the zone's records in its config bundle.
    """
    res = await db.execute(
        select(DNSServer)
        .where(DNSServer.group_id == zone.group_id, DNSServer.is_primary.is_(True))
        .limit(1)
    )
    primary = res.scalar_one_or_none()
    if primary is not None:
        return primary
    candidate = await primary_candidate(db, zone.group_id)
    if candidate is not None:
        logger.warning(
            "dns_group_has_no_primary",
            zone=zone.name,
            group_id=str(zone.group_id),
            standing_in=str(candidate.id),
            driver=candidate.driver,
            hint="Writing through the server the election picks; the beat self-heal marks it.",
        )
    return candidate


async def heal_primaryless_groups(
    db: AsyncSession, healed_groups: list[uuid.UUID] | None = None
) -> int:
    """Mark a primary in every group that has servers and no primary (#2276).

    Self-heal for installs left without one — by deleting the primary on a
    build that did not re-elect. Run from the 60 s agent stale sweep.
    Idempotent: a group that has a primary is untouched. The UPDATE re-checks
    "no primary in this group" in the same statement, which closes the gap
    between the scan and the write and makes two concurrent sweeps converge
    on one server (the pick is deterministic). It does NOT serialise against
    an operator promotion that is still uncommitted — READ COMMITTED cannot
    see it, and the promotion takes no group lock — so that narrow window can
    still leave two primaries, exactly as two concurrent promotions or a
    promotion racing create-time auto-election always could. Every primary
    lookup caps at one row, so that state mis-picks rather than 500s (#934),
    and only a group already without a primary is ever touched, which after
    this fix means one left over from an older build. Returns the number of
    groups healed; when ``healed_groups`` is given, their ids are appended so
    the caller can wake the group channels after its commit.

    ``is_primary`` is a bundle input and the UPDATE is Core, which the
    bundle-dirty listener never sees, so each healed group is marked dirty
    here (#2655) — otherwise the stored bundle stays "current" and, e.g., a
    catalog-zone group keeps serving a bundle with no producer.
    """
    primaried = select(DNSServer.group_id).where(DNSServer.is_primary.is_(True))
    group_ids = (
        (
            await db.execute(
                select(DNSServer.group_id).where(DNSServer.group_id.not_in(primaried)).distinct()
            )
        )
        .scalars()
        .all()
    )
    healed = 0
    for group_id in group_ids:
        candidate = await primary_candidate(db, group_id)
        if candidate is None:
            continue
        other = aliased(DNSServer)
        res = await db.execute(
            update(DNSServer)
            .where(
                DNSServer.id == candidate.id,
                ~select(other.id)
                .where(other.group_id == group_id, other.is_primary.is_(True))
                .exists(),
            )
            .values(is_primary=True)
            .execution_options(synchronize_session=False)
        )
        if res.rowcount:
            healed += 1
            if healed_groups is not None:
                healed_groups.append(group_id)
            await mark_bundles_dirty(db, group_ids=[group_id])
            collect_wake(dns_group_channel(group_id))
            logger.warning(
                "dns_group_primary_healed",
                group_id=str(group_id),
                server_id=str(candidate.id),
                server=candidate.name,
            )
    # The marks above shift the stored bundle; the 12 s tick alone would NOT
    # pick the flag up (it only re-checks ``is_current``). Record writes reach
    # the stand-in through ``resolve_primary_server`` in the meantime.
    return healed


def rrset_from_payload(record: dict[str, Any]) -> RRsetData | None:
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


# ── After-commit dispatch for agentless ops (#1539) ─────────────────────────
#
# An agentless op used to reach the provider in the middle of the request's
# transaction. If the commit then failed (audit insert error, deadlock, a
# dropped connection) the DNSRecord change AND its op row rolled back while
# the provider kept the write — a change nothing in the database recorded.
#
# Now the op row is written ``pending`` inside the transaction (the outbox)
# and the driver is called only once that transaction has committed, from an
# ``after_transaction_end`` listener on the session. Three properties carry
# the design:
#
# * **The outer commit, not a savepoint.** ``after_commit`` also fires when a
#   SAVEPOINT is released (``begin_nested``), so it only marks the state
#   committed when no nested transaction is open; dispatch waits for the end
#   of the ROOT transaction.
# * **No connection held across a provider call.** ``after_commit`` fires
#   while the committing session still holds its connection; a Celery task
#   engine is ``pool_size=1, max_overflow=0`` (``task_sessionmaker``), so a
#   second session opened there would wait for a connection that is only
#   released after the hook returns. ``after_transaction_end`` fires after
#   the root transaction has returned its connection to the pool. The
#   dispatch itself claims the rows and commits in one short session, calls
#   the driver holding no connection at all, then records the outcome in a
#   second short session.
# * **Claimed, not timed.** A row is moved ``pending`` → ``in_flight`` by a
#   conditional UPDATE before any driver call, and the retry sweep claims the
#   same way under ``FOR UPDATE SKIP LOCKED``; whichever claims first sends
#   it, the other finds nothing. ``next_attempt_at`` on an ``in_flight``
#   agentless row is its lease: past it, the sweep assumes the dispatcher
#   died and returns the row to the retry path. The outcome is written only
#   if the row still carries this dispatch's claim (``updated_at``), so a
#   dispatch that outlived its lease cannot overwrite a newer one.
#
# A rolled-back transaction leaves no row and nothing to dispatch; a process
# that dies after the commit leaves a committed ``pending`` row, which
# :func:`apply_pending_agentless_ops` replays once its grace window passes.

#: How long a freshly queued agentless op is left to the committing process
#: before the retry sweep may claim it instead.
AGENTLESS_DISPATCH_GRACE = timedelta(seconds=120)
#: Lease on a claimed (``in_flight``) agentless op: past it the sweep treats
#: the dispatch as lost. Generous on purpose — only a crashed or hung
#: dispatcher reaches it — and grown per op, since a Windows batch is one
#: PowerShell round trip per few records.
AGENTLESS_DISPATCH_LEASE = timedelta(minutes=10)
AGENTLESS_DISPATCH_LEASE_PER_OP = timedelta(seconds=1)
# Ids per ``IN`` list when claiming: one bind parameter each, well under
# asyncpg's 32767.
_CLAIM_CHUNK = 5000

_DISPATCH_KEY = "spatium_agentless_dispatch"
_LISTENING_KEY = "spatium_agentless_dispatch_listening"


def agentless_dispatch_lease(count: int) -> timedelta:
    return AGENTLESS_DISPATCH_LEASE + AGENTLESS_DISPATCH_LEASE_PER_OP * count


@dataclass
class _AgentlessUnit:
    #: None on a zone-provision unit, which covers every agentless server
    #: of the zone's group.
    server_id: uuid.UUID | None
    op_rows: list[DNSRecordOp]
    batched: bool
    #: Set on a zone-provision unit (#1932): create this zone at the
    #: provider before the record ops queued after it; ``op_rows`` is empty.
    zone_id: uuid.UUID | None = None


@dataclass
class _DispatchState:
    bind: Any
    units: list[_AgentlessUnit] = field(default_factory=list)
    committed: bool = False


def _applied_values(now: datetime) -> dict[str, Any]:
    """The columns an applied op carries, besides one more attempt (#2108):
    ``_mark_applied`` sets them on a loaded row and ``mark_ops_applied`` in
    one UPDATE, so the two cannot stamp an applied op differently."""
    return {
        "state": "applied",
        "applied_at": now,
        "last_error": None,
        "next_attempt_at": None,
        "updated_at": now,
    }


def _mark_applied(row: DNSRecordOp, now: datetime) -> None:
    row.attempts = (row.attempts or 0) + 1
    for name, value in _applied_values(now).items():
        setattr(row, name, value)


async def mark_ops_applied(
    db: AsyncSession,
    ids: Sequence[uuid.UUID],
    now: datetime,
    loaded: dict[uuid.UUID, DNSRecordOp] | None = None,
) -> None:
    """``_mark_applied`` for ``ids`` as one UPDATE, without loading the rows
    (#2227: a split-horizon render retiring 800k queued ops as ORM objects
    held about 4 kB each, 3.7 GB, in the worker). The caller has locked the
    rows. ``loaded`` are rows of these ids already in the session: they get
    the same values as committed state, so a later read of one in this
    session sees the op applied and a flush does not write it again."""
    if not ids:
        return
    values = _applied_values(now)
    await db.execute(
        update(DNSRecordOp)
        .where(DNSRecordOp.id.in_(ids))
        .values(attempts=func.coalesce(DNSRecordOp.attempts, 0) + 1, **values)
        .execution_options(synchronize_session=False)
    )
    for op_id in ids:
        row = (loaded or {}).get(op_id)
        if row is None:
            continue
        if "attempts" in row.__dict__:
            set_committed_value(row, "attempts", (row.attempts or 0) + 1)
        for name, value in values.items():
            set_committed_value(row, name, value)


_MIRRORED_OP_FIELDS = (
    "state",
    "attempts",
    "applied_at",
    "last_error",
    "next_attempt_at",
    "updated_at",
    "superseded_by",
)


def _mirror_outcomes(
    targets: dict[uuid.UUID, DNSRecordOp], outcomes: dict[uuid.UUID, DNSRecordOp]
) -> None:
    """Copy a dispatch's recorded outcome onto the caller's in-memory rows,
    as committed state, so a handler reading ``op.state`` after its commit
    sees what happened without another round trip."""
    for oid, row in outcomes.items():
        orig = targets.get(oid)
        if orig is None or orig is row:
            continue
        for name in _MIRRORED_OP_FIELDS:
            set_committed_value(orig, name, getattr(row, name))


async def _claim(s: AsyncSession, ids: list[uuid.UUID], *, now: datetime) -> list[DNSRecordOp]:
    """Move the ``pending`` rows among ``ids`` to ``in_flight`` and return
    them in queue order. The caller commits.

    The conditional UPDATE is the claim: when the inline dispatch and the
    retry sweep race for a row, Postgres re-checks ``state = 'pending'``
    after the lock wait, so exactly one of them gets it.
    """
    claimed: list[uuid.UUID] = []
    lease_until = now + agentless_dispatch_lease(len(ids))
    for i in range(0, len(ids), _CLAIM_CHUNK):
        claimed.extend(
            (
                await s.execute(
                    update(DNSRecordOp)
                    .where(
                        DNSRecordOp.id.in_(ids[i : i + _CLAIM_CHUNK]),
                        DNSRecordOp.state == "pending",
                    )
                    .values(state="in_flight", updated_at=now, next_attempt_at=lease_until)
                    .returning(DNSRecordOp.id)
                    .execution_options(synchronize_session=False)
                )
            )
            .scalars()
            .all()
        )
    rows: list[DNSRecordOp] = []
    for i in range(0, len(claimed), _CLAIM_CHUNK):
        rows.extend(
            (
                await s.execute(
                    select(DNSRecordOp)
                    .where(DNSRecordOp.id.in_(claimed[i : i + _CLAIM_CHUNK]))
                    .execution_options(populate_existing=True)
                )
            )
            .scalars()
            .all()
        )
    rows.sort(key=lambda r: (r.created_at, r.seq or 0))
    return rows


async def _dispatch_claimed(
    bind: Any,
    server: DNSServer,
    rows: list[DNSRecordOp],
    *,
    batched: bool,
    claimed_at: datetime,
) -> dict[uuid.UUID, DNSRecordOp]:
    """Send claimed rows to ``server``'s driver, then record the outcome.

    The driver is called holding no database connection; the outcome is
    written in a fresh short session and only onto rows that still carry
    this dispatch's claim. Returns the updated rows by id.
    """
    pairs: list[tuple[uuid.UUID, RecordChange]] = []
    unreplayable: set[uuid.UUID] = set()
    for r in rows:
        change = _change_from_op_row(r)
        if change is None:
            unreplayable.add(r.id)
        else:
            pairs.append((r.id, change))

    errors: dict[uuid.UUID, str | None] = {}
    if pairs:
        # #1932 — a zone SpatiumDDI auto-created and has not yet confirmed at
        # the provider is created before its ops are sent, by whichever path
        # sends them first. Ops whose zone still could not be created are held
        # back with that error instead of failing "no such zone".
        blocked = await _ensure_pending_zones_for_ops(bind, server, {r.zone_name for r in rows})
        if blocked:
            by_id = {r.id: r for r in rows}
            kept: list[tuple[uuid.UUID, RecordChange]] = []
            for oid, change in pairs:
                zone_error = blocked.get(by_id[oid].zone_name)
                if zone_error is None:
                    kept.append((oid, change))
                else:
                    errors[oid] = (
                        f"zone {by_id[oid].zone_name} could not be created at the provider: "
                        f"{zone_error}"
                    )[:500]
            pairs = kept
    if pairs:
        try:
            driver = get_driver(server.driver)
            if batched:
                results = await driver.apply_record_changes(server, [c for _i, c in pairs])
                for (oid, _c), res in zip(pairs, results, strict=True):
                    errors[oid] = None if res.ok else (res.error or "unknown")[:500]
            else:
                for oid, change in pairs:
                    try:
                        await driver.apply_record_change(server, change)
                        errors[oid] = None
                    except Exception as exc:  # noqa: BLE001 — per-op wire error
                        logger.warning(
                            "record_op_failed_agentless",
                            server=str(server.id),
                            driver=server.driver,
                            zone=change.zone_name,
                            op=change.op,
                            error=str(exc),
                        )
                        errors[oid] = str(exc)[:500]
        except Exception as exc:  # noqa: BLE001 — whole-batch wire/auth failure
            logger.warning(
                "record_op_batch_failed",
                server=str(server.id),
                driver=server.driver,
                count=len(pairs),
                error=str(exc),
            )
            for oid, _c in pairs:
                errors.setdefault(oid, str(exc)[:500])

    now = datetime.now(UTC)
    ids = [r.id for r in rows]
    async with AsyncSession(bind, expire_on_commit=False) as s:
        current: list[DNSRecordOp] = []
        for i in range(0, len(ids), _CLAIM_CHUNK):
            current.extend(
                (
                    await s.execute(
                        select(DNSRecordOp)
                        .where(
                            DNSRecordOp.id.in_(ids[i : i + _CLAIM_CHUNK]),
                            DNSRecordOp.state == "in_flight",
                            DNSRecordOp.updated_at == claimed_at,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
        if len(current) < len(ids):
            # The lease ran out and the sweep took the row back (or it was
            # purged with its zone): its outcome is no longer ours to write.
            # A replay of the same RRset is idempotent.
            logger.warning(
                "agentless_dispatch_outcome_dropped",
                server=str(server.id),
                dropped=len(ids) - len(current),
            )
        failures: list[tuple[DNSRecordOp, str]] = []
        applied = 0
        for row in current:
            if row.id in unreplayable:
                # No record payload to send (a DNSSEC signal op reaching an
                # agentless primary): it can never apply, so say so once.
                row.state = "failed"
                row.last_error = "op carries no replayable record payload for an agentless driver"
                row.next_attempt_at = None
                row.updated_at = now
                continue
            error = errors.get(row.id, "dispatch produced no result")
            if error is None:
                _mark_applied(row, now)
                applied += 1
            else:
                failures.append((row, error))
        if failures:
            await fail_attempts(s, failures, now=now)
            # The request's own audit row was committed before the provider
            # was called, so a provider refusal gets its own (#1539) — the
            # failure is never visible only in a log line.
            for row, message in failures:
                rec = row.record or {}
                s.add(
                    AuditLog(
                        user_display_name="<system>",
                        auth_source="system",
                        action="agentless_push_failed",
                        resource_type="dns_record_op",
                        resource_id=str(row.id),
                        resource_display=(
                            f"{row.op} {rec.get('type')} {rec.get('name')}.{row.zone_name}"
                        )[:500],
                        result="error",
                        error_detail=message,
                        new_value={"state": row.state, "attempts": row.attempts},
                    )
                )
        await s.commit()
    if applied or failures:
        logger.info(
            "record_op_applied_agentless",
            server=str(server.id),
            driver=server.driver,
            applied=applied,
            failed=len(failures),
        )
    return {r.id: r for r in current}


# #1932 — a zone SpatiumDDI auto-creates (a subnet's reverse zone, from IPAM
# create / auto-sync / DDNS) has to reach an agentless group's provider before
# any record op for it can. ``DNSZone.agentless_create_due_at`` records that the
# create is outstanding: set in the creating transaction, cleared once every
# agentless server of the group holds the zone. It is the ONLY thing that makes
# SpatiumDDI create a zone outside a zone endpoint, so a zone that reached the
# provider once is never re-created behind the operator's back — deleting it
# there is a deliberate act, which Sync with Servers and the drift report also
# leave alone.
#: Retry interval for an outstanding provider create, on the sweep path.
AGENTLESS_ZONE_CREATE_RETRY = timedelta(minutes=5)
#: Zone creates run inline from one commit; the rest are the sweep's. A
#: /17 subnet auto-creates 128 reverse zones (#1840), and the request that
#: created them waits on its own after-commit dispatch.
AGENTLESS_INLINE_ZONE_CREATES = 16
#: Zone creates per retry-sweep tick (one provider call per zone and server;
#: Route 53 throttles its API at a few requests per second per account).
AGENTLESS_SWEEP_ZONE_CREATES = 32


async def _create_zone_at_provider(server: DNSServer, zone: DNSZone) -> str | None:
    """Create ``zone`` on one agentless server. Returns None when the zone is
    there afterwards, else the error. Never raises: callers are past a commit.

    A provider that already holds a zone of this name counts as present —
    whether the driver adopts it (an empty Technitium zone, a Route 53 zone
    from this row's own earlier attempt) or refuses to adopt it
    (``CloudDNSConflictError``): either way the record ops have a zone to
    write into, and a foreign zone is the operator's to resolve."""
    from app.drivers.dns._cloud_base import CloudDNSConflictError  # noqa: PLC0415

    try:
        driver = get_driver(server.driver)
        if not hasattr(driver, "apply_zone_change"):
            return None
        await driver.apply_zone_change(server, zone, "create")
    except CloudDNSConflictError as exc:
        logger.info(
            "dns.zone.provision_agentless_exists",
            server=str(server.id),
            zone=zone.name,
            detail=str(exc)[:500],
        )
        return None
    except Exception as exc:  # noqa: BLE001 — post-commit; retried
        logger.warning(
            "dns.zone.provision_agentless_failed",
            server=str(server.id),
            zone=zone.name,
            error=str(exc)[:500],
        )
        return str(exc)[:500] or exc.__class__.__name__
    return None


async def _agentless_zone_targets(s: AsyncSession, group_id: uuid.UUID) -> list[DNSServer]:
    """The group's agentless servers with credentials, enabled or not."""
    servers = (
        (
            await s.execute(
                select(DNSServer).where(
                    DNSServer.group_id == group_id,
                    DNSServer.credentials_encrypted.isnot(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return [srv for srv in servers if is_agentless(srv.driver)]


async def _ensure_zone_at_provider(bind: Any, zone_id: uuid.UUID) -> dict[uuid.UUID, str | None]:
    """Create an outstanding zone on its group's enabled agentless servers.

    Does nothing unless ``agentless_create_due_at`` is set. Clears it when
    every agentless server holds the zone; otherwise pushes it back by
    :data:`AGENTLESS_ZONE_CREATE_RETRY` (a paused server counts as not yet
    holding it, so the zone follows it once it is resumed). Returns the
    per-server outcome (None = present). No connection is held across a
    provider call."""
    async with AsyncSession(bind, expire_on_commit=False) as s:
        zone = await s.get(DNSZone, zone_id)
        if zone is None or zone.deleted_at is not None or zone.agentless_create_due_at is None:
            return {}
        group_id = zone.group_id
        servers = await _agentless_zone_targets(s, group_id)
    outcomes: dict[uuid.UUID, str | None] = {}
    for server in servers:
        if server.is_enabled:
            outcomes[server.id] = await _create_zone_at_provider(server, zone)
    done = len(outcomes) == len(servers) and all(e is None for e in outcomes.values())
    async with AsyncSession(bind) as s:
        await s.execute(
            update(DNSZone)
            .where(
                DNSZone.id == zone_id,
                DNSZone.group_id == group_id,
                DNSZone.agentless_create_due_at.is_not(None),
            )
            .values(
                agentless_create_due_at=(
                    None if done else datetime.now(UTC) + AGENTLESS_ZONE_CREATE_RETRY
                )
            )
            .execution_options(synchronize_session=False)
        )
        await s.commit()
    return outcomes


async def provision_zone_at_agentless_servers(db: AsyncSession, zone: DNSZone) -> bool:
    """Have a zone this transaction auto-created reach its group's agentless
    servers (#1932). Returns whether a provider create was queued.

    The zone endpoints push synchronously (the router's
    ``_push_zone_to_agentless_servers``) and fail the request on a provider
    error. An auto-created reverse zone is a side effect of a larger
    transaction that must not fail over a provider, so the zone is marked
    (``agentless_create_due_at``) and the create runs after the commit, ahead
    of the record ops the caller enqueues next. Whatever sends one of those
    ops — the inline dispatch or the retry sweep, in either order — creates a
    still-marked zone first, and a create that fails holds its ops back with
    that error rather than letting them fail "no such zone". Agent-managed
    groups are untouched: the bundle carries their zones.
    """
    if not await _agentless_zone_targets(db, zone.group_id):
        return False
    # The grace leaves the first attempt to the committing process, as for
    # its record ops; the sweep picks the zone up if that process dies.
    zone.agentless_create_due_at = datetime.now(UTC) + AGENTLESS_DISPATCH_GRACE
    await db.flush()
    _defer_unit(db, _AgentlessUnit(server_id=None, op_rows=[], batched=False, zone_id=zone.id))
    return True


async def _ensure_pending_zones_for_ops(
    bind: Any, server: DNSServer, zone_names: Collection[str]
) -> dict[str, str]:
    """Create any still-outstanding zone among ``zone_names`` before its ops
    are sent. Returns ``{zone_name: error}`` for zones ``server`` still lacks."""
    async with AsyncSession(bind) as s:
        pending = (
            await s.execute(
                select(DNSZone.id, DNSZone.name).where(
                    DNSZone.group_id == server.group_id,
                    DNSZone.name.in_(sorted(set(zone_names))),
                    DNSZone.agentless_create_due_at.is_not(None),
                )
            )
        ).all()
    blocked: dict[str, str] = {}
    for zone_id, name in pending:
        outcomes = await _ensure_zone_at_provider(bind, zone_id)
        error = outcomes.get(server.id)
        if error is not None:
            blocked[name] = error
    return blocked


async def provision_pending_agentless_zones(
    bind: Any, *, now: datetime | None = None, limit: int = AGENTLESS_SWEEP_ZONE_CREATES
) -> int:
    """Sweep half of #1932: create the outstanding zones whose retry is due
    (a failed create, more inline creates than one commit runs, or a process
    that died before its dispatch). Returns how many zones it tried."""
    now = now or datetime.now(UTC)
    async with AsyncSession(bind) as s:
        due = (
            (
                await s.execute(
                    select(DNSZone.id)
                    .where(
                        DNSZone.agentless_create_due_at.is_not(None),
                        DNSZone.agentless_create_due_at <= now,
                    )
                    .order_by(DNSZone.agentless_create_due_at)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
    for zone_id in due:
        await _ensure_zone_at_provider(bind, zone_id)
    return len(due)


def _merge_units(units: list[_AgentlessUnit]) -> list[_AgentlessUnit]:
    """Fold adjacent single-op units for one server into one, keeping queue
    order — an IPAM sync of N addresses is N ``enqueue_record_op`` calls and
    must not cost 2N short sessions."""
    merged: list[_AgentlessUnit] = []
    for unit in units:
        last = merged[-1] if merged else None
        if (
            last is not None
            and unit.zone_id is None
            and last.zone_id is None
            and not unit.batched
            and not last.batched
            and last.server_id == unit.server_id
        ):
            last.op_rows.extend(unit.op_rows)
        else:
            merged.append(
                _AgentlessUnit(
                    server_id=unit.server_id,
                    op_rows=list(unit.op_rows),
                    batched=unit.batched,
                    zone_id=unit.zone_id,
                )
            )
    return merged


async def _dispatch_agentless_units(bind: Any, units: list[_AgentlessUnit]) -> None:
    """Claim and send the agentless op rows a committed transaction queued."""
    targets = {r.id: r for u in units for r in u.op_rows}
    zone_creates = 0
    for unit in _merge_units(units):
        if unit.zone_id is not None:
            # Past the cap, the zone stays marked: the dispatch of its own ops
            # (below, or the sweep's) or the sweep's zone pass creates it.
            if zone_creates < AGENTLESS_INLINE_ZONE_CREATES:
                zone_creates += 1
                await _ensure_zone_at_provider(bind, unit.zone_id)
            continue
        if unit.server_id is None:
            continue
        claimed_at = datetime.now(UTC)
        async with AsyncSession(bind, expire_on_commit=False) as s:
            server = await s.get(DNSServer, unit.server_id)
            if server is None or not server.is_enabled or not is_agentless(server.driver):
                # Paused or gone meanwhile: the committed ``pending`` row is
                # the sweep's to replay (or not) once the server is back.
                continue
            rows = await _claim(s, [r.id for r in unit.op_rows], now=claimed_at)
            await s.commit()
        if not rows:
            continue  # rolled back with a savepoint, or the sweep has it
        outcomes = await _dispatch_claimed(
            bind, server, rows, batched=unit.batched, claimed_at=claimed_at
        )
        _mirror_outcomes(targets, outcomes)


def _on_after_commit(sync_session: Any) -> None:
    # Fires for a SAVEPOINT release too, while that nested transaction is
    # still the session's current one: only the outer commit counts.
    if sync_session.in_nested_transaction():
        return
    state: _DispatchState | None = sync_session.info.get(_DISPATCH_KEY)
    if state is not None:
        state.committed = True


def _on_after_transaction_end(sync_session: Any, transaction: Any) -> None:
    if transaction.parent is not None:
        return  # a savepoint or subtransaction; the root has not ended
    state: _DispatchState | None = sync_session.info.pop(_DISPATCH_KEY, None)
    if state is None or not state.committed or not state.units:
        return  # nothing queued, or the root transaction rolled back
    try:
        # Runs inside the greenlet ``AsyncSession.commit()`` spawned, after
        # the root transaction returned its connection to the pool.
        await_only(_dispatch_agentless_units(state.bind, state.units))
    except Exception as exc:  # noqa: BLE001 — the DB commit already succeeded
        # Never fail the caller over it: the rows are committed ``pending``
        # (or ``in_flight`` under a lease) and the beat sweep replays them.
        logger.warning("agentless_dispatch_after_commit_failed", error=str(exc))


def _defer_agentless(
    db: AsyncSession,
    server: DNSServer,
    op_rows: list[DNSRecordOp],
    *,
    batched: bool,
) -> None:
    """Register ``op_rows`` for dispatch once ``db``'s transaction commits."""
    _defer_unit(db, _AgentlessUnit(server_id=server.id, op_rows=op_rows, batched=batched))


def _defer_unit(db: AsyncSession, unit: _AgentlessUnit) -> None:
    sync = db.sync_session
    state: _DispatchState | None = sync.info.get(_DISPATCH_KEY)
    if state is None:
        state = _DispatchState(bind=db.bind)
        sync.info[_DISPATCH_KEY] = state
        if not sync.info.get(_LISTENING_KEY):
            sync.info[_LISTENING_KEY] = True
            event.listen(sync, "after_commit", _on_after_commit)
            event.listen(sync, "after_transaction_end", _on_after_transaction_end)
    state.units.append(unit)


async def _apply_agentless(
    db: AsyncSession,
    server: DNSServer,
    zone: DNSZone,
    op: str,
    record: dict[str, Any],
    target_serial: int | None,
) -> DNSRecordOp:
    """Queue a record op for an agentless server's driver.

    Writes a ``pending`` DNSRecordOp row inside the caller's transaction and
    registers it for dispatch AFTER that transaction commits (#1539): a commit
    that fails leaves the provider untouched. The post-commit dispatch marks
    the row ``applied``, or reschedules it with backoff on a provider error
    (#1538) — visible in the record-ops dashboard and replayed by the beat
    sweep, never dropped.

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
        await stamp_rrsets_for_ops(db, zone, [{"op": op, "record": record}], agentless=True)

    op_row = DNSRecordOp(
        server_id=server.id,
        zone_id=zone.id,
        zone_name=zone.name,
        op=op,
        record=record,
        target_serial=target_serial,
        state="pending",
        next_attempt_at=datetime.now(UTC) + AGENTLESS_DISPATCH_GRACE,
    )
    db.add(op_row)
    await db.flush()
    # #1539 — the provider is called after the commit, never before it.
    _defer_agentless(db, server, [op_row], batched=False)
    return op_row


# #1800 — drivers whose A/AAAA delete also deletes the matching PTR.
# Technitium's web API (``WebServiceZonesApi.DeleteRecord``, v15.4.0) looks up
# the reverse zone for the address on the same server and deletes the PTR whose
# target is the deleted record's owner; no parameter turns that off. (``add``
# with ``overwrite=true`` and ``update`` do NOT do it, so a value change that
# rides an ``update`` op is already safe.)
PTR_CLEANUP_DRIVERS: frozenset[str] = frozenset({"technitium", "technitium_api"})


def _is_address_delete(op: Any, record: Any) -> bool:
    return (
        op == "delete"
        and isinstance(record, dict)
        and (record.get("type") or "").upper() in ("A", "AAAA")
    )


def _qualified_owner(zone: DNSZone, name: str) -> str:
    zone_name = zone.name.rstrip(".").lower()
    name = (name or "@").rstrip(".").lower()
    return zone_name if name == "@" else f"{name}.{zone_name}"


async def _ptr_delete_queued_last(db: AsyncSession, zone_name: str, ptr_name: str) -> bool:
    """Whether the newest still-relevant op for a PTR RRset is a delete.

    "Still relevant" is queued (``pending`` / ``in_flight``) or written by THIS
    transaction (an agentless op is already ``applied`` when we look). A caller
    that queued the PTR's delete before the A's has deliberately removed it; a
    re-assert queued after would bring it back."""
    key = (zone_name, ptr_name.lower() or "@", "PTR")
    rows = (
        await db.execute(
            select(DNSRecordOp.op, DNSRecordOp.created_at, DNSRecordOp.seq)
            .where(
                DNSRecordOp.state.in_(("pending", "in_flight", "applied")),
                or_(
                    DNSRecordOp.state != "applied",
                    DNSRecordOp.created_at == func.now(),
                ),
                rrset_match_where([key]),
            )
            .order_by(DNSRecordOp.created_at.desc(), DNSRecordOp.seq.desc())
            .limit(1)
        )
    ).all()
    return bool(rows) and rows[0][0] == "delete"


async def reassert_ptrs_after_a_deletes(
    db: AsyncSession,
    zone: DNSZone,
    primary: DNSServer,
    ops: Collection[dict[str, Any]],
) -> int:
    """Queue a PTR ``create`` after every A/AAAA ``delete`` that took its PTR.

    Technitium removes the PTR with the A/AAAA (see ``PTR_CLEANUP_DRIVERS``),
    so a record-op delete silently dropped a PTR SpatiumDDI still owns until
    the next structural pass (#1800). Re-asserting from the AGENT's cached
    bundle is unsafe — a PTR delete op that ran earlier, with a bundle not yet
    re-rendered, would be resurrected — so the decision is made here, against
    the database that is the source of truth: a PTR is re-asserted only while
    its row is live and no newer delete of it is queued. The ``create`` rows are
    inserted after the delete rows (``seq``), so every server applies them in
    that order.

    Returns the number of PTR creates queued. Does nothing for other drivers.
    """
    if primary.driver not in PTR_CLEANUP_DRIVERS:
        return 0
    owners: dict[str, str] = {}  # reverse pointer (lower, no dot) -> owner fqdn
    for o in ops:
        rec = o.get("record") or {}
        if not _is_address_delete(o.get("op"), rec):
            continue
        try:
            ip = ipaddress.ip_address(str(rec.get("value") or "").strip())
        except ValueError:
            continue
        owners[ip.reverse_pointer.lower()] = _qualified_owner(zone, rec.get("name") or "@")
    if not owners:
        return 0
    rows = (
        await db.execute(
            select(DNSRecord, DNSZone)
            .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
            .where(
                DNSZone.group_id == zone.group_id,
                DNSRecord.record_type == "PTR",
                DNSRecord.deleted_at.is_(None),
                func.lower(func.rtrim(DNSRecord.fqdn, ".")).in_(list(owners)),
            )
        )
    ).all()
    by_zone: dict[uuid.UUID, tuple[DNSZone, list[dict[str, Any]]]] = {}
    for ptr, rev_zone in rows:
        owner = owners.get(ptr.fqdn.rstrip(".").lower())
        if owner is None or ptr.value.rstrip(".").lower() != owner:
            continue
        if await _ptr_delete_queued_last(db, rev_zone.name, ptr.name):
            continue
        entry = by_zone.setdefault(rev_zone.id, (rev_zone, []))
        entry[1].append(
            {
                "op": "create",
                "record": record_op_payload(ptr),
                "target_serial": bump_zone_serial(rev_zone),
            }
        )
    queued = 0
    for rev_zone, rev_ops in by_zone.values():
        await enqueue_record_ops_batch(db, rev_zone, rev_ops)
        queued += len(rev_ops)
    if queued:
        logger.info(
            "technitium_ptr_reasserted_after_delete",
            zone=zone.name,
            driver=primary.driver,
            ptrs=queued,
        )
    return queued


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
      via the driver from the control plane once the caller's
      transaction commits (#1539); the row lands ``pending`` and is then
      marked ``applied`` or rescheduled.
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

    Returns the op for the primary server (or ``None`` when nothing was
    queued: an empty group, or every eligible server disabled). A group with
    servers but no ``is_primary`` flag writes through the server the election
    would pick (#2276), never drops. Callers that need to ack
    every server's apply outcome should query ``DNSRecordOp`` directly
    by ``server_id``; the singular return preserves the prior
    contract for the typed-event audit path.
    """
    primary = await resolve_primary_server(db, zone)
    if primary is None:
        # The group has no servers at all (a group with servers but no
        # primary resolves to the election's stand-in, #2276). Nothing is
        # lost: a server added later gets the zone's records in its bundle.
        logger.info(
            "record_op_skipped_empty_group",
            zone=zone.name,
            group_id=str(zone.group_id),
            op=op,
            name=record.get("name"),
            type=record.get("type"),
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
        row = await _apply_agentless(db, primary, zone, op, record, target_serial)
        await reassert_ptrs_after_a_deletes(db, zone, primary, [{"op": op, "record": record}])
        return row

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
            zone_id=zone.id,
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
    await reassert_ptrs_after_a_deletes(db, zone, primary, [{"op": op, "record": record}])
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
    a new one can't be silently dropped from a provider push (#632).

    ``record_id`` names the row, so a delete's RRset drops exactly that row
    and not an identical twin that stays live (#1230). Drivers ignore it."""
    return {
        "record_id": str(record.id),
        "name": record.name,
        "type": record.record_type,
        "value": record.value,
        # #2073 — a TTL stored negative before the API bounded it is sent as
        # null (inherit the zone's), never as a value no server accepts.
        "ttl": servable_ttl(record.ttl),
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
    *,
    exclude_server_ids: Collection[uuid.UUID] = (),
    only_server_ids: Collection[uuid.UUID] | None = None,
) -> list[DNSRecordOp | None]:
    """Queue ``ops`` for every ENABLED agent-based server in the zone's group.

    ``exclude_server_ids`` / ``only_server_ids`` narrow that set for
    :func:`enqueue_agent_record_ops` (#2654); every other caller passes
    neither and gets the whole group.

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
    agent_servers = [
        s
        for s in agent_rows
        if not is_agentless(s.driver)
        and s.id not in exclude_server_ids
        and (only_server_ids is None or s.id in only_server_ids)
    ]
    if not agent_servers:
        if exclude_server_ids or only_server_ids is not None:
            # A narrowed fan-out with nobody left to send to is the normal
            # outcome for a one-server group, not a dropped write.
            return [None] * len(ops)
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
                zone_id=zone.id,
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


async def enqueue_agent_record_ops(
    db: AsyncSession,
    zone: DNSZone,
    ops: list[dict[str, Any]],
    *,
    exclude_server_ids: Collection[uuid.UUID] = (),
    only_server_ids: Collection[uuid.UUID] | None = None,
) -> int:
    """Queue ``ops`` for a SUBSET of the group's enabled agent servers (#2654).

    For records the control plane LEARNED from one server rather than ones an
    operator wrote: the DDNS ingest-back mirror and Sync with Server(s)
    imports. The server the record came from already holds it, so it is
    excluded; the rest of the group gets it the only way an agent ever
    receives a record in a no-views group, as a record op. Same row shape,
    RRset stamping (#773), PTR re-assert and wake as
    :func:`enqueue_record_ops_batch`.

    Agent-based groups only. An agentless primary is the single writer for
    its group and the agents in such a (mixed) group are not fed by record
    ops at all, so nothing is queued there. Returns how many of ``ops`` were
    queued (each to every targeted server); 0 when no server was targeted.
    """
    if not ops:
        return 0
    primary = await resolve_primary_server(db, zone)
    if primary is None or is_agentless(primary.driver):
        return 0
    rows = await _fanout_agent_ops(
        db,
        zone,
        primary,
        ops,
        exclude_server_ids=exclude_server_ids,
        only_server_ids=only_server_ids,
    )
    queued = sum(1 for r in rows if r is not None)
    if queued:
        await reassert_ptrs_after_a_deletes(db, zone, primary, ops)
    return queued


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
        # Empty group — see enqueue_record_op (#2276).
        logger.info(
            "record_op_batch_skipped_empty_group",
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
        batch_rows = await _apply_agentless_batch(db, primary, zone, ops)
        await reassert_ptrs_after_a_deletes(db, zone, primary, ops)
        return batch_rows

    # Agent-based: DB rows only; the agent batches at poll time. One fan-out
    # to every ENABLED agent-based server regardless of whether the designated
    # primary is disabled (#481), with the RRsets resolved for the whole batch
    # first (#773) so every op at a shared (name, type) carries the same
    # complete set whatever order the agent drains them in.
    fan_rows = await _fanout_agent_ops(db, zone, primary, ops)
    await reassert_ptrs_after_a_deletes(db, zone, primary, ops)
    return fan_rows


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
        # Empty group — see enqueue_record_op (#2276).
        logger.info(
            "record_op_bulk_dropped",
            zone=zone.name,
            group_id=str(zone.group_id),
            count=len(ops),
            reason="the zone's group has no servers",
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
        await reassert_ptrs_after_a_deletes(db, zone, primary, ops)
        return sum(1 for r in rows if r is not None)
    # Agent-based: same fan-out as the batch path — every enabled agent-based
    # server, resolved once, one add_all + flush (#481 semantics included).
    rows = await _fanout_agent_ops(db, zone, primary, ops)
    await reassert_ptrs_after_a_deletes(db, zone, primary, ops)
    return sum(1 for r in rows if r is not None)


# Ids per ``IN`` clause: asyncpg refuses a statement with more than 32 767 bind
# parameters, and a purge sweep can hand over many subnets / many records.
_RETRACT_CHUNK = 5000


async def _queue_record_deletes(
    db: AsyncSession, records: list[DNSRecord]
) -> tuple[set[uuid.UUID], int]:
    """Queue one ``delete`` op per record, per zone in one batch, and return
    ``(groups_to_wake, zones_touched)``. A record whose zone is gone or in the
    trash is skipped: a trashed zone is not served, nothing is on the wire.
    The records must still be live rows when this runs — the RRset stamp reads
    the zone's members and removes each op's own value."""
    by_zone: dict[uuid.UUID, tuple[DNSZone, list[DNSRecord]]] = {}
    for rec in records:
        zone = rec.zone
        if zone is None or zone.deleted_at is not None:
            continue  # a zone in the trash is not served: nothing on the wire
        by_zone.setdefault(zone.id, (zone, []))[1].append(rec)
    wake: set[uuid.UUID] = set()
    # #1800 — reverse zones first, so a Technitium A/AAAA delete finds its PTR's
    # delete already queued and the re-assert queues no create that delete
    # would only undo.
    for zone, recs in sorted(by_zone.values(), key=lambda zr: zr[0].kind != "reverse"):
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
    return wake, len(by_zone)


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

    wake, zones = await _queue_record_deletes(db, records)

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
        zones=zones,
    )
    return len(records), wake


async def _apply_agentless_batch(
    db: AsyncSession,
    server: DNSServer,
    zone: DNSZone,
    ops: list[dict[str, Any]],
) -> list[DNSRecordOp | None]:
    """Queue many record ops for an agentless server, applied in one driver
    call AFTER the surrounding transaction commits (#1539).

    Writes per-op ``pending`` DNSRecordOp rows; the post-commit dispatch
    marks them applied / rescheduled so the audit trail matches the agent
    path. A whole-batch exception (WinRM auth failure, PS parse error in the
    generated script) reschedules every row with the same error — per-op
    failures (a bad record type for example) only reschedule their own row.

    #783 — the whole batch is folded and stamped with its desired RRsets in
    ONE query before any row is written, exactly as the agent batch path
    does. Folding matters here for the same reason it does there: a bulk
    delete of two of three values at one name resolves both ops against the
    same pre-delete snapshot, so reconciling each in isolation would ship
    two contradictory sets and whichever landed last would reinstate a value
    the operator deleted.
    """
    ops = [{**o, "record": dict(o["record"])} for o in ops]
    await stamp_rrsets_for_ops(db, zone, ops, agentless=True)

    op_rows: list[DNSRecordOp] = []
    due = datetime.now(UTC) + AGENTLESS_DISPATCH_GRACE
    for o in ops:
        row = DNSRecordOp(
            server_id=server.id,
            zone_id=zone.id,
            zone_name=zone.name,
            op=o["op"],
            record=o["record"],
            target_serial=o.get("target_serial"),
            state="pending",
            next_attempt_at=due,
        )
        db.add(row)
        op_rows.append(row)
    await db.flush()
    # #1539 — one driver call per batch (Windows chunks inside it), made
    # after the commit rather than inside the transaction.
    _defer_agentless(db, server, op_rows, batched=True)
    return list(op_rows)


def _change_from_op_row(op_row: DNSRecordOp) -> RecordChange | None:
    """Rebuild the driver change an agentless op row describes, for replay.

    The row carries its complete desired RRset (#783), so replaying it is
    the same whole-RRset write the original attempt made. Returns ``None``
    for rows that carry no replayable record payload (the DNSSEC signal
    op has no ``value``; it is driven by zone state, not by replay).
    """
    record = op_row.record or {}
    if "name" not in record or "type" not in record or "value" not in record:
        return None
    return RecordChange(
        op=op_row.op,  # type: ignore[arg-type]
        zone_name=op_row.zone_name,
        record=RecordData(
            name=record["name"],
            record_type=record["type"],
            value=record["value"],
            ttl=record.get("ttl"),
            priority=record.get("priority"),
            weight=record.get("weight"),
            port=record.get("port"),
        ),
        target_serial=op_row.target_serial or 0,
        rrset=rrset_from_payload(record),
    )


async def apply_pending_agentless_ops(
    db: AsyncSession, *, now: datetime | None = None, limit: int = 200
) -> dict[str, int]:
    """Replay due ``pending`` agentless ops (#1538). **Commits ``db``.**

    Agentless failures go through :func:`fail_attempts`, which leaves the op
    ``pending`` with a ``next_attempt_at`` backoff — but an agentless server
    has no agent heartbeat to drain its queue, so without this sweep (run
    from a Celery beat task) the rescheduled op would sit forever. Also the
    recovery half of the after-commit ordering (#1539): an op row that
    committed ``pending`` and was never dispatched is drained here.

    Due rows are claimed (``in_flight``, under ``FOR UPDATE SKIP LOCKED``)
    and the claim committed BEFORE any provider is called, so neither a
    concurrent sweep nor an inline after-commit dispatch can send the same
    row, and no transaction is held open across a provider call. A row left
    ``in_flight`` past its lease (the dispatcher died mid-call) is counted
    as a failed attempt and returns to the retry path. Returns counts for
    the caller's log line.
    """
    now = now or datetime.now(UTC)
    counts = {"applied": 0, "rescheduled": 0, "skipped": 0, "recovered": 0}
    # #1932 — outstanding auto-created zones first, so a due op finds its
    # zone (the op dispatch would also create it, but a zone with no ops
    # yet has only this path). Own short sessions; ``db`` holds nothing yet.
    counts["zones"] = await provision_pending_agentless_zones(db.bind, now=now)

    stale = (
        (
            await db.execute(
                select(DNSRecordOp)
                .join(DNSServer, DNSServer.id == DNSRecordOp.server_id)
                .where(
                    DNSRecordOp.state == "in_flight",
                    DNSServer.driver.in_(sorted(AGENTLESS_DRIVERS)),
                    DNSRecordOp.next_attempt_at.is_not(None),
                    DNSRecordOp.next_attempt_at <= now,
                )
                .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
                .limit(limit)
                .with_for_update(of=DNSRecordOp, skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if stale:
        message = (
            "the provider dispatch did not complete within its lease "
            "(the process restarted, or the call hung); retrying"
        )
        await fail_attempts(db, [(op, message) for op in stale], now=now)
        counts["recovered"] = len(stale)
        logger.warning("agentless_record_op_lease_expired", count=len(stale))

    due = (
        await db.execute(
            select(DNSRecordOp, DNSServer)
            .join(DNSServer, DNSServer.id == DNSRecordOp.server_id)
            .where(
                DNSRecordOp.state == "pending",
                DNSServer.driver.in_(sorted(AGENTLESS_DRIVERS)),
                DNSServer.is_enabled.is_(True),
                (DNSRecordOp.next_attempt_at.is_(None)) | (DNSRecordOp.next_attempt_at <= now),
            )
            .order_by(DNSRecordOp.created_at, DNSRecordOp.seq)
            .limit(limit)
            .with_for_update(of=DNSRecordOp, skip_locked=True)
        )
    ).all()
    servers: dict[uuid.UUID, DNSServer] = {}
    for _op, server in due:
        servers[server.id] = server
    claimed_at = datetime.now(UTC)
    claimed = await _claim(db, [op.id for op, _s in due], now=claimed_at) if due else []
    if stale or claimed:
        await db.flush()
        await db.commit()
    if not claimed:
        return counts

    by_server: dict[uuid.UUID, list[DNSRecordOp]] = {}
    for op in claimed:
        by_server.setdefault(op.server_id, []).append(op)
    targets = {op.id: op for op in claimed}
    for server_id, ops in by_server.items():
        outcomes = await _dispatch_claimed(
            db.bind, servers[server_id], ops, batched=False, claimed_at=claimed_at
        )
        _mirror_outcomes(targets, outcomes)
        for row in outcomes.values():
            if row.state == "applied":
                counts["applied"] += 1
            elif row.last_error and row.last_error.startswith("op carries no replayable"):
                counts["skipped"] += 1
            else:
                counts["rescheduled"] += 1
    if counts["applied"] or counts["rescheduled"] or counts["recovered"]:
        logger.info("agentless_record_op_retry_sweep", **counts)
    return counts


async def lock_heartbeat_ops(
    db: AsyncSession, server_id: uuid.UUID, acks: Collection[dict[str, Any]], now: datetime
) -> None:
    """Lock every op a heartbeat writes — the ones it acks and the ones
    ``reset_unacknowledged_ops`` returns to the retry path — in one ascending
    statement, before the heartbeat writes the server row (#1929, the order in
    ``row_locks``). The server row used to be written first, by the autoflush
    of the heartbeat's own ``last_seen_at``, which is the reverse of the order
    a group move and the config poll take; and an op a move deleted between
    the heartbeat's read and its flush made the flush match nothing."""
    ids: list[uuid.UUID] = []
    for ack in acks:
        try:
            ids.append(uuid.UUID(str(ack.get("op_id"))))
        except ValueError:
            continue
    await lock_op_ids(
        db,
        DNSRecordOp.server_id == server_id,
        or_(
            ids_in(ids),
            and_(
                DNSRecordOp.state == "in_flight",
                DNSRecordOp.updated_at < now - IN_FLIGHT_ACK_TIMEOUT,
            ),
        ),
    )


async def apply_acks(
    db: AsyncSession, server_id: uuid.UUID, acks: Collection[dict[str, Any]]
) -> None:
    """Record an agent's verdicts on its ops (#1232). One load, one batched
    successor lookup, however many acks.

    Only this server's ops: an ack for another server's op is ignored, where
    it used to be applied to whatever op the id named.

    An ``ok`` marks the op applied from any state — a late ack for an op the
    unacknowledged-op reset already returned to ``pending`` is still true. An
    error is a failed attempt only while the op is ``in_flight`` AND the ack
    answers the current dispatch: the page stamps each op with ``dispatch``
    (its attempt count when shipped) and the agent echoes it. A late error for
    an earlier dispatch has already been counted — by the reset — and counting
    it again would spend the retry budget twice. An agent too old to echo
    ``dispatch`` is taken at its word, as before.
    """
    parsed: list[tuple[uuid.UUID, dict[str, Any]]] = []
    for ack in acks:
        try:
            parsed.append((uuid.UUID(str(ack.get("op_id"))), ack))
        except ValueError:
            continue
    if not parsed:
        return
    ops = {
        op.id: op
        for op in (
            await db.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.id.in_([i for i, _ in parsed]),
                    DNSRecordOp.server_id == server_id,
                )
            )
        )
        .scalars()
        .all()
    }
    now = datetime.now(UTC)
    failures: dict[uuid.UUID, tuple[DNSRecordOp, str]] = {}
    retried_deletes: list[DNSRecordOp] = []
    for op_id, ack in parsed:
        op = ops.get(op_id)
        if op is None:
            continue
        dispatch = ack.get("dispatch")
        current = not isinstance(dispatch, int) or dispatch == op.attempts
        if ack.get("result", "error") == "ok":
            if op.state != "applied":
                if op.state == "in_flight" and current:
                    op.attempts += 1
                op.state = "applied"
                op.applied_at = now
                op.last_error = None
                op.next_attempt_at = None
                op.updated_at = now
                failures.pop(op_id, None)
                if op.attempts > 1 and _is_address_delete(op.op, op.record):
                    retried_deletes.append(op)
        elif op.state == "in_flight" and current and op_id not in failures:
            failures[op_id] = (op, str(ack.get("message") or "the agent reported an error"))
    if failures:
        await fail_attempts(db, list(failures.values()), now=now)
    await db.flush()
    if retried_deletes:
        await _reassert_after_retried_deletes(db, server_id, retried_deletes)


async def _reassert_after_retried_deletes(
    db: AsyncSession, server_id: uuid.UUID, ops: list[DNSRecordOp]
) -> None:
    """#1800 — re-assert PTRs a RETRIED A/AAAA delete took with it.

    The PTR ``create`` queued after the delete ships in the same page, and the
    agent keeps going past a failed op. So when the delete failed and the
    create applied, the delete's retry lands AFTER the create and Technitium
    removes the PTR again. The ack of that retry is the first moment we know
    it happened; queue the create once more. The same database guards apply
    (row live, target matches, no newer delete queued), so a PTR deleted in
    the meantime stays deleted."""
    server = await db.get(DNSServer, server_id)
    if server is None or server.driver not in PTR_CLEANUP_DRIVERS:
        return
    by_zone: dict[str, list[dict[str, Any]]] = {}
    for op in ops:
        by_zone.setdefault(op.zone_name.rstrip(".").lower(), []).append(
            {"op": "delete", "record": op.record}
        )
    for zone_name, zone_ops in by_zone.items():
        zone = (
            (
                await db.execute(
                    select(DNSZone).where(
                        DNSZone.group_id == server.group_id,
                        func.lower(func.rtrim(DNSZone.name, ".")) == zone_name,
                    )
                )
            )
            .scalars()
            .first()
        )
        if zone is not None:
            await reassert_ptrs_after_a_deletes(db, zone, server, zone_ops)


async def ack_op(
    db: AsyncSession,
    op_id: str,
    result: str,
    message: str | None = None,
    *,
    server_id: uuid.UUID,
) -> None:
    """One ack; see :func:`apply_acks`."""
    await apply_acks(db, server_id, [{"op_id": op_id, "result": result, "message": message}])


async def retract_trashed_subnet_records(
    db: AsyncSession, batch: Any, now: datetime, user_id: uuid.UUID | None
) -> tuple[int, set[uuid.UUID]]:
    """Withdraw the auto-generated DNS records of every subnet in a soft-delete
    ``batch`` and trash them with it (spatiumddi#1906).

    A soft-deleted subnet keeps its ``ip_address`` rows, so nothing ever took
    the A / AAAA / PTR / gateway PTR IPAM published for them out of service:
    in a reverse zone kept for a surviving sibling (#1066) or a forward zone
    the subnet only shared, they went on answering — authoritatively — for
    addresses IPAM no longer held. They are retracted through the record-op
    queue (agents and agentless primaries alike, #632) and stamped with the
    batch, so a restore brings them back and ``push_records_restore`` re-asserts
    them.

    Call AFTER ``apply_soft_delete``: records of a zone that itself rides the
    batch (the auto-created reverse zone, #1066) are already stamped and hidden
    — they are not served, and restore with their zone — so only the records
    in zones that STAY are found. Hand-made records are left alone, as on the
    permanent path (#1151). Returns ``(records_retracted, dns_group_ids)``.
    """
    subnet_ids = [row.obj.id for row in batch.rows if row.resource_type == "subnet"]
    if not subnet_ids:
        return 0, set()
    records: list[DNSRecord] = []
    for start in range(0, len(subnet_ids), _RETRACT_CHUNK):
        chunk = subnet_ids[start : start + _RETRACT_CHUNK]
        records.extend(
            (
                await db.execute(
                    select(DNSRecord)
                    .where(
                        DNSRecord.auto_generated.is_(True),
                        DNSRecord.deleted_at.is_(None),
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
    wake, _zones = await _queue_record_deletes(db, records)
    ids = [r.id for r in records]
    for start in range(0, len(ids), _RETRACT_CHUNK):
        await db.execute(
            update(DNSRecord)
            .where(DNSRecord.id.in_(ids[start : start + _RETRACT_CHUNK]))
            .values(deleted_at=now, deleted_by_user_id=user_id, deletion_batch_id=batch.batch_id)
            .execution_options(synchronize_session="evaluate")
        )
    logger.info("ipam_trashed_subnet_records_retracted", subnets=len(subnet_ids), records=len(ids))
    return len(ids), wake
