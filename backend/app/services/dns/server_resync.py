"""Force an agent-based DNS server to re-render every zone (#2281).

A disabled server is skipped by the record-op fan-out
(``record_ops.enqueue_record_op``) and by the bundle worker, while its agent
keeps polling and its daemon keeps serving the config it last applied. When
the server is enabled again the next bundle carries the current records, but
in a group without views records are not part of the structural etag, and
the agent re-renders zone files only when that etag moves. There are no ops
to drain either. So every record created, changed or deleted while the
server was off stayed missing or wrong on it until some unrelated structural
change or an agent restart.

``force_zone_resync`` closes that: it bumps ``DNSServer.zone_resync_seq``,
which ``agent_config`` folds into the structural fingerprint, so the next
bundle makes the agent render every zone from the records in the body. The
record ops still queued from before the server was disabled are retired with
it: each carries a whole RRset as it was when queued (#773), and shipped
after the re-render it would put back a record deleted while the server was
off. The re-render delivers the current state of every one of them.

**Dynamic zones wait for the ingest report first (#2654).** The re-render
replaces each zone with the DATABASE's copy. A record an RFC 2136 writer
added on the server while it was disabled is not in the database yet: the
server's ingest reports are ignored while it is disabled, and only its first
report after the re-enable can mirror it (comparing against the snapshot it
left behind when it was disabled). Forced at once, the re-render landed a
second or two after the re-enable, minutes before that report, and the
record was gone from the daemon before anything had read it.

So ``resync_after_reenable`` retires the queued ops at once, as before, but
for a server whose agent reads dynamic zones back (BIND9 / PowerDNS) in a
group that has any, it only RECORDS that a re-render is owed
(``zone_resync_pending_since``). ``complete_deferred_resync`` — called by the
ingest endpoint — bumps the seq once that server has reported every dynamic
zone of its group since then, so the re-render's database copy already holds
what the server learned. ``force_overdue_resyncs`` (the 60 s agent stale
sweep) bumps it after ``RESYNC_INGEST_WAIT`` regardless, so a server whose
reports never arrive (a broken transfer, an agent without ``dig``) still
catches up, just later.

The trade-off: until the re-render, the re-enabled server still serves what
it held when it was disabled for records the ingest does not cover —
managed-record changes and non-dynamic zones — for up to one ingest interval
(180 s) rather than one poll. Changes made after the re-enable reach it as
ordinary record ops meanwhile, and in dynamic zones the ingest itself queues
per-value corrections for what it lacks or still holds.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import is_agentless
from app.models.dns import DNSIngestSnapshot, DNSServer, DNSZone
from app.services.dns.agent_config import retire_queued_ops

# Drivers whose agent runs the ingest read-back (``agent/dns`` supervisor:
# BIND9 via loopback AXFR, PowerDNS via its REST API). Technitium has none.
INGEST_DRIVERS = frozenset({"bind9", "powerdns"})

# How long a re-enabled server's re-render waits for its ingest reports: two
# 180 s sweeps plus the agent's 30 s start delay and the transfer time of a
# sweep over many zones. Past it the re-render goes ahead without them.
RESYNC_INGEST_WAIT = timedelta(minutes=7)


async def force_zone_resync(db: AsyncSession, server: DNSServer) -> int:
    """Make ``server``'s next bundle re-render every zone. Returns the number
    of queued record ops retired. A no-op for an agentless server, whose
    writes go straight to the daemon and which has no bundle."""
    if is_agentless(server.driver):
        return 0
    _bump(server)
    return await retire_queued_ops(db, server)


def _bump(server: DNSServer) -> None:
    server.zone_resync_seq = (server.zone_resync_seq or 0) + 1
    server.zone_resync_pending_since = None


def _dynamic_zones_query(group_id: uuid.UUID) -> Any:
    """Names of the group's zones the agent's ingest sweep reads back: the
    same filter the agent applies to its bundle (``IngestWorker``)."""
    return select(DNSZone.name).where(
        DNSZone.group_id == group_id,
        DNSZone.deleted_at.is_(None),
        DNSZone.dynamic_update_enabled.is_(True),
        DNSZone.zone_type == "primary",
    )


async def resync_after_reenable(db: AsyncSession, server: DNSServer) -> int:
    """The #2281 re-render for a server being enabled again; see the module
    docstring for why it may wait for the server's ingest reports. Returns
    the number of queued record ops retired."""
    if is_agentless(server.driver):
        return 0
    retired = await retire_queued_ops(db, server)
    has_dynamic = (
        server.driver in INGEST_DRIVERS
        and (await db.execute(_dynamic_zones_query(server.group_id).limit(1))).first() is not None
    )
    if has_dynamic:
        server.zone_resync_pending_since = datetime.now(UTC)
    else:
        _bump(server)
    return retired


async def complete_deferred_resync(db: AsyncSession, server: DNSServer) -> bool:
    """Bump ``server``'s owed re-render once it has reported every dynamic
    zone of its group since it was re-enabled. Returns True when it bumped.
    Called after an ingest report is reconciled, in the same transaction, so
    the bundle that re-renders already holds what that report mirrored."""
    since = server.zone_resync_pending_since
    if since is None or not server.is_enabled:
        return False
    expected = {
        str(n).rstrip(".").lower()
        for n in (await db.execute(_dynamic_zones_query(server.group_id))).scalars()
    }
    reported = {
        str(n).rstrip(".").lower()
        for n in (
            await db.execute(
                select(DNSZone.name)
                .join(DNSIngestSnapshot, DNSIngestSnapshot.zone_id == DNSZone.id)
                .where(
                    DNSIngestSnapshot.server_id == server.id,
                    DNSIngestSnapshot.reported_at >= since,
                )
            )
        ).scalars()
    }
    if not expected <= reported:
        return False
    _bump(server)
    return True


async def force_overdue_resyncs(db: AsyncSession) -> list[DNSServer]:
    """Bump every owed re-render older than ``RESYNC_INGEST_WAIT``. Returns
    the servers bumped (the caller commits and wakes them). Idempotent."""
    cutoff = datetime.now(UTC) - RESYNC_INGEST_WAIT
    rows = (
        (
            await db.execute(
                select(DNSServer).where(
                    DNSServer.zone_resync_pending_since.is_not(None),
                    DNSServer.zone_resync_pending_since < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    for server in rows:
        _bump(server)
    if rows:
        await db.flush()
    return list(rows)
