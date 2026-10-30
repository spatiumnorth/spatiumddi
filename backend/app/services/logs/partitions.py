"""Time partitioning for the agent-shipped log tables (#2185).

``dns_query_log_entry``, ``dhcp_log_entry`` and ``dns_rpz_hit`` are
``PARTITION BY RANGE (ts)``. Retention is a partition drop instead of a
mass ``DELETE``: no WAL burst, no bloat, no long autovacuum competing with
the control plane's own reads and writes.

:func:`maintain` is the whole lifecycle for one table, run by the
``maintain_log_partitions`` beat task every 15 minutes:

* **create ahead** — a partition is created as a plain table and then
  ``ATTACH``ed, which takes ``SHARE UPDATE EXCLUSIVE`` on the parent, so it
  neither waits for a long reader nor queues the agents' inserts behind it.
  (Attaching also takes ``SHARE ROW EXCLUSIVE`` on ``dns_server`` /
  ``dhcp_server`` for the foreign key, and dropping a retired partition
  ``ACCESS EXCLUSIVE``, both for milliseconds and under a short
  ``lock_timeout``: see :data:`LOCK_TIMEOUT_MS`.)
  Partitions are created from the end of the last one, so the ranges never
  overlap and a few skipped ticks change nothing.
* **retire** — a partition whose whole range is older than the retention
  window is ``DETACH ... CONCURRENTLY`` and dropped. If the concurrent
  detach times out PostgreSQL leaves the partition marked detach-pending
  and refuses to start another, so the next tick finishes it with
  ``DETACH ... FINALIZE``.
* **orphans** — a table left by a crash between the two statements of either
  step is dropped on the next tick.

There is deliberately no ``DEFAULT`` partition. Ingest drops lines outside
what the partitions cover (:func:`coverage`), counted with the lines that
are already too old, so nothing ever has to be moved out of a default
before a partition can be created, and ``DETACH ... CONCURRENTLY`` stays
available (PostgreSQL refuses it when a default partition exists).

The grain is hourly for the DNS query log while its window is
:data:`HOURLY_MAX_WINDOW` or shorter, daily above that, and daily for the
other two tables. It is decided from ``log_retention_hours`` as each new
partition is created: mixed hourly and daily ranges are fine as long as
they do not overlap, so changing the setting needs no re-partitioning.

Retention is applied at the grain of the partitions, so rows can outlive
the window by up to one partition (an hour, or a day).

Every step is idempotent, so a retried or overlapping run is harmless
(non-negotiable #9); a session advisory lock per table keeps two workers
from racing anyway.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker

from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

#: The query / activity log window when no settings row exists (the column's
#: own default is the same). Anyone wanting longer history should ship to Loki
#: or a SIEM in addition to (or instead of) the agent push.
DEFAULT_RETENTION_HOURS = 24

#: RPZ policy hits are kept far longer than raw queries (issue #699): a hit
#: is summary-shaped, and "has this host been reaching for blocked domains
#: all week" is unanswerable inside the query-log window. Matches the
#: threat rollup's retention so both age out together.
RPZ_HIT_RETENTION_DAYS = 30

#: The DNS query log uses hourly partitions while its window is this long
#: or shorter.
HOURLY_MAX_WINDOW = timedelta(hours=48)
#: How far ahead of now partitions are created. Ingest drops lines dated
#: beyond what is covered, so this is also how far an agent's clock may run
#: ahead.
HOURLY_LEAD = timedelta(hours=24)
DAILY_LEAD = timedelta(days=3)
#: A bound on one tick's DDL, in case the table was left empty for a long time.
MAX_CREATES_PER_TICK = 400

#: Namespace for the per-table session advisory lock (the table name hashes
#: into the second key).
LOCK_NAMESPACE = 0x4C4F4750  # "LOGP"
#: Every DDL statement here waits at most this long for its lock; a timeout is
#: retried by the next tick, and partitions are created a day or more ahead,
#: so a missed tick costs nothing. Kept short because of the foreign key:
#: attaching or detaching a partition takes ``SHARE ROW EXCLUSIVE`` on
#: ``dns_server`` / ``dhcp_server``, and dropping a retired one takes ``ACCESS
#: EXCLUSIVE`` there. Normally that is held for milliseconds; this bounds how
#: long the server table's writers (and, for the drop, its readers) can queue
#: behind a statement that is itself waiting.
LOCK_TIMEOUT_MS = 500

#: How long a process trusts what it read of a table's partitions.
COVERAGE_TTL_S = 30.0


@dataclass(frozen=True)
class LogTable:
    """One partitioned log table and its retention rule."""

    name: str
    #: The retention window, given ``PlatformSettings.log_retention_hours``.
    window: Callable[[int], timedelta]
    #: Whether partitions are hourly while the window is short.
    hourly_ok: bool = False

    def hourly(self, window: timedelta) -> bool:
        return self.hourly_ok and window <= HOURLY_MAX_WINDOW

    def lead(self, window: timedelta) -> timedelta:
        """How far ahead of now maintenance keeps partitions."""
        return HOURLY_LEAD if self.hourly(window) else DAILY_LEAD


DNS_QUERY_LOG = LogTable(
    "dns_query_log_entry", lambda hours: timedelta(hours=hours), hourly_ok=True
)
DHCP_LOG = LogTable("dhcp_log_entry", lambda hours: timedelta(hours=hours))
DNS_RPZ_HIT = LogTable("dns_rpz_hit", lambda _hours: timedelta(days=RPZ_HIT_RETENTION_DAYS))
LOG_TABLES: tuple[LogTable, ...] = (DNS_QUERY_LOG, DHCP_LOG, DNS_RPZ_HIT)


@dataclass(frozen=True)
class Partition:
    name: str
    lower: datetime | None
    upper: datetime | None
    detach_pending: bool = False

    @property
    def is_default(self) -> bool:
        return self.lower is None


@dataclass
class MaintenanceResult:
    table: str
    created: int = 0
    dropped: int = 0
    finalized: int = 0
    orphans_dropped: int = 0
    failed: int = 0
    skipped_locked: bool = False
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "dropped": self.dropped,
            "finalized": self.finalized,
            "orphans_dropped": self.orphans_dropped,
            "failed": self.failed,
            "skipped_locked": self.skipped_locked,
        }


# ── The catalog ────────────────────────────────────────────────────────────

#: The bounds come back as ``timestamptz`` from the database itself: the text
#: ``pg_get_expr`` prints follows the session's ``DateStyle`` and ``TimeZone``,
#: and casting it back in the same session reads it the same way, whatever
#: those are set to.
_PARTITIONS_SQL = r"""
SELECT c.relname,
       (regexp_match(b.expr, 'FROM \(''([^'']+)''\)'))[1]::timestamptz,
       (regexp_match(b.expr, 'TO \(''([^'']+)''\)'))[1]::timestamptz,
       i.inhdetachpending
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
CROSS JOIN LATERAL (SELECT pg_get_expr(c.relpartbound, c.oid) AS expr) b
WHERE i.inhparent = to_regclass(:parent)
ORDER BY c.relname
"""


async def list_partitions(conn: AsyncConnection | AsyncSession, table: str) -> list[Partition]:
    """The partitions of ``table`` as the catalog has them, detach-pending ones
    included. A default partition, or any bound that is not a plain range, has
    no ``lower`` / ``upper``."""
    rows = await conn.execute(text(_PARTITIONS_SQL), {"parent": table})
    return [
        (
            Partition(name, lower, upper, bool(pending))
            if lower is not None and upper is not None
            else Partition(name, None, None, bool(pending))
        )
        for name, lower, upper, pending in rows
    ]


# ── What ingest may store ──────────────────────────────────────────────────


@dataclass(frozen=True)
class Coverage:
    """The time range a table's attached partitions cover."""

    lower: datetime | None
    upper: datetime | None

    def contains(self, ts: datetime) -> bool:
        if self.lower is None or self.upper is None:
            return False
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return self.lower <= ts < self.upper


_coverage_cache: dict[str, tuple[float, Coverage]] = {}


def invalidate_coverage_cache() -> None:
    _coverage_cache.clear()


async def coverage(db: AsyncSession, table: LogTable) -> Coverage:
    """What ``table`` can store right now, cached for :data:`COVERAGE_TTL_S`.

    A line outside it has no partition to land in; ingest counts it with the
    lines that are already too old instead of failing the whole batch.
    """
    cached = _coverage_cache.get(table.name)
    now = time.monotonic()
    if cached is not None and now - cached[0] < COVERAGE_TTL_S:
        return cached[1]
    lowers: list[datetime] = []
    uppers: list[datetime] = []
    for p in await list_partitions(db, table.name):
        if p.lower is not None and p.upper is not None and not p.detach_pending:
            lowers.append(p.lower)
            uppers.append(p.upper)
    result = Coverage(min(lowers), max(uppers)) if lowers else Coverage(None, None)
    if not lowers:
        logger.warning("log_table_has_no_partitions", table=table.name)
    _coverage_cache[table.name] = (now, result)
    return result


# ── Maintenance ────────────────────────────────────────────────────────────


def _floor(moment: datetime, unit: timedelta) -> datetime:
    moment = moment.astimezone(UTC)
    if unit == DAY:
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.replace(minute=0, second=0, microsecond=0)


def _partition_name(table: str, lower: datetime, upper: datetime) -> str:
    """``<table>_p20261027`` for a whole day, ``<table>_p2026102713`` otherwise."""
    if upper - lower == DAY and lower == _floor(lower, DAY):
        return f"{table}_p{lower:%Y%m%d}"
    return f"{table}_p{lower:%Y%m%d%H}"


def partition_name_pattern(table: str) -> str:
    """The names :func:`_partition_name` gives ``table``'s partitions, as a regex."""
    return rf"{table}_p[0-9]{{8}}([0-9]{{2}})?"


def _orphan_pattern(table: str) -> str:
    return f"^{partition_name_pattern(table)}$"


async def _lock(conn: AsyncConnection, table: str, *, acquire: bool) -> bool:
    fn = "pg_try_advisory_lock" if acquire else "pg_advisory_unlock"
    row = await conn.execute(
        text(f"SELECT {fn}(:ns, hashtext(:t))"), {"ns": LOCK_NAMESPACE, "t": table}
    )
    return bool(row.scalar())


async def _drop_orphans(conn: AsyncConnection, table: str, result: MaintenanceResult) -> None:
    rows = await conn.execute(
        text(
            "SELECT c.relname FROM pg_class c "
            "WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind = 'r' "
            "AND NOT c.relispartition AND c.relname ~ :pattern"
        ),
        {"pattern": _orphan_pattern(table)},
    )
    for (name,) in rows.fetchall():
        try:
            await conn.exec_driver_sql(f'DROP TABLE IF EXISTS "{name}"')
        except DBAPIError as exc:
            result.failed += 1
            result.errors.append(f"drop orphan {name}: {exc.orig!r}")
            logger.warning("log_partition_orphan_drop_failed", table=table, partition=name)
        else:
            result.orphans_dropped += 1


async def _create_ahead(
    conn: AsyncConnection,
    table: LogTable,
    window: timedelta,
    now: datetime,
    result: MaintenanceResult,
) -> None:
    hourly = table.hourly(window)
    uppers = [
        p.upper
        for p in await list_partitions(conn, table.name)
        if p.upper is not None and not p.detach_pending
    ]
    start = _floor(now - window, HOUR if hourly else DAY)
    cursor = max([start, *uppers])
    target = now + table.lead(window)

    while cursor < target and result.created < MAX_CREATES_PER_TICK:
        # Daily once a day starts at midnight; the hours left over from an
        # earlier hourly grain are one partition up to the next midnight.
        upper = cursor + HOUR if hourly else _floor(cursor, DAY) + DAY
        name = _partition_name(table.name, cursor, upper)
        try:
            await conn.exec_driver_sql(f'CREATE TABLE "{name}" (LIKE "{table.name}")')
            try:
                await conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" ATTACH PARTITION "{name}" '
                    f"FOR VALUES FROM ('{cursor.isoformat()}') TO ('{upper.isoformat()}')"
                )
            except BaseException:
                with suppress(Exception):
                    await conn.exec_driver_sql(f'DROP TABLE IF EXISTS "{name}"')
                raise
        except DBAPIError as exc:
            result.failed += 1
            result.errors.append(f"create {name}: {exc.orig!r}")
            logger.warning(
                "log_partition_create_failed",
                table=table.name,
                partition=name,
                error=repr(exc.orig),
            )
            return
        result.created += 1
        cursor = upper


async def _retire(
    conn: AsyncConnection,
    table: LogTable,
    window: timedelta,
    now: datetime,
    result: MaintenanceResult,
) -> None:
    parts = await list_partitions(conn, table.name)
    # PostgreSQL refuses ``DETACH ... CONCURRENTLY`` while a default partition
    # exists. We never create one; an operator might have.
    concurrent = "" if any(p.is_default for p in parts) else " CONCURRENTLY"
    cutoff = now - window
    # A timed-out concurrent detach leaves its partition pending, and no other
    # detach can start on the table until that one is finished: so those come
    # first, and the first failure ends the pass (the next tick retries).
    todo = [(p, True) for p in parts if p.detach_pending] + [
        (p, False)
        for p in parts
        if not p.detach_pending and p.upper is not None and p.upper <= cutoff
    ]
    for p, pending in todo:
        try:
            if pending:
                await conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" DETACH PARTITION "{p.name}" FINALIZE'
                )
                result.finalized += 1
            else:
                await conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" DETACH PARTITION "{p.name}"{concurrent}'
                )
            await conn.exec_driver_sql(f'DROP TABLE "{p.name}"')
        except DBAPIError as exc:
            result.failed += 1
            result.errors.append(f"retire {p.name}: {exc.orig!r}")
            logger.warning(
                "log_partition_retire_failed",
                table=table.name,
                partition=p.name,
                error=repr(exc.orig),
            )
            return
        result.dropped += 1


async def maintain(
    conn: AsyncConnection,
    table: LogTable,
    retention_hours: int,
    *,
    now: datetime | None = None,
) -> MaintenanceResult:
    """Run one table's whole lifecycle once.

    ``conn`` must be in ``AUTOCOMMIT``: ``DETACH ... CONCURRENTLY`` cannot
    run inside a transaction block, and the advisory lock is held by this
    connection for the length of the run.
    """
    now = (now or datetime.now(UTC)).astimezone(UTC)
    window = table.window(retention_hours)
    result = MaintenanceResult(table.name)
    if not await _lock(conn, table.name, acquire=True):
        result.skipped_locked = True
        return result
    previous = (await conn.exec_driver_sql("SHOW lock_timeout")).scalar()
    try:
        await conn.exec_driver_sql(f"SET lock_timeout = {LOCK_TIMEOUT_MS}")
        # Creating comes before retiring: ingest stalls without a partition
        # to write into, while an expired one that lingers costs only space.
        await _drop_orphans(conn, table.name, result)
        await _create_ahead(conn, table, window, now, result)
        await _retire(conn, table, window, now, result)
    finally:
        # The connection may go back to a pool: leave it as it came.
        await conn.execute(
            text("SELECT set_config('lock_timeout', :v, false)"), {"v": str(previous)}
        )
        await _lock(conn, table.name, acquire=False)
        _coverage_cache.pop(table.name, None)
    return result


async def log_retention_hours(db: AsyncSession) -> int:
    """The configured query / activity log window, in hours (#2273).

    Read by the partition maintenance and by the two agent ingest endpoints,
    which skip lines already older than the window. Falls back to
    :data:`DEFAULT_RETENTION_HOURS` when no settings row exists yet.
    """
    ps = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    if ps is not None and isinstance(ps.log_retention_hours, int) and ps.log_retention_hours > 0:
        return ps.log_retention_hours
    return DEFAULT_RETENTION_HOURS


async def maintain_all(sessions: async_sessionmaker[AsyncSession]) -> dict[str, dict[str, Any]]:
    """Run :func:`maintain` for every log table, each on a session of its own.

    One table that fails (a dropped connection, a statement timeout, anything
    :func:`maintain` does not already absorb) is logged and reported, and the
    others still run.
    """
    async with sessions() as db:
        hours = await log_retention_hours(db)
    out: dict[str, dict[str, Any]] = {}
    for table in LOG_TABLES:
        try:
            async with sessions() as db:
                # ``DETACH ... CONCURRENTLY`` cannot run inside a transaction block.
                conn = await db.connection(execution_options={"isolation_level": "AUTOCOMMIT"})
                out[table.name] = (await maintain(conn, table, hours)).as_dict()
        except Exception as exc:  # noqa: BLE001 — the next table, and the next tick, still run
            logger.error("log_partitions_table_failed", table=table.name, error=repr(exc))
            out[table.name] = {"error": type(exc).__name__}
    return out


async def partition_health(db: AsyncSession, *, now: datetime | None = None) -> tuple[str, str]:
    """``ok`` / ``warn`` / ``error`` and a one-line detail, for the platform health rollup.

    ``error`` when no partition covers the present for a table: its current
    lines are being dropped at ingest. ``warn`` when what is covered ahead has
    shrunk below half of what maintenance keeps, which takes many missed ticks.
    """
    now = now or datetime.now(UTC)
    hours = await log_retention_hours(db)
    behind: list[str] = []
    short: list[str] = []
    for table in LOG_TABLES:
        covered = await coverage(db, table)
        if covered.upper is None or not covered.contains(now):
            behind.append(table.name)
        elif covered.upper - now < table.lead(table.window(hours)) / 2:
            short.append(table.name)
    if behind:
        return "error", (
            f"no partition covers the present for {', '.join(behind)}: "
            "current log lines are dropped until maintain_log_partitions runs"
        )
    if short:
        return "warn", (
            f"partitions run out soon for {', '.join(short)}: "
            "maintain_log_partitions has missed many runs"
        )
    return "ok", "partitions cover the present and the time ahead"
