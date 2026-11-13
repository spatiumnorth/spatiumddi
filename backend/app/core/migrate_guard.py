"""Keep ``alembic upgrade`` from hanging on a lock nobody will release (#3932).

The 1.0.0 upgrade drill found an API "initialising" for over two hours: the
migration's ``ALTER TABLE`` queued behind a session the previous release's api
pod had left **idle in transaction**. The pod was gone, its database session
was not (the primary had moved, so the server never noticed the peer died), and
nothing in the stack ends such a session: ``lock_timeout`` and
``idle_in_transaction_session_timeout`` were off and the TCP keepalive default
is ~2 h 11 min. The charts and the compose file now set the server-side
backstops; this module is the migrate command's own half:

* :func:`apply_lock_timeout` makes every lock wait finish, so a blocked
  revision gives up its place in the lock queue (``55P03``) instead of
  waiting silently with every other query on that table queued behind it;
* while a revision waits, :class:`BlockerWatcher` samples
  ``pg_blocking_pids`` of the migrating backend from a second connection;
  after each timed-out wait :func:`log_blockers` names those sessions and
  :func:`terminate_stale_idle_sessions` ends the ones among them that are
  provably abandoned (never before a wait has timed out, so a healthy
  upgrade ends nothing, and never a session that does not block it);
* ``env.py`` then retries the revision after a backoff, by default without
  limit: a migration blocked by a LEGITIMATE long holder (a ``pg_dump``
  backup holds ACCESS SHARE on every table for its whole run) waited and
  then succeeded before #3932, and must still do so. A failed migrate Job
  means an api that never starts, which is worse than a slow one.

Every knob is an environment variable so an operator can retune a single
migrate run without a new image. All of this is a no-op safety net for a
healthy install: it only acts on a session that blocks the migration and is idle in
transaction past the threshold.
"""

from __future__ import annotations

import asyncio
import os
import threading
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.engine import Connection

logger = structlog.get_logger(__name__)

LOCK_TIMEOUT_ENV = "MIGRATION_LOCK_TIMEOUT_SECONDS"
LOCK_RETRIES_ENV = "MIGRATION_LOCK_RETRIES"
STALE_IDLE_ENV = "MIGRATION_STALE_IDLE_TXN_SECONDS"
STATEMENT_TIMEOUT_ENV = "MIGRATION_STATEMENT_TIMEOUT_SECONDS"

DEFAULT_LOCK_TIMEOUT_SECONDS = 30
# 0 = no statement_timeout. Off by default (#1253): a data migration on a big
# table legitimately runs for minutes, and killing it midway on a guessed
# ceiling is worse than a slow upgrade. An operator who wants a ceiling sets
# MIGRATION_STATEMENT_TIMEOUT_SECONDS; a single revision can still tighten or
# lift it for itself with ``SET LOCAL statement_timeout``.
DEFAULT_STATEMENT_TIMEOUT_SECONDS = 0
# None = retry until the lock is granted (see the module docstring); an
# operator can bound it with MIGRATION_LOCK_RETRIES.
DEFAULT_LOCK_RETRIES: int | None = None
# Longer than any legitimate pause inside one request, shorter than a human
# notices a stuck upgrade. 0 disables the reaper.
DEFAULT_STALE_IDLE_SECONDS = 300
MAX_BACKOFF_SECONDS = 30

# SQLSTATE lock_not_available — what ``lock_timeout`` raises.
LOCK_NOT_AVAILABLE = "55P03"


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning("migrate_guard_bad_env", name=name, value=raw, using=default)
        return default


def lock_timeout_seconds() -> int:
    return _int_env(LOCK_TIMEOUT_ENV, DEFAULT_LOCK_TIMEOUT_SECONDS)


def statement_timeout_seconds() -> int:
    return _int_env(STATEMENT_TIMEOUT_ENV, DEFAULT_STATEMENT_TIMEOUT_SECONDS)


def lock_retries() -> int | None:
    """Retries after a timed-out lock wait; ``None`` means unlimited.

    Unset, empty or negative is unlimited; ``0`` gives up on the first
    timeout.
    """
    raw = os.environ.get(LOCK_RETRIES_ENV, "").strip()
    if not raw:
        return DEFAULT_LOCK_RETRIES
    try:
        value = int(raw)
    except ValueError:
        logger.warning("migrate_guard_bad_env", name=LOCK_RETRIES_ENV, value=raw, using="unlimited")
        return DEFAULT_LOCK_RETRIES
    return None if value < 0 else value


def stale_idle_seconds() -> int:
    return _int_env(STALE_IDLE_ENV, DEFAULT_STALE_IDLE_SECONDS)


def backoff_seconds(attempt: int) -> float:
    """Pause before retry ``attempt`` (1-based): 2, 4, 8, ... capped."""
    return float(min(MAX_BACKOFF_SECONDS, 2**attempt))


def is_lock_timeout(exc: BaseException | None) -> bool:
    """True when ``exc`` (or anything it wraps) is PostgreSQL's 55P03.

    SQLAlchemy wraps asyncpg's error in an adapter that re-exports
    ``sqlstate`` only sometimes, so walk ``orig`` / ``__cause__`` both.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if getattr(exc, "sqlstate", None) == LOCK_NOT_AVAILABLE:
            return True
        if getattr(exc, "pgcode", None) == LOCK_NOT_AVAILABLE:
            return True
        exc = getattr(exc, "orig", None) or exc.__cause__
    return False


def apply_lock_timeout(connection: Connection, seconds: int | None = None) -> int:
    """``SET lock_timeout`` for this session (0 leaves the server default).

    Session scope, not ``SET LOCAL``: ``env.py`` runs one transaction per
    revision and the setting has to cover all of them. A revision that sets
    its own ``SET LOCAL lock_timeout`` still wins for that transaction.
    """
    seconds = lock_timeout_seconds() if seconds is None else seconds
    if seconds > 0:
        connection.execute(text(f"SET lock_timeout = '{int(seconds)}s'"))
        connection.commit()
    return seconds


def apply_statement_timeout(connection: Connection, seconds: int | None = None) -> int:
    """``SET statement_timeout`` for this session; 0 (the default) leaves the
    server's own setting alone. Unlike ``lock_timeout`` this bounds how long a
    statement may RUN, so it is opt-in (see ``DEFAULT_STATEMENT_TIMEOUT_SECONDS``)."""
    seconds = statement_timeout_seconds() if seconds is None else seconds
    if seconds > 0:
        connection.execute(text(f"SET statement_timeout = '{int(seconds)}s'"))
        connection.commit()
    return seconds


_BLOCKERS_SQL = """
    SELECT a.pid, a.state, a.application_name, a.usename,
           EXTRACT(EPOCH FROM (now() - a.state_change))::int AS state_age_seconds,
           EXTRACT(EPOCH FROM (now() - a.xact_start))::int AS xact_age_seconds
      FROM pg_stat_activity a
     WHERE a.pid = ANY(pg_blocking_pids($1::int))
"""


class BlockerWatcher:
    """Sample ``pg_blocking_pids`` of the migrating backend while it waits.

    The wait is over by the time ``lock_timeout`` fires, so what blocks the
    migration can only be read DURING the wait, from a second connection.
    ``env.py`` runs sync code inside an asyncio ``run_sync``, so the watcher
    is a daemon thread with its own event loop and its own asyncpg
    connection. :meth:`take` returns (and clears) the sessions in the most
    recent non-empty sample of blockers, so a session that stopped blocking
    earlier in the wait is never a target. Any failure here is swallowed: with no samples the
    guard ends nothing, which is the safe direction.
    """

    def __init__(self, dsn: str, migrator_pid: int, interval: float = 2.0) -> None:
        self._dsn = dsn
        self._pid = migrator_pid
        self._interval = interval
        self._seen: dict[int, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="migrate-blocker-watch", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def take(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = sorted(self._seen.values(), key=lambda r: -(r["xact_age_seconds"] or 0))
            self._seen = {}
        return rows

    def _run(self) -> None:
        try:
            asyncio.run(self._poll())
        except Exception as exc:  # noqa: BLE001 — the watcher is advisory
            logger.warning("migrate_blocker_watch_failed", error=str(exc))

    async def _poll(self) -> None:
        import asyncpg

        conn = await asyncpg.connect(self._dsn)
        try:
            while not self._stop.is_set():
                rows = await conn.fetch(_BLOCKERS_SQL, self._pid)
                # Keep only the latest NON-empty sample: a session that blocked
                # earlier in the wait but no longer does must not be ended at the
                # next timed-out wait. An empty sample (the wait just ended) keeps
                # the last real blocker set for take().
                if rows:
                    with self._lock:
                        self._seen = {r["pid"]: dict(r) for r in rows}
                await asyncio.sleep(self._interval)
        finally:
            await conn.close()


def asyncpg_dsn(url: str) -> str:
    """A SQLAlchemy URL (``postgresql+asyncpg://``) as a plain asyncpg DSN."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


def terminate_stale_idle_sessions(
    connection: Connection, blocker_pids: list[int], min_idle_seconds: int | None = None
) -> list[dict[str, Any]]:
    """End abandoned ``idle in transaction`` sessions the migration WAITS ON.

    ``pg_terminate_backend`` is not undoable, so a pid is ended only when ALL
    hold:

    * it is in ``blocker_pids``, what ``pg_blocking_pids`` of the migrating
      backend named during the wait. A session that merely holds some lock
      (a backup's own session holds ACCESS SHARE on a few tables for the whole
      dump) blocks nothing, and ending it costs that backup its end commit;
    * ``state = 'idle in transaction'`` exactly: an ``active`` holder (a
      ``pg_dump``) is waited out, never ended;
    * ``state_change`` older than the threshold;
    * the same database and the SAME role as the migrator;
    * not the migrator's own backend.

    Each victim is logged (pid, application, age, last query).
    """
    threshold = stale_idle_seconds() if min_idle_seconds is None else min_idle_seconds
    if threshold <= 0 or not blocker_pids:
        return []
    rows = (
        connection.execute(
            text("""
                SELECT pid, application_name, client_addr::text AS client_addr,
                       EXTRACT(EPOCH FROM (now() - state_change))::int AS idle_seconds,
                       left(query, 200) AS last_query,
                       pg_terminate_backend(pid) AS terminated
                  FROM pg_stat_activity
                 WHERE pid = ANY(CAST(:pids AS int[]))
                   AND datname = current_database()
                   AND usename = current_user
                   AND pid <> pg_backend_pid()
                   AND state = 'idle in transaction'
                   AND state_change < now() - make_interval(secs => :threshold)
                """),
            {"pids": [int(p) for p in blocker_pids], "threshold": threshold},
        )
        .mappings()
        .all()
    )
    connection.commit()
    out = [dict(r) for r in rows]
    for r in out:
        logger.warning(
            "migration_terminated_stale_session",
            pid=r["pid"],
            application_name=r["application_name"],
            client_addr=r["client_addr"],
            idle_seconds=r["idle_seconds"],
            last_query=r["last_query"],
            terminated=r["terminated"],
            hint="idle in transaction past the threshold and blocking the migration",
        )
    return out


def log_blockers(blockers: list[dict[str, Any]], *, attempt: int, retries: int | None) -> None:
    if not blockers:
        logger.warning(
            "migration waiting on a lock; no blocking session was sampled",
            attempt=attempt,
            retries=retries,
        )
    for b in blockers:
        logger.warning(
            f"migration waiting on lock held by pid {b['pid']} "
            f"({b['state']}, {b['state_age_seconds']}s, {b['application_name'] or '-'})",
            pid=b["pid"],
            state=b["state"],
            state_age_seconds=b["state_age_seconds"],
            xact_age_seconds=b["xact_age_seconds"],
            application_name=b["application_name"],
            attempt=attempt,
            retries=retries,
        )
