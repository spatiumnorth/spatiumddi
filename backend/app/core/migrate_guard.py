"""Keep ``alembic upgrade`` from hanging on a lock nobody will release (#3932).

The 1.0.0 upgrade drill found an API "initialising" for over two hours: the
migration's ``ALTER TABLE`` queued behind a session the previous release's api
pod had left **idle in transaction**. The pod was gone, its database session
was not (the primary had moved, so the server never noticed the peer died), and
nothing in the stack ends such a session: ``lock_timeout`` and
``idle_in_transaction_session_timeout`` were off and the TCP keepalive default
is ~2 h 11 min. The charts and the compose file now set the server-side
backstops; this module is the migrate command's own half:

* :func:`terminate_stale_idle_sessions` ends the sessions that are provably
  abandoned, before the first ``ALTER``;
* :func:`apply_lock_timeout` makes every lock wait finish, so a blocked
  migration fails fast (``55P03``) instead of waiting silently;
* :func:`blocker_report` says who is probably holding the lock, and
  ``env.py`` retries a bounded number of times, re-running the reaper (a
  session's idle age only grows) with a backoff.

Every knob is an environment variable so an operator can retune a single
migrate run without a new image. All of this is a no-op safety net for a
healthy install: it only acts on a session that is idle in transaction past
the threshold.
"""

from __future__ import annotations

import os
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.engine import Connection

logger = structlog.get_logger(__name__)

LOCK_TIMEOUT_ENV = "MIGRATION_LOCK_TIMEOUT_SECONDS"
LOCK_RETRIES_ENV = "MIGRATION_LOCK_RETRIES"
STALE_IDLE_ENV = "MIGRATION_STALE_IDLE_TXN_SECONDS"

DEFAULT_LOCK_TIMEOUT_SECONDS = 30
DEFAULT_LOCK_RETRIES = 10
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


def lock_retries() -> int:
    return _int_env(LOCK_RETRIES_ENV, DEFAULT_LOCK_RETRIES)


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


def terminate_stale_idle_sessions(
    connection: Connection, min_idle_seconds: int | None = None
) -> list[dict[str, Any]]:
    """End abandoned ``idle in transaction`` sessions of THIS role (#3932).

    Deliberately narrow, because ``pg_terminate_backend`` is not undoable:

    * ``state = 'idle in transaction'`` exactly: not ``active`` (working),
      not plain ``idle`` (holds nothing), not ``idle in transaction (aborted)``
      (already rolled back, holds no lock);
    * the same database and the SAME role as the migrator, so another
      application's sessions, a DBA's psql and the replication / CNPG
      management roles are never touched;
    * ``state_change`` older than the threshold, so a transaction a live
      request is between two statements of is left alone;
    * never the migrator's own backend.

    Each victim is logged (pid, application, age, last query) before the
    result is returned.
    """
    threshold = stale_idle_seconds() if min_idle_seconds is None else min_idle_seconds
    if threshold <= 0:
        return []
    rows = (
        connection.execute(
            text("""
                SELECT pid, application_name, client_addr::text AS client_addr,
                       EXTRACT(EPOCH FROM (now() - state_change))::int AS idle_seconds,
                       left(query, 200) AS last_query,
                       pg_terminate_backend(pid) AS terminated
                  FROM pg_stat_activity
                 WHERE datname = current_database()
                   AND usename = current_user
                   AND pid <> pg_backend_pid()
                   AND state = 'idle in transaction'
                   AND state_change < now() - make_interval(secs => :threshold)
                """),
            {"threshold": threshold},
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
            hint="idle in transaction past the threshold; its lock would block the migration",
        )
    return out


def blocker_report(connection: Connection) -> list[dict[str, Any]]:
    """Other sessions in this database that hold a lock inside an open
    transaction, i.e. the likely reason a lock wait just timed out.

    The wait is over by the time this runs, so ``pg_blocking_pids`` has
    nothing left to say; list the lock holders instead, oldest first.
    """
    rows = connection.execute(text("""
                SELECT a.pid, a.state, a.application_name, a.usename,
                       EXTRACT(EPOCH FROM (now() - a.state_change))::int AS state_age_seconds,
                       EXTRACT(EPOCH FROM (now() - a.xact_start))::int AS xact_age_seconds
                  FROM pg_stat_activity a
                 WHERE a.datname = current_database()
                   AND a.pid <> pg_backend_pid()
                   AND a.xact_start IS NOT NULL
                   AND EXISTS (SELECT 1 FROM pg_locks l
                                WHERE l.pid = a.pid AND l.granted
                                  AND l.locktype IN ('relation', 'transactionid'))
                 ORDER BY a.xact_start
                """)).mappings().all()
    connection.commit()
    return [dict(r) for r in rows]


def log_blockers(blockers: list[dict[str, Any]], *, attempt: int, retries: int) -> None:
    if not blockers:
        logger.warning(
            "migration waiting on a lock; no other open transaction found",
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
