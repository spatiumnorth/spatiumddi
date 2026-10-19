"""Tell a database that is briefly unreachable from a real failure (#2177).

A CloudNativePG failover closes every connection the old primary held, and
for the seconds until the new primary listens a fresh connect is refused.
Code that waits through it (the rolling upgrade's drive) has to tell that
apart from a bug: the first is retried, the second must still fail at once.

Transient here means "the connection, not the statement": the connect was
refused or timed out, the connection closed under the statement, or the
server said it is shutting down, starting up or no longer the primary. A
statement the database rejected (a constraint, a syntax error, a missing
row) is never transient, whatever the connection's state.
"""

from __future__ import annotations

from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import InterfaceError as SAInterfaceError
from sqlalchemy.exc import TimeoutError as SAPoolTimeoutError

# SQLSTATEs a server sends while it cannot serve the connection: class 08
# (connection exception), admin / crash shutdown and "cannot connect now"
# (57P01-57P03), and a read-only transaction, which is what a demoted primary
# answers a write with until its connections are closed.
_TRANSIENT_SQLSTATES = frozenset({"57P01", "57P02", "57P03", "25006"})
_TRANSIENT_SQLSTATE_CLASSES = ("08",)

# asyncpg's client-side errors for a connection that is gone. They carry no
# SQLSTATE; matched by name so this module does not import asyncpg.
_ASYNCPG_CONNECTION_GONE = frozenset(
    {
        "ConnectionDoesNotExistError",
        "ConnectionFailureError",
        "CannotConnectNowError",
        "InterfaceError",
        "InternalClientError",
    }
)


def _sqlstate_transient(sqlstate: object) -> bool:
    if not isinstance(sqlstate, str) or not sqlstate:
        return False
    return sqlstate in _TRANSIENT_SQLSTATES or sqlstate.startswith(_TRANSIENT_SQLSTATE_CLASSES)


def _leaf_transient(exc: BaseException) -> bool:
    # A refused / reset connect (asyncpg raises these bare, untranslated by
    # SQLAlchemy) and asyncpg's connect / command timeout (a bare TimeoutError).
    if isinstance(exc, (ConnectionError, TimeoutError, SAPoolTimeoutError)):
        return True
    if isinstance(exc, DBAPIError):
        if exc.connection_invalidated:
            return True
        if _sqlstate_transient(getattr(exc.orig, "sqlstate", None)):
            return True
        # The adapter re-exports ``sqlstate`` but the asyncpg error itself
        # hangs off ``__cause__`` (#922).
        cause = exc.orig.__cause__ if exc.orig is not None else None
        if cause is not None and _sqlstate_transient(getattr(cause, "sqlstate", None)):
            return True
        if cause is not None and type(cause).__name__ in _ASYNCPG_CONNECTION_GONE:
            return True
        # An interface error is about the connection, never the statement.
        return isinstance(exc, SAInterfaceError)
    if type(exc).__module__.startswith("asyncpg"):
        if _sqlstate_transient(getattr(exc, "sqlstate", None)):
            return True
        return type(exc).__name__ in _ASYNCPG_CONNECTION_GONE
    return False


def is_transient_db_error(exc: BaseException) -> bool:
    """Whether ``exc`` says the database was unreachable, not that it refused.

    An ``ExceptionGroup`` (SQLAlchemy's asyncpg adapter can wrap a pre-ping
    timeout in one) is transient only when every leaf is.
    """
    if isinstance(exc, BaseExceptionGroup):
        return bool(exc.exceptions) and all(is_transient_db_error(e) for e in exc.exceptions)
    return _leaf_transient(exc)


__all__ = ["is_transient_db_error"]
