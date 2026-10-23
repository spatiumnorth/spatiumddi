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

import errno

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
# SQLSTATE; matched by name so this module does not import asyncpg. Not the
# plain ``InterfaceError`` base: asyncpg raises it for "another operation is in
# progress" (a session used concurrently) and its ``DataError`` subclass for an
# argument of the wrong type, both bugs; only its "connection is closed" form is
# about the connection (``_interface_error_says_closed``). Nor the plain
# ``InternalClientError``: a protocol desync is not a failover.
_ASYNCPG_CONNECTION_GONE = frozenset(
    {
        "ConnectionDoesNotExistError",
        "ConnectionFailureError",
        "CannotConnectNowError",
        "TargetServerAttributeNotMatched",
    }
)

# Modules whose frames mark an exception as raised by the database driver. A
# bare ``ConnectionError`` / ``TimeoutError`` counts only from one of these: the
# same classes come from any socket, and one that escaped a kubeapi or Redis
# call is not the database failing over. Retrying it as one would loop the
# drive through its retries and the orphan sweep for as long as the fault
# lasted, instead of failing the run with the reason.
_DB_DRIVER_MODULES = ("sqlalchemy", "asyncpg")


def _sqlstate_transient(sqlstate: object) -> bool:
    if not isinstance(sqlstate, str) or not sqlstate:
        return False
    return sqlstate in _TRANSIENT_SQLSTATES or sqlstate.startswith(_TRANSIENT_SQLSTATE_CLASSES)


def _raised_by_db_driver(exc: BaseException) -> bool:
    tb = exc.__traceback__
    while tb is not None:
        module = tb.tb_frame.f_globals.get("__name__", "")
        if isinstance(module, str) and module.startswith(_DB_DRIVER_MODULES):
            return True
        tb = tb.tb_next
    return False


# A connect to a host with several addresses that all failed: asyncio raises a
# plain ``OSError("Multiple exceptions: ...")``, not a ``ConnectionError``. And
# the errnos of a host or network a failover has briefly taken away.
_UNREACHABLE_ERRNOS = frozenset(
    {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN, errno.ENETDOWN}
)


def _socket_unreachable(exc: BaseException) -> bool:
    if not isinstance(exc, OSError) or isinstance(exc, ConnectionError):
        return False
    if exc.errno in _UNREACHABLE_ERRNOS:
        return True
    return exc.errno is None and str(exc).startswith("Multiple exceptions:")


def _interface_error_says_closed(exc: BaseException) -> bool:
    return type(exc).__name__ == "InterfaceError" and "closed" in str(exc).lower()


def _leaf_transient(exc: BaseException, *, db_origin: bool) -> bool:
    # A refused / reset connect (asyncpg raises these bare, untranslated by
    # SQLAlchemy) and asyncpg's connect / command timeout (a bare TimeoutError),
    # when the driver raised them (see ``_DB_DRIVER_MODULES``).
    if isinstance(exc, SAPoolTimeoutError):
        return True
    if isinstance(exc, (ConnectionError, TimeoutError)) or _socket_unreachable(exc):
        return db_origin or _raised_by_db_driver(exc)
    if isinstance(exc, DBAPIError):
        if exc.connection_invalidated:
            return True
        if _sqlstate_transient(getattr(exc.orig, "sqlstate", None)):
            return True
        # The adapter re-exports ``sqlstate`` but the asyncpg error itself
        # hangs off ``__cause__`` (#922).
        cause = exc.orig.__cause__ if exc.orig is not None else None
        if cause is not None:
            if _sqlstate_transient(getattr(cause, "sqlstate", None)):
                return True
            if type(cause).__name__ in _ASYNCPG_CONNECTION_GONE:
                return True
            if isinstance(cause, (ConnectionError, TimeoutError)):
                return True
            return _interface_error_says_closed(cause)
        # No driver error behind it: SQLAlchemy's own "connection is closed".
        return isinstance(exc, SAInterfaceError) and "closed" in str(exc.orig or exc).lower()
    if type(exc).__module__.startswith("asyncpg"):
        if _sqlstate_transient(getattr(exc, "sqlstate", None)):
            return True
        return type(exc).__name__ in _ASYNCPG_CONNECTION_GONE or _interface_error_says_closed(exc)
    return False


def is_transient_db_error(exc: BaseException) -> bool:
    """Whether ``exc`` says the database was unreachable, not that it refused.

    An ``ExceptionGroup`` (SQLAlchemy's asyncpg adapter can wrap a pre-ping
    timeout in one) is transient only when every leaf is. A bare
    ``ConnectionError`` / ``TimeoutError`` is transient only when the database
    driver raised it: from a kubeapi or Redis call it is not a failover.
    """
    return _transient(exc, db_origin=False)


def _transient(exc: BaseException, *, db_origin: bool) -> bool:
    if isinstance(exc, BaseExceptionGroup):
        inner = db_origin or _raised_by_db_driver(exc)
        return bool(exc.exceptions) and all(_transient(e, db_origin=inner) for e in exc.exceptions)
    return _leaf_transient(exc, db_origin=db_origin)


__all__ = ["is_transient_db_error"]
