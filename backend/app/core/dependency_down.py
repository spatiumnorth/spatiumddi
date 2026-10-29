"""One classifier for "the database (or another dependency) did not answer" (#1083, #3017).

During a PostgreSQL switchover or a partition's failover the app sees a spread
of low-level errors, and every one of them means *retry shortly*, not *the
server has a bug*. They used to be classified inside ``create_app`` as a
closure, which is why the one place that read the database OUTSIDE the
exception handlers (``MaintenanceModeMiddleware``) could not reuse it and
answered 500. The classification lives here so the exception handlers, that
middleware and ``get_db``'s cleanup all agree.

Membership is deliberately narrow:

* ``TimeoutError`` / ``ConnectionError`` (asyncpg's connect and command
  bounds, a refused or reset connection) and SQLAlchemy's pool checkout
  timeout;
* a plain ``OSError`` only when its ``errno`` names an unreachable network or
  host. ``EHOSTUNREACH`` (113) and ``ENETUNREACH`` (101) are NOT
  ``ConnectionError`` subclasses; a new connection to a primary on a node that
  just left the network raises exactly that. Matching by errno, never the
  whole class, keeps a disk error (``ENOSPC``, ``EIO``) a 500;
* a ``PendingRollbackError`` that SQLAlchemy raises because the session's
  CONNECTION was invalidated ("Can't reconnect until invalid transaction is
  rolled back"), or whose cause chain holds a dependency-down error. The
  other ``PendingRollbackError`` ("transaction has been rolled back due to a
  previous exception during flush") is a logic error and stays a 500.
"""

from __future__ import annotations

import errno
from typing import Any

from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.exc import TimeoutError as SAPoolTimeoutError

# Plain-OSError errnos that mean "the peer is not reachable". ETIMEDOUT and
# ECONNRESET and friends already construct TimeoutError / ConnectionError, so
# they are caught by the class check; they are listed so a hand-built or
# re-wrapped OSError(errno, ...) is treated the same.
NETWORK_UNREACHABLE_ERRNOS = frozenset(
    {
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.EHOSTDOWN,
        errno.ENETDOWN,
        errno.ETIMEDOUT,
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.EPIPE,
    }
)

DEPENDENCY_DOWN_CLASSES = (TimeoutError, ConnectionError, SAPoolTimeoutError)

_INVALIDATED_MARKER = "can't reconnect until invalid"

_RETRY_AFTER_S = "2"
_DETAIL = (
    "A backend dependency did not answer in time "
    "(database failover or restart in progress). Retry."
)


def _cause_chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen and len(seen) < 8:
        seen.append(cur)
        cur = cur.__cause__ or cur.__context__
    return seen


def is_dependency_down(exc: BaseException) -> bool:
    """True when ``exc`` (a single exception, not a group) means a dependency
    did not answer. See the module docstring for what is and is not included."""
    if isinstance(exc, DEPENDENCY_DOWN_CLASSES):
        return True
    if isinstance(exc, PendingRollbackError):
        if _INVALIDATED_MARKER in str(exc).lower():
            return True
        return any(
            is_dependency_down(c)
            for c in _cause_chain(exc)[1:]
            if not isinstance(c, ExceptionGroup)
        )
    if isinstance(exc, OSError):
        return exc.errno in NETWORK_UNREACHABLE_ERRNOS
    return False


def split_dependency_down(
    exc: BaseException,
) -> tuple[BaseException | None, BaseException | None]:
    """Split an exception (group or not) into ``(dependency_down, rest)``."""
    if isinstance(exc, BaseExceptionGroup):
        return exc.split(is_dependency_down)  # type: ignore[return-value]
    if is_dependency_down(exc):
        return exc, None
    return None, exc


def is_only_dependency_down(exc: BaseException) -> bool:
    """True when every leaf of ``exc`` is dependency-down."""
    matched, rest = split_dependency_down(exc)
    return matched is not None and rest is None


def first_leaf(exc: BaseException) -> BaseException:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def dependency_down_response(method: str, path: str, exc: BaseException, logger: Any) -> Any:
    """The 503 + ``Retry-After`` every dependency-down path answers with.

    Not captured to the diagnostics surface on purpose: the capture opens a
    database session, which during the outage is another 5 s connect timeout
    in front of the 503."""
    from fastapi.responses import JSONResponse  # noqa: PLC0415

    leaf = first_leaf(exc)
    logger.warning(
        "dependency_unavailable",
        method=method,
        path=path,
        error_class=type(leaf).__name__,
        error=str(leaf)[:200],
    )
    return JSONResponse(
        status_code=503,
        content={"detail": _DETAIL},
        headers={"Retry-After": _RETRY_AFTER_S},
    )
