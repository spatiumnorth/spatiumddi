"""One answer to "did a dependency fail to answer?" for the request path (#1083, #3017).

During a PostgreSQL switchover or a partition's failover the app sees a spread
of low-level errors, and every one of them means *retry shortly*, not *the
server has a bug*. They used to be classified inside ``create_app`` as a
closure, which is why the one place that read the database OUTSIDE the
exception handlers (``MaintenanceModeMiddleware``) could not reuse it and
answered 500. The classification lives here so the exception handlers, that
middleware and ``get_db``'s cleanup all agree.

It is the union of two rules that already existed, deliberately not a third
copy of either:

* the #1087 rule, unchanged: a ``TimeoutError`` / ``ConnectionError`` from
  anywhere, and SQLAlchemy's pool checkout timeout. Kept exactly as broad as
  it shipped, so nothing that answers 503 today starts answering 500;
* :func:`app.core.db_transient.is_transient_db_error` (#2177), the classifier
  the rolling upgrade and the supervisor heartbeat (#2845) already use. It is
  what covers the #3017 leftovers: a plain ``OSError`` 113 / 101
  (``EHOSTUNREACH`` / ``ENETUNREACH`` are not ``ConnectionError``
  subclasses), asyncio's ``OSError("Multiple exceptions: ...")``, a
  ``DBAPIError`` SQLAlchemy flagged as a disconnect, the old primary's
  "the database system is shutting down" (57P01) and its read-only answer
  (25006), and asyncpg's "connection is closed". It counts a plain
  ``OSError`` only when the database driver raised it, so an unreachable
  WinRM / webhook / DNS target in a route is not relabelled a database
  failover, and a disk error (``ENOSPC``, ``EIO``) never is one.

Plus one shape neither covers, ``PendingRollbackError``. SQLAlchemy raises it
when the session's CONNECTION was invalidated ("Can't reconnect until invalid
transaction is rolled back", ``engine/base.py``; the text is the same across
the 2.0.x series ``pyproject.toml`` pins), and code that swallowed the
original failure meets it on the session's next use, so it also counts when a
dependency-down error is in its context chain. The other
``PendingRollbackError`` ("transaction has been rolled back due to a previous
exception during flush", raised with no chain) stays a 500: nothing in it says
the database went away rather than our flush being wrong.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.exc import TimeoutError as SAPoolTimeoutError

from app.core.db_transient import is_transient_db_error

# The #1087 classes, answered 503 from any origin, as they have been since.
DEPENDENCY_DOWN_CLASSES = (TimeoutError, ConnectionError, SAPoolTimeoutError)

_INVALIDATED_MARKER = "can't reconnect until invalid"

_RETRY_AFTER_S = "2"
# Not "the database is down": a bare ConnectionError / TimeoutError reaching
# here can come from Redis or another dependency, so the wording names the
# likely cause without asserting it.
_DETAIL = (
    "A backend dependency did not answer in time "
    "(a database failover or restart may be in progress). Retry."
)


def _context_chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen and len(seen) < 8:
        seen.append(cur)
        cur = cur.__cause__ or cur.__context__
    return seen


def is_dependency_down(exc: BaseException) -> bool:
    """True when ``exc`` means a dependency did not answer. A group counts
    only when every leaf does."""
    if isinstance(exc, BaseExceptionGroup):
        return is_only_dependency_down(exc)
    if isinstance(exc, DEPENDENCY_DOWN_CLASSES):
        return True
    if isinstance(exc, PendingRollbackError):
        if _INVALIDATED_MARKER in str(exc).lower():
            return True
        return any(is_dependency_down(c) for c in _context_chain(exc)[1:])
    return is_transient_db_error(exc)


def is_only_dependency_down(exc: BaseException) -> bool:
    """True when ``exc``, or every leaf of it when it is a group, is
    dependency-down."""
    if not isinstance(exc, BaseExceptionGroup):
        return is_dependency_down(exc)
    # Checked on the group first: for a leaf raised inside the driver's task
    # group it is the GROUP's traceback that carries the driver frames
    # ``is_transient_db_error`` needs; a per-leaf check alone would miss it.
    if is_transient_db_error(exc):
        return True
    return bool(exc.exceptions) and all(is_only_dependency_down(e) for e in exc.exceptions)


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
