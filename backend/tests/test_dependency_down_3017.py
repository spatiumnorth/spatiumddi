"""Every database-unavailable error answers 503, not 500, during a switchover (#3017).

#1083 / #1087 turned ``TimeoutError`` / ``ConnectionError`` into a 503 inside a
route. The nightly-2026.10.28 partition drill still logged 35 500s from four
places that fix did not reach: the maintenance-mode middleware's own settings
read (outside the exception handlers), a plain ``OSError`` 113 inside an
``ExceptionGroup``, ``get_db``'s cleanup after the response had started, and a
``PendingRollbackError``. Each is pinned here without a database.
"""

from __future__ import annotations

import errno
import json
from typing import Any

import pytest
from sqlalchemy.exc import InterfaceError, PendingRollbackError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core import maintenance_mode
from app.core.dependency_down import is_dependency_down, is_only_dependency_down
from app.main import app

_INVALIDATED = (
    "Can't reconnect until invalid transaction is rolled back.  "
    "Please rollback() fully before proceeding"
)
_FLUSH = (
    "This Session's transaction has been rolled back due to a previous "
    "exception during flush. To begin a new transaction with this Session, "
    "first issue Session.rollback()."
)


def _request(method: str = "GET", path: str = "/api/v1/appliance/cluster/health") -> Request:
    return Request(
        {"type": "http", "method": method, "path": path, "headers": [], "query_string": b""}
    )


def _handler_for(exc: BaseException) -> Any:
    for cls in type(exc).__mro__:
        if cls in app.exception_handlers:
            return app.exception_handlers[cls]
    raise AssertionError(f"no handler for {type(exc).__name__}")


def _assert_503(resp: Response) -> None:
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "2"
    assert "retry" in json.loads(bytes(resp.body))["detail"].lower()


def _closed_interface_error() -> InterfaceError:
    return InterfaceError(
        "ROLLBACK",
        {},
        Exception("cannot call Transaction.rollback(): the underlying connection is closed"),
    )


# ── classifier ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.EHOSTUNREACH, "No route to host"),
        OSError(errno.ENETUNREACH, "Network is unreachable"),
        OSError(errno.EHOSTDOWN, "Host is down"),
        TimeoutError("t"),
        ConnectionRefusedError(111, "Connection refused"),
        PendingRollbackError(_INVALIDATED),
    ],
)
def test_classifier_accepts(exc: BaseException) -> None:
    assert is_dependency_down(exc)


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.ENOSPC, "No space left on device"),
        OSError(errno.EIO, "I/O error"),
        FileNotFoundError(2, "nope"),
        PermissionError(13, "denied"),
        ValueError("x"),
        PendingRollbackError(_FLUSH),
    ],
)
def test_classifier_rejects(exc: BaseException) -> None:
    assert not is_dependency_down(exc)


def test_pending_rollback_with_dependency_cause_is_down() -> None:
    try:
        try:
            raise TimeoutError("ping")
        except TimeoutError as inner:
            raise PendingRollbackError(_FLUSH) from inner
    except PendingRollbackError as e:
        assert is_dependency_down(e)


def test_group_needs_every_leaf_down() -> None:
    assert is_only_dependency_down(ExceptionGroup("g", [OSError(errno.EHOSTUNREACH, "x")]))
    assert not is_only_dependency_down(
        ExceptionGroup("g", [OSError(errno.EHOSTUNREACH, "x"), ValueError("bug")])
    )


# ── exception handlers ─────────────────────────────────────────────────────


async def test_oserror_113_inside_group_answers_503() -> None:
    exc = ExceptionGroup("unhandled errors in a TaskGroup", [OSError(113, "No route to host")])
    resp = await _handler_for(exc)(_request(), exc)
    _assert_503(resp)


@pytest.mark.parametrize("code", [errno.EHOSTUNREACH, errno.ENETUNREACH])
async def test_bare_unreachable_oserror_answers_503(code: int) -> None:
    exc = OSError(code, "unreachable")
    _assert_503(await _handler_for(exc)(_request(), exc))


async def test_disk_error_is_not_swallowed_as_503() -> None:
    exc = OSError(errno.ENOSPC, "No space left on device")
    with pytest.raises(OSError):
        await _handler_for(exc)(_request(), exc)
    grp = ExceptionGroup("g", [OSError(113, "x"), OSError(errno.EIO, "io")])
    with pytest.raises(ExceptionGroup):
        await _handler_for(grp)(_request(), grp)


async def test_pending_rollback_handler() -> None:
    down = PendingRollbackError(_INVALIDATED)
    _assert_503(await _handler_for(down)(_request("POST"), down))
    bug = PendingRollbackError(_FLUSH)
    with pytest.raises(PendingRollbackError):
        await _handler_for(bug)(_request("POST"), bug)


async def test_last_resort_handler_skips_diagnostics_for_dependency_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.services.diagnostics as diag

    async def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("diagnostics capture attempted while the database is away")

    monkeypatch.setattr(diag, "record_unhandled_exception_async", boom)
    exc = ExceptionGroup("g", [ConnectionRefusedError(111, "refused")])
    _assert_503(await app.exception_handlers[Exception](_request("POST"), exc))


# ── maintenance-mode middleware ────────────────────────────────────────────


class _NullSession:
    async def __aenter__(self) -> _NullSession:
        return self

    async def __aexit__(self, *a: Any) -> None:
        return None


async def _dispatch(monkeypatch: pytest.MonkeyPatch, raised: BaseException | None) -> Response:
    import app.db as dbmod

    monkeypatch.setattr(dbmod, "AsyncSessionLocal", lambda: _NullSession())

    async def fake_state(db: Any) -> Any:
        if raised is not None:
            raise raised
        return False, "", None

    monkeypatch.setattr(maintenance_mode, "get_maintenance_state", fake_state)
    called: list[bool] = []

    async def call_next(request: Request) -> Response:
        called.append(True)
        return JSONResponse({"ok": True})

    mw = maintenance_mode.MaintenanceModeMiddleware(app)
    resp = await mw.dispatch(_request("POST", "/api/v1/dhcp/agents/heartbeat"), call_next)
    resp.called_next = bool(called)  # type: ignore[attr-defined]
    return resp


@pytest.mark.parametrize(
    "raised",
    [
        ConnectionRefusedError(111, "Connection refused"),
        TimeoutError("connect"),
        ExceptionGroup("tg", [ConnectionRefusedError(111, "Connection refused")]),
        ExceptionGroup("tg", [TimeoutError("ping")]),
        ExceptionGroup("tg", [OSError(113, "No route to host")]),
    ],
    ids=["refused", "timeout", "group-refused", "group-timeout", "group-113"],
)
async def test_maintenance_read_failure_answers_503_and_does_not_pass_through(
    monkeypatch: pytest.MonkeyPatch, raised: BaseException
) -> None:
    resp = await _dispatch(monkeypatch, raised)
    _assert_503(resp)
    # The request is NOT let through as "not in maintenance".
    assert resp.called_next is False  # type: ignore[attr-defined]


async def test_maintenance_read_real_bug_still_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError):
        await _dispatch(monkeypatch, ValueError("bug"))
    with pytest.raises(ExceptionGroup):
        await _dispatch(monkeypatch, ExceptionGroup("g", [TimeoutError("t"), ValueError("bug")]))


async def test_maintenance_read_success_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    resp = await _dispatch(monkeypatch, None)
    assert resp.status_code == 200
    assert resp.called_next is True  # type: ignore[attr-defined]


# ── get_db cleanup ─────────────────────────────────────────────────────────


class _FakeSession:
    def __init__(self, close_exc: BaseException | None) -> None:
        self.close_exc = close_exc

    async def close(self) -> None:
        if self.close_exc is not None:
            raise self.close_exc


async def _run_get_db(
    monkeypatch: pytest.MonkeyPatch,
    close_exc: BaseException | None,
    body_exc: BaseException | None = None,
) -> None:
    import app.db as dbmod

    monkeypatch.setattr(dbmod, "AsyncSessionLocal", lambda: _FakeSession(close_exc))
    gen = dbmod.get_db()
    await gen.__anext__()
    if body_exc is None:
        with pytest.raises(StopAsyncIteration):
            await gen.__anext__()
    else:
        await gen.athrow(body_exc)


@pytest.mark.parametrize(
    "close_exc",
    [_closed_interface_error(), TimeoutError("rollback"), OSError(113, "No route to host")],
    ids=["closed-connection", "timeout", "113"],
)
async def test_get_db_swallows_dependency_down_cleanup(
    monkeypatch: pytest.MonkeyPatch, close_exc: BaseException
) -> None:
    await _run_get_db(monkeypatch, close_exc)


async def test_get_db_cleanup_real_bug_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError):
        await _run_get_db(monkeypatch, ValueError("bug"))
    # An unrelated InterfaceError is not "the connection went away".
    with pytest.raises(InterfaceError):
        await _run_get_db(monkeypatch, InterfaceError("s", {}, Exception("something else")))


async def test_get_db_body_exception_still_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(KeyError):
        await _run_get_db(monkeypatch, TimeoutError("rollback"), body_exc=KeyError("route bug"))
