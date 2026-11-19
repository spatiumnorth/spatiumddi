"""A heartbeat whose database fails over under it answers 503 (#2845).

A CNPG switchover drops the connection under whichever statement is in
flight. On a long-polling heartbeat that is most often the re-read of the
row after the hold, a minute after the telemetry commit. It used to escape
as a 500 (on older code, a ``MissingGreenlet`` from a log line reading the
row the failed refresh's rollback had expired). The database being briefly
away is not a bug and not a revocation: the endpoint answers 503 with
``Retry-After`` and no ``X-Spatium-Revocation``, which the supervisor logs
as a server error and retries without counting a strike.

The failure is injected at the driver boundary: the first statement after
the hold raises the asyncpg error a switchover produces. A stand-in
``wake_subscription`` arms it and wakes, so each case takes milliseconds.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import asyncpg
import pytest
from httpx import AsyncClient
from sqlalchemy import event
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.core.agent_wake import WakeResult
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services.appliance.ca import generate_session_token
from tests.conftest import _test_engine

_HEARTBEAT = "/api/v1/appliance/supervisor/heartbeat"
_HEADER = "X-Spatium-Revocation"


@pytest.fixture(autouse=True)
def _no_failure_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


class _Fault:
    """Raises ``exc`` from the first statement executed once armed."""

    def __init__(self) -> None:
        self.exc: BaseException | None = None
        self.armed = False
        self.fired = 0

    def __call__(self, *_args: Any, **_kwargs: Any) -> None:
        if self.armed and self.exc is not None:
            self.armed = False
            self.fired += 1
            raise self.exc


@pytest.fixture
def fault() -> Iterator[_Fault]:
    f = _Fault()
    event.listen(_test_engine.sync_engine, "before_cursor_execute", f)
    try:
        yield f
    finally:
        event.remove(_test_engine.sync_engine, "before_cursor_execute", f)


def _hold_arming(monkeypatch: pytest.MonkeyPatch, fault: _Fault, exc: BaseException) -> None:
    """The hold's first wait arms ``fault`` and wakes: the next statement,
    the post-hold re-read, fails with ``exc``."""

    class _Sub:
        async def wait(self, _timeout: float) -> WakeResult:
            fault.exc = exc
            fault.armed = True
            return WakeResult.WAKE

    @asynccontextmanager
    async def _fake(_channels: Any) -> AsyncIterator[_Sub]:
        yield _Sub()

    monkeypatch.setattr(supervisor_mod, "wake_subscription", _fake)


async def _approved(db: AsyncSession) -> tuple[uuid.UUID, str]:
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="switchover-node",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.commit()
    return row.id, token


async def _held_heartbeat(client: AsyncClient, appliance_id: uuid.UUID, token: str) -> Any:
    return await client.post(
        _HEARTBEAT,
        json={"appliance_id": str(appliance_id), "session_token": token, "wait_seconds": 5},
    )


@pytest.mark.parametrize(
    "exc",
    [
        # What the old primary sends its sessions as it shuts down (57P01).
        # The generic connection-closed handler in main.py matches on
        # message text and does not recognise it, so this was a 500.
        pytest.param(
            asyncpg.exceptions.AdminShutdownError(
                "terminating connection due to administrator command"
            ),
            id="admin-shutdown",
        ),
        # The same, as SQLAlchemy's asyncpg adapter hands it up: a DBAPI
        # error whose driver error carries the SQLSTATE.
        pytest.param(
            OperationalError(
                "SELECT appliance.id FROM appliance",
                {},
                asyncpg.exceptions.AdminShutdownError(
                    "terminating connection due to administrator command"
                ),
            ),
            id="admin-shutdown-wrapped",
        ),
        pytest.param(
            asyncpg.exceptions.ConnectionDoesNotExistError(
                "connection was closed in the middle of operation"
            ),
            id="connection-gone",
        ),
        # A demoted primary answers a write with this until it drops its
        # connections (25006).
        pytest.param(
            asyncpg.exceptions.ReadOnlySQLTransactionError(
                "cannot execute UPDATE in a read-only transaction"
            ),
            id="read-only",
        ),
    ],
)
async def test_a_switchover_after_the_hold_answers_503(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    fault: _Fault,
    exc: BaseException,
) -> None:
    """REGRESSION (#2845): escaped as a 500 (MissingGreenlet on older code)."""
    appliance_id, token = await _approved(db_session)
    _hold_arming(monkeypatch, fault, exc)

    r = await _held_heartbeat(client, appliance_id, token)

    assert fault.fired == 1
    assert r.status_code == 503, r.text
    assert r.headers.get("Retry-After") == "1"
    # Never a revocation: the supervisor would count a strike.
    assert _HEADER not in r.headers


async def test_a_bug_after_the_hold_is_still_not_a_503(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    fault: _Fault,
) -> None:
    """A statement the database REFUSED is not the database being away: it
    must not be laundered into a retryable 503."""
    appliance_id, token = await _approved(db_session)
    _hold_arming(
        monkeypatch,
        fault,
        asyncpg.exceptions.UndefinedColumnError('column "nope" does not exist'),
    )

    with pytest.raises(asyncpg.exceptions.UndefinedColumnError):
        await _held_heartbeat(client, appliance_id, token)
    assert fault.fired == 1


async def test_the_heartbeat_recovers_once_the_database_is_back(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    fault: _Fault,
) -> None:
    """The 503 left nothing behind: the supervisor's next heartbeat is a 200."""
    appliance_id, token = await _approved(db_session)
    _hold_arming(
        monkeypatch,
        fault,
        asyncpg.exceptions.AdminShutdownError("terminating connection"),
    )
    assert (await _held_heartbeat(client, appliance_id, token)).status_code == 503
    # In production each request gets its own session (``get_db``); the test
    # client shares one, so end the failed request's transaction by hand.
    await db_session.rollback()

    r = await client.post(
        _HEARTBEAT,
        json={"appliance_id": str(appliance_id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == APPLIANCE_STATE_APPROVED
