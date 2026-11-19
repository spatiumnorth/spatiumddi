"""A rolling upgrade's drive rides out a Postgres failover (#2177).

Found by ddi-pg's drill of #1918: the CNPG primary's node went NotReady while
the drive was in that node's ``stage`` step. The step's next read raised
``InterfaceError``, which the chain recorded as the step crashing; the run-row
writes after it met ``ConnectionRefusedError``, Celery's two retries both
landed within a second, and the drive died holding its Lease. Nothing drove
the run for 10 min, until the Lease expired and the orphan sweep re-drove it.

* A step that loses its connection is retried in place after a rollback,
  within a budget, so the node carries on; the commit of the slot stamp is
  part of its step.
* Only connection errors retry; anything else still fails at once.
* A drive that loses the database outside a step releases its own Lease, does
  not mark the run failed, and is retried on an explicit countdown.
* The crash handler releases the Lease even when it cannot write the row.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.exc import DBAPIError, IntegrityError, InterfaceError, ProgrammingError

from app.core.db_transient import is_transient_db_error
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import mutex, per_node

TARGET = "2026.10.19-900"


def _raised_in(module: str, exc: BaseException) -> BaseException:
    """``exc`` as raised by code in ``module``: its traceback carries a frame
    of that module, which is how the classifier tells the database driver's
    bare socket errors from anyone else's."""
    ns: dict[str, Any] = {"__name__": module, "exc": exc}
    try:
        exec("def _raise():\n    raise exc\n_raise()", ns)  # noqa: S102 — test helper
    except Exception as caught:  # every exception these tests raise is an Exception
        return caught
    raise AssertionError("unreachable")


def _refused() -> BaseException:
    """What asyncpg's connect raises, bare, through SQLAlchemy's pool."""
    return _raised_in(
        "sqlalchemy.pool.base",
        ConnectionRefusedError(111, "Connect call failed ('postgres-rw', 5432)"),
    )


class _AsyncpgError(Exception):
    """Stands in for an asyncpg exception class, matched by name."""


def _asyncpg(name: str, msg: str) -> BaseException:
    cls = type(name, (_AsyncpgError,), {"__module__": "asyncpg.exceptions"})
    return cls(msg)


def _wrapped(cls: type[DBAPIError], cause: BaseException) -> DBAPIError:
    """A SQLAlchemy error over the adapter's error, raised ``from`` asyncpg's,
    the shape SQLAlchemy's asyncpg dialect produces."""
    orig = _Orig(str(cause))
    orig.__cause__ = cause
    return cls("SELECT 1", {}, orig)


class _Orig(Exception):
    def __init__(self, msg: str, sqlstate: str | None = None) -> None:
        super().__init__(msg)
        self.sqlstate = sqlstate


# ── The classifier ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc",
    [
        _refused(),
        _raised_in("asyncpg.connect_utils", ConnectionResetError(104, "reset")),
        _raised_in("asyncpg.connect_utils", TimeoutError()),
        _raised_in(
            "asyncpg.connect_utils",
            OSError("Multiple exceptions: [Errno 111] Connect call failed, [Errno 99] ..."),
        ),
        _raised_in("asyncpg.connect_utils", OSError(113, "No route to host")),
        InterfaceError("SELECT 1", {}, _Orig("connection is closed")),
        _wrapped(InterfaceError, _asyncpg("ConnectionDoesNotExistError", "closed mid-op")),
        _wrapped(InterfaceError, _asyncpg("InterfaceError", "connection is closed")),
        _asyncpg("ConnectionDoesNotExistError", "connection was closed"),
        DBAPIError("SELECT 1", {}, _Orig("gone"), connection_invalidated=True),
        DBAPIError("SELECT 1", {}, _Orig("terminating connection", "57P01")),
        DBAPIError("SELECT 1", {}, _Orig("connection failure", "08006")),
        DBAPIError("UPDATE x", {}, _Orig("read-only transaction", "25006")),
        _raised_in("sqlalchemy.pool.base", ExceptionGroup("pre-ping", [TimeoutError()])),
    ],
)
def test_a_connection_error_is_transient(exc: BaseException) -> None:
    assert is_transient_db_error(exc) is True


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("bad step name"),
        RuntimeError("loop crashed"),
        KeyError("node_order"),
        IntegrityError("INSERT", {}, _Orig("null value", "23502")),
        ProgrammingError("SELECT", {}, _Orig("syntax error", "42601")),
        ExceptionGroup("mixed", [TimeoutError(), ValueError("bug")]),
        # The same socket errors from anything but the database driver: a
        # kubeapi or Redis call that failed is not a failover (#2177 review).
        ConnectionRefusedError(111, "refused"),
        _raised_in("app.services.appliance.k8s", ConnectionResetError(104, "reset")),
        _raised_in("redis.connection", TimeoutError()),
        _raised_in("app.services.appliance.k8s", OSError(113, "No route to host")),
        _raised_in("asyncpg.connect_utils", PermissionError(13, "denied")),
        ExceptionGroup("not the driver", [TimeoutError()]),
        # asyncpg's InterfaceError family carries statement bugs too.
        _wrapped(InterfaceError, _asyncpg("DataError", "invalid input for query argument $1")),
        _wrapped(
            InterfaceError,
            _asyncpg(
                "InterfaceError", "cannot perform operation: another operation is in progress"
            ),
        ),
        _asyncpg("InterfaceError", "cannot perform operation: another operation is in progress"),
    ],
)
def test_a_real_error_is_not_transient(exc: BaseException) -> None:
    assert is_transient_db_error(exc) is False


# ── In a step: retried in place ──────────────────────────────────────────────


def _db() -> Any:
    db = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.flush = AsyncMock()
    return db


def _chain_stubs(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[str],
    raises: dict[str, list[BaseException]],
) -> None:
    """Every step records its name; ``raises[name]`` is raised by that step's
    successive calls, in order, before it succeeds."""

    def _step(name: str) -> Any:
        async def _run(*_a: Any, **_k: Any) -> per_node.StepResult:
            calls.append(name)
            pending = raises.get(name) or []
            if pending:
                raise pending.pop(0)
            return per_node.StepResult(name=name, started_at="t").finish(True)  # type: ignore[arg-type]

        return _run

    for name in per_node.CHAIN:
        monkeypatch.setattr(per_node, f"_step_{name}", _step(name))


@pytest.fixture
def fake_clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """The retry's sleep advances a fake clock instead of waiting."""
    slept: list[float] = []
    now = [1000.0]

    async def _sleep(delay: float) -> None:
        slept.append(delay)
        now[0] += delay

    monkeypatch.setattr(per_node, "_db_retry_sleep", _sleep, raising=False)
    monkeypatch.setattr(per_node, "_db_retry_clock", lambda: now[0], raising=False)
    return slept


async def _chain(db: Any) -> per_node.SingleNodeResult:
    return await per_node.single_node_upgrade(
        db,
        node_name="ddipg-member-1",
        target_version=TARGET,
        slot_image=SlotImageTarget(url="https://node/slot.raw.xz"),
        cnpg_cluster_name="pg-cluster",
    )


@pytest.mark.asyncio
async def test_refused_connections_across_a_step_boundary_do_not_end_the_node(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    """The repro: ``stage`` loses its connection, the database refuses for a
    while, and the read that ends the stage before the node leaves service
    meets the same outage. The node carries on and completes."""
    calls: list[str] = []
    _chain_stubs(
        monkeypatch,
        calls,
        {
            "stage": [
                InterfaceError("SELECT", {}, _Orig("connection is closed")),
                _refused(),
                _refused(),
            ]
        },
    )
    db = _db()
    commits: list[BaseException | None] = [None, _refused()]  # trigger ok, end-of-stage lost

    async def _commit() -> None:
        if commits:
            nxt = commits.pop(0)
            if nxt is not None:
                raise nxt

    db.commit = AsyncMock(side_effect=_commit)

    result = await _chain(db)

    assert result.ok is True, result.error
    assert calls.count("stage") == 4
    # Each step ran to completion exactly once in the recorded results.
    assert [s.name for s in result.steps].count("stage") == 1
    assert all(s.ok for s in result.steps)
    assert calls[-1] == "cluster_verify"
    assert fake_clock == [1.0, 2.0, 4.0]
    # Rolled back before each retry, and once for the lost end-of-stage commit.
    assert db.rollback.await_count == 4


@pytest.mark.asyncio
async def test_a_slot_stamp_lost_with_its_commit_is_stamped_again(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {})
    db = _db()
    commits: list[BaseException | None] = [_refused()]

    async def _commit() -> None:
        if commits:
            nxt = commits.pop(0)
            if nxt is not None:
                raise nxt

    db.commit = AsyncMock(side_effect=_commit)

    result = await _chain(db)

    assert result.ok is True, result.error
    # The rollback discarded the stamp, so the step ran again to re-stamp it.
    assert calls.count("trigger_slot_apply") == 2
    assert calls.index("stage") > len(calls) - calls[::-1].index("trigger_slot_apply") - 1
    assert fake_clock == [1.0]


@pytest.mark.asyncio
async def test_a_real_error_in_a_step_fails_it_at_once(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {"stage": [ValueError("bad appliance row")]})

    result = await _chain(_db())

    assert result.ok is False
    assert result.failed_at == "stage"
    assert result.error and "bad appliance row" in result.error
    assert calls.count("stage") == 1
    assert fake_clock == []
    assert "cordon" not in calls


@pytest.mark.asyncio
async def test_a_database_down_past_the_budget_fails_the_step(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {"stage": [_refused() for _ in range(50)]})

    result = await _chain(_db())

    assert result.ok is False
    assert result.failed_at == "stage"
    assert result.error and "database unreachable" in result.error
    # Bounded: the waits fit inside the budget, and the step stopped there.
    assert sum(fake_clock) <= per_node.DB_FAILOVER_BUDGET_S
    assert sum(fake_clock) >= per_node.DB_FAILOVER_BUDGET_S - 15.0
    assert calls.count("stage") == len(fake_clock) + 1
    assert "cordon" not in calls


# ── Outside a step: the drive releases its Lease and is retried ──────────────


def _session_with(db: Any) -> Any:
    @asynccontextmanager
    async def _session() -> Any:
        yield db

    return _session


@pytest.mark.asyncio
async def test_a_drive_that_loses_the_database_releases_its_lease_and_does_not_fail_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task

    used: list[str | None] = []
    released: list[str | None] = []

    async def _drive(
        _db: Any, _rid: Any, *, holder: str | None = None, avoid_version: str | None = None
    ) -> Any:
        used.append(holder)
        raise _refused()

    db = SimpleNamespace(rollback=AsyncMock(), execute=AsyncMock(), commit=AsyncMock())
    monkeypatch.setattr(task, "task_session", _session_with(db))
    monkeypatch.setattr(task, "drive_upgrade", _drive)
    monkeypatch.setattr(
        mutex, "release_if_held", lambda **kw: released.append(kw.get("holder")) or True
    )

    with pytest.raises(task.DriveDatabaseUnavailable):
        await task._async_drive(str(uuid.uuid4()))

    assert used and released == used
    # The row is not touched: an outage is not the upgrade failing.
    db.execute.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_crash_handler_releases_the_lease_when_it_cannot_write_the_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task

    used: list[str | None] = []
    released: list[str | None] = []

    async def _drive(
        _db: Any, _rid: Any, *, holder: str | None = None, avoid_version: str | None = None
    ) -> Any:
        used.append(holder)
        raise RuntimeError("loop crashed")

    db = SimpleNamespace(
        rollback=AsyncMock(), execute=AsyncMock(side_effect=_refused()), commit=AsyncMock()
    )
    monkeypatch.setattr(task, "task_session", _session_with(db))
    monkeypatch.setattr(task, "drive_upgrade", _drive)
    monkeypatch.setattr(
        mutex, "release_if_held", lambda **kw: released.append(kw.get("holder")) or True
    )

    with pytest.raises(task.DriveDatabaseUnavailable):
        await task._async_drive(str(uuid.uuid4()))

    assert used and used[0] in released


@pytest.mark.asyncio
async def test_a_real_crash_still_fails_the_run_and_releases_the_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task

    used: list[str | None] = []
    released: list[str | None] = []
    row = SimpleNamespace(state="running", lease_holder=None, last_error=None, finished_at=None)

    async def _drive(
        _db: Any, _rid: Any, *, holder: str | None = None, avoid_version: str | None = None
    ) -> Any:
        used.append(holder)
        row.lease_holder = holder
        raise KeyError("node_order")

    db = SimpleNamespace(
        rollback=AsyncMock(),
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: row)),
        commit=AsyncMock(),
    )
    monkeypatch.setattr(task, "task_session", _session_with(db))
    monkeypatch.setattr(task, "drive_upgrade", _drive)
    monkeypatch.setattr(
        mutex, "release_if_held", lambda **kw: released.append(kw.get("holder")) or True
    )

    out = await task._async_drive(str(uuid.uuid4()))

    assert out["state"] == "failed"
    assert row.state == "failed"
    assert row.last_error and "node_order" in row.last_error
    assert released == used


def test_the_task_retries_a_lost_database_on_its_own_countdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task

    monkeypatch.delenv("NODE_NAME", raising=False)
    retried: list[dict[str, Any]] = []

    class _Retry(Exception):
        pass

    def _retry(**kw: Any) -> Exception:
        retried.append(kw)
        return _Retry()

    async def _drive(_rid: str, *, avoid_version: str | None = None) -> dict[str, str]:
        raise task.DriveDatabaseUnavailable("ConnectionRefusedError: refused")

    monkeypatch.setattr(task, "_async_drive", _drive)
    monkeypatch.setattr(task.drive_upgrade_run, "retry", _retry)

    for attempt, countdown in enumerate(task._DB_RETRY_COUNTDOWNS_S):
        task.drive_upgrade_run.push_request(retries=attempt)
        try:
            with pytest.raises(_Retry):
                task.drive_upgrade_run.run("run-1")
        finally:
            task.drive_upgrade_run.pop_request()
        assert retried[-1]["countdown"] == countdown

    # Together the waits cover a CNPG failover, not a second of one.
    assert sum(task._DB_RETRY_COUNTDOWNS_S) >= 60

    # Spent: the error surfaces (the Lease is already free for the sweep).
    task.drive_upgrade_run.push_request(retries=len(task._DB_RETRY_COUNTDOWNS_S))
    try:
        with pytest.raises(task.DriveDatabaseUnavailable):
            task.drive_upgrade_run.run("run-1")
    finally:
        task.drive_upgrade_run.pop_request()
    assert len(retried) == len(task._DB_RETRY_COUNTDOWNS_S)


def test_the_task_no_longer_autoretries_every_database_error() -> None:
    """Celery's ``autoretry_for`` retried after ~1 s of jitter, twice; a real
    error must not be retried at all, and a lost database is retried by the
    task itself on ``_DB_RETRY_COUNTDOWNS_S``."""
    from app.tasks import upgrade_orchestrator as task

    assert not getattr(task.drive_upgrade_run, "autoretry_for", ())
    assert task.drive_upgrade_run.max_retries == len(task._DB_RETRY_COUNTDOWNS_S)


# ── Review: what a re-run must not do (#2177) ───────────────────────────────


@pytest.mark.asyncio
async def test_a_socket_error_from_a_kubeapi_step_is_not_retried_as_a_failover(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    """A cordon that raised a bare socket error may already have cordoned the
    node; run again it would read the node as cordoned before the upgrade and
    leave it cordoned on a later failure (#1542). Only the database driver's
    socket errors are a failover."""
    calls: list[str] = []
    _chain_stubs(
        monkeypatch,
        calls,
        {"cordon": [_raised_in("app.services.appliance.k8s", TimeoutError("timed out"))]},
    )
    monkeypatch.setattr(
        per_node,
        "_step_release_node",
        AsyncMock(
            return_value=per_node.StepResult(name="release_node", started_at="t").finish(True)
        ),
    )

    result = await _chain(_db())

    assert result.ok is False
    assert result.failed_at == "cordon"
    assert calls.count("cordon") == 1
    assert fake_clock == []


@pytest.mark.asyncio
async def test_a_stamp_whose_commit_landed_but_was_not_acknowledged_stays_fresh(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    """The first commit reached the database and only its acknowledgement was
    lost: the retry finds its own stamp already on the row (``fresh_stamp``
    False). It is still this run's stamp, so the waits that follow judge the
    host against the first attempt's time, not as a re-driven node's would
    (no ``stamped_at``), which counts a ``done`` or ``failed`` left from an
    earlier attempt as this one's (#1449)."""
    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {})
    fresh = [True, False]

    async def _trigger(*_a: Any, **_k: Any) -> per_node.StepResult:
        calls.append("trigger_slot_apply")
        return per_node.StepResult(name="trigger_slot_apply", started_at="t").finish(
            True, fresh_stamp=fresh.pop(0)
        )

    seen: dict[str, Any] = {}

    def _wait(name: str) -> Any:
        async def _run(*_a: Any, stamped_at: Any = None, **_k: Any) -> per_node.StepResult:
            calls.append(name)
            seen[name] = stamped_at
            return per_node.StepResult(name=name, started_at="t").finish(True)  # type: ignore[arg-type]

        return _run

    monkeypatch.setattr(per_node, "_step_trigger_slot_apply", _trigger)
    for name in ("stage", "reboot", "health_gate"):
        monkeypatch.setattr(per_node, f"_step_{name}", _wait(name))
    db = _db()
    commits: list[BaseException | None] = [_refused()]

    async def _commit() -> None:
        if commits:
            raise commits.pop(0)  # type: ignore[misc]

    db.commit = AsyncMock(side_effect=_commit)

    result = await _chain(db)

    assert result.ok is True, result.error
    assert calls.count("trigger_slot_apply") == 2
    trigger = next(s for s in result.steps if s.name == "trigger_slot_apply")
    assert trigger.detail.get("fresh_stamp") is True
    assert trigger.detail.get("stamp_commit_ack_lost") is True
    assert seen["stage"] is not None
    assert seen["stage"] == seen["reboot"] == seen["health_gate"]


@pytest.mark.asyncio
async def test_a_long_step_rides_out_a_second_failover_with_its_own_budget(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    """A wait step (stage, health gate) runs for many minutes. A failover
    twenty minutes after the first must not fail it because the first one
    spent the budget; but the restarts are capped."""
    now = {"t": 0.0}

    def _clock() -> float:
        return 5000.0 + sum(fake_clock) + now["t"]

    monkeypatch.setattr(per_node, "_db_retry_clock", _clock)
    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {})
    # Each attempt: serve for 20 min, then lose the connection. Then a few
    # quick refusals while the new primary comes up.
    script: list[str] = ["long", "quick", "long", "quick", "ok"]

    async def _health_gate(*_a: Any, **_k: Any) -> per_node.StepResult:
        calls.append("health_gate")
        what = script.pop(0)
        if what == "long":
            now["t"] += 1200.0
            raise _refused()
        if what == "quick":
            raise _refused()
        return per_node.StepResult(name="health_gate", started_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_health_gate", _health_gate)

    result = await _chain(_db())

    assert result.ok is True, result.error
    assert calls.count("health_gate") == 5


@pytest.mark.asyncio
async def test_repeated_failovers_in_one_step_are_capped(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    now = {"t": 0.0}
    monkeypatch.setattr(per_node, "_db_retry_clock", lambda: sum(fake_clock) + now["t"])
    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {})
    monkeypatch.setattr(
        per_node,
        "_step_release_node",
        AsyncMock(
            return_value=per_node.StepResult(name="release_node", started_at="t").finish(True)
        ),
    )

    async def _health_gate(*_a: Any, **_k: Any) -> per_node.StepResult:
        calls.append("health_gate")
        now["t"] += 1200.0
        raise _refused()

    monkeypatch.setattr(per_node, "_step_health_gate", _health_gate)

    result = await _chain(_db())

    assert result.ok is False
    assert result.failed_at == "health_gate"
    assert calls.count("health_gate") == per_node._DB_MAX_OUTAGES_PER_STEP + 1
    assert result.error and "database lost" in result.error


@pytest.mark.asyncio
async def test_a_bare_socket_error_from_outside_the_database_fails_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Classified as a lost database it would be retried five times, handed
    to the orphan sweep and re-driven every ten minutes for as long as the
    fault lasted, with the run reading ``running`` throughout. It is a crash:
    the run fails with the reason."""
    from app.tasks import upgrade_orchestrator as task

    used: list[str | None] = []
    released: list[str | None] = []
    row = SimpleNamespace(state="running", lease_holder=None, last_error=None, finished_at=None)

    async def _drive(
        _db: Any, _rid: Any, *, holder: str | None = None, avoid_version: str | None = None
    ) -> Any:
        used.append(holder)
        row.lease_holder = holder
        raise _raised_in("app.services.appliance.k8s", ConnectionRefusedError(111, "kubeapi"))

    db = SimpleNamespace(
        rollback=AsyncMock(),
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: row)),
        commit=AsyncMock(),
    )
    monkeypatch.setattr(task, "task_session", _session_with(db))
    monkeypatch.setattr(task, "drive_upgrade", _drive)
    monkeypatch.setattr(
        mutex, "release_if_held", lambda **kw: released.append(kw.get("holder")) or True
    )

    out = await task._async_drive(str(uuid.uuid4()))

    assert out["state"] == "failed"
    assert row.state == "failed"
    assert released == used


# ── The second live sighting, with the real driver (#2177) ───────────────────
#
# 18:40:51Z: the CNPG primary's node went NotReady in its own ``stage`` step.
# The step's commit raised SQLAlchemy's ``InterfaceError`` over asyncpg's
# "cannot call Transaction.commit(): the underlying connection is closed",
# then every reconnect raised a bare ``ConnectionRefusedError`` until the new
# primary listened. The classifier has to accept both as raised by the real
# driver stack, not as hand-built stand-ins.

_SIGHTING_COMMIT_MSG = "cannot call Transaction.commit(): the underlying connection is closed"


@pytest.mark.asyncio
async def test_a_refused_connect_from_the_real_driver_is_transient() -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    # Port 1 on loopback: nothing listens, so the connect is refused.
    engine = create_async_engine(
        "postgresql+asyncpg://u:p@127.0.0.1:1/x", connect_args={"timeout": 5}
    )
    try:
        with pytest.raises(BaseException) as caught:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
    finally:
        await engine.dispose()
    exc = caught.value
    assert isinstance(exc, OSError), repr(exc)
    assert is_transient_db_error(exc) is True, repr(exc)


@pytest.mark.asyncio
async def test_a_commit_on_a_connection_the_server_closed_is_transient() -> None:
    """The sighting's first error, produced for real: the server ends the
    backend under an open transaction (as a failover does), then the commit."""
    import asyncio
    import os

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    # The conftest points DATABASE_URL at this worker's own test database.
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("needs a database")
    engine = create_async_engine(url, pool_pre_ping=False)
    killer = create_async_engine(url)
    try:
        conn = await engine.connect()
        await conn.begin()
        pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        async with killer.connect() as k:
            await k.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
        await asyncio.sleep(0.5)  # let asyncpg see the socket close
        with pytest.raises(BaseException) as caught:
            await conn.commit()
        exc = caught.value
        assert is_transient_db_error(exc) is True, repr(exc)
        await conn.invalidate()
    finally:
        await engine.dispose()
        await killer.dispose()


def test_the_sightings_exact_commit_error_is_transient() -> None:
    """The exact shape logged at 18:40:51.102Z: SQLAlchemy's asyncpg dialect
    ``InterfaceError`` over asyncpg's ``_base.InterfaceError``."""
    asyncpg_exc = pytest.importorskip("asyncpg.exceptions._base")
    from sqlalchemy.dialects.postgresql.asyncpg import AsyncAdapt_asyncpg_dbapi

    cause = asyncpg_exc.InterfaceError(_SIGHTING_COMMIT_MSG)
    adapted = AsyncAdapt_asyncpg_dbapi.InterfaceError(f"{type(cause)}: {cause}")
    adapted.__cause__ = cause
    exc = InterfaceError("COMMIT", {}, adapted)
    assert is_transient_db_error(exc) is True


@pytest.mark.asyncio
async def test_the_second_sighting_rides_out_in_place_without_restarting_the_node(
    monkeypatch: pytest.MonkeyPatch, fake_clock: list[float]
) -> None:
    """The chain end to end: ``stage`` loses its commit, the reconnects are
    refused while CNPG promotes, then the database is back. The step is
    retried in place; nothing before it runs again (the re-drive used to
    restart the node from ``preflight``) and the node completes."""
    asyncpg_exc = pytest.importorskip("asyncpg.exceptions._base")
    from sqlalchemy.dialects.postgresql.asyncpg import AsyncAdapt_asyncpg_dbapi

    cause = asyncpg_exc.InterfaceError(_SIGHTING_COMMIT_MSG)
    adapted = AsyncAdapt_asyncpg_dbapi.InterfaceError(f"{type(cause)}: {cause}")
    adapted.__cause__ = cause
    lost_commit = InterfaceError("COMMIT", {}, adapted)

    calls: list[str] = []
    _chain_stubs(monkeypatch, calls, {"stage": [lost_commit, _refused(), _refused()]})

    result = await _chain(_db())

    assert result.ok is True, result.error
    assert calls.count("stage") == 4
    for before in ("preflight", "etcd_snapshot", "mirror_ready", "trigger_slot_apply"):
        assert calls.count(before) == 1, before
    assert calls[-1] == "cluster_verify"
    assert [s.name for s in result.steps].count("stage") == 1
    assert sum(fake_clock) < per_node.DB_FAILOVER_BUDGET_S
