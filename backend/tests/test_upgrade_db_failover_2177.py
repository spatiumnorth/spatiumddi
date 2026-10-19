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


def _refused() -> ConnectionRefusedError:
    return ConnectionRefusedError(111, "Connect call failed ('postgres-rw', 5432)")


class _Orig(Exception):
    def __init__(self, msg: str, sqlstate: str | None = None) -> None:
        super().__init__(msg)
        self.sqlstate = sqlstate


# ── The classifier ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc",
    [
        _refused(),
        ConnectionResetError(104, "reset"),
        TimeoutError(),
        InterfaceError("SELECT 1", {}, _Orig("connection is closed")),
        DBAPIError("SELECT 1", {}, _Orig("gone"), connection_invalidated=True),
        DBAPIError("SELECT 1", {}, _Orig("terminating connection", "57P01")),
        DBAPIError("SELECT 1", {}, _Orig("connection failure", "08006")),
        DBAPIError("UPDATE x", {}, _Orig("read-only transaction", "25006")),
        ExceptionGroup("pre-ping", [TimeoutError()]),
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

    async def _drive(_db: Any, _rid: Any, *, holder: str | None = None) -> Any:
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

    async def _drive(_db: Any, _rid: Any, *, holder: str | None = None) -> Any:
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

    async def _drive(_db: Any, _rid: Any, *, holder: str | None = None) -> Any:
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

    async def _drive(_rid: str) -> dict[str, str]:
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
