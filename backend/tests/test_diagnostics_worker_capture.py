"""Worker task failures reach the Diagnostics table (#1193).

Celery's ``task_failure`` hook calls ``record_unhandled_exception``. It used
to open a ``postgresql://`` engine, which needs psycopg2, and the backend
ships only asyncpg, so every worker failure was logged as a capture failure
and dropped. These tests go through the real function and the real signal
and read the row back from ``internal_error``.
"""

from __future__ import annotations

import importlib
import uuid

import pytest
from celery.signals import task_failure
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.diagnostics import InternalError
from app.services.diagnostics import record_unhandled_exception


def _failure(message: str) -> RuntimeError:
    """An exception with a real traceback, as a failing task produces."""
    try:
        raise RuntimeError(message)
    except RuntimeError as exc:
        return exc


class _Task:
    """Stands in for the Celery task that failed: the hook reads its ``name``."""

    name = "app.tasks.signalled"


async def _rows(db: AsyncSession, message: str) -> list[InternalError]:
    result = await db.execute(select(InternalError).where(InternalError.message == message))
    return list(result.scalars().all())


@pytest.mark.asyncio
async def test_a_worker_failure_is_recorded(db_session: AsyncSession) -> None:
    message = f"worker failure {uuid.uuid4()}"
    record_unhandled_exception(
        service="worker",
        exc=_failure(message),
        route_or_task="app.tasks.example",
        request_id="task-1193",
        context={"task_args": ("a",), "task_kwargs": {"password": "hunter2"}},
    )
    rows = await _rows(db_session, message)
    assert len(rows) == 1
    row = rows[0]
    assert row.service == "worker"
    assert row.route_or_task == "app.tasks.example"
    assert row.request_id == "task-1193"
    assert row.exception_class == "builtins.RuntimeError"
    assert "_failure" in row.traceback
    assert row.context_json["task_kwargs"] == {"password": "<redacted>"}


@pytest.mark.asyncio
async def test_a_repeat_failure_bumps_the_count(db_session: AsyncSession) -> None:
    message = f"repeat failure {uuid.uuid4()}"
    exc = _failure(message)
    record_unhandled_exception(service="worker", exc=exc)
    record_unhandled_exception(service="worker", exc=exc)
    rows = await _rows(db_session, message)
    assert [row.occurrence_count for row in rows] == [2]


@pytest.mark.asyncio
async def test_the_task_failure_signal_records_the_task(db_session: AsyncSession) -> None:
    """The hook ``app.celery_app`` connects, fired the way Celery fires it."""
    importlib.import_module("app.celery_app")
    message = f"signalled failure {uuid.uuid4()}"
    task_id = str(uuid.uuid4())
    task_failure.send(
        sender=_Task,
        task_id=task_id,
        exception=_failure(message),
        args=(1, 2),
        kwargs={"zone": "example.com"},
        traceback=None,
        einfo=None,
    )
    rows = await _rows(db_session, message)
    assert len(rows) == 1
    assert rows[0].service == "worker"
    assert rows[0].route_or_task == "app.tasks.signalled"
    assert rows[0].request_id == task_id
    assert rows[0].context_json["task_kwargs"] == {"zone": "example.com"}


@pytest.mark.asyncio
async def test_an_unreachable_database_does_not_raise(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hook runs inside Celery's failure handling, so it must never raise."""
    monkeypatch.setattr(
        settings, "database_url", "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/nothing"
    )
    message = f"unrecorded failure {uuid.uuid4()}"
    record_unhandled_exception(service="worker", exc=_failure(message))
    monkeypatch.undo()
    assert await _rows(db_session, message) == []
