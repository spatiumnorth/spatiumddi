"""#1719 — the per-task engine must bound connect and command time."""

import asyncio
import time
from unittest.mock import patch

import pytest

from app import db as app_db
from app.config import settings


async def _captured_kwargs(**session_kwargs):
    seen = {}
    real = app_db.create_async_engine

    def spy(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    with patch.object(app_db, "create_async_engine", spy):
        async with app_db.task_session(**session_kwargs):
            pass
    return seen


@pytest.mark.asyncio
async def test_task_engine_has_default_bounds():
    kw = await _captured_kwargs()
    assert kw["connect_args"] == {
        "timeout": settings.task_db_connect_timeout,
        "command_timeout": settings.task_db_command_timeout,
    }
    assert 0 < kw["connect_args"]["timeout"] <= 10
    assert 0 < kw["connect_args"]["command_timeout"] <= 300
    assert kw["pool_pre_ping"] is True


@pytest.mark.asyncio
async def test_task_engine_command_timeout_override():
    kw = await _captured_kwargs(command_timeout=settings.task_db_long_command_timeout)
    assert kw["connect_args"]["command_timeout"] == settings.task_db_long_command_timeout
    assert settings.task_db_long_command_timeout > settings.task_db_command_timeout


@pytest.mark.parametrize(
    "module,attr",
    [
        ("app.tasks.prune_metrics", "_sweep"),
        ("app.tasks.prune_logs", None),
        ("app.tasks.trash_purge", None),
        ("app.tasks.audit_chain_verify", None),
    ],
)
def test_slow_tasks_opt_into_long_timeout(module, attr):
    import importlib
    import inspect

    src = inspect.getsource(importlib.import_module(module))
    assert "task_session(command_timeout=settings.task_db_long_command_timeout)" in src


@pytest.mark.asyncio
async def test_unroutable_primary_fails_within_connect_bound():
    """A black-holed address must raise within the bound, not hang."""
    import asyncpg

    start = time.monotonic()
    with pytest.raises((asyncio.TimeoutError, OSError, asyncpg.PostgresError)):
        await asyncpg.connect(
            "postgresql://u:p@10.255.255.1:5432/x",
            **{"timeout": app_db.task_connect_args()["timeout"]},
        )
    assert time.monotonic() - start < app_db.task_connect_args()["timeout"] + 5
