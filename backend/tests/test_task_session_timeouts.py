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


# ── Every task / service engine on the app database is bounded ──────────

_APP_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent / "app"

# Engines that do NOT point at ``settings.database_url`` and are exempt by
# design: the backup drill builds its own engine on a scratch database, and
# the backup migration helper takes an explicit URL from its caller.
_EXEMPT = {
    "services/backup/drill.py",
    "services/backup/migrations.py",
}


def _engine_calls():
    """Yield ``(relpath, lineno, call)`` for each ``create_async_engine``."""
    import ast

    for sub in ("tasks", "services"):
        for path in sorted((_APP_ROOT / sub).rglob("*.py")):
            rel = path.relative_to(_APP_ROOT).as_posix()
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
                if name == "create_async_engine":
                    yield rel, node.lineno, node


def test_every_app_db_engine_in_tasks_and_services_is_bounded():
    """#1719 — a per-task engine with no ``connect_args`` hangs ~15 min on
    a black-holed CNPG primary. Every ``create_async_engine`` on the app
    database in ``app/tasks`` and ``app/services`` must pass
    ``connect_args=task_connect_args(...)``."""
    import ast

    seen = 0
    unbounded = []
    for rel, lineno, call in _engine_calls():
        if rel in _EXEMPT:
            continue
        seen += 1
        kw = {k.arg: k.value for k in call.keywords if k.arg}
        ca = kw.get("connect_args")
        ok = (
            isinstance(ca, ast.Call)
            and getattr(ca.func, "id", getattr(ca.func, "attr", None)) == "task_connect_args"
        )
        if not ok:
            unbounded.append(f"{rel}:{lineno}")
    # Guard against the scan silently matching nothing.
    assert seen > 30, seen
    assert not unbounded, f"engines without connect_args=task_connect_args(): {unbounded}"


def test_exempt_engines_still_exist():
    """Keep the allowlist honest: drop an entry once its engine is gone."""
    found = {rel for rel, _, _ in _engine_calls()}
    assert _EXEMPT <= found, _EXEMPT - found


@pytest.mark.parametrize(
    "module,needle",
    [
        # The 1.09 M-row records query (#1111) runs past 120 s on big groups.
        # The long bound, or the render's own soft limit once that is longer
        # (#2240): ``_render_command_timeout``; the behavioural test below
        # and tests/test_agent_bundles_render_limits_2240.py pin the values.
        (
            "app.tasks.agent_bundles",
            "task_session(command_timeout=_render_command_timeout(",
        ),
        (
            "app.tasks.dns_threat",
            "task_session(command_timeout=settings.task_db_long_command_timeout)",
        ),
        (
            "app.tasks.snmp_poll",
            "task_connect_args(command_timeout=settings.task_db_long_command_timeout)",
        ),
    ],
)
def test_long_statement_tasks_use_long_bound(module, needle):
    import importlib
    import inspect

    src = inspect.getsource(importlib.import_module(module))
    assert needle in src


@pytest.mark.asyncio
async def test_agent_bundle_render_session_gets_long_bound(monkeypatch, db_session):  # noqa: ARG001
    """Behavioural: the render's engine carries the 900 s command bound."""
    import uuid

    from app.tasks import agent_bundles

    seen = {}
    real = app_db.create_async_engine

    def spy(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(app_db, "create_async_engine", spy)
    result = await agent_bundles._render_once(uuid.uuid4())
    assert result == {"status": "gone"}
    assert seen["connect_args"]["command_timeout"] == settings.task_db_long_command_timeout
