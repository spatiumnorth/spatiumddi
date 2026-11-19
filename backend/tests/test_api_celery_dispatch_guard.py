"""No inline Celery publish inside an ``async def`` under ``app/api``.

``task.delay(...)`` writes to the broker synchronously; inside a handler
that stalls the event loop. Handlers go through
``app.core.celery_dispatch.dispatch`` instead.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_ROOT = Path(__file__).resolve().parent.parent / "app" / "api"
PUBLISH_ATTRS = ("delay", "apply_async")


def find_inline_publishes(source: str) -> list[int]:
    """Line numbers of ``.delay(`` / ``.apply_async(`` calls in async code."""
    hits: list[int] = []

    def visit(node: ast.AST, in_async: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.AsyncFunctionDef):
                visit(child, True)
            elif isinstance(child, (ast.FunctionDef, ast.Lambda)):
                visit(child, False)
            else:
                if (
                    in_async
                    and isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr in PUBLISH_ATTRS
                ):
                    hits.append(child.lineno)
                visit(child, in_async)

    visit(ast.parse(source), False)
    return hits


def test_no_inline_publish_in_async_api_code() -> None:
    offenders = []
    for path in sorted(API_ROOT.rglob("*.py")):
        for line in find_inline_publishes(path.read_text()):
            offenders.append(f"{path.relative_to(API_ROOT.parent)}:{line}")
    assert not offenders, (
        "inline Celery publish inside async def; use "
        "`await dispatch(task, ...)` from app.core.celery_dispatch: " + ", ".join(offenders)
    )


def test_guard_flags_a_bare_publish_in_async_code() -> None:
    src = "async def h():\n    t.delay(1)\n    t.apply_async(args=[1])\n"
    assert find_inline_publishes(src) == [2, 3]


def test_guard_allows_sync_functions_and_dispatch() -> None:
    src = (
        "def s():\n    t.delay(1)\n"
        "async def h():\n    await dispatch(t, 1)\n"
        "    def inner():\n        t.delay(2)\n"
    )
    assert find_inline_publishes(src) == []


@pytest.mark.asyncio
async def test_dispatch_returns_the_task_result_and_runs_off_loop() -> None:
    import threading

    from app.core.celery_dispatch import dispatch, dispatch_apply_async

    seen: dict[str, object] = {}

    class T:
        def delay(self, *a: object, **k: object) -> str:
            seen["thread"] = threading.current_thread()
            return f"r{a}{k}"

        def apply_async(self, *a: object, **k: object) -> str:
            return f"a{a}{k}"

    assert await dispatch(T(), 1, x=2) == "r(1,){'x': 2}"
    assert seen["thread"] is not threading.main_thread()
    assert await dispatch_apply_async(T(), args=[1]) == "a(){'args': [1]}"
