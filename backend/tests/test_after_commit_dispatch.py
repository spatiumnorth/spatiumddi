"""After-commit side effects survive a Celery task's loop ending (#1168).

``audit_forward`` and ``event_publisher`` dispatch their work after the
commit. On a bare ``loop.create_task`` a Celery task's ``asyncio.run``
cancelled it as the task returned — and a task usually commits last — so
worker-written audit rows produced no typed webhook events and no syslog
forwarding. These are sync tests on purpose: each runs a task-shaped
``asyncio.run`` of its own, which an async test could not.
"""

from __future__ import annotations

import asyncio

import pytest

from app.services import after_commit_dispatch as acd


def _task_shaped_run(done: list[str]) -> None:
    """A Celery task body: dispatch after "commit", then return at once."""

    async def side_effect() -> None:
        await asyncio.sleep(0.05)  # an outbox write takes a few ms
        done.append("written")

    async def task_body() -> None:
        acd.dispatch("test", side_effect, count=1)

    asyncio.run(task_body())


def test_on_the_callers_loop_the_work_dies_with_the_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure, pinned: what the listeners used to do inside a task."""
    monkeypatch.setattr(acd, "_background", False)
    done: list[str] = []
    _task_shaped_run(done)
    assert done == []


def test_on_the_background_loop_the_work_outlives_the_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(acd, "_background", True)
    done: list[str] = []
    _task_shaped_run(done)
    assert acd.wait_for_pending(timeout=5)
    assert done == ["written"]


def test_celery_worker_and_beat_switch_the_background_loop_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not at import: the api imports ``app.celery_app`` too, and its request
    loop is long-lived. Only a Celery process's own startup signal flips it."""
    from celery.signals import beat_init, worker_init

    import app.celery_app  # noqa: F401 — connects the receivers

    for signal in (worker_init, beat_init):
        monkeypatch.setattr(acd, "_background", False)
        signal.send(sender=None)
        assert acd.using_background_loop(), signal.name
