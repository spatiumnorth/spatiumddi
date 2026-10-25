"""Run after-commit side effects on a loop that outlives the caller (#1168).

``audit_forward`` and ``event_publisher`` capture audit rows in
``after_flush`` and, after the commit, hand them to a coroutine that forwards
them (syslog / webhook) or writes the typed-event outbox. They used to do
that with a fire-and-forget ``loop.create_task`` on whatever loop was
running.

In the api that loop is uvicorn's and lives as long as the process. In a
Celery task it is the task's own ``asyncio.run``, and a task's commit is
usually the last thing it does: the coroutine returns, ``asyncio.run``
cancels every task still pending, and the dispatch dies before its write.
Measured on a scratch database (2026-09-24): five task-shaped commits of a
``backup_target_run_failed`` audit row with a matching subscription wrote
**0** outbox rows; the same five with the loop kept alive for a second wrote
5. So a scheduled backup that failed at 03:00 produced no
``system.backup_failed`` webhook, and no syslog line either.

So Celery processes dispatch to a background loop of their own instead: one
daemon thread per process running a private event loop, started lazily and
per PID — prefork children are forked from a master that may already have
touched this module, and a thread does not survive ``fork``. The api keeps
dispatching on its request loop (now holding a reference to each task, which
``asyncio`` requires or a pending task may be garbage-collected mid-flight).

The dispatched coroutines already open their own short-lived engine
(``_ephemeral_session``) precisely because they must not depend on the
caller's loop, so running them on another loop needs nothing else.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections.abc import Callable, Coroutine
from concurrent.futures import Future
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_background = False
_lock = threading.Lock()


class _LoopState:
    """The background loop and the PID that started it. Held on an object
    rather than rebound as module globals, which code scanning reads as
    assigned and never used."""

    loop: asyncio.AbstractEventLoop | None = None
    pid: int | None = None


_state = _LoopState()

# Strong references: an unreferenced asyncio task can be collected mid-run.
_tasks: set[asyncio.Task[Any]] = set()
_futures: set[Future[Any]] = set()


def use_background_loop() -> None:
    """Dispatch on a per-process background loop from now on. Called from the
    Celery ``worker_init`` / ``beat_init`` signals (``app.celery_app``)."""
    global _background
    _background = True


def using_background_loop() -> bool:
    return _background


def _ensure_loop() -> asyncio.AbstractEventLoop:
    with _lock:
        current = _state.loop
        if current is not None and _state.pid == os.getpid() and current.is_running():
            return current
        loop = asyncio.new_event_loop()
        started = threading.Event()

        def _run() -> None:
            asyncio.set_event_loop(loop)
            loop.call_soon(started.set)
            loop.run_forever()

        threading.Thread(target=_run, name="after-commit-dispatch", daemon=True).start()
        started.wait(timeout=5)
        _state.loop, _state.pid = loop, os.getpid()
        return loop


def dispatch(label: str, make: Callable[[], Coroutine[Any, Any, None]], *, count: int) -> None:
    """Run ``make()`` after a commit without tying it to the caller's loop
    in a Celery process. ``label`` names the log line when it is dropped."""
    if _background:
        future = asyncio.run_coroutine_threadsafe(make(), _ensure_loop())
        _futures.add(future)
        future.add_done_callback(_futures.discard)
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug(f"{label}_no_loop_dropped", count=count)
        return
    task = loop.create_task(make())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def wait_for_pending(timeout: float = 5.0) -> bool:
    """Block until background dispatches finish, up to ``timeout`` seconds.
    True when none are left. For tests and for draining at process exit."""
    deadline = time.monotonic() + timeout
    for future in list(_futures):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            future.result(timeout=remaining)
        except Exception:  # noqa: BLE001 — the coroutine logs its own failure
            logger.debug("after_commit_dispatch_failed_while_draining")
    return not _futures


async def shutdown(timeout: float = 5.0) -> None:
    """Let in-flight dispatches finish (up to ``timeout``), then close the
    shared dispatch engine (#2782). Awaited from the api lifespan on its own
    loop; the Celery background loop is handled by ``shutdown_background``."""
    pending = [t for t in _tasks if not t.done()]
    if pending:
        await asyncio.wait(pending, timeout=timeout)
    from app.services import dispatch_db  # noqa: PLC0415

    await dispatch_db.dispose()


def shutdown_background(timeout: float = 5.0) -> None:
    """Celery ``worker_shutdown`` (beat has no shutdown signal; it exits with the process): drain, then dispose the
    engine on the background loop that owns it, and stop that loop."""
    wait_for_pending(timeout)
    loop = _state.loop
    if loop is None or _state.pid != os.getpid() or not loop.is_running():
        return
    try:
        asyncio.run_coroutine_threadsafe(shutdown(0), loop).result(timeout=timeout)
    except Exception:  # noqa: BLE001 — exiting anyway; the server reaps the sockets
        logger.debug("after_commit_dispatch_shutdown_failed")
    loop.call_soon_threadsafe(loop.stop)


__all__ = [
    "shutdown",
    "shutdown_background",
    "dispatch",
    "use_background_loop",
    "using_background_loop",
    "wait_for_pending",
]
