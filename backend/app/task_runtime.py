"""Per-prefork-child event loop and async engine for Celery tasks (#4515).

A task used to run its coroutine with ``asyncio.run`` (a new loop) and build
and dispose of its own ``create_async_engine``, on every invocation. That is
correct but not free: it leaks roughly 1 KB of native memory per run and pays
a connect and engine setup each time.

In a prefork child this module instead keeps ONE event loop (created at
``worker_process_init``, closed at ``worker_process_shutdown``) and lazily ONE
async engine per command-timeout bound on that loop. Everything degrades to
the old behaviour wherever no child loop is installed (the API process, tests,
CLI scripts, the solo / threads pools): :func:`run_task` falls back to
``asyncio.run`` and :func:`task_engine` to a throwaway engine that
:func:`release_task_engine` disposes.

Isolation between tasks:

* sessions are opened per call and closed on return, and the pool resets (rolls
  back) every connection it takes back, so no transaction state carries over;
* ``pool_pre_ping`` replaces a connection a failover or restart killed;
* when a task's coroutine ends, or raises, :func:`run_task` cancels whatever it
  left running on the loop (what ``asyncio.run`` did by closing its loop), so
  a failed or timed-out task cannot poison the next one;
* every piece of state is stamped with the pid that created it, and a forked
  child discards, rather than uses, state it inherited.
"""

import asyncio
import os
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from app.config import settings

logger = structlog.get_logger(__name__)

# Pool sizing for the shared engine. A task is one coroutine on one loop and
# opens its sessions in turn, so ONE connection stays pooled (idle between
# tasks); the overflow, closed again at check-in, absorbs a task that holds a
# couple of sessions at once. The deployment's ``max_connections`` budget
# (chart helper ``postgresMaxConnections``, appliance
# ``postgres_connection_budget``) allows 3 per prefork child, and a child holds
# at most one engine per command-timeout bound, but a task uses one at a time:
# 1 idle per engine, 3 live at most while a task runs.
_POOL_SIZE = 1
_MAX_OVERFLOW = 2
# Recycle so a connection never lives across a long idle stretch (a NAT or
# load balancer dropping it); pre-ping covers the rest.
_POOL_RECYCLE_S = 1800


class _ChildState:
    """The loop and engines owned by one process."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self.loop = asyncio.new_event_loop()
        self.engines: dict[float | None, AsyncEngine] = {}


_state: _ChildState | None = None


def _current() -> _ChildState | None:
    """The installed state, or ``None`` when absent or inherited over a fork."""
    global _state
    st = _state
    if st is not None and st.pid != os.getpid():
        # Inherited from the parent: its sockets and loop belong to it. Drop
        # the engines without closing the parent's connections.
        for eng in st.engines.values():
            try:
                eng.sync_engine.dispose(close=False)
            except Exception:  # noqa: BLE001 — best effort on a forked copy
                logger.debug("task_engine_fork_discard_failed", exc_info=True)
        _state = None
        return None
    return st


def install_child_loop() -> None:
    """Create this process's loop. Called from ``worker_process_init``."""
    global _state
    if _current() is not None:
        return
    st = _ChildState()
    asyncio.set_event_loop(st.loop)
    _state = st


def close_child_loop() -> None:
    """Dispose this process's engines and close its loop. Never raises."""
    global _state
    st = _current()
    if st is None:
        return
    _state = None
    try:
        if not st.loop.is_closed() and not st.loop.is_running():
            for eng in st.engines.values():
                try:
                    st.loop.run_until_complete(eng.dispose())
                except Exception:  # noqa: BLE001 — shutdown must not be blocked
                    logger.warning("task_engine_dispose_failed", exc_info=True)
            _cancel_leftovers(st.loop)
            st.loop.run_until_complete(st.loop.shutdown_asyncgens())
            st.loop.close()
    except Exception:  # noqa: BLE001 — shutdown must not be blocked
        logger.warning("task_loop_close_failed", exc_info=True)
    finally:
        asyncio.set_event_loop(None)


def _cancel_leftovers(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel and await every task still pending on ``loop`` (as ``asyncio.run``
    does when it closes its loop)."""
    pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
    if not pending:
        return
    for t in pending:
        t.cancel()
    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))


def run_task[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run a task's coroutine to completion: on the child's loop when one is
    installed, else with ``asyncio.run``."""
    st = _current()
    if st is None or st.loop.is_closed():
        return asyncio.run(coro)
    try:
        return st.loop.run_until_complete(coro)
    finally:
        # Also on an exception (a soft time limit raises inside the loop): the
        # task's unfinished work must not run into the next task.
        _cancel_leftovers(st.loop)


def _make_engine(command_timeout: float | None) -> AsyncEngine:
    from app.db import _json_serializer, task_connect_args  # noqa: PLC0415

    return create_async_engine(
        settings.database_url,
        future=True,
        json_serializer=_json_serializer,
        pool_size=_POOL_SIZE,
        max_overflow=_MAX_OVERFLOW,
        # A connection outlives a failover or a database restart between tasks
        # now; replace a dead one at checkout (#1445).
        pool_pre_ping=True,
        pool_recycle=_POOL_RECYCLE_S,
        connect_args=task_connect_args(command_timeout),
    )


def task_engine(command_timeout: float | None = None) -> AsyncEngine:
    """The engine a task should use. Call it from inside the task's coroutine.

    Shared per child (one per ``command_timeout`` bound) when running on the
    child's loop; otherwise a fresh engine the caller hands to
    :func:`release_task_engine`.
    """
    st = _current()
    if st is not None:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is st.loop:
            eng = st.engines.get(command_timeout)
            if eng is None:
                eng = st.engines[command_timeout] = _make_engine(command_timeout)
            return eng
    return _make_engine(command_timeout)


async def release_task_engine(engine: AsyncEngine) -> None:
    """Dispose ``engine`` unless it is the child's shared one."""
    if is_shared_engine(engine):
        return
    await engine.dispose()


def is_shared_engine(engine: AsyncEngine) -> bool:
    st = _current()
    return st is not None and any(e is engine for e in st.engines.values())


async def release_session_locks(session: AsyncSession) -> None:
    """Free the session-level advisory locks a task took on ``session``'s
    connection. A throwaway engine's dispose used to close the connection and
    with it the lock; the shared engine keeps the connection, so a task that
    took ``pg_try_advisory_lock`` must not leave it held for the child's life.
    A no-op off the shared engine. Never raises."""
    bind = session.bind
    if not isinstance(bind, AsyncEngine) or not is_shared_engine(bind):
        return
    try:
        await session.rollback()
        await session.execute(text("SELECT pg_advisory_unlock_all()"))
        await session.rollback()
    except Exception:  # noqa: BLE001 — a dead connection holds no lock
        logger.debug("task_session_lock_release_failed", exc_info=True)


@asynccontextmanager
async def session_locks_released(session: AsyncSession) -> AsyncIterator[None]:
    """``async with factory() as db, session_locks_released(db):`` — frees the
    session's advisory locks (:func:`release_session_locks`) before it closes."""
    try:
        yield
    finally:
        await release_session_locks(session)
