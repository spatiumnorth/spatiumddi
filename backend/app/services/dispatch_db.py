"""Bounded database access for the after-commit hooks (#2782).

``event_publisher`` and ``audit_forward`` run after every commit that wrote
an audit row. They used to open a fresh ``NullPool`` engine per dispatch,
outside the api's own pool, so the connection count followed the write rate
(measured live: 6-7 extra backends per api pod at 90 bulk requests in flight,
with no ceiling).

Both now share ONE small engine per process:

* ``POOL_SIZE`` connections, ``max_overflow=0`` -- that is the hard cap on
  what these hooks can hold, per process, however many commits fire at once.
  Two is enough: a session is held only for a few indexed SELECTs / one
  INSERT batch (the webhook / syslog delivery runs after the session
  closes), so two connections turn over thousands of times a second.
* Excess work WAITS for a free connection (up to ``POOL_TIMEOUT_S``), it is
  not dropped. The wait happens inside the already fire-and-forget dispatch
  task, never on the request path. Past the timeout the caller's existing
  failure handling logs a warning, as it always did for a database error.

This is outside the api's 10 + 20 pool, so the Postgres connection budget
counts ``POOL_SIZE`` extra per api / worker / beat process.

An asyncpg connection is bound to the loop that made it, and dispatch runs on
exactly one loop per process (the api's request loop, or the Celery
background loop of ``after_commit_dispatch``), so the engine is created
lazily for the running loop and rebuilt if that ever changes (tests).

Also here: a tiny negative cache so a commit with nothing to deliver to
opens no connection at all.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from app.config import settings as _app_settings
from app.db import task_connect_args

logger = structlog.get_logger(__name__)

POOL_SIZE = 2
POOL_TIMEOUT_S = 60
NEGATIVE_TTL_S = 5.0


class _EngineState:
    engine: AsyncEngine | None = None
    loop: asyncio.AbstractEventLoop | None = None
    pid: int | None = None


_state = _EngineState()


def _engine() -> AsyncEngine:
    loop = asyncio.get_running_loop()
    if _state.engine is not None and (_state.loop is not loop or _state.pid != os.getpid()):
        # Another loop / a forked child: the old pool's connections are not
        # ours to await on. Drop the references without closing.
        _state.engine.sync_engine.dispose(close=False)
        _state.engine = None
    if _state.engine is None:
        _state.engine = create_async_engine(
            _app_settings.database_url,
            pool_size=POOL_SIZE,
            max_overflow=0,
            pool_timeout=POOL_TIMEOUT_S,
            pool_pre_ping=True,
            pool_recycle=300,
            echo=False,
            connect_args=task_connect_args(),
        )
        _state.loop, _state.pid = loop, os.getpid()
    return _state.engine


@asynccontextmanager
async def session() -> AsyncIterator[AsyncSession]:
    """A session on the shared, capped engine."""
    async with AsyncSession(_engine(), expire_on_commit=False) as s:
        yield s


async def dispose() -> None:
    """Close the pool. Call on the owning loop at shutdown."""
    engine, _state.engine = _state.engine, None
    if engine is not None:
        await engine.dispose()


class NegativeCache:
    """Remembers "there is nothing to deliver to" for ``NEGATIVE_TTL_S``.

    Only the empty answer is cached: a non-empty one is needed in full
    anyway. In-process; the writing routes call ``invalidate`` so this
    process sees a new subscription / target at once, and another process
    sees it within the TTL."""

    def __init__(self) -> None:
        self._until = 0.0

    def known_empty(self) -> bool:
        return time.monotonic() < self._until

    def mark_empty(self) -> None:
        self._until = time.monotonic() + NEGATIVE_TTL_S

    def invalidate(self) -> None:
        self._until = 0.0
