"""Process-wide "this api process is shutting down" signal (#3015).

uvicorn runs the ASGI lifespan shutdown only AFTER in-flight requests have
finished (or after ``--timeout-graceful-shutdown`` cancels them), so the
lifespan is too late to tell a parked long-poll to go home. SIGTERM is the
earliest moment: :func:`install_signal_hook` (called from the lifespan
STARTUP, which uvicorn runs inside ``Server.capture_signals`` so its own
``handle_exit`` is already installed) wraps the SIGTERM / SIGINT handler so
the flag is set the instant the signal lands, then chains to uvicorn's.

Every long-poll wait races this flag and returns its ordinary "nothing new"
answer at once; the client re-polls another pod. The ETag compare stays the
source of truth — shutdown only ends the *wait*, never decides content.

Implemented as a flag + a set of per-waiter futures rather than one
``asyncio.Event`` so it is safe across event loops (tests) and callable from
a signal handler.
"""

from __future__ import annotations

import asyncio
import signal
import threading
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_requested = False
_waiters: set[asyncio.Future[None]] = set()
_HOOK_MARK = "_spatium_shutdown_hook"


def shutdown_requested() -> bool:
    return _requested


def _release(fut: asyncio.Future[None]) -> None:
    if not fut.done():
        fut.set_result(None)


def request_shutdown() -> None:
    """Mark shutdown as begun and wake every waiter. Idempotent; safe to call
    from a signal handler (main thread) or any other thread."""
    global _requested
    _requested = True
    for fut in list(_waiters):
        try:
            fut.get_loop().call_soon_threadsafe(_release, fut)
        except RuntimeError:  # loop already closed
            _waiters.discard(fut)


def reset() -> None:
    """Clear the flag (lifespan startup, tests)."""
    global _requested
    _requested = False
    _waiters.clear()


def shutdown_future() -> asyncio.Future[None]:
    """A future that completes when shutdown begins (already complete if it
    has). The caller must hand it to :func:`discard` when done with it."""
    fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    if _requested:
        fut.set_result(None)
    else:
        _waiters.add(fut)
    return fut


def discard(fut: asyncio.Future[None]) -> None:
    _waiters.discard(fut)
    if not fut.done():
        fut.cancel()


async def sleep_or_shutdown(timeout: float) -> bool:
    """Sleep up to ``timeout``; return True if shutdown began first."""
    if _requested:
        return True
    fut = shutdown_future()
    try:
        await asyncio.wait({fut}, timeout=max(timeout, 0.0))
    finally:
        discard(fut)
    return _requested


async def get_or_shutdown(queue: asyncio.Queue[Any], timeout: float) -> tuple[Any, bool]:
    """``queue.get()`` for at most ``timeout`` seconds, ended early by shutdown.

    Returns ``(item, False)`` on an item, ``(None, True)`` on timeout or
    shutdown. An item that arrives in the instant of cancellation is still
    returned, never dropped.
    """
    if _requested and queue.empty():
        return None, True
    getter = asyncio.ensure_future(queue.get())
    fut = shutdown_future()
    try:
        await asyncio.wait(
            {getter, fut}, timeout=max(timeout, 0.0), return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        discard(fut)
        if not getter.done():
            getter.cancel()
        try:
            await getter
        except asyncio.CancelledError:
            pass
    if getter.cancelled():
        return None, True
    return getter.result(), False


def install_signal_hook() -> bool:
    """Wrap the current SIGTERM / SIGINT handlers so they call
    :func:`request_shutdown` first. Returns False when it cannot (not the main
    thread, or a handler that is not a Python callable — wrapping SIG_DFL
    would swallow the termination)."""
    if threading.current_thread() is not threading.main_thread():
        return False
    installed = False
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            current = signal.getsignal(sig)
            if not callable(current) or getattr(current, _HOOK_MARK, False):
                continue

            def _hook(signum: int, frame: Any, _chain: Any = current) -> None:
                request_shutdown()
                _chain(signum, frame)

            setattr(_hook, _HOOK_MARK, True)
            signal.signal(sig, _hook)
            installed = True
        except (ValueError, OSError) as exc:  # pragma: no cover - platform quirks
            logger.warning("shutdown_hook_install_failed", signal=int(sig), error=str(exc))
    return installed
