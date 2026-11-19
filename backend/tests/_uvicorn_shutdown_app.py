"""A minimal ASGI app for ``test_longpoll_shutdown_uvicorn_3015.py`` (#3015).

Run under a REAL uvicorn in a subprocess. It is wired through the same
``app.core.shutdown`` module and the same lifespan shape as ``app.main``
(reset + ``install_signal_hook()`` at startup, ``request_shutdown()`` after
the yield), and its long-polls use the real wait helpers: ``wake_subscription``
/ ``WakeSubscription.wait`` and ``get_or_shutdown``. The full app is not used
because its lifespan seeds a database and starts a dozen background loops;
``test_lifespan_calls_install_signal_hook`` pins that ``app.main``'s lifespan
makes the same call.

``SPATIUM_TEST_NEUTER_SHUTDOWN_HOOK=1`` replaces ``install_signal_hook`` with
a no-op — the negative control, which must reproduce the #3015 failure.
Not collected by pytest (no ``test_`` prefix).
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response

from app.core import shutdown
from app.core.agent_wake import WakeResult, WakeSubscription, wake_subscription

HOLD_S = 30.0  # the production long-poll hold
TICK_S = 12.0  # WAKE_TICK_SECONDS

if os.environ.get("SPATIUM_TEST_NEUTER_SHUTDOWN_HOOK") == "1":
    shutdown.install_signal_hook = lambda: False  # type: ignore[assignment]

_parked = 0
_degraded: dict[str, bool] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    shutdown.reset()
    shutdown.install_signal_hook()
    yield
    shutdown.request_shutdown()


app = FastAPI(lifespan=lifespan)


@app.get("/ready")
async def ready() -> dict[str, int]:
    return {"parked": _parked}


async def _config_style_poll(wake: WakeSubscription) -> Response:
    """The DNS / DHCP / LG config long-poll loop, minus the bundle."""
    global _parked
    loop = asyncio.get_running_loop()
    deadline = loop.time() + HOLD_S
    _parked += 1
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return Response(status_code=304, headers={"ETag": '"unchanged"'})
            if await wake.wait(min(TICK_S, remaining)) == WakeResult.SHUTDOWN:
                deadline = loop.time()
    finally:
        _parked -= 1


@app.get("/poll/pubsub")
async def poll_pubsub() -> Response:
    async with wake_subscription(["spatium:wake:test-3015-uvicorn"]) as wake:
        _degraded["pubsub"] = wake.degraded
        resp = await _config_style_poll(wake)
    resp.headers["X-Degraded"] = "1" if _degraded["pubsub"] else "0"
    return resp


@app.get("/poll/degraded")
async def poll_degraded() -> Response:
    resp = await _config_style_poll(WakeSubscription(None, None, True))
    resp.headers["X-Degraded"] = "1"
    return resp


@app.get("/poll/queue")
async def poll_queue() -> dict[str, str]:
    """The supervisor nettool / storage / k8s-proxy poll shape."""
    global _parked
    queue: asyncio.Queue[str] = asyncio.Queue()
    _parked += 1
    try:
        item, _ended = await shutdown.get_or_shutdown(queue, HOLD_S)
    finally:
        _parked -= 1
    return {"request_id": item or ""}
