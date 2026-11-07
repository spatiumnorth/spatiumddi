"""The kubeapi-proxy and agent-command reply waits end when the api begins
shutting down (#3015), instead of holding the pod for up to their 15 s / 30 s
timeouts. Both moved from a single ``wait_for`` to a Redis-reading loop in
#3705 / #3713; the loop must race the shutdown flag like every other hold."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import pytest

from app.core import shutdown
from app.services.appliance import agent_cmd, k8s_proxy


class _SlowRedis:
    """A Redis whose BLPOP never answers within the test."""

    async def blpop(self, key: str, timeout: float = 0) -> Any:
        await asyncio.sleep(60)
        return None


@pytest.fixture(autouse=True)
def _reset_shutdown() -> Any:
    shutdown.reset()
    yield
    shutdown.reset()


async def _ends_on_shutdown(start_wait: Any) -> float:
    loop = asyncio.get_running_loop()
    task = asyncio.ensure_future(start_wait(loop.time() + 30))
    await asyncio.sleep(0.2)
    assert not task.done()
    t0 = time.monotonic()
    shutdown.request_shutdown()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(task, timeout=5)
    return time.monotonic() - t0


@pytest.mark.asyncio
@pytest.mark.parametrize("client", [None, _SlowRedis()], ids=["fallback", "redis"])
async def test_k8s_proxy_reply_wait_ends_on_shutdown(client: Any) -> None:
    fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    took = await _ends_on_shutdown(
        lambda deadline: k8s_proxy._await_reply(client, uuid.uuid4().hex, fut, deadline)
    )
    assert took < 2


@pytest.mark.asyncio
@pytest.mark.parametrize("client", [None, _SlowRedis()], ids=["fallback", "redis"])
async def test_agent_cmd_reply_wait_ends_on_shutdown(client: Any) -> None:
    fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    took = await _ends_on_shutdown(
        lambda deadline: agent_cmd._await_reply(
            client, agent_cmd.CHANNEL_NETTOOL, uuid.uuid4().hex, fut, deadline
        )
    )
    assert took < 2


@pytest.mark.asyncio
async def test_a_reply_already_delivered_still_wins_over_shutdown() -> None:
    fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    fut.set_result("answer")
    shutdown.request_shutdown()
    loop = asyncio.get_running_loop()
    assert await k8s_proxy._await_reply(None, "x", fut, loop.time() + 30) == "answer"
