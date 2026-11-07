"""#3703 — the kubeapi proxy queue and its replies are shared across api
replicas. On a multi-node control plane the operator's request lands on one
api pod while the member supervisor's long-poll is parked on another; with a
per-process queue the poll never saw it and every read answered 504.

Two "replicas" are modelled by clearing the module's in-process state between
the sides: they share nothing but Redis.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from typing import Any

import pytest

from app.services.appliance import k8s_proxy

pytestmark = pytest.mark.asyncio


async def test_request_and_reply_cross_replicas(monkeypatch: pytest.MonkeyPatch) -> None:
    aid = uuid.uuid4()
    # Replica A: the operator's request. Its private maps are its own.
    a_queues: dict = {}
    a_futures: dict = {}
    a_owner: dict = {}
    # Replica B: the supervisor's poll + reply.
    b_queues: dict = {}
    b_futures: dict = {}
    b_owner: dict = {}

    def use(q: dict, f: dict, o: dict) -> None:
        monkeypatch.setattr(k8s_proxy, "_request_queues", _dd(q))
        monkeypatch.setattr(k8s_proxy, "_response_futures", f)
        monkeypatch.setattr(k8s_proxy, "_request_owner", o)

    def _dd(d: dict):  # type: ignore[no-untyped-def]
        import collections

        out: collections.defaultdict = collections.defaultdict(asyncio.Queue, d)
        return out

    use(a_queues, a_futures, a_owner)
    call = asyncio.create_task(
        k8s_proxy.k8s_call(aid, "GET", "/api/v1/namespaces/spatium/pods", timeout=5.0)
    )
    await asyncio.sleep(0.2)

    # Replica B sees none of A's memory.
    use(b_queues, b_futures, b_owner)
    queued = await k8s_proxy.pop_request(aid, timeout=3.0)
    assert queued is not None
    assert queued.path == "/api/v1/namespaces/spatium/pods"
    delivered: Any = k8s_proxy.deliver_response(
        k8s_proxy.K8sProxyResponse(request_id=queued.request_id, status=200, body_b64="e30="),
        appliance_id=aid,
    )
    if inspect.isawaitable(delivered):  # async since #3703; sync before it
        delivered = await delivered
    assert delivered is True

    status, body = await asyncio.wait_for(call, 5.0)
    assert (status, body) == (200, b"{}")


async def test_abandoned_request_is_not_handed_out_and_late_reply_is_stale() -> None:
    aid = uuid.uuid4()
    with pytest.raises(TimeoutError):
        await k8s_proxy.k8s_call(aid, "GET", "/api/v1/nodes", timeout=0.3)
    assert await k8s_proxy.pop_request(aid, timeout=1.2) is None


async def test_queue_is_bounded() -> None:
    aid = uuid.uuid4()
    tasks = [
        asyncio.create_task(k8s_proxy.k8s_call(aid, "GET", f"/p/{i}", timeout=2.0))
        for i in range(k8s_proxy.MAX_QUEUED_PER_APPLIANCE + 5)
    ]
    await asyncio.sleep(0.5)
    got = 0
    while await k8s_proxy.pop_request(aid, timeout=0.3) is not None:
        got += 1
    assert got == k8s_proxy.MAX_QUEUED_PER_APPLIANCE
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


class _StalledRedis:
    """Accepts the enqueue, then never answers a read — a master that took
    the connection and went quiet, or a sentinel walk past dead pod names."""

    def pipeline(self) -> Any:
        class _Pipe:
            def __getattr__(self, _name: str) -> Any:
                return lambda *a, **k: None

            async def execute(self) -> list[Any]:
                return []

        return _Pipe()

    async def ping(self) -> bool:
        return True

    async def blpop(self, *_a: Any, **_k: Any) -> Any:
        await asyncio.sleep(3600)

    async def delete(self, *_a: Any) -> int:
        await asyncio.sleep(3600)
        return 0

    async def aclose(self) -> None:
        return None


async def test_a_stalled_redis_cannot_stretch_the_wait_past_its_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(k8s_proxy, "_client", lambda: _StalledRedis())
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            k8s_proxy.k8s_call(uuid.uuid4(), "GET", "/api/v1/nodes", timeout=0.5),
            timeout=8.0,
        )
    # 0.5 s wait + the bounded best-effort key cleanup, never the stall.
    assert loop.time() - started < 4.0


class _AmbiguousRedis(_StalledRedis):
    """Connects fine, then the enqueue pipeline times out — Redis may or may
    not have run it."""

    async def ping(self) -> bool:
        return True

    def pipeline(self) -> Any:
        class _Pipe:
            def __getattr__(self, _name: str) -> Any:
                return lambda *a, **k: None

            async def execute(self) -> list[Any]:
                import redis.exceptions

                raise redis.exceptions.TimeoutError("Timeout reading from socket")

        return _Pipe()

    async def blpop(self, *_a: Any, timeout: float = 1.0, **_k: Any) -> Any:
        await asyncio.sleep(timeout)
        return None

    async def delete(self, *_a: Any) -> int:
        return 0


class _RefusingRedis(_StalledRedis):
    """Cannot even connect: nothing was sent."""

    async def ping(self) -> bool:
        import redis.exceptions

        raise redis.exceptions.ConnectionError("Error 111 connecting. Connection refused.")

    async def blpop(self, *_a: Any, **_k: Any) -> Any:
        return await self.ping()

    async def get(self, *_a: Any) -> Any:
        return await self.ping()


async def test_an_ambiguous_enqueue_is_never_also_queued_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(k8s_proxy, "_client", lambda: _AmbiguousRedis())
    aid = uuid.uuid4()
    call = asyncio.create_task(k8s_proxy.k8s_call(aid, "GET", "/api/v1/nodes", timeout=0.6))
    await asyncio.sleep(0.2)
    # Redis may hold it; a local copy too would let a supervisor run it twice.
    assert k8s_proxy.queue_depth(aid) == 0
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(call, timeout=5.0)
    assert k8s_proxy.queue_depth(aid) == 0


async def test_an_unreachable_redis_still_falls_back_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(k8s_proxy, "_client", lambda: _RefusingRedis())
    aid = uuid.uuid4()
    call = asyncio.create_task(k8s_proxy.k8s_call(aid, "GET", "/api/v1/nodes", timeout=5.0))
    queued = await k8s_proxy.pop_request(aid, timeout=2.0)
    assert queued is not None
    assert await k8s_proxy.deliver_response(
        k8s_proxy.K8sProxyResponse(request_id=queued.request_id, status=200, body_b64="e30="),
        appliance_id=aid,
    )
    assert await asyncio.wait_for(call, 5.0) == (200, b"{}")
