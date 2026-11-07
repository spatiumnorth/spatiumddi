"""#3706 — the nettool and storage command queues are shared across api
replicas and the Celery worker through Redis.

A command enqueued on one process must reach the supervisor whose poll is
parked on another, and the reply must reach the waiter. Each "process" gets
its own private fallback state (``_dispatches``); the only thing they share
is Redis — the real one the suite uses for the cross-process tests, and a fake
one only where a fault has to be injected. Storage commands run ``mdadm``, so
the at-most-once tests matter most for that channel.
"""

from __future__ import annotations

import asyncio
import collections
import inspect
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.services.appliance import agent_cmd

CHANNELS = [agent_cmd.CHANNEL_NETTOOL, agent_cmd.CHANNEL_STORAGE]


class FakeRedis:
    """The few Redis commands agent_cmd uses, over a store shared by every
    client — i.e. by every simulated process."""

    def __init__(self) -> None:
        self.kv: dict[str, Any] = {}
        self.lists: dict[str, list[str]] = collections.defaultdict(list)

    def client(self) -> Any:
        store = self

        class _Pipe:
            def __init__(self) -> None:
                self.ops: list[Any] = []

            def set(self, k: str, v: str, ex: int | None = None) -> None:
                self.ops.append(lambda: store.kv.__setitem__(k, v))

            def rpush(self, k: str, v: str) -> None:
                self.ops.append(lambda: store.lists[k].append(v))

            def ltrim(self, k: str, start: int, end: int) -> None:
                self.ops.append(lambda: store.lists.__setitem__(k, store.lists[k][start:]))

            def expire(self, *_a: Any) -> None:
                self.ops.append(lambda: None)

            async def execute(self) -> list[Any]:
                for op in self.ops:
                    op()
                return []

        class _Client:
            async def ping(self) -> bool:
                return True

            def pipeline(self) -> Any:
                return _Pipe()

            async def get(self, k: str) -> Any:
                return store.kv.get(k)

            async def exists(self, k: str) -> int:
                return int(k in store.kv)

            async def delete(self, *keys: str) -> int:
                for k in keys:
                    store.kv.pop(k, None)
                    store.lists.pop(k, None)
                return len(keys)

            async def blpop(self, key: str, timeout: float = 1.0) -> Any:
                loop = asyncio.get_running_loop()
                end = loop.time() + timeout
                while loop.time() < end:
                    if store.lists.get(key):
                        return (key, store.lists[key].pop(0))
                    await asyncio.sleep(0.01)
                return None

            async def aclose(self) -> None:
                return None

        return _Client()


@pytest.fixture
def redis(monkeypatch: pytest.MonkeyPatch) -> FakeRedis:
    fake = FakeRedis()
    monkeypatch.setattr(agent_cmd, "_client", fake.client)
    return fake


class Process:
    """Swap in one simulated process's private fallback state."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.dispatches: dict[str, agent_cmd._Dispatch] = collections.defaultdict(
            agent_cmd._Dispatch
        )
        self.mp = monkeypatch

    def use(self) -> None:
        self.mp.setattr(agent_cmd, "_dispatches", self.dispatches)


@pytest.fixture
def procs(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Process, Process]]:
    yield Process(monkeypatch), Process(monkeypatch)


# The cross-process tests below run against the REAL Redis the suite uses
# (``settings.redis_url``, as #3703's do), not the fake: what they prove is
# that BLPOP hands one command to one poll and the reply list reaches a waiter
# in another process. Each simulated process keeps its own fallback state, so on
# the pre-#3706 module (one process's memory) the poll on the other side gets
# nothing and the assertion on it fails.


async def _deliver(result: agent_cmd.NetToolResult, **kw: Any) -> bool:
    out: Any = agent_cmd.deliver_result(result, **kw)
    if inspect.isawaitable(out):  # async since #3706; sync before it
        out = await out
    return bool(out)


@pytest.mark.parametrize("channel", CHANNELS)
async def test_command_and_reply_cross_replicas(
    procs: tuple[Process, Process], channel: str
) -> None:
    a, b = procs
    aid = uuid.uuid4()
    a.use()
    call = asyncio.create_task(
        agent_cmd.enqueue_command(aid, "ping", {"host": "10.0.0.1"}, timeout=5.0, channel=channel)
    )
    await asyncio.sleep(0.2)

    b.use()  # the supervisor's poll + reply land on another replica
    queued = await agent_cmd.pop_command(aid, timeout=3.0, channel=channel)
    assert queued is not None, "the command never crossed to the other replica"
    assert (queued.tool, queued.params) == ("ping", {"host": "10.0.0.1"})
    assert await _deliver(
        agent_cmd.NetToolResult(request_id=queued.request_id, result={"ok": True}),
        appliance_id=aid,
        channel=channel,
    )
    a.use()
    outcome = await asyncio.wait_for(call, 5.0)
    assert outcome.result == {"ok": True}


async def test_worker_wake_reaches_supervisor_poll_on_an_api_replica(
    procs: tuple[Process, Process],
) -> None:
    """A scheduled Wake-on-LAN calls ``wol.wake_via_appliance`` from the Celery
    worker, which has no supervisor poll of its own; the packet is sent by the
    appliance whose poll is parked on an api replica, and the worker gets the
    result back."""
    from app.services import wol

    worker, api = procs
    aid = uuid.uuid4()
    appliance = SimpleNamespace(
        id=aid, state="approved", last_seen_at=datetime.now(UTC), hostname="edge-1"
    )

    class _DB:
        async def get(self, _model: Any, ident: Any) -> Any:
            return appliance if ident == aid else None

    wire = wol.WolWireRequest(mac="aa:bb:cc:dd:ee:ff", broadcast="192.0.2.255", port=9)
    worker.use()
    call = asyncio.create_task(wol.wake_via_appliance(_DB(), aid, wire))  # type: ignore[arg-type]
    await asyncio.sleep(0.2)

    api.use()
    queued = await agent_cmd.pop_command(aid, timeout=3.0)
    assert queued is not None, "the worker's wake never reached the api replica's poll"
    assert queued.tool == "wol" and queued.params["mac"] == wire.mac
    assert await _deliver(
        agent_cmd.NetToolResult(
            request_id=queued.request_id,
            result={"mac": wire.mac, "broadcast": wire.broadcast, "port": 9, "sent": True},
        ),
        appliance_id=aid,
    )
    worker.use()
    result = await asyncio.wait_for(call, 5.0)
    assert result.sent is True
    assert result.ran_from == "appliance:edge-1"


async def test_wrong_appliance_reply_refused_and_abandoned_command_skipped(
    procs: tuple[Process, Process],
) -> None:
    a, b = procs
    aid = uuid.uuid4()
    a.use()
    call = asyncio.create_task(
        agent_cmd.enqueue_command(aid, "ping", {}, timeout=5.0, channel=agent_cmd.CHANNEL_STORAGE)
    )
    await asyncio.sleep(0.2)
    b.use()
    queued = await agent_cmd.pop_command(aid, timeout=3.0, channel=agent_cmd.CHANNEL_STORAGE)
    assert queued is not None
    forged = agent_cmd.NetToolResult(request_id=queued.request_id, result={"forged": True})
    assert not await _deliver(forged, appliance_id=uuid.uuid4(), channel=agent_cmd.CHANNEL_STORAGE)
    # Not the same channel either.
    assert not await _deliver(forged, appliance_id=aid)
    # The genuine reply still lands after the refused ones.
    assert await _deliver(
        agent_cmd.NetToolResult(request_id=queued.request_id, result={"ok": 1}),
        appliance_id=aid,
        channel=agent_cmd.CHANNEL_STORAGE,
    )
    a.use()
    assert (await asyncio.wait_for(call, 5.0)).result == {"ok": 1}

    with pytest.raises(TimeoutError):
        await agent_cmd.enqueue_command(aid, "ping", {}, timeout=0.3)
    b.use()
    assert await agent_cmd.pop_command(aid, timeout=1.2) is None


@pytest.mark.parametrize("channel", CHANNELS)
async def test_a_command_is_handed_out_at_most_once(
    procs: tuple[Process, Process], channel: str
) -> None:
    a, b = procs
    aid = uuid.uuid4()
    a.use()
    call = asyncio.create_task(
        agent_cmd.enqueue_command(aid, "ping", {}, timeout=2.5, channel=channel)
    )
    await asyncio.sleep(0.2)
    # Two polls on another replica (or a supervisor retry) race for one command
    # through a real BLPOP; exactly one gets it.
    b.use()
    got = await asyncio.gather(
        agent_cmd.pop_command(aid, timeout=1.5, channel=channel),
        agent_cmd.pop_command(aid, timeout=1.5, channel=channel),
    )
    assert sum(g is not None for g in got) == 1
    a.use()
    with pytest.raises(TimeoutError):
        await call


class _AmbiguousRedis:
    """Runs the enqueue pipeline, then fails the way a timeout after the
    server executed it would."""

    def __init__(self, fake: FakeRedis) -> None:
        self.inner = fake.client()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def pipeline(self) -> Any:
        pipe = self.inner.pipeline()
        real = pipe.execute

        async def execute() -> list[Any]:
            await real()
            import redis.exceptions

            raise redis.exceptions.TimeoutError("Timeout reading from socket")

        pipe.execute = execute
        return pipe


@pytest.mark.parametrize("channel", CHANNELS)
async def test_an_ambiguous_enqueue_is_never_also_queued_in_process(
    redis: FakeRedis, monkeypatch: pytest.MonkeyPatch, channel: str
) -> None:
    calls = {"n": 0}
    healthy = agent_cmd._client

    def client() -> Any:
        calls["n"] += 1
        # The enqueue's client is ambiguous; the polls' clients are healthy.
        return _AmbiguousRedis(redis) if calls["n"] == 1 else healthy()

    monkeypatch.setattr(agent_cmd, "_client", client)
    aid = uuid.uuid4()
    call = asyncio.create_task(
        agent_cmd.enqueue_command(aid, "ping", {}, timeout=2.0, channel=channel)
    )
    await asyncio.sleep(0.3)
    assert agent_cmd.queue_depth(aid, channel=channel) == 0  # no local copy
    assert sum(len(v) for v in redis.lists.values()) == 1  # Redis ran it once
    first = await agent_cmd.pop_command(aid, timeout=1.0, channel=channel)
    second = await agent_cmd.pop_command(aid, timeout=0.5, channel=channel)
    assert first is not None and second is None  # delivered exactly once
    with pytest.raises(TimeoutError):
        await call
    assert agent_cmd.queue_depth(aid, channel=channel) == 0


class _StalledRedis:
    async def ping(self) -> bool:
        return True

    def pipeline(self) -> Any:
        class _Pipe:
            def __getattr__(self, _n: str) -> Any:
                return lambda *a, **k: None

            async def execute(self) -> list[Any]:
                return []

        return _Pipe()

    async def blpop(self, *_a: Any, **_k: Any) -> Any:
        await asyncio.sleep(3600)

    async def delete(self, *_a: Any) -> int:
        await asyncio.sleep(3600)
        return 0

    async def aclose(self) -> None:
        return None


@pytest.mark.parametrize("channel", CHANNELS)
async def test_a_stalled_redis_cannot_stretch_the_wait_past_its_timeout(
    monkeypatch: pytest.MonkeyPatch, channel: str
) -> None:
    monkeypatch.setattr(agent_cmd, "_client", lambda: _StalledRedis())
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            agent_cmd.enqueue_command(uuid.uuid4(), "ping", {}, timeout=0.5, channel=channel),
            timeout=8.0,
        )
    assert loop.time() - started < 4.0


async def test_an_unreachable_redis_still_falls_back_in_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Refusing(_StalledRedis):
        async def ping(self) -> bool:
            import redis.exceptions

            raise redis.exceptions.ConnectionError("Connection refused")

        async def blpop(self, *_a: Any, **_k: Any) -> Any:
            return await self.ping()

        async def get(self, *_a: Any) -> Any:
            return await self.ping()

    monkeypatch.setattr(agent_cmd, "_client", lambda: _Refusing())
    aid = uuid.uuid4()
    call = asyncio.create_task(agent_cmd.enqueue_command(aid, "ping", {}, timeout=5.0))
    queued = await agent_cmd.pop_command(aid, timeout=2.0)
    assert queued is not None
    assert await agent_cmd.deliver_result(
        agent_cmd.NetToolResult(request_id=queued.request_id, result={"ok": 1}),
        appliance_id=aid,
    )
    assert (await asyncio.wait_for(call, 5.0)).result == {"ok": 1}


async def test_queued_payload_carries_only_the_command() -> None:
    cmd = agent_cmd.NetToolCommand(request_id="r", tool="wol", params={"mac": "aa"})
    import dataclasses

    assert set(json.loads(json.dumps(dataclasses.asdict(cmd)))) == {
        "request_id",
        "tool",
        "params",
        "cancelled",
    }
