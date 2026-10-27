"""#2870 — before ``SENTINEL FAILOVER`` the Redis master move steers Sentinel
to the replica on the node that drains last, so one roll fails the master over
once instead of twice. The priority is restored afterwards, whatever happens.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services.upgrades import redis_master

URL = "sentinel://:pw@redis-0.h.spatium.svc.cluster.local:26379/0"
SEED = "redis-seed.h.spatium.svc"
M1 = "redis-m1.h.spatium.svc"
M2 = "redis-m2.h.spatium.svc"
NODES = {SEED: "seed", M1: "member-1", M2: "member-2"}


class Fake:
    """A Sentinel + Redis pair: replicas with priorities, a failover that
    promotes the lowest non-zero priority replica."""

    def __init__(self) -> None:
        self.master = SEED
        self.prio = {M1: 100, M2: 100}
        self.sets: list[tuple[str, int]] = []
        self.set_error: str | None = None
        self.promoted: str | None = None
        self.failovers = 0
        self.stored: list[dict[str, Any]] | None = None
        self.failover_raises = False
        self.sentinel_sees_priority = True
        self._seen = dict(self.prio)

    async def masters(self, *_a: Any) -> list[str]:
        if self.failovers and self.promoted:
            self.master = self.promoted
        return [self.master, self.master]

    async def healthy(self, *_a: Any) -> int:
        return len(self.prio)

    async def replicas(self, *_a: Any) -> list[dict[str, str]]:
        if self.sentinel_sees_priority:
            self._seen = dict(self.prio)
        return [
            {"ip": h, "port": "6379", "flags": "slave", "slave-priority": str(p)}
            for h, p in self._seen.items()
        ]

    async def failover(self, *_a: Any) -> str | None:
        self.failovers += 1
        eligible = {h: p for h, p in self._seen.items() if p > 0}
        self.promoted = min(eligible, key=lambda h: eligible[h])
        if self.failover_raises:
            raise RuntimeError("boom")
        return None

    async def set_priority(self, _url: str, host: str, _port: int, value: int) -> None:
        if self.set_error and value == redis_master._STEER_PRIORITY:
            raise RuntimeError(self.set_error)
        self.sets.append((host, value))
        self.prio[host] = value

    async def store(self, _url: str, entries: list[dict[str, Any]]) -> None:
        self.stored = entries

    async def clear(self, _url: str) -> None:
        self.stored = None


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Fake:
    f = Fake()
    monkeypatch.setattr(redis_master, "_sentinel_masters", f.masters)
    monkeypatch.setattr(redis_master, "_sentinel_healthy_replicas", f.healthy)
    monkeypatch.setattr(redis_master, "_sentinel_replicas", f.replicas)
    monkeypatch.setattr(redis_master, "_sentinel_failover", f.failover)
    monkeypatch.setattr(redis_master, "_set_priority", f.set_priority)
    monkeypatch.setattr(redis_master, "_store_originals", f.store)
    monkeypatch.setattr(redis_master, "_clear_originals", f.clear)

    async def _no_leftover(_url: str) -> None:
        return None

    monkeypatch.setattr(redis_master, "_restore_leftover", _no_leftover)
    monkeypatch.setattr(redis_master, "redis_host_node", lambda h, _ns: NODES.get(h))
    monkeypatch.setattr(redis_master, "_POLL_INTERVAL_S", 0.0)
    return f


ORDER = ["seed", "member-2", "member-1"]  # roll order: member-1 drains last


@pytest.mark.asyncio
async def test_steers_to_the_node_that_drains_last_then_restores(fake: Fake) -> None:
    out = await redis_master.move_master_off_node(
        "seed", url=URL, timeout_s=5, remaining_nodes=ORDER
    )
    assert fake.promoted == M1, "Sentinel's pick is the replica on member-1"
    assert out.detail["master"] == M1 and out.detail["moved"] is True
    assert out.detail["steered_to"] == "member-1"
    assert fake.sets == [(M1, 1), (M1, 100)], "set for the failover, then restored"
    assert fake.prio == {M1: 100, M2: 100}
    assert fake.stored is None, "the record of originals is cleared"
    assert fake.failovers == 1


@pytest.mark.asyncio
async def test_without_steering_the_failover_picks_the_next_node(fake: Fake) -> None:
    """The bug: left alone Sentinel's tie-break picks member-2 here."""
    fake.prio = {M2: 100, M1: 100}
    fake._seen = dict(fake.prio)
    await redis_master.move_master_off_node("seed", url=URL, timeout_s=5)
    assert fake.promoted == M2 and fake.sets == []


@pytest.mark.asyncio
async def test_a_replica_on_an_already_upgraded_node_is_preferred(fake: Fake) -> None:
    # member-1 is done (not in remaining); member-2 is still to drain.
    await redis_master.move_master_off_node(
        "seed", url=URL, timeout_s=5, remaining_nodes=["seed", "member-2"]
    )
    assert fake.promoted == M1


@pytest.mark.asyncio
async def test_config_refused_falls_back_to_a_plain_failover(fake: Fake) -> None:
    fake.set_error = "ERR unknown command 'CONFIG'"
    out = await redis_master.move_master_off_node(
        "seed", url=URL, timeout_s=5, remaining_nodes=ORDER
    )
    assert fake.failovers == 1
    assert out.warning is None and out.detail["moved"] is True
    assert fake.prio == {M1: 100, M2: 100}
    assert fake.stored is None or fake.stored[0]["priority"] == 100


@pytest.mark.asyncio
async def test_restore_runs_when_the_failover_raises(fake: Fake) -> None:
    fake.failover_raises = True
    with pytest.raises(RuntimeError):
        await redis_master.move_master_off_node("seed", url=URL, timeout_s=5, remaining_nodes=ORDER)
    assert fake.prio == {M1: 100, M2: 100}
    assert fake.sets[-1] == (M1, 100)


@pytest.mark.asyncio
async def test_a_single_replica_is_not_steered(fake: Fake) -> None:
    del fake.prio[M2]
    fake._seen = dict(fake.prio)
    out = await redis_master.move_master_off_node(
        "seed", url=URL, timeout_s=5, remaining_nodes=ORDER
    )
    assert fake.sets == []
    assert fake.failovers == 1 and out.detail["moved"] is True


@pytest.mark.asyncio
async def test_priority_zero_is_never_written(fake: Fake) -> None:
    await redis_master.move_master_off_node("seed", url=URL, timeout_s=5, remaining_nodes=ORDER)
    assert all(v != 0 for _h, v in fake.sets)


@pytest.mark.asyncio
async def test_a_replica_that_cannot_be_promoted_is_not_a_choice(fake: Fake) -> None:
    """member-1's replica is priority 0 (never promote): one eligible replica
    is left, so there is nothing to steer and nothing is changed."""
    fake.prio[M1] = 0
    fake._seen = dict(fake.prio)
    await redis_master.move_master_off_node("seed", url=URL, timeout_s=5, remaining_nodes=ORDER)
    assert fake.sets == [] and fake.promoted == M2


@pytest.mark.asyncio
async def test_sentinel_not_seeing_the_priority_still_fails_over_and_restores(
    fake: Fake, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.sentinel_sees_priority = False
    monkeypatch.setattr(redis_master, "_PRIORITY_SEEN_TIMEOUT_S", 0.0)
    out = await redis_master.move_master_off_node(
        "seed", url=URL, timeout_s=5, remaining_nodes=ORDER
    )
    assert out.warning is None and fake.failovers == 1
    assert fake.prio == {M1: 100, M2: 100}


@pytest.mark.asyncio
async def test_a_leftover_record_is_restored_at_the_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sets: list[tuple[str, int]] = []
    cleared: list[bool] = []

    class _Client:
        async def get(self, _k: str) -> str:
            return json.dumps([{"host": M1, "port": 6379, "priority": 100}])

        async def delete(self, _k: str) -> None:
            cleared.append(True)

        async def aclose(self) -> None:
            return None

    async def _set(_u: str, host: str, _p: int, v: int) -> None:
        sets.append((host, v))

    monkeypatch.setattr(redis_master, "make_async_redis", lambda _u: _Client())
    monkeypatch.setattr(redis_master, "_set_priority", _set)
    await redis_master._restore_leftover(URL)
    assert sets == [(M1, 100)] and cleared == [True]
