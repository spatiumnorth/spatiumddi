"""#2870 — before ``SENTINEL FAILOVER`` the Redis master move steers Sentinel
to the replica on the node that drains last, so one roll fails the master over
once instead of twice. The priority is restored afterwards, whatever happens.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

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
        self.run_ids = {M1: "run-m1", M2: "run-m2", SEED: "run-seed"}

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

    async def replica_state(self, _url: str, host: str, _port: int) -> tuple[str, int]:
        return self.run_ids[host], self.prio.get(host, 100)

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
    monkeypatch.setattr(redis_master, "_replica_state", f.replica_state)
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
    # member-1 is done (not in remaining); member-2 is still to drain. The
    # fake's tie-break is insertion order, so put member-2 first: unsteered,
    # the failover would pick it.
    fake.prio = {M2: 100, M1: 100}
    fake._seen = dict(fake.prio)
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


class _RecordClient:
    def __init__(self, raw: str, cleared: list[bool]) -> None:
        self.raw, self.cleared = raw, cleared

    async def get(self, _k: str) -> str:
        return self.raw

    async def delete(self, _k: str) -> None:
        self.cleared.append(True)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_a_leftover_record_is_restored_at_the_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sets: list[tuple[str, int]] = []
    cleared: list[bool] = []
    raw = json.dumps([{"host": M1, "port": 6379, "priority": 100, "run_id": "run-m1"}])

    async def _set(_u: str, host: str, _p: int, v: int) -> None:
        sets.append((host, v))

    async def _state(_u: str, _h: str, _p: int) -> tuple[str, int]:
        return "run-m1", 1

    async def _rc(_u: str) -> _RecordClient:
        return _RecordClient(raw, cleared)

    monkeypatch.setattr(redis_master, "_record_client", _rc)
    monkeypatch.setattr(redis_master, "_set_priority", _set)
    monkeypatch.setattr(redis_master, "_replica_state", _state)
    await redis_master._restore_leftover(URL)
    assert sets == [(M1, 100)] and cleared == [True]


@pytest.mark.asyncio
async def test_a_leftover_record_never_touches_another_process_at_that_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pod restarted (or, on an install announcing pod IPs, another pod
    took the address): a different ``run_id`` answers, so nothing is written,
    and the record is cleared since there is nothing left to undo."""
    sets: list[tuple[str, int]] = []
    cleared: list[bool] = []
    raw = json.dumps([{"host": M1, "port": 6379, "priority": 50, "run_id": "run-m1"}])

    async def _set(_u: str, host: str, _p: int, v: int) -> None:
        sets.append((host, v))

    async def _state(_u: str, _h: str, _p: int) -> tuple[str, int]:
        return "run-someone-else", 100

    async def _rc(_u: str) -> _RecordClient:
        return _RecordClient(raw, cleared)

    monkeypatch.setattr(redis_master, "_record_client", _rc)
    monkeypatch.setattr(redis_master, "_set_priority", _set)
    monkeypatch.setattr(redis_master, "_replica_state", _state)
    await redis_master._restore_leftover(URL)
    assert sets == [] and cleared == [True]


@pytest.mark.asyncio
async def test_an_unreachable_replica_keeps_the_record_for_the_next_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleared: list[bool] = []
    raw = json.dumps([{"host": M1, "port": 6379, "priority": 100, "run_id": "run-m1"}])

    async def _state(_u: str, _h: str, _p: int) -> tuple[str, int]:
        raise ConnectionError("no route")

    async def _rc(_u: str) -> _RecordClient:
        return _RecordClient(raw, cleared)

    monkeypatch.setattr(redis_master, "_record_client", _rc)
    monkeypatch.setattr(redis_master, "_replica_state", _state)
    await redis_master._restore_leftover(URL)
    assert cleared == []


@pytest.mark.asyncio
async def test_the_recorded_original_is_the_live_value_with_its_run_id(
    fake: Fake, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sentinel's copy of a priority lags by an INFO period; the record must
    hold the value read from the replica itself, and which process it was."""
    fake.prio[M1] = 40
    fake.sentinel_sees_priority = False
    fake._seen = {M1: 100, M2: 100}  # Sentinel has not read 40 yet
    monkeypatch.setattr(redis_master, "_PRIORITY_SEEN_TIMEOUT_S", 0.0)
    recorded: list[list[dict[str, Any]]] = []

    async def _store(url: str, entries: list[dict[str, Any]]) -> None:
        recorded.append(entries)
        await fake.store(url, entries)

    monkeypatch.setattr(redis_master, "_store_originals", _store)
    await redis_master.move_master_off_node("seed", url=URL, timeout_s=5, remaining_nodes=ORDER)
    assert recorded == [[{"host": M1, "port": 6379, "priority": 40, "run_id": "run-m1"}]]
    assert fake.prio[M1] == 40, "restored to the live value, not Sentinel's stale 100"


@pytest.mark.asyncio
async def test_the_steered_replica_is_restored_after_it_became_the_master(fake: Fake) -> None:
    """After the failover the steered replica IS the master; the restore still
    goes to it (by address and run_id), since the priority would outlive its
    demotion later."""
    await redis_master.move_master_off_node("seed", url=URL, timeout_s=5, remaining_nodes=ORDER)
    assert fake.master == M1
    assert fake.sets[-1] == (M1, 100)


def test_drain_order_puts_the_drives_own_node_last() -> None:
    """#2870 — the orchestrator defers its own node to the end of the roll,
    so that, not the plan's last entry, is the node that drains last."""
    from app.services.upgrades import node_order

    plan = ["member-1", "member-2", "seed", "member-3"]
    assert node_order.drain_order(plan, ["member-1"], current="member-2", defer="seed") == [
        "member-2",
        "member-3",
        "seed",
    ]
    # A resumed in-flight node (#2809) is driven first whatever the plan says.
    assert node_order.drain_order(plan, [], current="member-3", defer=None) == [
        "member-3",
        "member-1",
        "member-2",
        "seed",
    ]
    # The drive's own node is the current one (the hand-off's successor runs it).
    assert node_order.drain_order(plan, ["member-1", "member-2"], current="seed", defer="seed") == [
        "seed",
        "member-3",
    ]


@pytest.mark.asyncio
async def test_the_drive_hands_the_chain_the_nodes_in_drain_order(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker runs on member-3, so member-3 drains last although the plan
    lists it before seed. Plan order would steer the master onto seed."""
    from app.models.system_upgrade import SystemUpgradeRun
    from app.services.upgrades import orchestrator as orch
    from app.services.upgrades import per_node

    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version="2026.10.14-1",
        source_versions={},
        plan={
            "node_order": ["member-1", "member-3", "member-2", "seed"],
            "slot_image_url": "https://example.test/x.raw.xz",
        },
        progress={"per_node": {"member-1": {"ok": True}}, "events": []},
        lease_holder="worker-a",
    )
    db_session.add(run)
    await db_session.commit()
    seen: list[dict[str, Any]] = []

    async def _single(*_a: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        seen.append(kwargs)
        return per_node.SingleNodeResult(
            node_name=kwargs["node_name"],
            target_version=kwargs["target_version"],
            ok=False,
            failed_at="preflight",
            steps=[],
        )

    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)
    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(orch.mutex, "release_if_held", lambda **_k: True)
    monkeypatch.setenv("NODE_NAME", "member-3")

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert seen[0]["node_name"] == "member-2"
    assert seen[0]["remaining_nodes"] == ["member-2", "seed", "member-3"]


@pytest.mark.asyncio
async def test_the_record_goes_to_the_master_the_sentinels_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not to redis-py's Sentinel routing, which keeps the OLD master until
    ``+switch-master``; a DEL sent there in that gap is undone by the old
    master's resync from the new one."""

    async def _cmd(_h: str, _p: int, _pw: str | None, *args: Any) -> Any:
        assert args[:2] == ("SENTINEL", "GET-MASTER-ADDR-BY-NAME")
        return [M1, "6380"]

    monkeypatch.setattr(redis_master, "_sentinel_command", _cmd)
    client = await redis_master._record_client(URL)
    try:
        kw = client.connection_pool.connection_kwargs
        assert (kw["host"], kw["port"]) == (M1, 6380)
    finally:
        await client.aclose()
