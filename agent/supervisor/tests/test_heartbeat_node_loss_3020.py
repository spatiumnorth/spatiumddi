"""#3020 — a surviving node's heartbeat stays fresh through a member's loss.

Two supervisor behaviours added up to a 92 s gap on a three-node cluster (the
demote guard calls a voter unhealthy past 90 s):

* a heartbeat answered 5xx (the api's 503 + Retry-After: 1 while the database is
  away, or the maintenance middleware's bare 500) waited the whole interval
  before the next, where one that never reached the api was re-sent after 5 s
  (#1805). Now both are re-sent the same way;
* after each accepted heartbeat the seed ran its kube API housekeeping inline,
  and through a node loss every call that reached the lost node waited out its
  10 s timeout (30 s in the red run) before the loop re-armed. Now that work runs
  on a worker, and the heartbeat waits for it at most ``HOUSEKEEPING_WAIT_S``.
"""

from __future__ import annotations

import threading
import time
import types
import uuid
from pathlib import Path

import httpx
import pytest
import structlog
from structlog.testing import capture_logs

from spatium_supervisor import appliance_state as st
from spatium_supervisor import heartbeat as hb
from spatium_supervisor import k8s_api, watchdog

# --- a 5xx is re-sent soon ---------------------------------------------------


def _quiet_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "collect", dict)
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(st, "read_firewall_state", dict)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(hb, "load_cert", lambda d: None)


@pytest.mark.parametrize(
    "status, headers",
    [
        # The heartbeat handler's own answer to a transient database error.
        (503, {"Retry-After": "1"}),
        # The maintenance middleware's database read raising first (#3017).
        (500, {}),
        (502, {}),
    ],
)
def test_a_5xx_heartbeat_did_not_land_and_is_resent_like_a_failed_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: int, headers: dict
) -> None:
    _quiet_heartbeat(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, json={"detail": "x"})

    cfg = types.SimpleNamespace(heartbeat_interval_seconds=30, state_dir=tmp_path)
    with capture_logs() as logs, httpx.Client(transport=httpx.MockTransport(handler)) as client:
        held = hb.heartbeat_once(
            cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
        )
    assert held is None
    assert [e["status_code"] for e in logs if e["event"] == "supervisor.heartbeat.server_error"] == [
        status
    ]
    # The loop counts it as a failure and re-sends after 5 s, not 30 s.
    assert hb.next_heartbeat_delay(held, 1, 30.0, 2.0) == 5.0


def test_the_red_runs_sequence_now_stays_far_inside_the_bound() -> None:
    # The run that read 94.7 s: a held heartbeat (28 s), the housekeeping stall
    # (30.4 s), the 2 s re-arm, a 500, then the whole 30 s interval. Now the stall
    # costs at most the housekeeping wait, and the 500 is re-sent after 5 s; one
    # more 5xx while the database is still away doubles to 10 s.
    before = 28.0 + 30.4 + 2.0 + 30.0
    after = 28.0 + hb.HOUSEKEEPING_WAIT_S + 2.0 + sum(
        hb.next_heartbeat_delay(None, n, 30.0, 2.0) for n in (1, 2)
    )
    assert before > 90.0
    assert after < 75.0 - 10.0


# --- the housekeeping worker -------------------------------------------------


class _Log:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def info(self, event: str, **kw: object) -> None:
        self.events.append((event, kw))

    warning = info

    def said(self, event: str) -> list[dict]:
        return [kw for e, kw in self.events if e == f"supervisor.heartbeat.{event}"]


def test_work_that_finishes_inside_the_wait_is_done_before_run_returns() -> None:
    keeper, log, done = hb._Housekeeper(), _Log(), []
    assert keeper.run(lambda: done.append(1), 2.0, log) is True
    assert done == [1]
    assert not keeper.busy()
    assert log.events == []


def test_slow_work_returns_after_the_wait_and_finishes_on_the_worker() -> None:
    keeper, log, done = hb._Housekeeper(), _Log(), []
    release = threading.Event()

    def slow() -> None:
        release.wait(10)
        done.append("slow")

    t = time.monotonic()
    try:
        assert keeper.run(slow, 0.2, log) is False
        assert time.monotonic() - t < 2.0
        assert keeper.busy()
        assert done == []
        assert len(log.said("housekeeping_deferred")) == 1
    finally:
        release.set()
    assert keeper.drain(5.0)
    assert done == ["slow"]
    assert len(log.said("housekeeping_done")) == 1


def test_work_queued_behind_running_work_runs_after_it_and_only_the_newest() -> None:
    keeper, log, done = hb._Housekeeper(), _Log(), []
    release = threading.Event()
    started = threading.Event()

    def first() -> None:
        started.set()
        release.wait(10)
        done.append("first")

    try:
        assert keeper.run(first, 0.1, log) is False
        assert started.wait(5)
        assert keeper.run(lambda: done.append("second"), 0.1, log) is False
        assert keeper.run(lambda: done.append("third"), 0.1, log) is False
        assert len(log.said("housekeeping_superseded")) == 1
    finally:
        release.set()
    assert keeper.drain(5.0)
    # Never two at once, never out of order, and the superseded one never ran.
    assert done == ["first", "third"]


def test_a_crash_is_logged_and_the_worker_lives_on() -> None:
    keeper, log, done = hb._Housekeeper(), _Log(), []

    def boom() -> None:
        raise RuntimeError("kubeapi GET /api/v1/nodes: timed out")

    assert keeper.run(boom, 2.0, log) is True
    assert log.said("housekeeping_crashed") == [
        {"error": "kubeapi GET /api/v1/nodes: timed out"}
    ]
    assert keeper.run(lambda: done.append(1), 2.0, log) is True
    assert done == [1]


def test_drain_gives_up_at_its_bound() -> None:
    keeper, log = hb._Housekeeper(), _Log()
    release = threading.Event()
    try:
        keeper.run(lambda: release.wait(10), 0.05, log)
        assert keeper.drain(0.1) is False
    finally:
        release.set()
    assert keeper.drain(5.0) is True


# --- heartbeat_once: the seed's housekeeping is off the heartbeat path --------


@pytest.fixture
def seed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """The seed of a formed cluster, as test_redis_storage_reclaim's seed_tick:
    everything the control-plane block calls is stubbed, and ``patch_cnpg_instances``
    (its first kube API call) waits on ``release`` while ``slow`` is set."""
    monkeypatch.setattr(st, "collect", dict)
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(st, "detect_appliance_variant", lambda: "control-plane")
    monkeypatch.setattr(st, "read_firewall_state", dict)
    for name in [n for n in dir(st) if n.startswith("maybe_fire_")]:
        monkeypatch.setattr(st, name, lambda *a, **k: False)
    for name in (
        "clear_fleet_upgrade_marker",
        "reset_cluster_join_attempts",
        "mark_cluster_join_state_consumed",
    ):
        monkeypatch.setattr(st, name, lambda *a, **k: None)
    monkeypatch.setattr(hb, "probe_port_conflicts", dict)
    monkeypatch.setattr(hb, "_capabilities_payload", dict)
    monkeypatch.setattr(hb, "_effective_control_plane_url", lambda cfg: "http://cp.invalid")
    monkeypatch.setattr(hb, "load_cert", lambda d: None)
    monkeypatch.setattr(hb, "record_shared_chart_hold", lambda *a, **k: None)
    scale = types.SimpleNamespace(
        current=3, ready=3, reported=3, scaled=False, deferred="", error=None,
        spec_after=lambda size: size,
    )
    state = types.SimpleNamespace(
        slow=False, release=threading.Event(), entered=threading.Event(), calls=0
    )

    def patch_cnpg_instances(*a: object, **k: object) -> object:
        state.calls += 1
        state.entered.set()
        if state.slow:
            state.release.wait(10)
        return scale

    def no_kube(*a: object, **k: object) -> tuple[int, bytes]:
        raise RuntimeError("no kubeapi in this test")

    monkeypatch.setattr(k8s_api, "_request", no_kube)
    monkeypatch.setattr(k8s_api, "patch_cnpg_instances", patch_cnpg_instances)
    monkeypatch.setattr(k8s_api, "sizing_memory_mib", lambda *a, **k: None)
    monkeypatch.setattr(k8s_api, "node_cpu_count", lambda *a, **k: None)
    for name in (
        "apply_control_plane_overrides",
        "apply_metallb_overrides",
        "apply_dataplane_vip_overrides",
        "ensure_coredns_ha",
        "ensure_kube_dns_node_local",
        "ensure_cnpg_operator_spread",
    ):
        monkeypatch.setattr(k8s_api, name, lambda *a, **k: (False, None))
    monkeypatch.setattr(k8s_api, "reclaim_stranded_mirror_storage", lambda *a, **k: ({}, None))
    monkeypatch.setattr(
        k8s_api, "reclaim_stranded_postgres_storage", lambda **k: k8s_api.PostgresReclaim()
    )
    monkeypatch.setattr(hb, "_reclaim_stranded_redis", lambda *a, **k: None)
    monkeypatch.setattr(hb, "_reclone_stuck_postgres", lambda *a, **k: None)
    monkeypatch.setattr(
        hb, "_etcd_evictions", types.SimpleNamespace(tick=lambda asked, wanted=(): ([], {}))
    )
    for name in ("_nodes_deleted", "_evicted_pending", "_stranded_pending"):
        monkeypatch.setattr(hb, name, set())
    monkeypatch.setattr(hb, "_evict_reasons", {})
    monkeypatch.setattr(hb, "_mirror_claims_owed", {})
    monkeypatch.setattr(hb, "_replace_hold", hb._ReplaceHold())
    monkeypatch.setattr(hb, "_demote_shrink", hb._DemoteShrink())
    keeper = hb._Housekeeper()
    monkeypatch.setattr(hb, "_housekeeper", keeper)
    monkeypatch.setattr(hb, "HOUSEKEEPING_WAIT_S", 0.3)
    cfg = types.SimpleNamespace(heartbeat_interval_seconds=0, state_dir=tmp_path)
    answer = {"control_plane_size": 3, "long_poll": True}

    def tick() -> bool | None:
        def backend(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=answer)

        with httpx.Client(transport=httpx.MockTransport(backend)) as client:
            return hb.heartbeat_once(
                cfg, uuid.uuid4(), "tok", None, client, structlog.get_logger()  # type: ignore[arg-type]
            )

    state.tick, state.keeper = tick, keeper
    yield state
    state.release.set()
    keeper.drain(5.0)


def test_a_healthy_seed_tick_finishes_its_housekeeping_before_it_returns(seed) -> None:
    assert seed.tick() is True
    assert seed.calls == 1
    assert not seed.keeper.busy()


def test_a_stalled_kube_api_call_no_longer_holds_the_next_heartbeat(seed) -> None:
    seed.slow = True
    t = time.monotonic()
    assert seed.tick() is True  # held: the loop re-arms after its 2 s floor
    assert time.monotonic() - t < 2.0
    assert seed.entered.is_set() and seed.keeper.busy()
    # The next heartbeat goes while the stalled work still runs; its own work
    # queues behind it and runs once the stall ends.
    t = time.monotonic()
    assert seed.tick() is True
    assert time.monotonic() - t < 2.0
    assert seed.calls == 1
    seed.release.set()
    assert seed.keeper.drain(5.0)
    assert seed.calls == 2


def test_the_watchdog_waits_while_housekeeping_runs(
    seed, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(st, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(st, "host_network_interfaces", list)
    monkeypatch.setattr(st, "read_cluster_restore_state", lambda: (None, None))
    monkeypatch.setattr(k8s_api, "list_etcd_snapshots", list)
    monkeypatch.setattr(hb, "_dispatch_firewall", lambda *a, **k: None)
    monkeypatch.setattr(hb, "_run_role_lifecycle", lambda *a, **k: None)
    monkeypatch.setattr(hb, "_last_watchdog_at", 0.0)
    checks: list[object] = []
    monkeypatch.setattr(watchdog, "check_health", lambda *a, **k: checks.append(a) or {})
    seed.slow = True
    seed.tick()
    assert len(checks) == 1  # due, and nothing was running yet
    monkeypatch.setattr(hb, "_last_watchdog_at", 0.0)
    seed.tick()
    assert len(checks) == 1  # still due, but the first tick's work still runs
    seed.release.set()
    assert seed.keeper.drain(5.0)
    seed.tick()
    assert len(checks) == 2
