"""#2815 — the rolling upgrade moves the Redis master off a node before
draining it, and the worker's liveness probe rides out a broker failover.

Draining the node that held the Redis master left the failover to a Sentinel
election, which can split on three nodes and leave the broker with no master
for ~128 s; the worker driving the upgrade then failed its broker-round-trip
liveness probe five times and was restarted with the drive inside it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app import worker_liveness
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import per_node, redis_master

URL = "sentinel://:pw@redis-0.h.spatium.svc.cluster.local:26379,redis-1.h.spatium.svc:26379/0"
M0 = "spatium-redis-0.spatium-redis-headless.spatium.svc.cluster.local"
M1 = "spatium-redis-1.spatium-redis-headless.spatium.svc.cluster.local"
NODES = {M0: "node-a", M1: "node-b"}


class FakeSentinels:
    """The Sentinel replies ``move_master_off_node`` sees, scripted."""

    def __init__(self, master: str, *, replicas: int = 2, switch_after: int = 1) -> None:
        self.master = master
        self.replicas = replicas
        self.failovers = 0
        self.failover_error: str | None = None
        self.switch_to: str | None = None
        self.switch_after = switch_after
        self.polls_since_failover = 0
        self.never_switch = False

    async def masters(self, _url: str, _name: str) -> list[str | None]:
        if self.failovers and not self.never_switch and self.switch_to:
            self.polls_since_failover += 1
            if self.polls_since_failover > self.switch_after:
                self.master = self.switch_to
        return [self.master, self.master]

    async def healthy(self, _url: str, _name: str) -> int:
        return self.replicas

    async def failover(self, _url: str, _name: str) -> str | None:
        self.failovers += 1
        return self.failover_error


@pytest.fixture
def sentinels(monkeypatch: pytest.MonkeyPatch) -> FakeSentinels:
    fake = FakeSentinels(M0)
    fake.switch_to = M1
    monkeypatch.setattr(redis_master, "_sentinel_masters", fake.masters)
    monkeypatch.setattr(redis_master, "_sentinel_healthy_replicas", fake.healthy)
    monkeypatch.setattr(redis_master, "_sentinel_failover", fake.failover)
    monkeypatch.setattr(redis_master, "redis_host_node", lambda host, _ns: NODES.get(host))
    monkeypatch.setattr(redis_master, "_POLL_INTERVAL_S", 0.0)
    return fake


# ── the move itself ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_master_on_the_draining_node_is_failed_over_and_waited_for(
    sentinels: FakeSentinels,
) -> None:
    out = await redis_master.move_master_off_node("node-a", url=URL, timeout_s=5)
    assert sentinels.failovers == 1
    assert out.warning is None
    assert out.detail["moved"] is True
    assert out.detail["master"] == M1
    assert out.detail["master_node"] == "node-b"


@pytest.mark.asyncio
async def test_a_master_elsewhere_is_left_alone(sentinels: FakeSentinels) -> None:
    out = await redis_master.move_master_off_node("node-b", url=URL, timeout_s=5)
    assert sentinels.failovers == 0
    assert out.warning is None and not out.skipped
    assert out.detail["master_node"] == "node-a"


@pytest.mark.asyncio
async def test_no_sentinel_skips(sentinels: FakeSentinels) -> None:
    out = await redis_master.move_master_off_node("node-a", url="redis://redis:6379/0", timeout_s=5)
    assert out.skipped is True
    assert sentinels.failovers == 0


@pytest.mark.asyncio
async def test_no_healthy_replica_skips_rather_than_failing_over_to_nothing(
    sentinels: FakeSentinels,
) -> None:
    sentinels.replicas = 0
    out = await redis_master.move_master_off_node("node-a", url=URL, timeout_s=5)
    assert out.skipped is True
    assert sentinels.failovers == 0


@pytest.mark.asyncio
async def test_a_failover_that_never_lands_times_out_with_a_warning(
    sentinels: FakeSentinels,
) -> None:
    sentinels.never_switch = True
    out = await redis_master.move_master_off_node("node-a", url=URL, timeout_s=0.05)
    assert sentinels.failovers == 1, "a failover still in flight is waited on, not re-sent"
    assert out.warning is not None and "not confirmed off node-a" in out.warning


@pytest.mark.asyncio
async def test_a_refused_failover_is_a_warning(sentinels: FakeSentinels) -> None:
    sentinels.failover_error = "s0: NOGOODSLAVE No suitable replica to promote"
    out = await redis_master.move_master_off_node("node-a", url=URL, timeout_s=5)
    assert out.warning is not None and "NOGOODSLAVE" in out.warning


@pytest.mark.asyncio
async def test_sentinels_that_disagree_are_waited_on_until_they_agree(
    monkeypatch: pytest.MonkeyPatch, sentinels: FakeSentinels
) -> None:
    """Mid-switch the Sentinels can name different masters; only an agreed
    master on another node is a confirmation."""
    replies = iter([[M0, M1], [M1, M0], [M1, M1]])
    monkeypatch.setattr(redis_master, "_sentinel_masters", lambda *_a: _aw(next(replies)))
    out = await redis_master.move_master_off_node("node-a", url=URL, timeout_s=5)
    assert sentinels.failovers == 0
    assert out.detail["master"] == M1 and out.warning is None


async def _aw(value: Any) -> Any:
    return value


@pytest.mark.asyncio
async def test_a_resume_after_a_takeover_is_a_noop_once_the_master_moved(
    sentinels: FakeSentinels,
) -> None:
    """The step is idempotent: the earlier drive's failover already landed, so
    the re-run finds the master elsewhere and sends nothing."""
    await redis_master.move_master_off_node("node-a", url=URL, timeout_s=5)
    assert sentinels.failovers == 1
    out = await redis_master.move_master_off_node("node-a", url=URL, timeout_s=5)
    assert sentinels.failovers == 1
    assert out.warning is None and "moved" not in out.detail


def test_the_master_host_names_its_pod_and_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, str | None]] = []

    def _get_pod(name: str, namespace: str | None = None) -> tuple[int, dict[str, Any]]:
        seen.append((name, namespace))
        return 200, {"spec": {"nodeName": "node-a"}}

    monkeypatch.setattr(redis_master.k8s, "get_pod", _get_pod)
    assert redis_master.redis_host_node(M0, "other") == "node-a"
    assert seen == [("spatium-redis-0", "spatium")]


def test_an_ip_master_is_matched_against_pod_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    pods = [
        {"status": {"podIP": "10.42.0.5"}, "spec": {"nodeName": "node-a"}},
        {"status": {"podIP": "10.42.1.7"}, "spec": {"nodeName": "node-b"}},
    ]
    monkeypatch.setattr(redis_master.k8s, "list_pods", lambda _ns=None: pods)
    assert redis_master.redis_host_node("10.42.1.7", "spatium") == "node-b"
    assert redis_master.redis_host_node("10.42.9.9", "spatium") is None


# ── the step in the chain ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_step_never_fails_the_node(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("sentinel exploded")

    monkeypatch.setattr(redis_master, "move_master_off_node", _boom)
    step = await per_node._step_move_redis_master("node-a", "spatium")
    assert step.ok is True
    assert "sentinel exploded" in step.detail["warning"]

    async def _warn(*_a: Any, **_k: Any) -> redis_master.MoveOutcome:
        return redis_master.MoveOutcome(warning="no Redis Sentinel answered", detail={})

    monkeypatch.setattr(redis_master, "move_master_off_node", _warn)
    step = await per_node._step_move_redis_master("node-a", "spatium")
    assert step.ok is True and step.detail["warning"] == "no Redis Sentinel answered"


def _patch_chain(monkeypatch: pytest.MonkeyPatch, calls: list[str]) -> None:
    def _ok(name: per_node.StepName) -> Any:
        async def _step(*_a: Any, **_k: Any) -> per_node.StepResult:
            calls.append(name)
            return per_node.StepResult(name=name, started_at="t").finish(True)

        return _step

    for name in per_node.CHAIN:
        monkeypatch.setattr(per_node, f"_step_{name}", _ok(name))


async def _chain(**kw: Any) -> per_node.SingleNodeResult:
    return await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock(), rollback=AsyncMock()),
        node_name="node-a",
        target_version="2026.11.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg",
        cnpg_namespace="spatium",
        **kw,
    )


@pytest.mark.asyncio
async def test_the_chain_moves_the_master_between_the_primary_check_and_the_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(redis_master.settings, "redis_url", URL)
    calls: list[str] = []
    _patch_chain(monkeypatch, calls)
    result = await _chain()
    assert result.ok is True
    i = calls.index("move_redis_master")
    assert calls[i - 1] == "verify_primary_moved" and calls[i + 1] == "drain"


@pytest.mark.asyncio
async def test_the_chain_skips_the_step_without_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redis_master.settings, "redis_url", "redis://redis:6379/0")
    calls: list[str] = []
    _patch_chain(monkeypatch, calls)
    result = await _chain()
    assert result.ok is True
    assert "move_redis_master" not in calls
    assert calls[calls.index("verify_primary_moved") + 1] == "drain"


@pytest.mark.asyncio
async def test_a_takeover_resumes_at_the_move_and_checkpoints_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drive that died inside the move resumes there: the checkpoint names
    the step, ``resume_from_checkpoint`` accepts it, and the chain re-runs it
    before the drain."""
    monkeypatch.setattr(redis_master.settings, "redis_url", URL)
    entry = per_node.checkpoint_entry(
        "node-a", "move_redis_master", stamped_at=None, pre_cordon={"was_unschedulable": False}
    )
    resume = per_node.resume_from_checkpoint(entry, "node-a")
    assert resume is not None and resume.step == "move_redis_master"
    calls: list[str] = []
    _patch_chain(monkeypatch, calls)
    stored: list[dict[str, Any]] = []

    async def _checkpoint(e: dict[str, Any]) -> None:
        stored.append(e)

    result = await _chain(resume=resume, checkpoint=_checkpoint)
    assert result.ok is True
    assert calls[:2] == ["move_redis_master", "drain"]
    assert stored[0]["step"] == "move_redis_master"


# ── the worker liveness probe ────────────────────────────────────────────────


GRACE = worker_liveness.DEFAULT_GRACE_S


def test_a_good_ping_is_alive_and_clears_the_failure_clock() -> None:
    assert worker_liveness.decide(
        now=1000, first_failure=900, ping_ok=True, broker_reachable=True, grace_s=GRACE
    ) == (True, None)


def test_a_broker_outage_is_not_counted_within_the_grace() -> None:
    alive, first = worker_liveness.decide(
        now=1000, first_failure=None, ping_ok=False, broker_reachable=False, grace_s=GRACE
    )
    assert alive is True and first == 1000
    alive, first = worker_liveness.decide(
        now=1000 + GRACE - 1,
        first_failure=1000,
        ping_ok=False,
        broker_reachable=False,
        grace_s=GRACE,
    )
    assert alive is True and first == 1000


def test_a_broker_outage_past_the_grace_counts_again() -> None:
    alive, _ = worker_liveness.decide(
        now=1000 + GRACE,
        first_failure=1000,
        ping_ok=False,
        broker_reachable=False,
        grace_s=GRACE,
    )
    assert alive is False


def test_a_silent_worker_on_a_healthy_broker_fails_at_once() -> None:
    alive, first = worker_liveness.decide(
        now=1000, first_failure=None, ping_ok=False, broker_reachable=True, grace_s=GRACE
    )
    assert alive is False and first == 1000


def test_a_flapping_broker_cannot_restart_the_grace() -> None:
    """Only a good ping clears the clock, so a broker that answers between
    outages does not buy a wedged worker a fresh grace."""
    _, first = worker_liveness.decide(
        now=1000, first_failure=None, ping_ok=False, broker_reachable=False, grace_s=GRACE
    )
    _, first = worker_liveness.decide(
        now=1030, first_failure=first, ping_ok=False, broker_reachable=True, grace_s=GRACE
    )
    alive, first = worker_liveness.decide(
        now=1000 + GRACE + 1,
        first_failure=first,
        ping_ok=False,
        broker_reachable=False,
        grace_s=GRACE,
    )
    assert alive is False and first == 1000


def test_main_records_and_clears_the_clock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state = tmp_path / "liveness"
    monkeypatch.setattr(worker_liveness, "_probe", lambda _n: (False, False))
    assert worker_liveness.main(["--state", str(state), "--node", "celery@w"]) == 0
    assert state.exists()
    monkeypatch.setattr(worker_liveness, "_probe", lambda _n: (False, True))
    assert worker_liveness.main(["--state", str(state), "--node", "celery@w"]) == 1
    monkeypatch.setattr(worker_liveness, "_probe", lambda _n: (True, True))
    assert worker_liveness.main(["--state", str(state), "--node", "celery@w"]) == 0
    assert not state.exists()


# ── the manifests that run it ────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parents[2]
_MANIFESTS = (
    _REPO / "charts" / "spatiumddi" / "templates" / "worker.yaml",
    _REPO / "k8s" / "base" / "worker.yaml",
)
_needs_manifests = pytest.mark.skipif(
    not _MANIFESTS[0].exists(), reason="charts/ not present in this checkout (dev container)"
)


def _worker_probe(path: Path) -> dict[str, Any]:
    text = path.read_text()
    # The worker container's probe is the first livenessProbe in the file
    # (beat's follows it in k8s/base).
    block = text[text.index("livenessProbe:") :]
    block = block[: block.index("failureThreshold:") + 40]
    grace = re.search(r"app\.worker_liveness --grace (\d+)", block)
    return {
        "grace": int(grace.group(1)) if grace else None,
        "period": int(re.search(r"periodSeconds: (\d+)", block).group(1)),  # type: ignore[union-attr]
        "timeout": int(re.search(r"timeoutSeconds: (\d+)", block).group(1)),  # type: ignore[union-attr]
        "threshold": int(re.search(r"failureThreshold: (\d+)", block).group(1)),  # type: ignore[union-attr]
    }


@_needs_manifests
@pytest.mark.parametrize("path", _MANIFESTS, ids=lambda p: str(p.relative_to(_REPO)))
def test_the_worker_probe_rides_out_a_broker_failover_but_stays_bounded(path: Path) -> None:
    probe = _worker_probe(path)
    assert probe["grace"] is not None, f"{path} does not run app.worker_liveness"
    # Longer than the ~128 s split-vote outage #2815 measured, with margin.
    assert probe["grace"] >= 240
    # A worker is restarted within 10 min of its last good ping, whatever the
    # broker does: the grace, then the kubelet's own failure budget.
    assert probe["grace"] + probe["period"] * probe["threshold"] <= 600
    # The probe's own worst case (import + 5 s connect + 5 s ping) fits.
    assert probe["timeout"] >= 12


@_needs_manifests
def test_the_chart_and_k8s_base_probes_agree() -> None:
    chart, base = (_worker_probe(p) for p in _MANIFESTS)
    assert chart == base
