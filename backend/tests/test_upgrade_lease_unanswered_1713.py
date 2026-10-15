"""An unanswered kubeapi read is UNKNOWN, never "not held" (#1713), and a
``running`` run whose drive is gone is re-driven."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_upgrade import SystemUpgradeRun
from app.services.appliance import k8s
from app.services.upgrades import mutex, orchestrator, per_node, preflight

ME = "worker-0_aaaa"


def _lease(holder: str | None, age_s: float = 5.0) -> dict[str, Any]:
    t = datetime.fromtimestamp(datetime.now(UTC).timestamp() - age_s, UTC)
    return {
        "metadata": {"resourceVersion": "7"},
        "spec": {
            "holderIdentity": holder,
            "leaseDurationSeconds": 600,
            "renewTime": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "leaseTransitions": 1,
        },
    }


@pytest.fixture
def kube(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    st: dict[str, Any] = {"get": [(200, _lease(ME))], "updates": 0}
    monkeypatch.setattr(k8s, "get_config", lambda: object())

    def get_lease(name: str, namespace: str | None = None) -> Any:
        item = st["get"].pop(0) if len(st["get"]) > 1 else st["get"][0]
        if isinstance(item, Exception):
            raise item
        return item

    def update_lease(*a: Any, **kw: Any) -> tuple[bool, str | None]:
        st["updates"] += 1
        return True, None

    monkeypatch.setattr(k8s, "get_lease", get_lease)
    monkeypatch.setattr(k8s, "update_lease", update_lease)
    return st


def test_renew_with_unanswered_read_is_unknown_not_lost(kube: dict[str, Any]) -> None:
    kube["get"] = [k8s.KubeapiUnavailableError("timed out")]
    with pytest.raises(mutex.LeaseUnknownError):
        mutex.renew(holder=ME)
    kube["get"] = [(503, None)]
    with pytest.raises(mutex.LeaseUnknownError):
        mutex.renew(holder=ME)


def test_renew_still_reports_a_lease_seen_held_by_another(kube: dict[str, Any]) -> None:
    kube["get"] = [(200, _lease("someone-else"))]
    ok, err = mutex.renew(holder=ME)
    assert ok is False and "someone-else" in (err or "")


def test_get_state_is_not_free_when_unanswered(kube: dict[str, Any]) -> None:
    kube["get"] = [k8s.KubeapiUnavailableError("timed out")]
    st = mutex.get_state()
    assert st.held is True and st.holder == "<unreachable>"


@pytest.mark.asyncio
async def test_renewal_loop_survives_one_unanswered_read(
    kube: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.01)
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_RETRY_S", 0.01)
    kube["get"] = [k8s.KubeapiUnavailableError("timed out"), (200, _lease(ME))]
    stop = asyncio.Event()
    task = asyncio.create_task(orchestrator._lease_renewal_loop(stop, ME))
    await asyncio.sleep(0.2)
    assert not stop.is_set(), "one unanswered read must not stop the drive"
    assert kube["updates"] >= 1
    stop.set()
    await task


@pytest.mark.asyncio
async def test_renewal_loop_gives_up_once_the_lease_could_have_expired(
    kube: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.01)
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_RETRY_S", 0.01)
    monkeypatch.setattr(orchestrator, "_LEASE_SAFE_HOLD_S", 0.1)
    kube["get"] = [k8s.KubeapiUnavailableError("timed out")]
    stop = asyncio.Event()
    task = asyncio.create_task(orchestrator._lease_renewal_loop(stop, ME))
    await asyncio.wait_for(task, 2)
    assert stop.is_set()


# ── the give-up bound vs. the Lease's expiry (split-brain) ──────────────────


def test_give_up_is_strictly_before_anyone_else_may_take_the_lease() -> None:
    """A would-be acquirer takes over once ITS clock says leaseDurationSeconds
    passed since renewTime. The drive must have stopped starting work before
    then, with room for the renewal call (a read + a write at the kubeapi
    helpers' 10 s timeout, twice over for connect and read) and a minute of
    clock skew between workers."""
    worst_call_s = 2 * 2 * 10
    skew_s = 60
    assert orchestrator._LEASE_SAFE_HOLD_S + worst_call_s + skew_s < orchestrator.LEASE_DURATION_S
    # And it outlasts the normal renewal cadence: one late tick is retried.
    assert orchestrator._LEASE_SAFE_HOLD_S > orchestrator._LEASE_RENEW_INTERVAL_S


@pytest.mark.asyncio
async def test_unanswered_window_is_measured_from_the_attempt_that_wrote_renew_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slow renewal that lands must count from when it STARTED (its
    renewTime is stamped then), and the give-up must come before
    _LEASE_SAFE_HOLD_S has passed since that point, however slow each
    unanswered retry is."""
    clock = {"t": 1000.0}
    monkeypatch.setattr(orchestrator, "_monotonic", lambda: clock["t"])
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.001)
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_RETRY_S", 0.001)
    calls: list[float] = []
    gave_up_at: dict[str, float] = {}

    def renew(**_kw: Any) -> tuple[bool, str | None]:
        calls.append(clock["t"])
        clock["t"] += 20.0  # every call takes 20 s
        if len(calls) == 1:
            return True, None  # started at 1000, landed at 1020
        raise mutex.LeaseUnknownError("timed out")

    monkeypatch.setattr(orchestrator.mutex, "renew", renew)
    stop, done = asyncio.Event(), asyncio.Event()

    async def watch() -> None:
        await stop.wait()
        gave_up_at["t"] = clock["t"]
        done.set()

    w = asyncio.create_task(watch())
    await asyncio.wait_for(orchestrator._lease_renewal_loop(stop, ME, done, 990.0), 5)
    await w
    # Lease renewTime ≈ 1000 (the first attempt's start). Gave up strictly
    # before 1000 + SAFE_HOLD + one call, i.e. well before 1000 + 600.
    assert gave_up_at["t"] <= 1000.0 + orchestrator._LEASE_SAFE_HOLD_S + 20.0
    assert gave_up_at["t"] < 1000.0 + orchestrator.LEASE_DURATION_S - 60


@pytest.mark.asyncio
async def test_renewal_outlives_a_give_up_and_reconfirms_the_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After giving up the drive starts nothing new, but its node in flight
    still runs: the renewal keeps trying, so the Lease stays its and no other
    drive is started beside that node."""
    clock = {"t": 0.0}
    monkeypatch.setattr(orchestrator, "_monotonic", lambda: clock["t"])
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_INTERVAL_S", 0.001)
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_RETRY_S", 0.001)
    n = {"calls": 0}

    def renew(**_kw: Any) -> tuple[bool, str | None]:
        n["calls"] += 1
        clock["t"] += 100.0
        if n["calls"] <= 6:
            raise mutex.LeaseUnknownError("timed out")
        return True, None

    monkeypatch.setattr(orchestrator.mutex, "renew", renew)
    stop, done, ok = asyncio.Event(), asyncio.Event(), asyncio.Event()
    ok.set()
    task = asyncio.create_task(orchestrator._lease_renewal_loop(stop, ME, done, 0.0, ok))
    for _ in range(500):
        if ok.is_set() and n["calls"] > 6:
            break
        await asyncio.sleep(0.005)
    assert stop.is_set(), "the drive must have been told to stop starting work"
    assert ok.is_set(), "a renewal that landed after the give-up re-confirms the Lease"
    done.set()
    await asyncio.wait_for(task, 2)


@pytest.mark.asyncio
async def test_drive_starts_no_node_while_the_lease_is_unknown(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version="2026.10.20-1",
        source_versions={},
        plan={"node_order": ["node-a", "node-b"], "slot_image_url": "http://x"},
        progress={"per_node": {}, "events": [{"event": "started"}]},
        lease_holder=ME,
        started_at=datetime.now(UTC),
    )
    db_session.add(run)
    await db_session.commit()
    started: list[str] = []

    async def node(*_a: Any, **_kw: Any) -> Any:
        started.append("node")
        raise AssertionError("no node may start while the Lease is unknown")

    monkeypatch.setattr(per_node, "single_node_upgrade", node)
    monkeypatch.setattr(orchestrator, "_LEASE_RENEW_RETRY_S", 0.01)
    monkeypatch.setattr(orchestrator.mutex, "release_if_held", lambda **_kw: False)
    stop, ok = asyncio.Event(), asyncio.Event()  # ok cleared: last renewal unanswered

    async def give_up() -> None:
        await asyncio.sleep(0.1)
        stop.set()

    await asyncio.gather(
        orchestrator._drive_loop(db_session, run, stop, ME, lease_ok=ok), give_up()
    )
    assert started == []


def test_own_runs_preflight_does_not_fail_on_an_unanswered_lease_read(
    kube: dict[str, Any],
) -> None:
    """The per-node preflight of the drive holding the Lease: an unanswered
    read is a warning, not a failed node (and a failed run)."""
    kube["get"] = [k8s.KubeapiUnavailableError("timed out")]
    assert preflight.check_inflight_conflict(own_holder=ME).level == "warn"
    # Plan (no holder) stays conservative.
    assert preflight.check_inflight_conflict().level == "fail"


# ── the orphan sweep ─────────────────────────────────────────────────────────


class FakeRedis:
    def __init__(self) -> None:
        self.d: dict[str, str] = {}

    def get(self, k: str) -> str | None:
        return self.d.get(k)

    def set(self, k: str, v: str, nx: bool = False, ex: int | None = None) -> bool:
        if nx and k in self.d:
            return False
        self.d[k] = v
        return True

    def delete(self, k: str) -> int:
        return 1 if self.d.pop(k, None) is not None else 0


@pytest.fixture
def driven(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    from app.tasks import upgrade_orchestrator as t

    calls: list[Any] = []
    monkeypatch.setattr(
        t.drive_upgrade_run, "apply_async", lambda **kw: calls.append(kw), raising=False
    )
    return calls


def _runs(rid: uuid.UUID, progress: dict[str, Any] | None = None) -> list[Any]:
    return [(rid, progress or {"events": [{"event": "started"}]})]


def test_running_run_with_dead_drive_is_redriven_exactly_once(
    kube: dict[str, Any], driven: list[Any]
) -> None:
    from app.tasks import upgrade_orchestrator as t

    kube["get"] = [(200, _lease(None, age_s=900))]  # released / expired
    r = FakeRedis()
    rid = uuid.uuid4()
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1000.0) == []  # first sighting
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1010.0) == []  # too soon
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1100.0) == [str(rid)]
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1160.0) == []  # cooldown
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1230.0) == []  # cooldown
    assert len(driven) == 1 and driven[0]["args"] == [str(rid)]


def test_sweep_leaves_a_run_whose_lease_is_held_or_unreadable(
    kube: dict[str, Any], driven: list[Any]
) -> None:
    from app.tasks import upgrade_orchestrator as t

    r = FakeRedis()
    rid = uuid.uuid4()
    for lease in ((200, _lease(ME)), k8s.KubeapiUnavailableError("timed out"), (503, None)):
        kube["get"] = [lease]
        for now in (1000.0, 1100.0, 1200.0):
            assert t.resume_orphaned_runs_sync(_runs(rid), r, now=now) == []
    assert driven == []


def test_a_lease_seen_held_restarts_the_count(kube: dict[str, Any], driven: list[Any]) -> None:
    """Two free sightings must be consecutive: a free, held, free sequence
    (a hand-off, a takeover) is not an orphan."""
    from app.tasks import upgrade_orchestrator as t

    r, rid = FakeRedis(), uuid.uuid4()
    kube["get"] = [(200, _lease(None, age_s=900))]
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1000.0) == []
    kube["get"] = [(200, _lease(ME))]
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1060.0) == []
    kube["get"] = [(200, _lease(None, age_s=900))]
    assert t.resume_orphaned_runs_sync(_runs(rid), r, now=1120.0) == []
    assert driven == []


def test_a_hand_off_in_transit_is_not_an_orphan_and_its_request_is_kept(
    kube: dict[str, Any], driven: list[Any]
) -> None:
    """A drive handing itself on releases the Lease while the task hops to a
    worker elsewhere (#1449). Inside that window nothing is re-driven; after
    it, the re-drive still asks not to run on the node being drained."""
    from app.tasks import upgrade_orchestrator as t

    kube["get"] = [(200, _lease(None, age_s=900))]
    at = datetime.fromtimestamp(10_000.0, UTC).isoformat()
    progress = {"events": [{"event": "drive_handoff", "node": "node-c", "at": at}]}
    r, rid = FakeRedis(), uuid.uuid4()
    for now in (10_060.0, 10_120.0, 10_200.0):
        assert t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=now) == []
    late = 10_000.0 + t._HANDOFF_GRACE_S
    assert t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=late) == []
    assert t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=late + 60) == [str(rid)]
    assert driven[0]["kwargs"] == {"avoid_node": "node-c"}


def test_a_version_hand_off_redrive_still_avoids_the_old_tag(
    kube: dict[str, Any], driven: list[Any]
) -> None:
    from app.tasks import upgrade_orchestrator as t

    kube["get"] = [(200, _lease(None, age_s=900))]
    at = datetime.fromtimestamp(10_000.0, UTC).isoformat()
    progress = {
        "events": [{"event": "drive_version_handoff", "at": at}],
        "shared_tags": {"from_tag": "2026.10.01-1", "flip": {"handed_off_at": at}},
    }
    r, rid = FakeRedis(), uuid.uuid4()
    assert t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=10_300.0) == []
    assert t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=10_400.0) == []
    late = 10_000.0 + t._VERSION_HANDOFF_GRACE_S
    t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=late)
    assert t.resume_orphaned_runs_sync(_runs(rid, progress), r, now=late + 60) == [str(rid)]
    assert driven[0]["kwargs"] == {"avoid_version": "2026.10.01-1"}


def test_sweep_task_is_a_no_op_without_a_kubeapi_and_survives_redis_down(
    monkeypatch: pytest.MonkeyPatch, driven: list[Any]
) -> None:
    from redis.exceptions import ConnectionError as RedisConnectionError

    from app.tasks import upgrade_orchestrator as t

    monkeypatch.setattr(k8s, "get_config", lambda: None)
    called: list[str] = []
    monkeypatch.setattr(t, "_running_runs", lambda: called.append("db"))
    assert t.resume_orphaned_runs() == []
    assert called == [], "docker-compose: not even the DB is read"

    class DownRedis(FakeRedis):
        def get(self, k: str) -> str | None:
            raise RedisConnectionError("down")

        def delete(self, k: str) -> int:
            raise RedisConnectionError("down")

    monkeypatch.setattr(k8s, "get_config", lambda: object())
    monkeypatch.setattr(k8s, "get_lease", lambda *_a, **_k: (200, _lease(None, age_s=900)))

    async def runs() -> list[Any]:
        return _runs(uuid.uuid4())

    monkeypatch.setattr(t, "_running_runs", runs)
    monkeypatch.setattr(t, "_sweep_redis", DownRedis)
    for _ in range(3):
        assert t.resume_orphaned_runs() == []
    assert driven == []
