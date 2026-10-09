"""#1449 — what ddi-pg's three-node roll of the rolling upgrade found.

* Draining the node the drive's worker runs on evicted the drive mid-chain,
  and the run sat in ``running`` with nothing driving it until Celery
  redelivered the task an hour later. That node now goes last, and the drive
  hands itself to a worker elsewhere before it is drained.
* One timed-out API read ended ``convergence`` as a crash while the node was
  rejoining after its reboot.
* A run that ended while the API was not answering kept the upgrade lease,
  refusing the next Start until it expired.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.services.appliance import k8s
from app.services.upgrades import mutex, node_order, per_node

# ── Node order: the drive's own node goes last ────────────────────────────────


def test_the_drives_own_node_is_taken_last() -> None:
    order = ["node-a", "node-b", "node-c"]
    assert node_order.next_node_to_upgrade(order, [], defer="node-a") == "node-b"
    assert node_order.next_node_to_upgrade(order, ["node-b"], defer="node-a") == "node-c"
    assert node_order.next_node_to_upgrade(order, ["node-b", "node-c"], defer="node-a") == "node-a"
    assert node_order.next_node_to_upgrade(order, order, defer="node-a") is None


def test_without_a_node_to_defer_the_plan_order_holds() -> None:
    order = ["node-a", "node-b"]
    assert node_order.next_node_to_upgrade(order, []) == "node-a"
    assert node_order.next_node_to_upgrade(order, [], defer="elsewhere") == "node-a"


# ── The drive hands itself off before its own node is drained ─────────────────


async def _running_run(db: Any, *, done: list[str]) -> Any:
    from app.models.system_upgrade import SystemUpgradeRun

    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version="2026.10.03-1",
        source_versions={},
        plan={
            "node_order": ["node-a", "node-b", "node-c"],
            "slot_image_url": "https://example.test/x.raw.xz",
        },
        progress={"per_node": {n: {"ok": True} for n in done}, "events": []},
        lease_holder="worker-a",
    )
    db.add(run)
    await db.commit()
    return run


@pytest.mark.asyncio
async def test_the_drive_hands_off_instead_of_draining_its_own_node(
    db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _running_run(db_session, done=["node-b", "node-c"])
    monkeypatch.setenv("NODE_NAME", "node-a")
    released: list[int] = []
    enqueued: list[tuple[Any, Any]] = []
    driven: list[str] = []

    def _release(**kw: Any) -> bool:
        released.append(kw.get("attempts", 1))
        return True

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        driven.append(node_name)
        raise AssertionError("the drive must not drain the node it runs on")

    monkeypatch.setattr(orch.mutex, "release_if_held", _release)
    monkeypatch.setattr(
        orch, "_enqueue_drive", lambda rid, *, avoid_node: enqueued.append((rid, avoid_node))
    )
    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    stop = asyncio.Event()
    await orch._drive_loop(db_session, run, stop)

    assert driven == []
    assert enqueued == [(run.id, "node-a")]
    assert released == [orch._LEASE_RELEASE_ATTEMPTS]
    # The renewal loop is stopped before the release, or a renew would write
    # this pod back in as the holder.
    assert stop.is_set()
    await db_session.refresh(run)
    assert run.state == "running"
    assert any(e.get("event") == "drive_handoff" for e in run.progress["events"])


@pytest.mark.asyncio
async def test_other_nodes_are_driven_before_the_drives_own(
    db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _running_run(db_session, done=[])
    monkeypatch.setenv("NODE_NAME", "node-a")
    driven: list[str] = []

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        driven.append(node_name)
        return per_node.SingleNodeResult(
            node_name=node_name, target_version="x", ok=False, failed_at="drain", steps=[]
        )

    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)
    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(orch.mutex, "release_if_held", lambda **_k: True)

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert driven == ["node-b"]


@pytest.mark.asyncio
async def test_a_failed_node_releases_the_lease_with_retries(
    db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _running_run(db_session, done=[])
    monkeypatch.delenv("NODE_NAME", raising=False)
    released: list[int] = []

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        return per_node.SingleNodeResult(
            node_name=node_name, target_version="x", ok=False, failed_at="convergence", steps=[]
        )

    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)
    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(
        orch.mutex, "release_if_held", lambda **kw: released.append(kw["attempts"]) or True
    )

    await orch._drive_loop(db_session, run, asyncio.Event())

    await db_session.refresh(run)
    assert run.state == "failed"
    assert released == [orch._LEASE_RELEASE_ATTEMPTS]


# ── The handed-off task is passed on, away from the node it is leaving ───────


def test_a_handed_off_drive_landing_on_the_node_it_left_is_passed_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task_mod

    monkeypatch.setenv("NODE_NAME", "node-a")
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(task_mod.drive_upgrade_run, "apply_async", lambda **kw: sent.append(kw))

    def _must_not_run(_rid: str) -> Any:
        raise AssertionError("ran on the node being drained")

    monkeypatch.setattr(task_mod, "_async_drive", _must_not_run)

    out = task_mod.drive_upgrade_run.run("run-1", avoid_node="node-a", hops=3)

    assert out["state"] == "passed_on"
    assert sent[0]["kwargs"] == {"avoid_node": "node-a", "hops": 4}
    assert sent[0]["countdown"] == task_mod._HANDOFF_HOP_DELAY_S


def test_a_handed_off_drive_runs_on_any_other_node(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.tasks import upgrade_orchestrator as task_mod

    monkeypatch.setenv("NODE_NAME", "node-b")
    ran: list[str] = []

    async def _drive(rid: str) -> dict[str, str]:
        ran.append(rid)
        return {"run_id": rid, "state": "running"}

    monkeypatch.setattr(task_mod, "_async_drive", _drive)

    task_mod.drive_upgrade_run.run("run-1", avoid_node="node-a")

    assert ran == ["run-1"]


def test_after_the_hop_limit_the_drive_runs_where_it_landed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No other worker took it (every other one down, say): running here,
    and being redelivered if the drain evicts it, beats never running."""
    from app.tasks import upgrade_orchestrator as task_mod

    monkeypatch.setenv("NODE_NAME", "node-a")
    ran: list[str] = []

    async def _drive(rid: str) -> dict[str, str]:
        ran.append(rid)
        return {"run_id": rid, "state": "running"}

    monkeypatch.setattr(task_mod, "_async_drive", _drive)

    task_mod.drive_upgrade_run.run("run-1", avoid_node="node-a", hops=task_mod._MAX_HANDOFF_HOPS)

    assert ran == ["run-1"]


# ── convergence waits through an API timeout ──────────────────────────────────


@pytest.mark.asyncio
async def test_convergence_keeps_polling_through_an_api_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    def _get_node(_name: str) -> tuple[int, dict[str, Any]]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise k8s.KubeapiUnavailableError("kubeapi GET /api/v1/nodes/seed: timed out")
        return 200, {"status": {"conditions": [{"type": "Ready", "status": "True"}]}}

    monkeypatch.setattr(per_node.k8s, "get_node", _get_node)
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _n: [])
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    result = await per_node._step_convergence("seed", timeout_s=5)

    assert result.ok, result.error
    assert calls["n"] == 2


# ── The lease release retries an unanswered API ───────────────────────────────


def _lease_body(holder: str) -> dict[str, Any]:
    return {
        "spec": {
            "holderIdentity": holder,
            "renewTime": "2099-01-01T00:00:00.000000Z",
            "leaseDurationSeconds": 600,
        }
    }


@pytest.fixture
def _with_sa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(k8s, "get_config", lambda: k8s._Config("h", 443, "t", "/ca", "spatium"))
    monkeypatch.setattr(mutex, "_identity", lambda: "worker-a")


@pytest.mark.usefixtures("_with_sa")
def test_release_retries_a_timed_out_read(monkeypatch: pytest.MonkeyPatch) -> None:
    reads = {"n": 0}
    cleared: list[str] = []

    def _get(*_a: Any, **_k: Any) -> tuple[int, dict[str, Any]]:
        reads["n"] += 1
        if reads["n"] == 1:
            raise k8s.KubeapiUnavailableError("timed out")
        return 200, _lease_body("worker-a")

    monkeypatch.setattr(mutex.k8s, "get_lease", _get)
    monkeypatch.setattr(mutex, "release", lambda **_k: cleared.append("x") or (True, None))

    assert mutex.release_if_held(attempts=3, retry_delay_s=0) is True
    assert cleared == ["x"]


@pytest.mark.usefixtures("_with_sa")
def test_release_retries_a_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter([(503, None), (200, _lease_body("worker-a"))])
    monkeypatch.setattr(mutex.k8s, "get_lease", lambda *_a, **_k: next(answers))
    monkeypatch.setattr(mutex, "release", lambda **_k: (True, None))

    assert mutex.release_if_held(attempts=3, retry_delay_s=0) is True


@pytest.mark.usefixtures("_with_sa")
def test_release_never_clears_a_lease_another_worker_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mutex.k8s, "get_lease", lambda *_a, **_k: (200, _lease_body("worker-b")))

    def _must_not_clear(**_k: Any) -> tuple[bool, None]:
        raise AssertionError("cleared another worker's lease")

    monkeypatch.setattr(mutex, "release", _must_not_clear)

    assert mutex.release_if_held(attempts=3, retry_delay_s=0) is False


@pytest.mark.usefixtures("_with_sa")
def test_release_gives_up_after_its_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    def _down(*_a: Any, **_k: Any) -> Any:
        raise k8s.KubeapiUnavailableError("timed out")

    monkeypatch.setattr(mutex.k8s, "get_lease", _down)

    assert mutex.release_if_held(attempts=2, retry_delay_s=0) is False


def test_release_without_a_service_account_is_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(k8s, "get_config", lambda: None)
    assert mutex.release_if_held(attempts=3, retry_delay_s=0) is False
