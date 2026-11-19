"""#1710, #1427 — a rolling upgrade moves the shared charts' image tag once, at the end.

A cluster shares three k3s HelmCharts, each with ONE image tag for workloads
on every node, and every pod is ``imagePullPolicy: Never``. The seed's
firstboot re-rendered the bootstrap and control charts from its own new slot,
and the first upgraded member's supervisor wrote the appliance chart from its
own: ddi-pg's three-node roll saw dhcp-kea and dns-bind9 roll onto the target
27 s after member-1 passed, on the seed and member-2 still on the old slot
(ErrImageNeverPull, DNS and DHCP down there), and the control plane move at
the seed's reboot while a member was still to go.

The contract (mzac, on #1427): the shared tags stay on the version the cluster
runs until every node reports the target, then move once.

* Before its first node the run pins the bootstrap and control charts' tag in
  their HelmChartConfigs, and re-asserts the pins before every node.
* With the tags it pins the control chart's ``applianceVersion``, the value
  that sets APPLIANCE_VERSION in the api, worker and beat env (#2004), to the
  version the control plane reports (#2176). The seed's firstboot moves it
  with the tag, and a pod template that changes rolls the pods whatever their
  image: the control plane rolled mid-run on the held image and shut down the
  worker the drive ran on.
* Each node of the run is told, in its heartbeat, that the cluster is held.
* When every node is done, the flip removes the pins (the keys, so nothing
  outlives the run), ends the hold, and hands the rest of the run to a worker
  on the new version, because the flip rolls the worker the drive is on.
* That worker waits for every workload the flip moves, then verifies.
* A failed run keeps its hold until every member reports one version.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from typing import Any

import pytest
import yaml
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance import k8s
from app.services.appliance.ca import generate_session_token
from app.services.upgrades import per_node

FROM = "2026.10.13-1"
TO = "2026.10.14-1"
# The version the control plane on FROM reports (APPLIANCE_VERSION). A
# release's is its tag; a nightly's is not (below).
FROM_VERSION = FROM
NODES = ["node-a", "node-b", "node-c"]
CONTROL_OVERRIDES = "api:\n  replicas: 3\nworker:\n  replicas: 3\n"


def _image(tag: str, name: str = "spatiumddi-api") -> str:
    return f"ghcr.io/spatiumnorth/{name}:{tag}"


def _deployment(name: str, image: str, *, rolled: bool = True) -> dict[str, Any]:
    return {
        "metadata": {"name": name, "generation": 2},
        "spec": {"replicas": 3, "template": {"spec": {"containers": [{"image": image}]}}},
        "status": {
            "observedGeneration": 2,
            "updatedReplicas": 3 if rolled else 1,
            "availableReplicas": 3 if rolled else 2,
        },
    }


def _daemonset(name: str, image: str, *, rolled: bool = True) -> dict[str, Any]:
    return {
        "metadata": {"name": name, "generation": 2},
        "spec": {"template": {"spec": {"containers": [{"image": image}]}}},
        "status": {
            "observedGeneration": 2,
            "desiredNumberScheduled": 3,
            "updatedNumberScheduled": 3 if rolled else 1,
            "numberAvailable": 3 if rolled else 2,
        },
    }


class FakeCluster:
    """The kubeapi the orchestrator sees: kube-system's HelmChartConfigs
    (name -> valuesContent) and the release namespace's workloads."""

    def __init__(self, hccs: dict[str, str] | None = None) -> None:
        self.hccs: dict[str, str] = dict(hccs or {})
        self.writes: list[str] = []
        self.deployments: list[dict[str, Any]] = []
        self.daemonsets: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(k8s, "get_config", lambda: k8s._Config("h", 443, "t", "/ca", "spatium"))
        monkeypatch.setattr(k8s, "get_helmchartconfig", self.get_helmchartconfig)
        monkeypatch.setattr(k8s, "upsert_helmchartconfig", self.upsert_helmchartconfig)
        monkeypatch.setattr(k8s, "list_deployments", self.list_deployments)
        monkeypatch.setattr(k8s, "list_daemonsets", self.list_daemonsets, raising=False)
        # The old end-of-roll path reads these one by one; nothing here.
        monkeypatch.setattr(k8s, "get_deployment", lambda *_a, **_k: (404, None))
        monkeypatch.setattr(k8s, "get_job", lambda *_a, **_k: (404, None))

    def get_helmchartconfig(self, name: str, namespace: str = "kube-system") -> Any:
        assert namespace == "kube-system"
        if name not in self.hccs:
            return 404, None
        return 200, {"spec": {"valuesContent": self.hccs[name]}}

    def upsert_helmchartconfig(
        self, name: str, values_yaml: str, *, namespace: str = "kube-system"
    ) -> tuple[bool, str | None]:
        assert namespace == "kube-system"
        self.hccs[name] = values_yaml
        self.writes.append(name)
        return True, None

    def list_deployments(self, _selector: str, namespace: str | None = None) -> Any:
        assert namespace == "spatium"
        return 200, list(self.deployments)

    def list_daemonsets(self, _selector: str = "", namespace: str | None = None) -> Any:
        assert namespace == "spatium"
        return 200, list(self.daemonsets)

    def values(self, name: str) -> Any:
        return yaml.safe_load(self.hccs.get(name) or "") or {}


def _held_cluster() -> FakeCluster:
    """The cluster in the middle of a held roll: every pin in place."""
    return FakeCluster(
        {
            "spatium-bootstrap": f"global:\n  imageTag: {FROM}\n",
            "spatium-control": CONTROL_OVERRIDES
            + f"applianceVersion: '{FROM_VERSION}'\nimage:\n  tag: {FROM}\n",
        }
    )


def _hold_record(**over: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "mode": "hold",
        "from_tag": FROM,
        "from_version": FROM_VERSION,
        "to_tag": TO,
        "nodes": list(NODES),
        "placed_at": "2026-10-13T18:00:00Z",
        "released_at": None,
        "release_reason": None,
    }
    record.update(over)
    return record


async def _run(
    db: AsyncSession,
    *,
    done: list[str],
    nodes: list[str] | None = None,
    state: str = "running",
    shared: dict[str, Any] | None = None,
) -> Any:
    from app.models.system_upgrade import SystemUpgradeRun

    progress: dict[str, Any] = {"per_node": {n: {"ok": True} for n in done}, "events": []}
    if shared is not None:
        progress["shared_tags"] = shared
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state=state,
        target_version=TO,
        source_versions={},
        plan={
            "node_order": list(nodes or NODES),
            "slot_image_url": "https://example.test/x.raw.xz",
        },
        progress=progress,
        lease_holder="worker-a",
    )
    db.add(run)
    await db.commit()
    return run


def _quiet(monkeypatch: pytest.MonkeyPatch, orch: Any) -> list[str]:
    """No alerts, no lease, no pause; returns the wakes published."""
    wakes: list[str] = []

    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    async def _wake(*channels: str) -> None:
        wakes.extend(channels)

    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(orch.mutex, "release_if_held", lambda **_k: True)
    monkeypatch.setattr(orch, "_BETWEEN_NODES_PAUSE_S", 0.0)
    monkeypatch.setattr("app.core.agent_wake.publish_wake", _wake)
    monkeypatch.delenv("NODE_NAME", raising=False)
    return wakes


def _node_result(node_name: str, ok: bool) -> per_node.SingleNodeResult:
    return per_node.SingleNodeResult(
        node_name=node_name,
        target_version=TO,
        ok=ok,
        failed_at=None if ok else "drain",
        steps=[],
    )


# ── Start: the hold is in place before the first node ────────────────────────


@pytest.mark.asyncio
async def test_the_run_pins_the_running_tag_before_its_first_node(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FakeCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", FROM)
    monkeypatch.setattr(settings, "appliance_version", FROM_VERSION)
    seen: dict[str, dict[str, Any]] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = {n: cluster.values(n) for n in ("spatium-bootstrap", "spatium-control")}
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event())

    # When the first node starts, both charts are pinned to the running tag,
    # and the control chart to the running version (#2176); the supervisor's
    # overrides in the control chart's config are kept.
    assert seen["node-a"]["spatium-bootstrap"] == {"global": {"imageTag": FROM}}
    assert seen["node-a"]["spatium-control"] == {
        "api": {"replicas": 3},
        "worker": {"replicas": 3},
        "image": {"tag": FROM},
        "applianceVersion": FROM_VERSION,
    }
    await db_session.refresh(run)
    record = run.progress["shared_tags"]
    assert record["mode"] == "hold"
    assert (record["from_tag"], record["to_tag"], record["nodes"]) == (FROM, TO, NODES)
    assert record["from_version"] == FROM_VERSION
    # The node failed: the run is failed, and the hold stays.
    assert run.state == "failed"
    assert record["released_at"] is None


@pytest.mark.asyncio
async def test_the_pins_are_put_back_before_every_node(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The seed supervisor writes the control chart's config as a read then a
    PATCH; a write racing the pin can drop it. The next node re-pins."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FakeCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", FROM)
    seen: dict[str, Any] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = cluster.values("spatium-control")
        if node_name == "node-a":
            cluster.hccs["spatium-control"] = CONTROL_OVERRIDES  # the race lost the pin
            return _node_result(node_name, ok=True)
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert seen["node-b"]["image"] == {"tag": FROM}


@pytest.mark.asyncio
async def test_2176_a_nightly_is_held_to_the_version_it_reports_not_to_its_tag(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """qa-review's roll e270838d (#2176): the control plane ran image tag
    ``nightly-20261017`` and reported ``0.0.0-nightly-20261017+cf80471``. The
    seed's firstboot on the target moved APPLIANCE_VERSION alone, and the
    api, worker and beat rolled on every node on the held image. The pin is
    the value the pods carry, set with the tag in one write of the control
    chart's config, so helm-controller renders it once."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=[])
    cluster = FakeCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", "nightly-20261017")
    monkeypatch.setattr(settings, "appliance_version", "0.0.0-nightly-20261017+cf80471")
    seen: dict[str, Any] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = cluster.values("spatium-control")
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert seen["node-a"]["image"] == {"tag": "nightly-20261017"}
    assert seen["node-a"]["applianceVersion"] == "0.0.0-nightly-20261017+cf80471"
    assert cluster.writes == ["spatium-bootstrap", "spatium-control"]
    await db_session.refresh(run)
    assert run.progress["shared_tags"]["from_version"] == "0.0.0-nightly-20261017+cf80471"


@pytest.mark.asyncio
async def test_2176_the_version_put_back_before_a_node_is_the_holds_own(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A write racing the pin can drop the version as it can the tag. The
    next node puts back the version the hold recorded at its placement,
    whatever the process driving the run now reports."""
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=["node-a"], shared=_hold_record())
    cluster = FakeCluster(
        {
            "spatium-bootstrap": f"global:\n  imageTag: {FROM}\n",
            "spatium-control": CONTROL_OVERRIDES + f"image:\n  tag: {FROM}\n",
        }
    )
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", FROM)
    monkeypatch.setattr(settings, "appliance_version", "something-else")
    seen: dict[str, Any] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = cluster.values("spatium-control")
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert seen["node-b"]["applianceVersion"] == FROM_VERSION
    assert seen["node-b"]["image"] == {"tag": FROM}


@pytest.mark.asyncio
async def test_2176_a_hold_placed_before_the_version_pin_pins_its_tags_only(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hold whose record names no version was placed by a drive from
    before #2176, which pinned the tags alone. Re-asserting it pins what that
    drive pinned, and writes no version of its own into the pod template."""
    from app.services.upgrades import orchestrator as orch

    record = _hold_record()
    del record["from_version"]
    run = await _run(db_session, done=["node-a"], shared=record)
    cluster = FakeCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", FROM)
    monkeypatch.setattr(settings, "appliance_version", FROM_VERSION)
    seen: dict[str, Any] = {}

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        seen[node_name] = cluster.values("spatium-control")
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert seen["node-b"] == {
        "api": {"replicas": 3},
        "worker": {"replicas": 3},
        "image": {"tag": FROM},
    }


@pytest.mark.asyncio
async def test_a_new_runs_hold_takes_over_a_failed_runs(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    old = await _run(db_session, done=["node-a"], state="failed", shared=_hold_record())
    run = await _run(db_session, done=[])
    _held_cluster().install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", FROM)

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, run, asyncio.Event())

    await db_session.refresh(old)
    await db_session.refresh(run)
    assert run.progress["shared_tags"]["mode"] == "hold"
    assert old.progress["shared_tags"]["release_reason"] == f"superseded:{run.id}"


@pytest.mark.asyncio
async def test_a_run_started_without_a_hold_is_not_held_mid_roll(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A drive from before the hold drove its first nodes with the tags free:
    they may have moved already, and pinning them now would roll the control
    plane back mid-run. Nor is a one-node run held: it has no other node."""
    from app.services.upgrades import orchestrator as orch

    legacy = await _run(db_session, done=["node-a"])
    lone = await _run(db_session, done=[], nodes=["node-a"])
    cluster = FakeCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)

    async def _single(*_a: Any, node_name: str, **_k: Any) -> Any:
        return _node_result(node_name, ok=False)

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)

    await orch._drive_loop(db_session, legacy, asyncio.Event())
    await orch._drive_loop(db_session, lone, asyncio.Event())

    assert cluster.writes == []
    await db_session.refresh(legacy)
    await db_session.refresh(lone)
    assert legacy.progress["shared_tags"]["mode"] == "legacy"
    assert "shared_tags" not in lone.progress


# ── The flip ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_flip_unpins_ends_the_hold_and_hands_off_to_the_new_version(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _run(db_session, done=NODES, shared=_hold_record())
    cluster = _held_cluster()
    cluster.deployments = [
        _deployment("spatium-control-spatiumddi-worker", _image(FROM)),
        _deployment("spatium-bootstrap-cloudnative-pg", "ghcr.io/cloudnative-pg/cnpg:1.30.1"),
    ]
    cluster.daemonsets = [_daemonset("dns-bind9", _image(FROM, "dns-bind9"))]
    cluster.install(monkeypatch)
    wakes = _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", FROM)  # this drive runs the old tag
    enqueued: list[tuple[Any, str]] = []
    monkeypatch.setattr(
        orch,
        "_enqueue_continuation",
        lambda rid, *, avoid_version: enqueued.append((rid, avoid_version)),
        raising=False,
    )

    async def _must_not_verify(**_k: Any) -> Any:
        raise AssertionError("the old-version drive must hand off before it waits or verifies")

    monkeypatch.setattr(orch.safety, "verify_post_upgrade", _must_not_verify)

    stop = asyncio.Event()
    await orch._drive_loop(db_session, run, stop, "worker-a")

    # Every pin is gone, the version's too (#2176): the keys, not set to the
    # target, so nothing pins the charts once the run is over. The
    # supervisor's overrides stay.
    assert cluster.values("spatium-bootstrap") == {}
    assert cluster.values("spatium-control") == {"api": {"replicas": 3}, "worker": {"replicas": 3}}
    await db_session.refresh(run)
    record = run.progress["shared_tags"]
    assert record["released_at"] and record["release_reason"] == "flip"
    assert record["flip"]["state"] == "flipped"
    # What the flip moves: only the workloads on the old tag.
    assert record["flip"]["workloads"] == [
        {"kind": "DaemonSet", "name": "dns-bind9"},
        {"kind": "Deployment", "name": "spatium-control-spatiumddi-worker"},
    ]
    # The supervisors hear of it now, and the rest goes to the new version.
    assert wakes
    assert enqueued == [(run.id, FROM)]
    assert stop.is_set()
    assert run.state == "running"


@pytest.mark.asyncio
async def test_the_new_version_waits_for_every_moved_workload_then_succeeds(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch
    from app.services.upgrades import safety

    flip = {
        "state": "flipped",
        "workloads": [
            {"kind": "DaemonSet", "name": "dns-bind9"},
            {"kind": "Deployment", "name": "spatium-control-spatiumddi-worker"},
        ],
        "handed_off_at": "2026-10-13T19:00:00Z",
    }
    run = await _run(
        db_session,
        done=NODES,
        shared=_hold_record(released_at="2026-10-13T19:00:00Z", release_reason="flip", flip=flip),
    )
    cluster = FakeCluster({"spatium-control": CONTROL_OVERRIDES})
    cluster.deployments = [_deployment("spatium-control-spatiumddi-worker", _image(TO))]
    cluster.daemonsets = [_daemonset("dns-bind9", _image(TO, "dns-bind9"))]
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)
    monkeypatch.setattr(settings, "version", TO)  # a worker on the new tag

    async def _verify(**_k: Any) -> Any:
        return [
            safety.VerificationCheck(name="cnpg_instances", level="ok", message="3/3", detail={})
        ]

    monkeypatch.setattr(orch.safety, "verify_post_upgrade", _verify)

    await orch._drive_loop(db_session, run, asyncio.Event(), "worker-a")

    await db_session.refresh(run)
    assert run.state == "succeeded"
    flip_after = run.progress["shared_tags"]["flip"]
    assert flip_after["state"] == "settled"
    assert sorted(flip_after["rolled"]) == [
        "DaemonSet/dns-bind9",
        "Deployment/spatium-control-spatiumddi-worker",
    ]
    # The old end-of-roll write is not made: the HelmChartConfig keeps no tag.
    assert cluster.values("spatium-control") == {"api": {"replicas": 3}, "worker": {"replicas": 3}}


@pytest.mark.asyncio
async def test_a_workload_counts_only_once_its_new_template_has_rolled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1829's race, in the flip's wait: a rollout status read before
    helm-controller re-rendered the workload is not 'rolled'."""
    from app.services.upgrades import shared_tags

    polls = iter(
        [
            [_deployment("w", _image(FROM))],  # not re-rendered yet, status complete
            [_deployment("w", _image(TO), rolled=False)],  # rolling
            [_deployment("w", _image(TO))],  # rolled
        ]
    )
    reads: list[int] = []

    def _list(_selector: str, namespace: str | None = None) -> Any:
        reads.append(1)
        return 200, next(polls)

    monkeypatch.setattr(k8s, "list_deployments", _list)
    monkeypatch.setattr(k8s, "list_daemonsets", lambda *_a, **_k: (200, []), raising=False)
    monkeypatch.setattr(shared_tags, "_POLL_INTERVAL_S", 0.0)

    ok, rolled, pending, error = await shared_tags.wait_rolled(
        [{"kind": "Deployment", "name": "w"}], to_tag=TO, from_tag=FROM, timeout_s=60
    )

    assert (ok, rolled, pending, error) == (True, ["Deployment/w"], [], None)
    assert len(reads) == 3


@pytest.mark.asyncio
async def test_the_wait_names_what_never_rolled(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.upgrades import shared_tags

    monkeypatch.setattr(
        k8s, "list_deployments", lambda *_a, **_k: (200, [_deployment("w", _image(FROM))])
    )
    monkeypatch.setattr(k8s, "list_daemonsets", lambda *_a, **_k: (200, []), raising=False)
    monkeypatch.setattr(shared_tags, "_POLL_INTERVAL_S", 0.0)

    ok, rolled, pending, error = await shared_tags.wait_rolled(
        [{"kind": "Deployment", "name": "w"}], to_tag=TO, from_tag=FROM, timeout_s=0
    )

    assert not ok and rolled == [] and pending == ["Deployment/w"]
    assert error is not None and "Deployment/w" in error


# ── The rest of the run goes to a worker on the new version ──────────────────


def test_the_rest_of_the_run_landing_on_an_old_version_worker_is_passed_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task_mod

    monkeypatch.setattr(settings, "version", FROM)
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(task_mod.drive_upgrade_run, "apply_async", lambda **kw: sent.append(kw))

    def _must_not_run(_rid: str) -> Any:
        raise AssertionError("ran on a worker the flip is rolling away")

    monkeypatch.setattr(task_mod, "_async_drive", _must_not_run)

    out = task_mod.drive_upgrade_run.run("run-1", avoid_version=FROM)

    assert out["state"] == "passed_on"
    assert sent[0]["kwargs"] == {"avoid_version": FROM, "hops": 1}
    assert sent[0]["countdown"] == task_mod._HANDOFF_HOP_DELAY_S


def test_the_rest_of_the_run_runs_on_a_new_version_worker_or_after_the_hops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import upgrade_orchestrator as task_mod

    ran: list[str] = []

    async def _drive(rid: str, *, avoid_version: str | None = None) -> dict[str, str]:
        ran.append(rid)
        return {"run_id": rid, "state": "running"}

    monkeypatch.setattr(task_mod, "_async_drive", _drive)

    monkeypatch.setattr(settings, "version", TO)
    task_mod.drive_upgrade_run.run("run-1", avoid_version=FROM)
    # No new worker came up in time: run here; a drive killed by the roll is
    # redelivered and resumes after the flip.
    monkeypatch.setattr(settings, "version", FROM)
    task_mod.drive_upgrade_run.run(
        "run-2", avoid_version=FROM, hops=getattr(task_mod, "_MAX_VERSION_HOPS", 0)
    )

    assert ran == ["run-1", "run-2"]


# ── Each node of the run hears of the hold in its heartbeat ──────────────────


async def _supervisor(
    db: AsyncSession, hostname: str, cluster_role: str | None = "member"
) -> tuple[Appliance, str]:
    platform = await db.get(PlatformSettings, 1)
    if platform is None:
        platform = PlatformSettings(id=1)
        db.add(platform)
    platform.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
        cluster_role=cluster_role,
    )
    db.add(row)
    await db.commit()
    return row, token


async def _heartbeat(client: AsyncClient, row: Appliance, token: str) -> Any:
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(row.id),
            "session_token": token,
            "capabilities": {"can_run_observer": True},
        },
    )
    assert r.status_code == 200, r.text
    return r.json().get("shared_chart_hold")


@pytest.mark.asyncio
async def test_each_node_of_a_held_run_and_only_those_hear_of_the_hold(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    run = await _run(db_session, done=["node-a"], shared=_hold_record())
    member, member_token = await _supervisor(db_session, "Node-B")  # names differ in case
    remote, remote_token = await _supervisor(db_session, "branch-dns-1")

    assert await _heartbeat(client, member, member_token) == {
        "run_id": str(run.id),
        "from_tag": FROM,
        "target_version": TO,
    }
    # An appliance outside the cluster writes its own chart: never held.
    assert await _heartbeat(client, remote, remote_token) is None


@pytest.mark.asyncio
async def test_the_hold_ends_in_the_heartbeat_when_the_run_releases_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    run = await _run(db_session, done=NODES, shared=_hold_record())
    member, token = await _supervisor(db_session, "node-c")
    assert await _heartbeat(client, member, token) is not None

    run.progress = {
        **run.progress,
        "shared_tags": _hold_record(released_at="2026-10-13T19:00:00Z", release_reason="flip"),
    }
    await db_session.commit()

    assert await _heartbeat(client, member, token) is None


@pytest.mark.asyncio
async def test_a_node_no_longer_in_the_cluster_is_not_held(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A node of the run demoted after it failed runs its own k3s and its own
    role chart: a hold on charts it no longer reads would only stop it
    writing its own."""
    await _run(db_session, done=["node-a"], state="failed", shared=_hold_record())
    left, token = await _supervisor(db_session, "node-b", cluster_role=None)

    assert await _heartbeat(client, left, token) is None


@pytest.mark.asyncio
async def test_a_hold_is_found_however_many_runs_came_after_it(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed run's hold outlives later Plans that never started. Looked up
    among the newest few runs only, it fell out of sight: the supervisors
    stopped hearing of it and the beat task never took its pins off."""
    from app.services.upgrades import shared_tags

    held = await _run(db_session, done=["node-a"], state="failed", shared=_hold_record())
    for _ in range(6):
        await _run(db_session, done=[], state="aborted")
    member, token = await _supervisor(db_session, "node-b")

    assert (await _heartbeat(client, member, token) or {}).get("run_id") == str(held.id)

    cluster = _held_cluster()
    cluster.install(monkeypatch)
    monkeypatch.setattr("app.core.agent_wake.publish_wake", _no_wake)
    await db_session.delete(member)
    await db_session.commit()
    for name, role in (("node-a", "primary"), ("node-b", "member"), ("node-c", "member")):
        await _member_row(db_session, name, role, TO)
    assert await shared_tags.release_lingering_hold(db_session) == {
        "run_id": str(held.id),
        "version": TO,
    }
    assert cluster.values("spatium-bootstrap") == {}


async def _no_wake(*_channels: str) -> None:
    return None


# ── A failed run's hold ends once every member reports one version ───────────


async def _member_row(db: AsyncSession, hostname: str, role: str, version: str | None) -> None:
    der = os.urandom(32)
    db.add(
        Appliance(
            id=uuid.uuid4(),
            hostname=hostname,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            cluster_role=role,
            installed_appliance_version=version,
        )
    )
    await db.commit()


@pytest.mark.asyncio
async def test_a_failed_runs_hold_ends_once_every_member_reports_one_version(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator gave up on the roll and upgraded the rest node by node.
    Without this the pins would keep the control plane on the old tag."""
    from app.services.upgrades import shared_tags

    run = await _run(db_session, done=["node-a"], state="failed", shared=_hold_record())
    cluster = _held_cluster()
    cluster.install(monkeypatch)
    wakes: list[str] = []

    async def _wake(*channels: str) -> None:
        wakes.extend(channels)

    monkeypatch.setattr("app.core.agent_wake.publish_wake", _wake)
    await _member_row(db_session, "node-a", "primary", TO)
    await _member_row(db_session, "node-b", "member", TO)
    await _member_row(db_session, "node-c", "member", FROM)

    # One member still on the old version: the hold stays.
    assert await shared_tags.release_lingering_hold(db_session) is None
    assert cluster.values("spatium-bootstrap") == {"global": {"imageTag": FROM}}

    # The last member upgraded by hand: the pins come off, the hold ends.
    from sqlalchemy import update

    await db_session.execute(
        update(Appliance)
        .where(Appliance.hostname == "node-c")
        .values(installed_appliance_version=TO)
    )
    await db_session.commit()
    assert await shared_tags.release_lingering_hold(db_session) == {
        "run_id": str(run.id),
        "version": TO,
    }
    assert cluster.values("spatium-bootstrap") == {}
    assert cluster.values("spatium-control") == {"api": {"replicas": 3}, "worker": {"replicas": 3}}
    await db_session.refresh(run)
    assert run.progress["shared_tags"]["release_reason"] == f"uniform:{TO}"
    assert wakes


@pytest.mark.asyncio
async def test_a_run_in_flight_keeps_its_hold_whatever_the_versions(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import shared_tags

    await _run(db_session, done=NODES, shared=_hold_record())
    cluster = _held_cluster()
    cluster.install(monkeypatch)
    for name, role in (("node-a", "primary"), ("node-b", "member"), ("node-c", "member")):
        await _member_row(db_session, name, role, TO)

    assert await shared_tags.release_lingering_hold(db_session) is None
    assert cluster.writes == []


def test_the_beat_releases_lingering_holds_every_minute() -> None:
    from app.celery_app import celery_app

    schedules = [
        e["schedule"]
        for e in celery_app.conf.beat_schedule.values()
        if e["task"] == "app.tasks.upgrade_orchestrator.release_lingering_shared_tag_hold"
    ]
    assert [s.run_every.total_seconds() for s in schedules] == [60]
