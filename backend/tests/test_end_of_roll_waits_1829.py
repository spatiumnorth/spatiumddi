"""#1829 — the end of a rolling upgrade waits for what actually rolled.

ddi-pg's three-node roll (seed last) failed in Phase E with nothing wrong: the
chart bump reported the control Deployments rolled 32 s before helm-controller
created their new ReplicaSets, because a rollout status read before the
re-render is the old template's, and complete; the migrate Job was looked up
under a name the chart never uses (``<chart>-spatiumddi-migrate``; the chart
names it ``-migrate-r<revision>``), so it always read as absent; and the
post-upgrade verify read CNPG once, at 2/3 ready, and failed the run.

The contract, on both ways a run ends (the chart bump of a run a drive from
before #1710 started, and the shared-tag flip):

* a workload counts as rolled only once its pod template runs the target tag
  and its rollout is complete for that template;
* the chart bump finds the migrate Job by its labels, the newest one on the
  target tag, and waits for it to finish;
* the verify waits, bounded, for CNPG to report every instance ready before it
  judges.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.appliance import k8s
from app.services.upgrades import chart_bump, per_node, safety

FROM = "2026.10.13-1"
TO = "2026.10.14-1"
NODES = ["node-a", "node-b", "node-c"]


def _deployment(tag: str, *, rolled: bool = True) -> dict[str, Any]:
    return {
        "metadata": {"generation": 3},
        "spec": {
            "replicas": 3,
            "template": {
                "spec": {"containers": [{"image": f"ghcr.io/spatiumnorth/spatiumddi-api:{tag}"}]}
            },
        },
        "status": {
            "observedGeneration": 3,
            "updatedReplicas": 3 if rolled else 1,
            "availableReplicas": 3 if rolled else 2,
        },
    }


def _job(name: str, tag: str, created: str, *, state: str | None) -> dict[str, Any]:
    status: dict[str, Any] = {}
    if state == "succeeded":
        status["succeeded"] = 1
    elif state == "failed":
        status["failed"] = 1
    return {
        "metadata": {
            "name": name,
            "creationTimestamp": created,
            "labels": {
                "app.kubernetes.io/component": "migrate",
                "app.kubernetes.io/instance": "spatium-control",
            },
        },
        "spec": {
            "template": {
                "spec": {"containers": [{"image": f"ghcr.io/spatiumnorth/spatiumddi-api:{tag}"}]}
            }
        },
        "status": status,
    }


def _cnpg(ready: int) -> tuple[int, dict[str, Any]]:
    return 200, {
        "spec": {"instances": 3},
        "status": {"readyInstances": ready, "currentPrimary": "spatium-db-1"},
    }


class ChartCluster:
    """The kubeapi the end of the roll reads: one control Deployment shape
    for every name, helm-controller's re-render arriving after ``stale``
    reads of each, the migrate Jobs, and the CNPG Cluster."""

    def __init__(self, *, stale: int = 1, jobs: list[list[dict[str, Any]]] | None = None) -> None:
        self.stale = stale
        self.reads: dict[str, int] = {}
        self.jobs = jobs or [[]]
        self.job_reads = 0
        self.cnpg_ready = [2, 3]
        self.cnpg_reads = 0

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(k8s, "get_config", MagicMock)
        monkeypatch.setattr(
            k8s, "get_helmchartconfig", lambda _n, namespace="kube-system": (404, None)
        )
        monkeypatch.setattr(k8s, "upsert_helmchartconfig", MagicMock(return_value=(True, None)))
        monkeypatch.setattr(k8s, "get_deployment", self.get_deployment)
        # The name the chart bump used to read: never there.
        monkeypatch.setattr(k8s, "get_job", lambda _n, namespace=None: (404, None))
        monkeypatch.setattr(k8s, "list_jobs", self.list_jobs, raising=False)
        monkeypatch.setattr(k8s, "get_cnpg_cluster", self.get_cnpg_cluster)
        monkeypatch.setattr(k8s, "list_pods", lambda namespace=None: [])
        monkeypatch.setattr(chart_bump, "_POLL_INTERVAL_S", 0.0)
        monkeypatch.setattr(safety, "_CNPG_POLL_INTERVAL_S", 0.0, raising=False)

    def get_deployment(self, name: str, namespace: str | None = None) -> Any:
        assert namespace == "spatium"
        n = self.reads[name] = self.reads.get(name, 0) + 1
        if n <= self.stale:
            # helm-controller has not re-rendered it yet: the old template,
            # whose rollout finished long ago.
            return 200, _deployment(FROM)
        if n == self.stale + 1:
            return 200, _deployment(TO, rolled=False)
        return 200, _deployment(TO)

    def list_jobs(self, selector: str, namespace: str | None = None) -> Any:
        assert namespace == "spatium"
        assert "app.kubernetes.io/component=migrate" in selector
        jobs = self.jobs[min(self.job_reads, len(self.jobs) - 1)]
        self.job_reads += 1
        return 200, jobs

    def get_cnpg_cluster(self, name: str, namespace: str | None = None) -> Any:
        ready = self.cnpg_ready[min(self.cnpg_reads, len(self.cnpg_ready) - 1)]
        self.cnpg_reads += 1
        return _cnpg(ready)


# ── The chart bump (a run a drive from before #1710 started) ────────────────


@pytest.mark.asyncio
async def test_the_chart_bump_does_not_take_the_old_templates_status_for_the_roll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cluster = ChartCluster(stale=2)
    cluster.install(monkeypatch)

    result = await chart_bump.bump_chart_image_tag(TO, deployment_names=["api"])

    assert result.ok, result.error
    assert result.rolled_deployments == ["api"]
    # Two reads of the old template, one of the new one rolling, one rolled.
    assert cluster.reads["api"] == 4


@pytest.mark.asyncio
async def test_the_chart_bump_waits_for_the_migrate_job_the_chart_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = _job("spatium-control-migrate-r6", FROM, "2026-10-12T02:00:00Z", state="succeeded")
    cluster = ChartCluster(
        jobs=[
            [old, _job("spatium-control-migrate-r7", TO, "2026-10-13T19:00:00Z", state=None)],
            [
                old,
                _job("spatium-control-migrate-r7", TO, "2026-10-13T19:00:00Z", state="succeeded"),
            ],
        ]
    )
    cluster.install(monkeypatch)

    result = await chart_bump.bump_chart_image_tag(TO, deployment_names=["api"])

    assert result.ok, result.error
    assert result.migrate_job_state == "succeeded"
    assert cluster.job_reads == 2


@pytest.mark.asyncio
async def test_a_failed_migrate_job_fails_the_chart_bump(monkeypatch: pytest.MonkeyPatch) -> None:
    old = _job("spatium-control-migrate-r6", FROM, "2026-10-12T02:00:00Z", state="succeeded")
    new = _job("spatium-control-migrate-r7", TO, "2026-10-13T19:00:00Z", state="failed")
    cluster = ChartCluster(jobs=[[new, old]])
    cluster.install(monkeypatch)

    result = await chart_bump.bump_chart_image_tag(TO, deployment_names=["api"])

    assert not result.ok
    assert result.migrate_job_state == "failed"
    assert "spatium-control-migrate-r7" in (result.error or "")


@pytest.mark.asyncio
async def test_a_migrate_job_gone_after_its_ttl_reads_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only an older revision's Job is left (the new one finished before
    the Deployments could start, and its TTL removed it): absent, as before."""
    old = _job("spatium-control-migrate-r6", FROM, "2026-10-12T02:00:00Z", state="succeeded")
    cluster = ChartCluster(jobs=[[old]])
    cluster.install(monkeypatch)

    result = await chart_bump.bump_chart_image_tag(TO, deployment_names=["api"])

    assert result.ok, result.error
    assert result.migrate_job_state == "absent"


# ── The verify (both ways a run ends) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_verify_waits_for_cnpg_before_it_judges(monkeypatch: pytest.MonkeyPatch) -> None:
    cluster = ChartCluster()
    cluster.cnpg_ready = [2, 2, 3]
    cluster.install(monkeypatch)

    checks = await safety.verify_post_upgrade(cnpg_cluster_name="spatium-db")

    assert safety.verification_overall(checks) == "ok"
    cnpg = next(c for c in checks if c.name == "cnpg_instances")
    assert cnpg.message.startswith("3/3")
    assert cluster.cnpg_reads == 3


@pytest.mark.asyncio
async def test_the_verify_still_fails_cnpg_that_never_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cluster = ChartCluster()
    cluster.cnpg_ready = [2]
    cluster.install(monkeypatch)
    monkeypatch.setattr(safety, "_CNPG_READY_WAIT_S", 0.0, raising=False)

    checks = await safety.verify_post_upgrade(cnpg_cluster_name="spatium-db")

    assert safety.verification_overall(checks) == "fail"
    cnpg = next(c for c in checks if c.name == "cnpg_instances")
    assert cnpg.detail["ready_instances"] == 2


# ── Through the drive ─────────────────────────────────────────────────────────


async def _done_run(db: AsyncSession, shared: dict[str, Any] | None) -> Any:
    from app.models.system_upgrade import SystemUpgradeRun

    progress: dict[str, Any] = {"per_node": {n: {"ok": True} for n in NODES}, "events": []}
    if shared is not None:
        progress["shared_tags"] = shared
    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version=TO,
        source_versions={},
        plan={"node_order": NODES, "cnpg_cluster_name": "spatium-db", "cnpg_namespace": "spatium"},
        progress=progress,
        lease_holder="worker-a",
    )
    db.add(run)
    await db.commit()
    return run


def _quiet(monkeypatch: pytest.MonkeyPatch, orch: Any) -> None:
    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    async def _wake(*_channels: str) -> None:
        return None

    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(orch.mutex, "release_if_held", lambda **_k: True)
    monkeypatch.setattr("app.core.agent_wake.publish_wake", _wake)
    monkeypatch.delenv("NODE_NAME", raising=False)

    async def _must_not_run(*_a: Any, **_k: Any) -> per_node.SingleNodeResult:
        raise AssertionError("every node is done")

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _must_not_run)


@pytest.mark.asyncio
async def test_a_run_started_before_the_hold_ends_through_the_chart_bump_and_waits(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    run = await _done_run(db_session, {"mode": "legacy"})
    cluster = ChartCluster(
        jobs=[[_job("spatium-control-migrate-r7", TO, "2026-10-13T19:00:00Z", state="succeeded")]]
    )
    cluster.install(monkeypatch)
    _quiet(monkeypatch, orch)

    await orch._drive_loop(db_session, run, asyncio.Event(), "pod_mine")

    await db_session.refresh(run)
    assert run.state == "succeeded", run.last_error
    assert run.progress["chart_bump"]["migrate_job_state"] == "succeeded"
    assert run.progress["post_upgrade_verify"]["overall"] == "ok"
    assert all(n == cluster.stale + 2 for n in cluster.reads.values())


@pytest.mark.asyncio
async def test_the_flips_run_verifies_once_cnpg_has_recovered(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.upgrades import orchestrator as orch

    flip = {
        "state": "flipped",
        "workloads": [{"kind": "Deployment", "name": "spatium-control-spatiumddi-api"}],
        "handed_off_at": "2026-10-13T19:00:00Z",
    }
    shared = {
        "mode": "hold",
        "from_tag": FROM,
        "to_tag": TO,
        "nodes": NODES,
        "released_at": "2026-10-13T19:00:00Z",
        "release_reason": "flip",
        "flip": flip,
    }
    run = await _done_run(db_session, shared)
    cluster = ChartCluster()
    cluster.install(monkeypatch)
    api = {
        **_deployment(TO),
        "metadata": {"name": "spatium-control-spatiumddi-api", "generation": 3},
    }
    monkeypatch.setattr(k8s, "list_deployments", lambda _s, namespace=None: (200, [api]))
    monkeypatch.setattr(
        k8s, "list_daemonsets", lambda _s="", namespace=None: (200, []), raising=False
    )
    monkeypatch.setattr(settings, "version", TO)
    _quiet(monkeypatch, orch)

    await orch._drive_loop(db_session, run, asyncio.Event(), "pod_new")

    await db_session.refresh(run)
    assert run.state == "succeeded", run.last_error
    assert run.progress["post_upgrade_verify"]["overall"] == "ok"
    assert cluster.cnpg_reads == 2


def test_the_deployment_wait_needs_the_tag_it_waits_for() -> None:
    """No status-only wait is left to call by mistake."""
    with pytest.raises(TypeError):
        asyncio.run(
            chart_bump._wait_for_deployments_rolled(
                ["api"], "spatium", stop_after_monotonic=time.monotonic()
            )
        )
