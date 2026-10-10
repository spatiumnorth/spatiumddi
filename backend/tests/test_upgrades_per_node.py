"""Per-node upgrade primitive tests (#296 Phase C).

Each step function is exercised in isolation against mocked kubeapi
helpers + appliance-row reads. The chained ``single_node_upgrade``
function gets one happy-path test (every step returns ok) and one
halt-on-failure test (cordon fails → chain stops + reports
``failed_at='cordon'``).

End-to-end exercise against a live cluster lives in the future Phase D
orchestrator's integration tests; this file is pure-Python.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import per_node, preflight

# ── Step 1: preflight ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_step_preflight_passes_on_overall_ok() -> None:
    ok = preflight.PreflightResult("x", "ok", "fine", {})
    report = preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="ok",
        can_start=True,
        results=[ok],
    )
    with patch.object(preflight, "run_all", AsyncMock(return_value=report)):
        step = await per_node._step_preflight("2026.06.01-1")
    assert step.ok is True
    assert step.name == "preflight"


@pytest.mark.asyncio
async def test_step_preflight_fails_on_overall_fail() -> None:
    bad = preflight.PreflightResult("quorum", "fail", "no", {})
    report = preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="fail",
        can_start=False,
        results=[bad],
    )
    with patch.object(preflight, "run_all", AsyncMock(return_value=report)):
        step = await per_node._step_preflight("2026.06.01-1")
    assert step.ok is False
    assert "quorum" in step.error
    assert step.detail["failed_checks"] == ["quorum"]


# ── Step 2: etcd snapshot (no-op placeholder) ────────────────────────


@pytest.mark.asyncio
async def test_step_etcd_snapshot_skips_with_reason() -> None:
    """Phase C v0 deliberately skips this step. Test pins the contract
    so a later commit that wires it up will fail this + force an
    explicit update."""
    step = await per_node._step_etcd_snapshot()
    assert step.ok is True
    assert step.detail["skipped"] is True
    assert "auto-snapshots" in step.detail["reason"]


# ── Step 3: CNPG maintenance window ──────────────────────────────────


@pytest.mark.asyncio
async def test_step_cnpg_maintenance_on_calls_patch_helper() -> None:
    with patch.object(
        per_node.k8s,
        "patch_cnpg_maintenance_window",
        return_value=(True, None),
    ) as mock:
        step = await per_node._step_cnpg_maintenance_on("pg-cluster", "spatium")
    assert step.ok is True
    mock.assert_called_once_with(
        "pg-cluster", in_progress=True, reuse_pvc=True, namespace="spatium"
    )


@pytest.mark.asyncio
async def test_step_cnpg_maintenance_on_propagates_error() -> None:
    with patch.object(
        per_node.k8s,
        "patch_cnpg_maintenance_window",
        return_value=(False, "rbac forbidden"),
    ):
        step = await per_node._step_cnpg_maintenance_on("pg-cluster", "spatium")
    assert step.ok is False
    assert "rbac forbidden" in step.error


# ── Step 4: cordon ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_step_cordon_idempotent_on_success() -> None:
    with patch.object(per_node.k8s, "cordon_node", return_value=(True, None)):
        step = await per_node._step_cordon("node-1")
    assert step.ok is True
    assert step.detail["node"] == "node-1"


@pytest.mark.asyncio
async def test_step_cordon_reports_error() -> None:
    with patch.object(per_node.k8s, "cordon_node", return_value=(False, "kubeapi status 403")):
        step = await per_node._step_cordon("node-1")
    assert step.ok is False
    assert "403" in step.error


# ── Step 5: verify primary moved (CNPG single-instance short-circuit) ─


@pytest.mark.asyncio
async def test_step_verify_primary_moved_no_cluster_skipped() -> None:
    """404 on the Cluster GET — no CNPG. Returns ok with skipped=True
    so single-node deploys don't trip a false failure."""
    with patch.object(per_node.k8s, "get_cnpg_cluster", return_value=(404, None)):
        step = await per_node._step_verify_primary_moved("pg-cluster", "node-1", "spatium")
    assert step.ok is True
    assert step.detail["skipped"] is True


@pytest.mark.asyncio
async def test_step_verify_primary_moved_single_instance_skipped() -> None:
    """instances=1 — nothing to switch over to."""
    cluster = {
        "spec": {"instances": 1},
        "status": {"currentPrimary": "pg-cluster-1"},
    }
    with patch.object(per_node.k8s, "get_cnpg_cluster", return_value=(200, cluster)):
        step = await per_node._step_verify_primary_moved("pg-cluster", "node-1", "spatium")
    assert step.ok is True
    assert step.detail["skipped"] is True


# ── Step 6: drain ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_step_drain_skips_daemonset_terminal_mirror_pods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drain filters out DS-owned pods (rebooted in place with the node),
    terminal Succeeded/Failed pods (already done), and static mirror
    pods (kubelet-managed, the eviction API can't touch them)."""
    # Build a pod list with one of each "skip" reason + one evictable.
    pods: list[dict[str, Any]] = [
        {
            "metadata": {
                "name": "ds-pod",
                "namespace": "kube-system",
                "ownerReferences": [{"kind": "DaemonSet"}],
            },
            "status": {"phase": "Running"},
        },
        {
            "metadata": {"name": "completed-pod", "namespace": "default"},
            "status": {"phase": "Succeeded"},
        },
        {
            "metadata": {
                "name": "static-mirror",
                "namespace": "kube-system",
                "annotations": {"kubernetes.io/config.mirror": "abc"},
            },
            "status": {"phase": "Running"},
        },
        {
            "metadata": {
                "name": "api-1",
                "namespace": "spatium",
                "ownerReferences": [{"kind": "ReplicaSet"}],
            },
            "status": {"phase": "Running"},
        },
    ]

    evictions: list[tuple[str, str]] = []

    def _evict(name: str, namespace: str, **_kw: Any) -> tuple[int, str | None]:
        evictions.append((name, namespace))
        return 200, None

    list_calls: list[list[dict[str, Any]]] = [pods, []]

    def _list_pods(node_name: str) -> list[dict[str, Any]]:
        # First call returns the pods, second call returns empty so
        # the loop's "all done" check fires.
        return list_calls.pop(0)

    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", _list_pods)
    monkeypatch.setattr(per_node.k8s, "evict_pod", _evict)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    step = await per_node._step_drain("node-1", timeout_s=5.0)
    assert step.ok is True
    # Only api-1 evictable; ds-pod / completed-pod / static-mirror skipped.
    assert evictions == [("api-1", "spatium")]
    assert step.detail["evicted_count"] == 1


@pytest.mark.asyncio
async def test_step_drain_timeout_reports_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """A pod that keeps coming back (PDB-blocked) trips the timeout."""
    pdb_blocked = [
        {
            "metadata": {
                "name": "blocked",
                "namespace": "default",
                "ownerReferences": [{"kind": "ReplicaSet"}],
            },
            "status": {"phase": "Running"},
        },
    ]

    def _list_pods(node_name: str) -> list[dict[str, Any]]:
        # Always returns the blocked pod — drain never gets to empty.
        return list(pdb_blocked)

    def _evict(name: str, namespace: str, **_kw: Any) -> tuple[int, str | None]:
        return 429, "PDB blocks"

    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", _list_pods)
    monkeypatch.setattr(per_node.k8s, "evict_pod", _evict)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    step = await per_node._step_drain("node-1", timeout_s=0.05)
    assert step.ok is False
    assert "timed out" in step.error
    assert step.detail["blocked"]
    assert step.detail["blocked"][0]["pod"] == "default/blocked"


@pytest.mark.asyncio
async def test_step_drain_refuses_controllerless_pods(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1546: a bare pod (no controller ownerReference) must never be
    evicted — nothing re-creates it. The drain fails fast and lists
    the pod as a blocker in the step detail instead of deleting it,
    matching kubectl drain without --force."""
    pods: list[dict[str, Any]] = [
        {
            "metadata": {"name": "debug-pod", "namespace": "default"},
            "status": {"phase": "Running"},
        },
        {
            "metadata": {
                "name": "api-1",
                "namespace": "spatium",
                "ownerReferences": [{"kind": "ReplicaSet"}],
            },
            "status": {"phase": "Running"},
        },
    ]
    evictions: list[tuple[str, str]] = []

    def _evict(name: str, namespace: str, **_kw: Any) -> tuple[int, str | None]:
        evictions.append((name, namespace))
        return 200, None

    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _n: list(pods))
    monkeypatch.setattr(per_node.k8s, "evict_pod", _evict)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    step = await per_node._step_drain("node-1", timeout_s=5.0)
    assert step.ok is False
    assert "no controller owner" in step.error
    assert step.detail["unowned_pods"] == ["default/debug-pod"]
    assert step.detail["blocked"] == [{"pod": "default/debug-pod", "reason": "no controller owner"}]
    # The bare pod was never evicted.
    assert ("debug-pod", "default") not in evictions


# ── Step 7: trigger slot apply ───────────────────────────────────────


class _FakeAppliance:
    """Minimal stand-in carrying every column the stamper reads or writes.

    "reads OR writes" is the whole contract, and #1026 is why the
    distinction is now spelled out: the stamper gained a READ of
    ``architecture`` for the cross-architecture refusal, this stub
    carried only the columns it WRITES, and every test using it died on
    ``AttributeError``.
    """

    def __init__(
        self,
        *,
        supervisor_version: str | None = None,
        architecture: str | None = None,
    ) -> None:
        self.id = uuid.uuid4()
        self.hostname = "node-1"
        # None = UNKNOWN, the answer from a supervisor predating #1026.
        # It never conflicts, so these cases keep exercising the paths
        # they were written for.
        self.architecture = architecture
        self.supervisor_version = supervisor_version
        self.installed_appliance_version: str | None = None
        self.desired_appliance_version: str | None = None
        self.desired_slot_image_url: str | None = None
        self.desired_slot_image_sha256: str | None = None
        self.desired_slot_image_tls_insecure: bool = False


@pytest.mark.asyncio
async def test_step_trigger_slot_apply_missing_appliance() -> None:
    """No Appliance row for the node name → step fails with a clear
    error rather than silently doing nothing."""
    db = MagicMock()
    # _resolve_appliance returns None → step fails.
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=None)):
        step = await per_node._step_trigger_slot_apply(
            db, "ghost-node", "2026.06.01-1", SlotImageTarget(url="http://mirror/x.raw.xz")
        )
    assert step.ok is False
    assert "ghost-node" in step.error


@pytest.mark.asyncio
async def test_step_trigger_slot_apply_stamps_desired_fields() -> None:
    """Happy path: the Appliance row's ``desired_*`` fields get
    stamped + flush is called. The supervisor's heartbeat picks them
    up from there + writes the trigger file."""
    appliance = _FakeAppliance()
    db = MagicMock()
    db.flush = AsyncMock()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=appliance)):
        step = await per_node._step_trigger_slot_apply(
            db, "node-1", "2026.06.01-1", SlotImageTarget(url="http://mirror/x.raw.xz")
        )
    assert step.ok is True
    assert appliance.desired_appliance_version == "2026.06.01-1"
    assert appliance.desired_slot_image_url == "http://mirror/x.raw.xz"
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_step_trigger_slot_apply_carries_integrity_hints() -> None:
    """#787 regression: an uploaded (self-served) image must arrive at the
    host with BOTH its sha256 and the insecure-TLS flag.

    Stamping only version + URL — what this step used to do — leaves the
    runner fetching our own self-signed cert with verification on, which
    is the #386 failure it was supposed to have fixed.
    """
    appliance = _FakeAppliance()
    db = MagicMock()
    db.flush = AsyncMock()
    target = SlotImageTarget(
        url="https://cp.local/raw.xz?t=abc", sha256="ab" * 32, tls_insecure=True
    )
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=appliance)):
        step = await per_node._step_trigger_slot_apply(db, "node-1", "2026.06.01-1", target)
    assert step.ok is True
    assert appliance.desired_slot_image_sha256 == "ab" * 32
    assert appliance.desired_slot_image_tls_insecure is True


@pytest.mark.asyncio
async def test_step_trigger_slot_apply_clears_a_stale_sha256() -> None:
    """An external URL has no hash — any sha256 left on the row from an
    earlier per-box schedule must be cleared, or the new image is verified
    against the old one's digest and fails as corrupt."""
    appliance = _FakeAppliance()
    appliance.desired_slot_image_sha256 = "cd" * 32
    appliance.desired_slot_image_tls_insecure = True
    db = MagicMock()
    db.flush = AsyncMock()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=appliance)):
        await per_node._step_trigger_slot_apply(
            db, "node-1", "2026.06.01-1", SlotImageTarget(url="https://github.com/x.raw.xz")
        )
    assert appliance.desired_slot_image_sha256 is None
    assert appliance.desired_slot_image_tls_insecure is False


@pytest.mark.asyncio
async def test_step_trigger_slot_apply_adds_refire_nonce_only_when_supported() -> None:
    """The ``#a=`` re-fire nonce is gated on the runner being able to strip
    it; an older appliance must get a clean URL (#419)."""
    db = MagicMock()
    db.flush = AsyncMock()
    target = SlotImageTarget(url="https://cp.local/raw.xz", nonce="n1")
    modern = _FakeAppliance(supervisor_version="2026.07.30-1")
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=modern)):
        await per_node._step_trigger_slot_apply(db, "node-1", "2026.07.30-1", target)
    assert "#a=" in (modern.desired_slot_image_url or "")

    legacy = _FakeAppliance(supervisor_version="2026.06.11-1")
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=legacy)):
        await per_node._step_trigger_slot_apply(db, "node-1", "2026.07.30-1", target)
    assert legacy.desired_slot_image_url == "https://cp.local/raw.xz"


# ── Step 8: health gate ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_step_health_gate_succeeds_on_version_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Appliance:
        installed_appliance_version = "2026.06.01-1"
        last_upgrade_state = "done"

    db = MagicMock()
    db.refresh = AsyncMock()
    db.commit = AsyncMock()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=_Appliance())):
        monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
        step = await per_node._step_health_gate(db, "node-1", "2026.06.01-1", timeout_s=5.0)
    assert step.ok is True


@pytest.mark.asyncio
async def test_step_health_gate_fails_on_supervisor_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 8c's auto-revert path: the supervisor reports the apply
    failed → the step must short-circuit + report the failure rather
    than waiting for the timeout."""

    class _Appliance:
        installed_appliance_version = "2026.05.22-2"  # still old
        last_upgrade_state = "failed"

    db = MagicMock()
    db.refresh = AsyncMock()
    db.commit = AsyncMock()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=_Appliance())):
        monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
        step = await per_node._step_health_gate(db, "node-1", "2026.06.01-1", timeout_s=5.0)
    assert step.ok is False
    assert "upgrade failed" in step.error


@pytest.mark.asyncio
async def test_step_health_gate_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """No version match + no failed state → timeout."""

    class _Appliance:
        installed_appliance_version = "2026.05.22-2"
        last_upgrade_state = "in-flight"

    db = MagicMock()
    db.refresh = AsyncMock()
    db.commit = AsyncMock()
    with patch.object(per_node, "_resolve_appliance", AsyncMock(return_value=_Appliance())):
        monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
        step = await per_node._step_health_gate(db, "node-1", "2026.06.01-1", timeout_s=0.05)
    assert step.ok is False
    assert "timed out" in step.error


# ── Step 9: convergence ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_step_convergence_waits_for_node_ready_and_ds_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Node Ready + every DS pod Ready → ok."""
    ready_node = {
        "metadata": {"name": "node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    ds_pod_ready = {
        "metadata": {
            "name": "bind9",
            "namespace": "kube-system",
            "ownerReferences": [{"kind": "DaemonSet"}],
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    }
    monkeypatch.setattr(per_node.k8s, "get_node", lambda _name: (200, ready_node))
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _name: [ds_pod_ready])
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    step = await per_node._step_convergence("node-1", timeout_s=5.0)
    assert step.ok is True
    assert step.detail["ds_pod_count"] == 1


@pytest.mark.asyncio
async def test_step_convergence_times_out_on_unready_ds_pod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Node Ready but DS pod NotReady → timeout. This catches the
    'kubernetes-Ready but DS pod still warming bundle cache' premature-
    uncordon case the issue's failure-mode #21 calls out."""
    ready_node = {
        "metadata": {"name": "node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    ds_pod_not_ready = {
        "metadata": {
            "name": "bind9",
            "namespace": "kube-system",
            "ownerReferences": [{"kind": "DaemonSet"}],
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "False"}],
        },
    }
    monkeypatch.setattr(per_node.k8s, "get_node", lambda _name: (200, ready_node))
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _name: [ds_pod_not_ready])
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    step = await per_node._step_convergence("node-1", timeout_s=0.05)
    assert step.ok is False
    assert "timed out" in step.error


@pytest.mark.asyncio
async def test_step_convergence_waits_for_cnpg_instances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: Node Ready + DS Ready is not enough — convergence must
    also wait until the CNPG Cluster reports every instance ready,
    or the chain uncordons and drains the next node with Postgres
    short an instance."""
    ready_node = {
        "metadata": {"name": "node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    cluster = {
        "spec": {"instances": 3},
        "status": {"readyInstances": 3, "currentPrimary": "pg-cluster-1"},
    }
    monkeypatch.setattr(per_node.k8s, "get_node", lambda _name: (200, ready_node))
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _name: [])
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, cluster))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    step = await per_node._step_convergence(
        "node-1", timeout_s=5.0, cnpg_cluster_name="pg-cluster", cnpg_namespace="spatium"
    )
    assert step.ok is True
    assert step.detail["cnpg_ready_instances"] == 3
    assert step.detail["cnpg_spec_instances"] == 3


@pytest.mark.asyncio
async def test_step_convergence_times_out_when_cnpg_instance_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: the upgraded node's CNPG instance never came back
    (readyInstances stays below spec) → convergence times out
    instead of passing on Node/DS readiness alone."""
    ready_node = {
        "metadata": {"name": "node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    cluster = {
        "spec": {"instances": 3},
        "status": {"readyInstances": 2, "currentPrimary": "pg-cluster-1"},
    }
    monkeypatch.setattr(per_node.k8s, "get_node", lambda _name: (200, ready_node))
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _name: [])
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, cluster))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    step = await per_node._step_convergence(
        "node-1", timeout_s=0.05, cnpg_cluster_name="pg-cluster", cnpg_namespace="spatium"
    )
    assert step.ok is False
    assert "timed out" in step.error


# ── Step 10: uncordon + clear window ─────────────────────────────────


@pytest.mark.asyncio
async def test_step_uncordon_clears_maintenance_window() -> None:
    """Both calls succeed → step ok."""
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        step = await per_node._step_uncordon("node-1", "pg-cluster", "spatium")
    assert step.ok is True
    un.assert_called_once_with("node-1")
    mw.assert_called_once_with("pg-cluster", in_progress=False, reuse_pvc=True, namespace="spatium")


@pytest.mark.asyncio
async def test_step_uncordon_skips_window_clear_without_cluster_name() -> None:
    """#1545: an empty cluster name disables CNPG steps — the
    maintenance-window clear must be skipped like the set is, or the
    PATCH to the clusters collection URL fails the step after a
    successful uncordon."""
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        step = await per_node._step_uncordon("node-1", "", "spatium")
    assert step.ok is True
    assert step.detail["maintenance_window_clear_skipped"] is True
    un.assert_called_once_with("node-1")
    mw.assert_not_called()


@pytest.mark.asyncio
async def test_step_uncordon_partial_failure_reports_state() -> None:
    """Uncordon ok but maintenance-window clear failed — degraded state
    the orchestrator needs to surface, not silently swallow."""
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)),
        patch.object(
            per_node.k8s,
            "patch_cnpg_maintenance_window",
            return_value=(False, "rbac"),
        ),
    ):
        step = await per_node._step_uncordon("node-1", "pg-cluster", "spatium")
    assert step.ok is False
    assert step.detail["uncordon_ok"] is True
    assert "rbac" in step.error


# ── Chained orchestration ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_single_node_upgrade_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every step returns ok → single_node_upgrade returns ok=True with
    12 step results (etcd_snapshot is the no-op placeholder)."""

    # Mock every step to return an ok StepResult so we exercise the
    # chained-call shape without re-doing each step's tests.
    async def _ok(name: per_node.StepName, **_kw: Any) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_preflight", lambda *a, **k: _ok("preflight"))
    monkeypatch.setattr(per_node, "_step_etcd_snapshot", lambda *a, **k: _ok("etcd_snapshot"))
    monkeypatch.setattr(
        per_node, "_step_cnpg_maintenance_on", lambda *a, **k: _ok("cnpg_maintenance_on")
    )
    monkeypatch.setattr(per_node, "_step_cordon", lambda *a, **k: _ok("cordon"))
    monkeypatch.setattr(
        per_node, "_step_verify_primary_moved", lambda *a, **k: _ok("verify_primary_moved")
    )
    monkeypatch.setattr(per_node, "_step_drain", lambda *a, **k: _ok("drain"))
    monkeypatch.setattr(
        per_node, "_step_trigger_slot_apply", lambda *a, **k: _ok("trigger_slot_apply")
    )
    monkeypatch.setattr(per_node, "_step_reboot", lambda *a, **k: _ok("reboot"))
    monkeypatch.setattr(per_node, "_step_health_gate", lambda *a, **k: _ok("health_gate"))
    monkeypatch.setattr(per_node, "_step_convergence", lambda *a, **k: _ok("convergence"))
    monkeypatch.setattr(per_node, "_step_uncordon", lambda *a, **k: _ok("uncordon"))
    monkeypatch.setattr(per_node, "_step_cluster_verify", lambda *a, **k: _ok("cluster_verify"))

    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg-cluster",
        cnpg_namespace="spatium",
    )
    assert result.ok is True
    assert result.failed_at is None
    assert [s.name for s in result.steps] == [
        "preflight",
        "etcd_snapshot",
        "cnpg_maintenance_on",
        "cordon",
        "verify_primary_moved",
        "drain",
        "trigger_slot_apply",
        "reboot",
        "health_gate",
        "convergence",
        "uncordon",
        "cluster_verify",
    ]


@pytest.mark.asyncio
async def test_single_node_upgrade_halts_on_cordon_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cordon returns ok=False → chain stops at step 4. No subsequent
    steps run; result reports failed_at='cordon'."""

    async def _ok(name: per_node.StepName) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)

    async def _fail_cordon(_node: str) -> per_node.StepResult:
        return per_node.StepResult(name="cordon", started_at="t", finished_at="t").finish(
            False, error="kubeapi status 403"
        )

    drain_called = False

    async def _track_drain(_node: str, **_kw: Any) -> per_node.StepResult:
        nonlocal drain_called
        drain_called = True
        return per_node.StepResult(name="drain", started_at="t", finished_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_preflight", lambda *a, **k: _ok("preflight"))
    monkeypatch.setattr(per_node, "_step_etcd_snapshot", lambda *a, **k: _ok("etcd_snapshot"))
    monkeypatch.setattr(
        per_node, "_step_cnpg_maintenance_on", lambda *a, **k: _ok("cnpg_maintenance_on")
    )
    monkeypatch.setattr(per_node, "_step_cordon", _fail_cordon)
    monkeypatch.setattr(per_node, "_step_drain", _track_drain)

    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg-cluster",
    )
    assert result.ok is False
    assert result.failed_at == "cordon"
    assert "403" in result.error
    assert drain_called is False
    # Steps after cordon never ran.
    assert [s.name for s in result.steps] == [
        "preflight",
        "etcd_snapshot",
        "cnpg_maintenance_on",
        "cordon",
    ]


@pytest.mark.asyncio
async def test_single_node_upgrade_releases_node_on_post_cordon_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1542: a failure after the cordon must not leave the node
    cordoned with the CNPG maintenance window on. The chain appends
    a release_node compensation step (uncordon + clear window) and
    still reports the ORIGINAL failing step + error."""

    async def _ok(name: per_node.StepName) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)

    async def _fail_drain(_node: str, **_kw: Any) -> per_node.StepResult:
        return per_node.StepResult(name="drain", started_at="t", finished_at="t").finish(
            False, error="drain timed out"
        )

    monkeypatch.setattr(per_node, "_step_preflight", lambda *a, **k: _ok("preflight"))
    monkeypatch.setattr(per_node, "_step_etcd_snapshot", lambda *a, **k: _ok("etcd_snapshot"))
    monkeypatch.setattr(
        per_node, "_step_cnpg_maintenance_on", lambda *a, **k: _ok("cnpg_maintenance_on")
    )
    monkeypatch.setattr(per_node, "_step_cordon", lambda *a, **k: _ok("cordon"))
    monkeypatch.setattr(
        per_node, "_step_verify_primary_moved", lambda *a, **k: _ok("verify_primary_moved")
    )
    monkeypatch.setattr(per_node, "_step_drain", _fail_drain)

    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
            cnpg_namespace="spatium",
        )
    assert result.ok is False
    assert result.failed_at == "drain"
    assert result.error == "drain timed out"
    release = result.steps[-1]
    assert release.name == "release_node"
    assert release.ok is True
    assert release.detail["maintenance_window_cleared"] is True
    un.assert_called_once_with("node-1")
    mw.assert_called_once_with("pg-cluster", in_progress=False, reuse_pvc=True, namespace="spatium")


@pytest.mark.asyncio
async def test_single_node_upgrade_records_failed_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1542: when the compensation itself fails, the release_node
    step records the failure distinctly in the per-node progress —
    the chain result still blames the original failing step."""

    async def _ok(name: per_node.StepName) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)

    async def _fail_drain(_node: str, **_kw: Any) -> per_node.StepResult:
        return per_node.StepResult(name="drain", started_at="t", finished_at="t").finish(
            False, error="drain timed out"
        )

    monkeypatch.setattr(per_node, "_step_preflight", lambda *a, **k: _ok("preflight"))
    monkeypatch.setattr(per_node, "_step_etcd_snapshot", lambda *a, **k: _ok("etcd_snapshot"))
    monkeypatch.setattr(
        per_node, "_step_cnpg_maintenance_on", lambda *a, **k: _ok("cnpg_maintenance_on")
    )
    monkeypatch.setattr(per_node, "_step_cordon", lambda *a, **k: _ok("cordon"))
    monkeypatch.setattr(
        per_node, "_step_verify_primary_moved", lambda *a, **k: _ok("verify_primary_moved")
    )
    monkeypatch.setattr(per_node, "_step_drain", _fail_drain)

    with patch.object(per_node.k8s, "uncordon_node", return_value=(False, "rbac forbidden")):
        result = await per_node.single_node_upgrade(
            MagicMock(),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
            cnpg_namespace="spatium",
        )
    assert result.ok is False
    assert result.failed_at == "drain"
    release = result.steps[-1]
    assert release.name == "release_node"
    assert release.ok is False
    assert "compensating uncordon failed" in release.error


def _patch_chain_ok(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
    """Every chain step returns ok unless ``overrides`` names a replacement."""

    def _ok(name: per_node.StepName) -> Any:
        async def _step(*_a: Any, **_k: Any) -> per_node.StepResult:
            return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)

        return _step

    for step in (
        "preflight",
        "etcd_snapshot",
        "cnpg_maintenance_on",
        "cordon",
        "verify_primary_moved",
        "drain",
        "trigger_slot_apply",
        "reboot",
        "health_gate",
        "convergence",
        "uncordon",
        "cluster_verify",
    ):
        monkeypatch.setattr(per_node, f"_step_{step}", overrides.get(step) or _ok(step))


def _failing(name: per_node.StepName, error: str) -> Any:
    async def _step(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(
            False, error=error
        )

    return _step


def _must_not_run(name: str) -> Any:
    # The chain builds each step's coroutine before ``_run`` decides to skip
    # it, so the stub must fail on AWAIT, not on call.
    async def _step(*_a: Any, **_k: Any) -> Any:
        raise AssertionError(f"{name} must not run")

    return _step


@pytest.mark.asyncio
async def test_single_node_upgrade_releases_node_on_reboot_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1542 x #1445: the reboot step (added after #1542 was written) is
    post-cordon, so its failure releases the node too."""
    _patch_chain_ok(
        monkeypatch,
        reboot=_failing("reboot", "slot was not staged within 3000s"),
        health_gate=_must_not_run("health_gate"),
        convergence=_must_not_run("convergence"),
    )
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
            cnpg_namespace="spatium",
        )
    assert result.ok is False
    assert result.failed_at == "reboot"
    assert result.error == "slot was not staged within 3000s"
    assert [s.name for s in result.steps][-2:] == ["reboot", "release_node"]
    assert result.steps[-1].ok is True
    un.assert_called_once_with("node-1")
    mw.assert_called_once_with("pg-cluster", in_progress=False, reuse_pvc=True, namespace="spatium")


@pytest.mark.asyncio
async def test_single_node_upgrade_reboot_failure_without_cnpg_only_uncordons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1545 x #1542: no CNPG cluster in the run (none configured, none
    detected) means no window was set, so the release must not PATCH a
    nameless Cluster."""
    _patch_chain_ok(monkeypatch, reboot=_failing("reboot", "supervisor reported upgrade failed"))
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window") as mw,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        )
    assert result.failed_at == "reboot"
    release = result.steps[-1]
    assert release.name == "release_node" and release.ok is True
    assert release.detail["maintenance_window_clear_skipped"] is True
    un.assert_called_once_with("node-1")
    mw.assert_not_called()


@pytest.mark.asyncio
async def test_single_node_upgrade_resumed_past_cordon_still_releases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run resumed at a step after the cordon did not cordon the node in
    THIS invocation, but the node is cordoned all the same (the earlier
    invocation did it) — so a failure must still release it, and clear
    the window the earlier invocation set."""
    _patch_chain_ok(
        monkeypatch,
        preflight=_must_not_run("preflight"),
        cnpg_maintenance_on=_must_not_run("cnpg_maintenance_on"),
        cordon=_must_not_run("cordon"),
        drain=_must_not_run("drain"),
        trigger_slot_apply=_must_not_run("trigger_slot_apply"),
        health_gate=_failing("health_gate", "health gate timed out after 1800s"),
    )
    db = MagicMock(commit=AsyncMock())
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(
            per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)
        ) as mw,
    ):
        result = await per_node.single_node_upgrade(
            db,
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
            cnpg_namespace="spatium",
            start_step="reboot",
        )
    assert result.failed_at == "health_gate"
    assert result.error == "health gate timed out after 1800s"
    assert [s.name for s in result.steps] == ["reboot", "health_gate", "release_node"]
    assert result.steps[-1].ok is True
    un.assert_called_once_with("node-1")
    mw.assert_called_once_with("pg-cluster", in_progress=False, reuse_pvc=True, namespace="spatium")
    # Resumed past the stamp: no #1445 commit from the chain itself.
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_single_node_upgrade_resumed_past_uncordon_does_not_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once the chain's own uncordon has run, a later failure leaves the
    node alone — it is already back in service."""
    _patch_chain_ok(monkeypatch, cluster_verify=_failing("cluster_verify", "pods not ready"))
    with patch.object(per_node.k8s, "uncordon_node") as un:
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
            start_step="cluster_verify",
        )
    assert result.failed_at == "cluster_verify"
    assert [s.name for s in result.steps] == ["cluster_verify"]
    un.assert_not_called()


@pytest.mark.asyncio
async def test_single_node_upgrade_releases_node_when_stamp_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The #1445 commit sits between steps, outside the per-step crash
    wrapper. It failing used to raise out of the chain with the node
    cordoned and drained; it now fails the stamp step and releases."""
    _patch_chain_ok(monkeypatch, reboot=_must_not_run("reboot"))
    db = MagicMock(commit=AsyncMock(side_effect=RuntimeError("connection lost")))
    db.rollback = AsyncMock()
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=(True, None)) as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window", return_value=(True, None)),
    ):
        result = await per_node.single_node_upgrade(
            db,
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
        )
    assert result.failed_at == "trigger_slot_apply"
    assert "connection lost" in result.error
    assert result.steps[-1].name == "release_node"
    db.rollback.assert_awaited_once()
    un.assert_called_once_with("node-1")


@pytest.mark.asyncio
async def test_single_node_upgrade_release_crash_does_not_mask_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compensation that raises is recorded as a failed release_node;
    the chain still returns the original failure instead of raising."""
    _patch_chain_ok(monkeypatch, drain=_failing("drain", "drain timed out"))
    with patch.object(per_node.k8s, "uncordon_node", side_effect=RuntimeError("boom")):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
        )
    assert result.failed_at == "drain"
    assert result.error == "drain timed out"
    release = result.steps[-1]
    assert release.name == "release_node" and release.ok is False
    assert "boom" in release.error


@pytest.mark.asyncio
async def test_single_node_upgrade_passes_cnpg_cluster_to_convergence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: the chain hands convergence the run's (possibly auto-detected)
    CNPG cluster so it can wait for the node's Postgres instance."""
    seen: dict[str, Any] = {}

    async def _convergence(node: str, **kw: Any) -> per_node.StepResult:
        seen.update(kw, node=node)
        return per_node.StepResult(name="convergence", started_at="t").finish(True)

    _patch_chain_ok(monkeypatch, convergence=_convergence)
    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg-cluster",
        cnpg_namespace="spatium",
    )
    assert result.ok is True
    assert seen == {
        "node": "node-1",
        "cnpg_cluster_name": "pg-cluster",
        "cnpg_namespace": "spatium",
    }


@pytest.mark.asyncio
async def test_single_node_upgrade_step_crash_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An uncaught exception in a step doesn't take down the chain —
    it gets wrapped as a failed StepResult with the exception message.
    Otherwise an orchestrator-pod crash mid-step would leave the
    SystemUpgradeRun row stuck in ``running`` forever."""

    async def _crash(_target_version: str, *_a: object) -> per_node.StepResult:
        raise RuntimeError("kubeapi unreachable")

    monkeypatch.setattr(per_node, "_step_preflight", _crash)

    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
    )
    assert result.ok is False
    assert result.failed_at == "preflight"
    assert "kubeapi unreachable" in result.error
