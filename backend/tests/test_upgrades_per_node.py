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
    assert "1 pod(s) still present (1 eviction(s) refused)" in step.error
    assert step.detail["blocked"]
    assert step.detail["blocked"][0]["pod"] == "default/blocked"
    assert step.detail["remaining"] == ["default/blocked"]
    assert step.detail["not_removed"] == []


@pytest.mark.asyncio
async def test_step_drain_timeout_counts_pods_whose_eviction_was_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1804 — a node whose kubelet is down accepts every eviction and removes
    nothing. The pods stay listed on the node until the drain times out, and
    the message must count them: it used to count only the evictions refused
    in the last cycle and read "0 pod(s) still present"."""
    pods = [
        {
            "metadata": {
                "name": name,
                "namespace": "spatium",
                "ownerReferences": [{"kind": "ReplicaSet"}],
            },
            "status": {"phase": "Running"},
        }
        for name in ("api-1", "worker-1")
    ]

    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _n: list(pods))
    monkeypatch.setattr(per_node.k8s, "evict_pod", lambda *_a, **_k: (201, None))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    step = await per_node._step_drain("node-1", timeout_s=0.05)
    assert step.ok is False
    assert "0 pod(s)" not in step.error
    assert "2 pod(s) still present" in step.error
    assert "2 evicted but never removed from the node" in step.error
    assert step.detail["blocked"] == []
    assert step.detail["remaining"] == ["spatium/api-1", "spatium/worker-1"]
    assert step.detail["not_removed"] == ["spatium/api-1", "spatium/worker-1"]


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
        last_upgrade_progress = None

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
async def test_step_convergence_does_not_wait_for_cnpg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544 / ddi-pg case 3: convergence runs while the node is still
    cordoned, when its own evicted Postgres instance cannot schedule. It
    must not read the CNPG count at all — that wait lives after the
    uncordon, in cluster_verify."""
    ready_node = {
        "metadata": {"name": "node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }
    monkeypatch.setattr(per_node.k8s, "get_node", lambda _name: (200, ready_node))
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _name: [])
    monkeypatch.setattr(
        per_node.k8s,
        "get_cnpg_cluster",
        lambda *a, **k: pytest.fail("convergence must not read the CNPG count"),
    )
    step = await per_node._step_convergence("node-1", timeout_s=5.0)
    assert step.ok is True


def _cnpg(ready: int, spec: int = 3) -> dict[str, Any]:
    return {
        "spec": {"instances": spec},
        "status": {"readyInstances": ready, "currentPrimary": "pg-cluster-1"},
    }


def _ok_check(name: str) -> preflight.PreflightResult:
    return preflight.PreflightResult(name, "ok", "fine", {})


@pytest.mark.asyncio
async def test_step_cluster_verify_waits_for_cnpg_instances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: after the uncordon, cluster_verify polls until the CNPG
    Cluster reports every instance ready, then runs repl + quorum."""
    reads = iter([_cnpg(2), _cnpg(2), _cnpg(3)])
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, next(reads)))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with (
        patch.object(preflight, "check_replication_lag", AsyncMock(return_value=_ok_check("repl"))),
        patch.object(preflight, "check_quorum", return_value=_ok_check("quorum")),
    ):
        step = await per_node._step_cluster_verify(
            "2026.06.01-1", cnpg_cluster_name="pg-cluster", cnpg_namespace="spatium"
        )
    assert step.ok is True
    assert step.detail["cnpg_ready_instances"] == 3
    assert step.detail["cnpg_spec_instances"] == 3


@pytest.mark.asyncio
async def test_step_cluster_verify_times_out_when_cnpg_instance_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: the instance never comes back after the uncordon → the step
    fails, with the count in the error, instead of passing on repl/quorum."""
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _cnpg(2)))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    step = await per_node._step_cluster_verify(
        "2026.06.01-1", cnpg_cluster_name="pg-cluster", cnpg_timeout_s=0.05
    )
    assert step.ok is False
    assert "2/3" in step.error and "after uncordon" in step.error


@pytest.mark.asyncio
async def test_step_preflight_waits_for_cnpg_before_the_node_is_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: preflight runs before this node's maintenance window and
    cordon; a cluster short an instance fails it, so this node's drain
    cannot start at 2/3."""
    report = preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="ok",
        can_start=True,
        results=[_ok_check("x")],
    )
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _cnpg(2)))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    with patch.object(preflight, "run_all", AsyncMock(return_value=report)):
        step = await per_node._step_preflight(
            "2026.06.01-1", cnpg_cluster_name="pg-cluster", cnpg_timeout_s=0.05
        )
    assert step.ok is False
    assert "CNPG instances not all ready" in step.error


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
    14 step results (etcd_snapshot is the no-op placeholder)."""

    # Mock every step to return an ok StepResult so we exercise the
    # chained-call shape without re-doing each step's tests.
    async def _ok(name: per_node.StepName, **_kw: Any) -> per_node.StepResult:
        return per_node.StepResult(name=name, started_at="t", finished_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_preflight", lambda *a, **k: _ok("preflight"))
    monkeypatch.setattr(per_node, "_step_etcd_snapshot", lambda *a, **k: _ok("etcd_snapshot"))
    monkeypatch.setattr(per_node, "_step_mirror_ready", lambda *a, **k: _ok("mirror_ready"))
    monkeypatch.setattr(
        per_node, "_step_trigger_slot_apply", lambda *a, **k: _ok("trigger_slot_apply")
    )
    monkeypatch.setattr(per_node, "_step_stage", lambda *a, **k: _ok("stage"))
    monkeypatch.setattr(
        per_node, "_step_cnpg_maintenance_on", lambda *a, **k: _ok("cnpg_maintenance_on")
    )
    monkeypatch.setattr(per_node, "_step_cordon", lambda *a, **k: _ok("cordon"))
    monkeypatch.setattr(
        per_node, "_step_verify_primary_moved", lambda *a, **k: _ok("verify_primary_moved")
    )
    monkeypatch.setattr(per_node, "_step_drain", lambda *a, **k: _ok("drain"))
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
        "mirror_ready",
        "trigger_slot_apply",
        "stage",
        "cnpg_maintenance_on",
        "cordon",
        "verify_primary_moved",
        "drain",
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
    """Cordon returns ok=False → chain stops at step 7. No subsequent
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
    monkeypatch.setattr(per_node, "_step_mirror_ready", lambda *a, **k: _ok("mirror_ready"))
    monkeypatch.setattr(
        per_node, "_step_trigger_slot_apply", lambda *a, **k: _ok("trigger_slot_apply")
    )
    monkeypatch.setattr(per_node, "_step_stage", lambda *a, **k: _ok("stage"))
    monkeypatch.setattr(
        per_node, "_step_cnpg_maintenance_on", lambda *a, **k: _ok("cnpg_maintenance_on")
    )
    monkeypatch.setattr(per_node, "_step_cordon", _fail_cordon)
    monkeypatch.setattr(per_node, "_step_drain", _track_drain)

    with (
        patch.object(per_node.k8s, "uncordon_node") as un,
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
        )
    assert result.ok is False
    assert result.failed_at == "cordon"
    assert "403" in result.error
    assert drain_called is False
    # Steps after cordon never ran; the window this run set was released.
    assert [s.name for s in result.steps] == [
        "preflight",
        "etcd_snapshot",
        "mirror_ready",
        "trigger_slot_apply",
        "stage",
        "cnpg_maintenance_on",
        "cordon",
        "release_node",
    ]
    # #1542: the window set before the failed cordon is cleared, and the
    # node — which this run never cordoned — is not uncordoned.
    release = result.steps[-1]
    assert release.ok is True
    assert release.detail["maintenance_window_cleared"] is True
    assert release.detail["uncordon_skipped"] == "the run never cordoned the node"
    mw.assert_called_once_with("pg-cluster", in_progress=False, reuse_pvc=True, namespace=None)
    un.assert_not_called()


@pytest.mark.asyncio
async def test_single_node_upgrade_cordon_failure_without_window_releases_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CNPG cluster → no window was set; a failed cordon holds nothing,
    so no release step runs at all."""
    _patch_chain_ok(monkeypatch, cordon=_failing("cordon", "kubeapi status 403"))
    with (
        patch.object(per_node.k8s, "uncordon_node") as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window") as mw,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        )
    assert result.failed_at == "cordon"
    assert result.steps[-1].name == "cordon"
    un.assert_not_called()
    mw.assert_not_called()


@pytest.mark.asyncio
async def test_step_cordon_records_pre_upgrade_unschedulable() -> None:
    node = {"spec": {"unschedulable": True}}
    with (
        patch.object(per_node.k8s, "get_node", return_value=(200, node)),
        patch.object(per_node.k8s, "cordon_node", return_value=(True, None)),
    ):
        step = await per_node._step_cordon("node-1")
    assert step.ok is True
    assert step.detail["was_unschedulable"] is True


@pytest.mark.asyncio
async def test_step_cordon_unknown_pre_state_when_node_unreadable() -> None:
    with (
        patch.object(
            per_node.k8s, "get_node", side_effect=per_node.k8s.KubeapiUnavailableError("down")
        ),
        patch.object(per_node.k8s, "cordon_node", return_value=(True, None)),
    ):
        step = await per_node._step_cordon("node-1")
    assert step.ok is True
    assert step.detail["was_unschedulable"] is None


@pytest.mark.asyncio
async def test_single_node_upgrade_does_not_uncordon_a_pre_cordoned_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A node an operator had cordoned before the upgrade stays cordoned
    when a later step fails; the window is still cleared."""

    async def _cordon(_node: str, **_kw: Any) -> per_node.StepResult:
        return per_node.StepResult(
            name="cordon", started_at="t", detail={"was_unschedulable": True}
        ).finish(True)

    _patch_chain_ok(monkeypatch, cordon=_cordon, drain=_failing("drain", "drain timed out"))
    with (
        patch.object(per_node.k8s, "uncordon_node") as un,
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
        )
    assert result.failed_at == "drain"
    release = result.steps[-1]
    assert release.name == "release_node" and release.ok is True
    assert release.detail["uncordon_skipped"] == (
        "the node was already cordoned before the upgrade"
    )
    assert release.detail["maintenance_window_cleared"] is True
    un.assert_not_called()
    mw.assert_called_once()


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
    monkeypatch.setattr(per_node, "_step_mirror_ready", lambda *a, **k: _ok("mirror_ready"))
    monkeypatch.setattr(
        per_node, "_step_trigger_slot_apply", lambda *a, **k: _ok("trigger_slot_apply")
    )
    monkeypatch.setattr(per_node, "_step_stage", lambda *a, **k: _ok("stage"))
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
            MagicMock(commit=AsyncMock()),
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
    monkeypatch.setattr(per_node, "_step_mirror_ready", lambda *a, **k: _ok("mirror_ready"))
    monkeypatch.setattr(
        per_node, "_step_trigger_slot_apply", lambda *a, **k: _ok("trigger_slot_apply")
    )
    monkeypatch.setattr(per_node, "_step_stage", lambda *a, **k: _ok("stage"))
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
            MagicMock(commit=AsyncMock()),
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
    # #1542: the step names what is still held, for the distinct alert.
    assert release.detail["stuck"] == ["cordon", "maintenance_window"]


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
        "mirror_ready",
        "trigger_slot_apply",
        "stage",
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


@pytest.mark.parametrize("step", ["mirror_ready", "trigger_slot_apply", "stage"])
@pytest.mark.asyncio
async def test_single_node_upgrade_pre_window_failure_releases_nothing(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """#1463 stages before the window and the cordon, so a failure there
    holds nothing: the node keeps serving, and no release_node runs."""
    _patch_chain_ok(
        monkeypatch,
        **{step: _failing(step, f"{step} failed")},
        cnpg_maintenance_on=_must_not_run("cnpg_maintenance_on"),
        cordon=_must_not_run("cordon"),
    )
    with (
        patch.object(per_node.k8s, "uncordon_node") as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window") as mw,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
        )
    assert result.failed_at == step
    assert result.steps[-1].name == step
    assert "release_node" not in [s.name for s in result.steps]
    un.assert_not_called()
    mw.assert_not_called()


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
async def test_single_node_upgrade_passes_cnpg_cluster_to_the_count_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: the chain hands the run's (possibly auto-detected) CNPG
    cluster to preflight and cluster_verify, where the count is waited
    for, and not to convergence."""
    seen: dict[str, dict[str, Any]] = {}

    def _capture(name: per_node.StepName) -> Any:
        async def _step(*_a: Any, **kw: Any) -> per_node.StepResult:
            seen[name] = kw
            return per_node.StepResult(name=name, started_at="t").finish(True)

        return _step

    _patch_chain_ok(
        monkeypatch,
        preflight=_capture("preflight"),
        convergence=_capture("convergence"),
        cluster_verify=_capture("cluster_verify"),
    )
    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg-cluster",
        cnpg_namespace="spatium",
    )
    assert result.ok is True
    cnpg = {"cnpg_cluster_name": "pg-cluster", "cnpg_namespace": "spatium"}
    # #1709 — and the run's uploaded image, for the mirror headroom check
    # (none here: the target is a URL).
    assert seen["preflight"] == {**cnpg, "slot_image_id": None, "disk_nodes": None}
    assert seen["cluster_verify"] == {
        **cnpg,
        "control_plane_release": "spatium-control",
        "control_plane_namespace": None,
    }
    assert seen["convergence"] == {}


class _CnpgPinnedToCordonedNode:
    """A fake cluster where the node's own Postgres instance (local-path
    volume, pinned to the node) is evicted by its drain and can only
    reschedule once the node is uncordoned — ddi-pg's case 3 on #1610."""

    def __init__(self) -> None:
        self.cordoned = False
        self.drained = False
        self.events: list[str] = []

    def cluster(self, *_a: Any, **_k: Any) -> tuple[int, dict[str, Any]]:
        ready = 2 if (self.cordoned and self.drained) else 3
        return 200, _cnpg(ready)

    def cordon(self, _node: str) -> tuple[bool, None]:
        self.cordoned = True
        self.events.append("cordon")
        return True, None

    def uncordon(self, _node: str) -> tuple[bool, None]:
        self.cordoned = False
        self.drained = False
        self.events.append("uncordon")
        return True, None


@pytest.mark.asyncio
async def test_chain_waits_for_cnpg_after_uncordon_not_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ddi-pg case 3 on #1610: CNPG reads 2/3 from the drain until the
    uncordon. The real convergence, uncordon and cluster_verify steps run;
    the node must succeed, with the count waited for after the uncordon.

    Negative control: on f941e21c, where convergence waited for the count
    before the uncordon, this chain fails at ``convergence`` (timed out).
    """
    fake = _CnpgPinnedToCordonedNode()
    ready_node = {
        "metadata": {"name": "node-1"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    }

    async def _drain(*_a: Any, **_k: Any) -> per_node.StepResult:
        fake.drained = True
        fake.events.append("drain")
        return per_node.StepResult(name="drain", started_at="t").finish(True)

    real_convergence = per_node._step_convergence
    real_cluster_verify = per_node._step_cluster_verify

    async def _convergence(node: str, **kw: Any) -> per_node.StepResult:
        return await real_convergence(node, **{**kw, "timeout_s": 0.3})

    async def _cluster_verify(target: str, **kw: Any) -> per_node.StepResult:
        fake.events.append("cluster_verify")
        return await real_cluster_verify(target, **kw)

    _patch_chain_ok(
        monkeypatch,
        cordon=lambda node, **_k: _as_step("cordon", fake.cordon(node)),
        drain=_drain,
        convergence=_convergence,
        uncordon=per_node._step_uncordon,
        cluster_verify=_cluster_verify,
    )
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node.k8s, "get_node", lambda _name: (200, ready_node))
    monkeypatch.setattr(per_node.k8s, "list_pods_on_node", lambda _name: [])
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", fake.cluster)
    monkeypatch.setattr(per_node.k8s, "uncordon_node", fake.uncordon)
    monkeypatch.setattr(per_node.k8s, "patch_cnpg_maintenance_window", lambda *a, **k: (True, None))
    with (
        patch.object(preflight, "check_replication_lag", AsyncMock(return_value=_ok_check("repl"))),
        patch.object(preflight, "check_quorum", return_value=_ok_check("quorum")),
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
            cnpg_namespace="spatium",
        )
    assert result.ok is True, (result.failed_at, result.error)
    assert fake.events == ["cordon", "drain", "uncordon", "cluster_verify"]
    verify = result.steps[-1]
    assert verify.name == "cluster_verify"
    assert verify.detail["cnpg_ready_instances"] == 3
    assert "release_node" not in [s.name for s in result.steps]


async def _as_step(name: per_node.StepName, outcome: tuple[bool, Any]) -> per_node.StepResult:
    return per_node.StepResult(name=name, started_at="t").finish(outcome[0])


@pytest.mark.asyncio
async def test_chain_does_not_drain_while_cnpg_is_short(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1544: the next node's chain starts with CNPG at 2/3 (the previous
    node's instance has not come back). Preflight waits, times out, and
    fails — before this node's window, cordon or drain."""
    report = preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="ok",
        can_start=True,
        results=[_ok_check("x")],
    )
    real_preflight = per_node._step_preflight

    async def _preflight(*a: Any, **kw: Any) -> per_node.StepResult:
        return await real_preflight(*a, **{**kw, "cnpg_timeout_s": 0.05})

    _patch_chain_ok(
        monkeypatch,
        preflight=_preflight,
        cnpg_maintenance_on=_must_not_run("cnpg_maintenance_on"),
        cordon=_must_not_run("cordon"),
        drain=_must_not_run("drain"),
    )
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _cnpg(2)))
    with (
        patch.object(preflight, "run_all", AsyncMock(return_value=report)),
        patch.object(per_node.k8s, "uncordon_node") as un,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-2",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
        )
    assert result.failed_at == "preflight"
    assert "CNPG instances not all ready" in result.error
    assert [s.name for s in result.steps] == ["preflight"]
    un.assert_not_called()


@pytest.mark.asyncio
async def test_chain_cnpg_timeout_after_uncordon_fails_without_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The count never recovers after the uncordon: cluster_verify fails
    the node and the run stops before the next drain. The node is already
    uncordoned with its window cleared, so no release_node runs."""
    real_cluster_verify = per_node._step_cluster_verify

    async def _cluster_verify(target: str, **kw: Any) -> per_node.StepResult:
        return await real_cluster_verify(target, **{**kw, "cnpg_timeout_s": 0.05})

    _patch_chain_ok(monkeypatch, cluster_verify=_cluster_verify)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _cnpg(2)))
    with (
        patch.object(per_node.k8s, "uncordon_node") as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window") as mw,
    ):
        result = await per_node.single_node_upgrade(
            MagicMock(commit=AsyncMock()),
            node_name="node-1",
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            cnpg_cluster_name="pg-cluster",
        )
    assert result.failed_at == "cluster_verify"
    assert "after uncordon" in result.error
    assert result.steps[-1].name == "cluster_verify"
    un.assert_not_called()
    mw.assert_not_called()


@pytest.mark.asyncio
async def test_single_node_upgrade_step_crash_caught(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An uncaught exception in a step doesn't take down the chain —
    it gets wrapped as a failed StepResult with the exception message.
    Otherwise an orchestrator-pod crash mid-step would leave the
    SystemUpgradeRun row stuck in ``running`` forever."""

    async def _crash(_target_version: str, *_a: object, **_k: object) -> per_node.StepResult:
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


# ── Control-plane Deployments readiness gate (#1544) ─────────────────


def _dep(
    name: str, *, replicas: int = 1, available: int | None = None, total: int | None = None
) -> dict[str, Any]:
    avail = replicas if available is None else available
    return {
        "metadata": {"name": name, "generation": 3},
        "spec": {"replicas": replicas},
        "status": {
            "observedGeneration": 3,
            "updatedReplicas": replicas,
            "availableReplicas": avail,
            "replicas": replicas if total is None else total,
        },
    }


def _patch_cp(monkeypatch: pytest.MonkeyPatch, reads: list[list[dict[str, Any]]]) -> list[str]:
    """Serve successive Deployment lists (the last repeats); return the
    selectors asked for."""
    seen: list[str] = []
    it = iter(reads)
    last: list[list[dict[str, Any]]] = [[]]

    def _list(selector: str, namespace: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        seen.append(selector)
        try:
            last[0] = next(it)
        except StopIteration:
            pass  # keep serving the final read
        return 200, last[0]

    monkeypatch.setattr(per_node.k8s, "get_config", object)
    monkeypatch.setattr(per_node.k8s, "list_deployments", _list)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    return seen


@pytest.mark.asyncio
async def test_cluster_verify_waits_through_single_replica_rollout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 1-replica api at zero available (retire-first rollout) is waited
    through, not failed; the Deployments are found by label selector."""
    seen = _patch_cp(
        monkeypatch,
        [
            [_dep("cp-api", available=0), _dep("cp-worker")],
            [_dep("cp-api", available=0, total=2), _dep("cp-worker")],
            [_dep("cp-api"), _dep("cp-worker")],
        ],
    )
    with (
        patch.object(preflight, "check_replication_lag", AsyncMock(return_value=_ok_check("repl"))),
        patch.object(preflight, "check_quorum", return_value=_ok_check("quorum")),
    ):
        step = await per_node._step_cluster_verify(
            "2026.06.01-1", control_plane_release="spatium-control"
        )
    assert step.ok is True
    assert step.detail["control_plane_deployments"] == 2
    assert len(seen) == 3
    assert "app.kubernetes.io/instance=spatium-control" in seen[0]


@pytest.mark.asyncio
async def test_cluster_verify_fails_when_a_deployment_never_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_cp(monkeypatch, [[_dep("cp-api"), _dep("cp-frontend", replicas=2, available=1)]])
    step = await per_node._step_cluster_verify(
        "2026.06.01-1", control_plane_release="spatium-control", control_plane_timeout_s=0.05
    )
    assert step.ok is False
    assert "cp-frontend" in step.error and "1/2" in step.error


@pytest.mark.asyncio
async def test_cluster_verify_not_settled_while_old_pods_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Available == desired but an old ReplicaSet's pod is still counted:
    a rollout is in progress, so the gate does not pass."""
    _patch_cp(monkeypatch, [[_dep("cp-api", total=2)]])
    step = await per_node._step_cluster_verify(
        "2026.06.01-1", control_plane_release="spatium-control", control_plane_timeout_s=0.05
    )
    assert step.ok is False
    assert "rollout in progress" in step.error


@pytest.mark.asyncio
async def test_chain_control_plane_timeout_fails_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chain stops at cluster_verify, so the next node is not started."""
    real_cluster_verify = per_node._step_cluster_verify

    async def _cluster_verify(target: str, **kw: Any) -> per_node.StepResult:
        return await real_cluster_verify(target, **{**kw, "control_plane_timeout_s": 0.05})

    _patch_chain_ok(monkeypatch, cluster_verify=_cluster_verify)
    _patch_cp(monkeypatch, [[_dep("cp-api", available=0)]])
    result = await per_node.single_node_upgrade(
        MagicMock(commit=AsyncMock()),
        node_name="node-1",
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        control_plane_release="spatium-control",
    )
    assert result.ok is False
    assert result.failed_at == "cluster_verify"
    assert "cp-api" in result.error


@pytest.mark.asyncio
async def test_cluster_verify_fails_when_no_deployment_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A selector that matches nothing must not read as "skipped": the
    orchestrator runs inside the release, so an empty list means the
    selector or namespace is wrong and the gate would be silently off."""
    seen = _patch_cp(monkeypatch, [[]])
    step = await per_node._step_cluster_verify(
        "2026.06.01-1",
        control_plane_release="spatium-control",
        control_plane_namespace="spatium",
        control_plane_timeout_s=60.0,
    )
    assert step.ok is False
    assert "no Deployments match" in step.error
    assert len(seen) == 1  # failed at once, did not poll to the timeout


@pytest.mark.parametrize("code", [401, 403, 404])
@pytest.mark.asyncio
async def test_cluster_verify_fails_fast_on_refused_list(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """Missing RBAC (or a wrong namespace) is not polled for ten minutes
    and is not reported as skipped."""
    calls: list[str] = []

    def _list(selector: str, namespace: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        calls.append(selector)
        return code, []

    monkeypatch.setattr(per_node.k8s, "get_config", object)
    monkeypatch.setattr(per_node.k8s, "list_deployments", _list)
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)
    step = await per_node._step_cluster_verify(
        "2026.06.01-1", control_plane_release="spatium-control", control_plane_timeout_s=60.0
    )
    assert step.ok is False
    assert str(code) in step.error and "RBAC" in step.error
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_cluster_verify_not_settled_before_controller_observes_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A just-patched Deployment whose status still describes the previous
    generation is not settled, even though its counters look complete."""
    stale = _dep("cp-api")
    stale["metadata"]["generation"] = 4  # status.observedGeneration is 3
    _patch_cp(monkeypatch, [[stale]])
    step = await per_node._step_cluster_verify(
        "2026.06.01-1", control_plane_release="spatium-control", control_plane_timeout_s=0.05
    )
    assert step.ok is False
    assert "cp-api" in step.error


# ── #1542 — ``stuck`` names exactly what the failed release left held ──


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("skip", "clear_window", "uncordon_rc", "window_rc", "expect_ok", "expect_stuck"),
    [
        # Uncordon fails: the window clear is never attempted.
        (None, True, (False, "403"), (True, None), False, ["cordon", "maintenance_window"]),
        # Uncordon fails, no window was set by this run.
        (None, False, (False, "403"), (True, None), False, ["cordon"]),
        # Uncordon ok, window clear fails.
        (None, True, (True, None), (False, "403"), False, ["maintenance_window"]),
        # Pre-cordoned node (#1610 leaves it cordoned on purpose): only the
        # window may be reported, never the operator's cordon.
        (
            "the node was already cordoned before the upgrade",
            True,
            (True, None),
            (False, "403"),
            False,
            ["maintenance_window"],
        ),
        # Both succeed: nothing stuck.
        (None, True, (True, None), (True, None), True, None),
    ],
)
async def test_release_node_stuck_names_what_is_held(
    skip: str | None,
    clear_window: bool,
    uncordon_rc: tuple[bool, str | None],
    window_rc: tuple[bool, str | None],
    expect_ok: bool,
    expect_stuck: list[str] | None,
) -> None:
    with (
        patch.object(per_node.k8s, "uncordon_node", return_value=uncordon_rc) as un,
        patch.object(per_node.k8s, "patch_cnpg_maintenance_window", return_value=window_rc),
    ):
        step = await per_node._step_release_node(  # noqa: SLF001
            "node-1",
            "pg-cluster",
            None,
            clear_window=clear_window,
            uncordon_skip_reason=skip,
        )
    assert step.ok is expect_ok
    assert step.detail.get("stuck") == expect_stuck
    if skip is not None:
        un.assert_not_called()
