"""#1445 — the rolling-upgrade orchestrator on a real multi-node cluster.

A community report from a 3-node upgrade (2026.09.04-1 → 2026.10.02-1) found
the orchestrator could not get past its lease, and that several per-node
steps would have misbehaved once it did. These pin each fix:

* every Lease write is a Kubernetes MicroTime, which the apiserver requires;
* ``verify_primary_moved`` waits until the CNPG primary runs on another node,
  and treats a pod it cannot read as unproven;
* ``single_node_upgrade`` commits the slot-apply stamp before the health gate
  waits on the supervisor that has to read it;
* ``check_replication_lag`` reads a replica state it is not allowed to see as
  unverified, not as "not streaming".
"""

from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.appliance import k8s
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import mutex, orchestrator, per_node, preflight

_MICRO_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


# ── Lease timestamps ──────────────────────────────────────────────────────────


def test_micro_time_has_exactly_six_fractional_digits() -> None:
    assert _MICRO_TIME.match(k8s._micro_time(1_759_436_411.25))
    assert k8s._micro_time(1_759_436_411.25).endswith(":11.250000Z")
    # And the lease reader parses it back.
    parsed = datetime.fromisoformat(k8s._micro_time(1_759_436_411.0).replace("Z", "+00:00"))
    assert parsed.second == 11


@pytest.fixture
def captured_requests(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    def _request(method: str, path: str, **kwargs: Any) -> tuple[int, bytes]:
        sent.append({"method": method, "path": path, "body": json.loads(kwargs["body"])})
        return (201 if method == "POST" else 200), b"{}"

    monkeypatch.setattr(k8s, "get_config", lambda: k8s._Config("h", 443, "t", "/ca", "spatium"))
    monkeypatch.setattr(k8s, "_request", _request)
    return sent


def test_every_lease_write_sends_micro_time(captured_requests: list[dict[str, Any]]) -> None:
    assert k8s.create_lease("upgrade", "api-0") == (True, None)
    assert k8s.update_lease("upgrade", "api-0", bump_transitions=True, expected_transitions=1) == (
        True,
        None,
    )
    assert k8s.clear_lease_holder("upgrade") == (True, None)

    stamps = []
    for req in captured_requests:
        spec = req["body"]["spec"]
        stamps += [spec[k] for k in ("acquireTime", "renewTime") if k in spec]
    assert len(stamps) == 5
    assert all(_MICRO_TIME.match(s) for s in stamps), stamps


# ── verify_primary_moved ──────────────────────────────────────────────────────

_CLUSTER = {
    "spec": {"instances": 3},
    "status": {"currentPrimary": "pg-1"},
}


def _pod_on(node: str) -> tuple[int, dict[str, Any]]:
    return 200, {"spec": {"nodeName": node}}


@pytest.mark.asyncio
async def test_a_primary_still_on_the_cordoned_node_is_not_moved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _CLUSTER))
    monkeypatch.setattr(per_node.k8s, "get_pod", lambda *a, **k: _pod_on("node-1"))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    step = await per_node._step_verify_primary_moved("pg", "node-1", "spatium", timeout_s=0.05)

    assert step.ok is False
    assert step.error is not None and "primary still on node-1" in step.error


@pytest.mark.asyncio
async def test_a_primary_on_another_node_has_moved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _CLUSTER))
    monkeypatch.setattr(per_node.k8s, "get_pod", lambda *a, **k: _pod_on("node-2"))

    step = await per_node._step_verify_primary_moved("pg", "node-1", "spatium", timeout_s=5)

    assert step.ok is True
    assert step.detail["primary_node"] == "node-2"


@pytest.mark.asyncio
async def test_a_primary_pod_that_cannot_be_read_proves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(per_node.k8s, "get_cnpg_cluster", lambda *a, **k: (200, _CLUSTER))
    monkeypatch.setattr(per_node.k8s, "get_pod", lambda *a, **k: (404, None))
    monkeypatch.setattr(per_node, "_POLL_INTERVAL_S", 0.0)

    step = await per_node._step_verify_primary_moved("pg", "node-1", "spatium", timeout_s=0.05)

    assert step.ok is False


# ── The slot-apply stamp is committed before the health gate ──────────────────


@pytest.mark.asyncio
async def test_the_slot_apply_stamp_is_committed_before_the_health_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    db = MagicMock()
    db.commit = AsyncMock(side_effect=lambda: events.append("commit"))

    def _ok(name: per_node.StepName) -> Any:
        async def _step(*_a: Any, **_k: Any) -> per_node.StepResult:
            events.append(name)
            return per_node.StepResult(name=name, started_at="t").finish(True)

        return _step

    for name in (
        "preflight",
        "etcd_snapshot",
        "cnpg_maintenance_on",
        "cordon",
        "verify_primary_moved",
        "drain",
        "trigger_slot_apply",
        "health_gate",
        "convergence",
        "uncordon",
        "cluster_verify",
    ):
        monkeypatch.setattr(per_node, f"_step_{name}", _ok(name))

    result = await per_node.single_node_upgrade(
        db,
        node_name="node-1",
        target_version="2026.10.03-1",
        slot_image=SlotImageTarget(url="https://example.test/slot.raw.xz"),
    )

    assert result.ok is True
    i = events.index("trigger_slot_apply")
    assert events[i + 1] == "commit"
    assert events[i + 2] == "health_gate"


# ── Replication state the app's role cannot see ───────────────────────────────


def _session_returning(rows: list[Any]) -> Any:
    session = MagicMock()
    result = MagicMock()
    result.all.return_value = rows
    session.execute = AsyncMock(return_value=result)

    @asynccontextmanager
    async def _factory() -> Any:
        yield session

    return _factory


def _row(state: str | None, lag: int | None = None) -> Any:
    return MagicMock(application_name="pg-2", state=state, lag_bytes=lag)


@pytest.mark.asyncio
async def test_replicas_whose_state_is_hidden_are_unverified_not_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preflight, "AsyncSessionLocal", _session_returning([_row(None), _row(None)])
    )

    result = await preflight.check_replication_lag()

    assert result.level == "warn"
    assert result.detail["unverified"] is True


@pytest.mark.asyncio
async def test_a_replica_that_is_visibly_not_streaming_still_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preflight, "AsyncSessionLocal", _session_returning([_row(None), _row("catchup", 0)])
    )

    result = await preflight.check_replication_lag()

    assert result.level == "fail"


# ── The run's own lease is not "another upgrade in flight" ─────────────────────


def _held_by(holder: str) -> mutex.LeaseState:
    return mutex.LeaseState(held=True, holder=holder, renew_time="t", transitions=1, expired=False)


def test_the_lease_held_by_this_run_is_not_a_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight.mutex, "get_state", lambda **_k: _held_by("worker-0"))

    assert preflight.check_inflight_conflict(own_holder="worker-0").level == "ok"
    # Anyone else, including a caller that does not say who it is, still conflicts.
    assert preflight.check_inflight_conflict(own_holder="api-1").level == "fail"
    assert preflight.check_inflight_conflict().level == "fail"


def _all_other_checks_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    def _ok(name: str) -> preflight.PreflightResult:
        return preflight.PreflightResult(name=name, level="ok", message="fine", detail={})

    for name in ("check_disk_headroom", "check_version_path", "check_quorum"):
        monkeypatch.setattr(preflight, name, lambda *_a, _n=name, **_k: _ok(_n))
    for name in (
        "check_replication_lag",
        "check_mirror_disk_headroom",
        "check_kea_ha_version_skew",
        "check_powerdns_lmdb_migration",
        "check_etcd_snapshot_freshness",
        "check_pre_upgrade_backup",
    ):

        async def _async_ok(*_a: Any, _n: str = name, **_k: Any) -> preflight.PreflightResult:
            return _ok(_n)

        monkeypatch.setattr(preflight, name, _async_ok)


@pytest.mark.asyncio
async def test_a_node_preflight_passes_on_its_own_runs_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Start takes the lease, then every node's chain opens with the full
    # preflight. Before the fix the in-flight check failed on that very
    # lease, so every run failed its first node (found by ddi-pg on #1449).
    _all_other_checks_ok(monkeypatch)
    monkeypatch.setattr(preflight.mutex, "get_state", lambda **_k: _held_by("worker-0"))

    own = await per_node._step_preflight("2026.10.03-1", "worker-0")
    anonymous = await per_node._step_preflight("2026.10.03-1")

    assert own.ok is True
    assert anonymous.ok is False
    assert anonymous.detail["failed_checks"] == ["inflight_conflict"]


@pytest.mark.asyncio
async def test_the_node_chain_forwards_the_lease_holder_to_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []

    async def _preflight(target_version: str, lease_holder: str | None = None) -> Any:
        seen.append(lease_holder)
        return per_node.StepResult(name="preflight", started_at="t").finish(True)

    async def _ok(*_a: Any, **_k: Any) -> per_node.StepResult:
        return per_node.StepResult(name="x", started_at="t").finish(True)

    monkeypatch.setattr(per_node, "_step_preflight", _preflight)
    for name in (
        "etcd_snapshot",
        "cordon",
        "drain",
        "trigger_slot_apply",
        "health_gate",
        "convergence",
        "uncordon",
        "cluster_verify",
    ):
        monkeypatch.setattr(per_node, f"_step_{name}", _ok)

    db = MagicMock(commit=AsyncMock())
    await per_node.single_node_upgrade(
        db,
        node_name="node-1",
        target_version="2026.10.03-1",
        slot_image=SlotImageTarget(url="https://example.test/slot.raw.xz"),
        lease_holder="worker-0",
    )

    assert seen == ["worker-0"]


# ── Plan detects the CNPG cluster when the field is left empty ────────────────


@pytest.mark.parametrize(
    ("url", "status", "expected"),
    [
        (
            "postgresql+asyncpg://u:p@spatium-control-spatiumddi-postgresql-rw:5432/db",
            200,
            "spatium-control-spatiumddi-postgresql",
        ),
        (
            "postgresql+asyncpg://u:p@pg-rw.spatium.svc.cluster.local:5432/db",
            200,
            "pg",
        ),
        # Ends in -rw, but no such Cluster: not a CNPG database.
        ("postgresql+asyncpg://u:p@db-rw:5432/db", 404, ""),
    ],
)
def test_the_cnpg_cluster_is_detected_from_the_database_host(
    monkeypatch: pytest.MonkeyPatch, url: str, status: int, expected: str
) -> None:
    asked: list[str] = []

    def _get(name: str, namespace: str | None = None) -> tuple[int, Any]:
        asked.append(name)
        return status, {}

    monkeypatch.setattr(orchestrator.settings, "database_url", url)
    monkeypatch.setattr(orchestrator.k8s, "get_cnpg_cluster", _get)

    assert orchestrator.detect_cnpg_cluster_name() == expected
    assert asked == [expected or "db"]


def test_a_database_host_without_rw_asks_kubernetes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _get(*_a: Any, **_k: Any) -> tuple[int, Any]:
        raise AssertionError("should not be called")

    monkeypatch.setattr(
        orchestrator.settings, "database_url", "postgresql+asyncpg://u:p@postgres:5432/db"
    )
    monkeypatch.setattr(orchestrator.k8s, "get_cnpg_cluster", _get)

    assert orchestrator.detect_cnpg_cluster_name() == ""


def test_an_unreachable_kubeapi_detects_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _get(*_a: Any, **_k: Any) -> tuple[int, Any]:
        raise k8s.KubeapiUnavailableError("no service account")

    monkeypatch.setattr(orchestrator.settings, "database_url", "postgresql+asyncpg://u:p@pg-rw/db")
    monkeypatch.setattr(orchestrator.k8s, "get_cnpg_cluster", _get)

    assert orchestrator.detect_cnpg_cluster_name() == ""
