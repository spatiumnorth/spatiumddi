"""The plan's kubeapi reads ride out a refused connection (#2767).

``POST /upgrades/plan`` read the appliance nodes with one request. The api
reaches kubeapi through the ``kubernetes`` Service, which spreads each new
connection across the control-plane nodes; while one restarts k3s a new
connection can be refused although the others answer, and the plan answered 409
``kubeapi unreachable``. The plan's node read, the CNPG cluster detection, the
quorum pre-flight read and the upgrade-lease read now try again, on the same
classifier the rolling run's writes use (#2449).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.services.appliance import k8s
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import kubeapi_retry, mutex, orchestrator, preflight
from tests.test_upgrades_orchestrator import _build_mock_db_for_plan, _ok_preflight

REFUSED = (
    "kubeapi GET /api/v1/nodes?labelSelector=spatium.io/role%3Dappliance: "
    "[Errno 111] Connection refused"
)
NODES = [{"metadata": {"name": "node-b"}}, {"metadata": {"name": "node-a"}}]


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []

    async def _sleep(d: float) -> None:
        slept.append(d)

    monkeypatch.setattr(kubeapi_retry, "_sleep", _sleep)
    monkeypatch.setattr(kubeapi_retry.time, "sleep", lambda d: slept.append(d))
    return slept


async def _plan(db: Any) -> Any:
    return await orchestrator.plan_upgrade(
        db,
        target_version="2026.06.01-1",
        slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        cnpg_cluster_name="pg",
    )


@pytest.mark.asyncio
async def test_plan_rides_out_a_refused_connection_on_the_node_read() -> None:
    db = _build_mock_db_for_plan(appliance_rows=[("node-a", None), ("node-b", None)])
    calls: list[int] = []

    def _list_nodes(label_selector: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        calls.append(1)
        if len(calls) == 1:
            raise k8s.KubeapiUnavailableError(REFUSED)
        return 200, NODES

    with (
        patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())),
        patch.object(orchestrator.k8s, "list_nodes", _list_nodes),
    ):
        plan = await _plan(db)
    assert len(calls) == 2
    assert plan.node_order == ["node-a", "node-b"]


@pytest.mark.asyncio
async def test_plan_rides_out_a_5xx_on_the_node_read() -> None:
    db = _build_mock_db_for_plan(appliance_rows=[("node-a", None), ("node-b", None)])
    answers = iter([(503, []), (200, NODES)])
    with (
        patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())),
        patch.object(orchestrator.k8s, "list_nodes", lambda **_k: next(answers)),
    ):
        plan = await _plan(db)
    assert plan.node_order == ["node-a", "node-b"]


@pytest.mark.asyncio
async def test_plan_still_answers_unreachable_when_every_attempt_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _build_mock_db_for_plan(appliance_rows=[])
    calls: list[int] = []

    def _list_nodes(label_selector: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        calls.append(1)
        raise k8s.KubeapiUnavailableError(REFUSED)

    with (
        patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())),
        patch.object(orchestrator.k8s, "list_nodes", _list_nodes),
    ):
        with pytest.raises(orchestrator.OrchestratorError) as exc:
            await _plan(db)
    assert str(exc.value) == f"kubeapi unreachable: {REFUSED}"
    assert len(calls) > 1  # it did try again before giving up


@pytest.mark.asyncio
async def test_a_permanent_answer_is_not_retried() -> None:
    db = _build_mock_db_for_plan(appliance_rows=[])
    calls: list[int] = []

    def _list_nodes(label_selector: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        calls.append(1)
        return 403, []

    with (
        patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=_ok_preflight())),
        patch.object(orchestrator.k8s, "list_nodes", _list_nodes),
    ):
        with pytest.raises(orchestrator.OrchestratorError, match="node list returned 403"):
            await _plan(db)
    assert calls == [1]


def test_cnpg_detection_retried_when_the_read_is_refused_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    calls: list[int] = []

    def _get(name: str, namespace: str | None = None) -> tuple[int, Any]:
        calls.append(1)
        if len(calls) == 1:
            raise k8s.KubeapiUnavailableError("kubeapi GET /x: [Errno 111] Connection refused")
        return 200, {}

    monkeypatch.setattr(orchestrator.settings, "database_url", "postgresql+asyncpg://u:p@pg-rw/db")
    monkeypatch.setattr(orchestrator.k8s, "get_cnpg_cluster", _get)
    got = asyncio.run(
        kubeapi_retry.read_with_retry(
            lambda: (0, orchestrator.detect_cnpg_cluster_name(raise_unavailable=True)),
            what="t",
        )
    )
    assert got[1] == "pg"
    assert len(calls) == 2


def _nodes_body() -> bytes:
    ready = {"conditions": [{"type": "Ready", "status": "True"}]}
    return json.dumps(
        {"items": [{"metadata": {"name": f"n{i}"}, "status": ready} for i in range(3)]}
    ).encode()


def test_quorum_read_rides_out_a_refused_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def _request(method: str, path: str, **_k: Any) -> tuple[int, bytes]:
        calls.append(1)
        if len(calls) == 1:
            raise k8s.KubeapiUnavailableError(REFUSED)
        return 200, _nodes_body()

    monkeypatch.setattr(k8s, "get_config", lambda: object())
    monkeypatch.setattr(k8s, "_request", _request)
    res = preflight.check_quorum(retry_budget_s=30.0)
    assert res.level == "ok" and len(calls) == 2
    # With no budget (the post-upgrade verify) it stays a single try.
    calls.clear()
    assert preflight.check_quorum().level == "warn" and len(calls) == 1


def test_lease_read_rides_out_a_refused_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def _get_lease(name: str, namespace: str | None = None) -> tuple[int, Any]:
        calls.append(1)
        if len(calls) == 1:
            raise k8s.KubeapiUnavailableError(REFUSED)
        return 404, None

    monkeypatch.setattr(k8s, "get_config", lambda: object())
    monkeypatch.setattr(k8s, "get_lease", _get_lease)
    state = mutex.get_state(retry_budget_s=30.0)
    assert state.holder != "<unreachable>" and not state.held and len(calls) == 2
    calls.clear()
    assert mutex.get_state().holder == "<unreachable>"  # no budget: unchanged


# ── One shared deadline per request (PR #2769 review) ────────────────


class _FakeClock:
    """A clock the kubeapi stubs advance by a socket timeout per attempt."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, d: float) -> None:
        self.now += d


def test_the_socket_timeout_the_deadline_assumes_is_the_helpers() -> None:
    import inspect

    default = inspect.signature(k8s._request).parameters["timeout"].default
    assert kubeapi_retry.SOCKET_TIMEOUT_S == default
    # Stays under the console's nginx proxy_read_timeout (60 s), with room.
    assert kubeapi_retry.PLAN_DEADLINE_S <= 40.0


@pytest.mark.asyncio
async def test_plan_with_kubeapi_down_answers_409_inside_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    monkeypatch.setattr(kubeapi_retry, "time", clock)

    async def _sleep(d: float) -> None:
        clock.now += d

    monkeypatch.setattr(kubeapi_retry, "_sleep", _sleep)

    attempts: list[float] = []

    def _down(*_a: Any, **_k: Any) -> Any:
        attempts.append(clock.now)
        clock.now += kubeapi_retry.SOCKET_TIMEOUT_S  # every try blocks its full timeout
        raise k8s.KubeapiUnavailableError(REFUSED)

    ok = preflight.PreflightResult(name="x", level="ok", message="fine", detail={})

    async def _async(*_a: Any, **_k: Any) -> preflight.PreflightResult:
        return ok

    async def _no_size(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(preflight, "_slot_image_size", _no_size)
    for name in (
        "check_replication_lag",
        "check_node_disk_headroom",
        "check_mirror_disk_headroom",
        "check_kea_ha_version_skew",
        "check_powerdns_lmdb_migration",
        "check_etcd_snapshot_freshness",
        "check_pre_upgrade_backup",
    ):
        monkeypatch.setattr(preflight, name, _async)
    monkeypatch.setattr(preflight, "check_version_path", lambda **_k: ok)
    monkeypatch.setattr(k8s, "get_config", lambda: object())
    monkeypatch.setattr(k8s, "get_cnpg_cluster", _down)
    monkeypatch.setattr(k8s, "get_lease", _down)
    monkeypatch.setattr(k8s, "_request", _down)
    monkeypatch.setattr(k8s, "list_nodes", _down)
    monkeypatch.setattr(orchestrator.settings, "database_url", "postgresql+asyncpg://u:p@pg-rw/db")

    start = clock.now
    db = _build_mock_db_for_plan(appliance_rows=[])
    with pytest.raises(orchestrator.OrchestratorError):
        await orchestrator.plan_upgrade(
            db,
            target_version="2026.06.01-1",
            slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
        )
    assert clock.now - start <= kubeapi_retry.PLAN_DEADLINE_S
    # No attempt began when less than a socket timeout of the deadline remained.
    assert all(
        start + kubeapi_retry.PLAN_DEADLINE_S - t >= kubeapi_retry.SOCKET_TIMEOUT_S
        for t in attempts
    )
    assert len(attempts) > 1  # it did retry within the deadline
