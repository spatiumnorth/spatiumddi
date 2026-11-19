"""An unreadable upgrade lease is its own pre-flight outcome (#2779)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.services.appliance import k8s
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import kubeapi_retry, mutex, orchestrator, preflight
from tests.test_upgrades_orchestrator import _build_mock_db_for_plan


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kubeapi_retry.time, "sleep", lambda d: None)


def _unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _get_lease(name: str, namespace: str | None = None) -> tuple[int, Any]:
        raise k8s.KubeapiUnavailableError("kubeapi GET lease: [Errno 111] Connection refused")

    monkeypatch.setattr(k8s, "get_config", object)
    monkeypatch.setattr(k8s, "get_lease", _get_lease)


def test_unreadable_lease_is_kubeapi_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    _unreachable(monkeypatch)
    res = preflight.check_inflight_conflict(retry_budget_s=1.0)
    assert res.name == "kubeapi_unreachable" and res.level == "fail"
    assert "Kubernetes API" in res.message and mutex.LEASE_NAME in res.message


def test_really_held_lease_is_still_inflight_conflict(monkeypatch: pytest.MonkeyPatch) -> None:
    held = mutex.LeaseState(
        held=True, holder="other-run", renew_time=None, transitions=1, expired=False
    )
    monkeypatch.setattr(mutex, "get_state", lambda **_k: held)
    res = preflight.check_inflight_conflict()
    assert res.name == "inflight_conflict" and res.level == "fail"


def test_own_run_with_unreadable_lease_still_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    _unreachable(monkeypatch)
    res = preflight.check_inflight_conflict(own_holder="me")
    assert res.name == "inflight_conflict" and res.level == "warn"


@pytest.mark.asyncio
async def test_plan_409_says_the_api_was_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = preflight.check_inflight_conflict  # real check, lease read raising
    _unreachable(monkeypatch)
    res = bad()
    report = preflight.PreflightReport(
        target_version="2026.06.01-1",
        current_version="2026.05.22-2",
        overall="fail",
        can_start=False,
        results=[res],
    )
    db = _build_mock_db_for_plan(appliance_rows=[("node-a", None)])
    with patch.object(orchestrator.preflight, "run_all", AsyncMock(return_value=report)):
        with pytest.raises(orchestrator.OrchestratorError) as ei:
            await orchestrator.plan_upgrade(
                db,
                target_version="2026.06.01-1",
                slot_image=SlotImageTarget(url="http://mirror/x.raw.xz"),
            )
    msg = str(ei.value)
    assert "kubeapi_unreachable" in msg and "Kubernetes API" in msg
    assert "inflight_conflict" not in msg
