"""The drive's first Lease read rides out a kubeapi blip, and a start it still
cannot make is written on the run (#4512)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.appliance import k8s
from app.services.upgrades import kubeapi_retry, orchestrator
from tests.test_upgrades_orchestrator import _db_for_state_test, _FakeRun


@pytest.fixture
def kube(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    st: dict[str, Any] = {"get": [], "reads": 0, "created": 0}
    monkeypatch.setattr(k8s, "get_config", object)
    monkeypatch.setattr(kubeapi_retry, "READ_RETRY_INTERVAL_S", 0.01)
    monkeypatch.setattr(kubeapi_retry.time, "sleep", lambda _s: None)

    def get_lease(name: str, namespace: str | None = None) -> Any:
        st["reads"] += 1
        item = st["get"].pop(0) if len(st["get"]) > 1 else st["get"][0]
        if isinstance(item, Exception):
            raise item
        return item

    def create_lease(*_a: Any, **_kw: Any) -> tuple[bool, str | None]:
        st["created"] += 1
        return True, None

    monkeypatch.setattr(k8s, "get_lease", get_lease)
    monkeypatch.setattr(k8s, "create_lease", create_lease)
    # The drive's node loop is out of scope: the run is "started" once it runs.
    monkeypatch.setattr(orchestrator, "_drive_loop", AsyncMock(return_value=None))
    monkeypatch.setattr(orchestrator.mutex, "release", MagicMock(return_value=(True, None)))
    monkeypatch.setattr(orchestrator.mutex, "release_if_held", lambda **_kw: False)
    monkeypatch.setattr(orchestrator.mutex, "renew", lambda **_kw: (True, None))
    return st


def _planned() -> tuple[_FakeRun, MagicMock]:
    run = _FakeRun(state="planned")
    run.plan = {"node_order": [], "slot_image_url": ""}
    return run, _db_for_state_test(run)


@pytest.mark.asyncio
async def test_one_transient_lease_read_does_not_strand_a_planned_run(
    kube: dict[str, Any],
) -> None:
    kube["get"] = [
        k8s.KubeapiUnavailableError("kubeapi GET /leases/x: [Errno 111] Connection refused"),
        (404, None),
    ]
    run, db = _planned()
    await orchestrator.drive_upgrade(db, run.id)
    assert kube["reads"] == 2
    assert kube["created"] == 1
    assert run.state == "running"  # the drive started
    assert run.last_error is None


@pytest.mark.asyncio
async def test_a_503_lease_read_is_retried_too(kube: dict[str, Any]) -> None:
    kube["get"] = [(503, None), (404, None)]
    run, db = _planned()
    await orchestrator.drive_upgrade(db, run.id)
    assert run.state == "running"


@pytest.mark.asyncio
async def test_unreadable_lease_after_the_retries_is_recorded_and_restartable(
    kube: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    kube["get"] = [(503, None)]
    monkeypatch.setattr(kubeapi_retry, "READ_RETRY_BUDGET_S", 0.05)
    run, db = _planned()
    with pytest.raises(orchestrator.OrchestratorError, match="unreachable"):
        await orchestrator.drive_upgrade(db, run.id)
    assert kube["reads"] > 1
    assert kube["created"] == 0
    # Written on the run, and still startable.
    assert run.last_error and "<unreachable>" in run.last_error
    assert run.state == "planned"
    assert run.lease_holder is None
    assert any(e["event"] == "start_refused" for e in run.progress["events"])
    db.commit.assert_awaited()

    # Start pressed again once the kubeapi is back: the run proceeds.
    kube["get"] = [(404, None)]
    await orchestrator.drive_upgrade(db, run.id)
    assert run.state == "running"
    assert run.last_error is None
