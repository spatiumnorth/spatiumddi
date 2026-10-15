"""An unanswered kubeapi read is UNKNOWN, never "not held" (#1713), and a
``running`` run whose drive is gone is re-driven."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.services.appliance import k8s
from app.services.upgrades import mutex, orchestrator

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
    monkeypatch.setattr(orchestrator, "LEASE_DURATION_S", 0.1)
    kube["get"] = [k8s.KubeapiUnavailableError("timed out")]
    stop = asyncio.Event()
    task = asyncio.create_task(orchestrator._lease_renewal_loop(stop, ME))
    await asyncio.wait_for(task, 2)
    assert stop.is_set()


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


@pytest.fixture
def driven(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    from app.tasks import upgrade_orchestrator as t

    calls: list[Any] = []
    monkeypatch.setattr(
        t.drive_upgrade_run, "apply_async", lambda **kw: calls.append(kw), raising=False
    )
    return calls


def test_running_run_with_dead_drive_is_redriven_exactly_once(
    kube: dict[str, Any], driven: list[Any]
) -> None:
    from app.tasks import upgrade_orchestrator as t

    kube["get"] = [(200, _lease(None, age_s=900))]  # released / expired
    r = FakeRedis()
    rid = uuid.uuid4()
    assert t.resume_orphaned_runs_sync([rid], r, now=1000.0) == []  # first sighting
    assert t.resume_orphaned_runs_sync([rid], r, now=1010.0) == []  # too soon
    assert t.resume_orphaned_runs_sync([rid], r, now=1100.0) == [str(rid)]
    assert t.resume_orphaned_runs_sync([rid], r, now=1160.0) == []  # cooldown
    assert len(driven) == 1 and driven[0]["args"] == [str(rid)]


def test_sweep_leaves_a_run_whose_lease_is_held_or_unreadable(
    kube: dict[str, Any], driven: list[Any]
) -> None:
    from app.tasks import upgrade_orchestrator as t

    r = FakeRedis()
    rid = uuid.uuid4()
    for lease in ((200, _lease(ME)), k8s.KubeapiUnavailableError("timed out")):
        kube["get"] = [lease]
        for now in (1000.0, 1100.0, 1200.0):
            assert t.resume_orphaned_runs_sync([rid], r, now=now) == []
    assert driven == []
