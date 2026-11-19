"""A role just applied reads ``starting``, not ``missing``, until its pod
appears (#2833).

A role apply returns once the chart is written; the pod appears a few seconds
later. The watchdog pass that fell due right after the apply read "no pod" as a
red ``missing``, cached it for the whole 300 s interval and fired a redundant
heal. These tests drive the real apply hook, due check and watchdog pass from a
fake clock.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from spatium_supervisor import heartbeat, k8s_api, service_lifecycle, watchdog

ROLE_ENV = "COMPOSE_PROFILES=dns-bind9\nAGENT_GROUP=default\nDNS_ENGINE=bind9\n"


class Rig:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.now = 10_000.0
        self.pods: list[k8s_api.PodStatus] = []
        self.heals = 0
        self.env = tmp_path / "role-compose.env"
        self.env.write_text(ROLE_ENV, encoding="utf-8")
        self.tmp = tmp_path
        clock = SimpleNamespace(
            monotonic=lambda: self.now,
            time=lambda: self.now,
            strftime=__import__("time").strftime,
            gmtime=__import__("time").gmtime,
        )
        monkeypatch.setattr(watchdog, "time", clock)
        monkeypatch.setattr(heartbeat, "time", clock)
        monkeypatch.setattr(watchdog, "_status_history", {})
        monkeypatch.setattr(watchdog, "_last_apply_at", None, raising=False)
        monkeypatch.setattr(heartbeat, "_last_watchdog_at", 0.0)
        monkeypatch.setattr(heartbeat, "_cached_role_health", {})
        monkeypatch.setattr(k8s_api, "check_kubeapi_ready", lambda *a, **k: True)
        monkeypatch.setattr(k8s_api, "list_pods", lambda **k: list(self.pods))

        def fake_apply(profiles, env_file):
            self.heals += 1
            return service_lifecycle.LifecycleResult(state="ready", started=tuple(profiles))

        monkeypatch.setattr(watchdog, "apply_role_assignment", fake_apply)
        monkeypatch.setattr(heartbeat, "apply_role_assignment", fake_apply)
        monkeypatch.setattr(heartbeat, "_role_apply_due", lambda *a: (True, "h" * 16))
        monkeypatch.setattr(heartbeat, "_persist_lifecycle_state", lambda *a: None)
        monkeypatch.setattr(heartbeat, "_write_last_apply_hash", lambda *a: None)
        monkeypatch.setattr(heartbeat, "reconcile_node_labels", lambda *a: (True, None))

    def role_apply(self) -> None:
        heartbeat._run_role_lifecycle(self.tmp, ["dns-bind9"], ROLE_ENV, self.env)

    def tick(self) -> str:
        """The heartbeat's watchdog step."""
        if heartbeat._watchdog_check_due():
            heartbeat._cached_role_health = watchdog.check_health(self.env, held_by=None)
            heartbeat._last_watchdog_at = self.now
        return heartbeat._cached_role_health["dns-bind9"]["status"]

    def ready_pod(self) -> None:
        self.pods = [
            k8s_api.PodStatus(
                name="dns-bind9-x",
                namespace="spatium",
                status="Running",
                container_statuses=[{"name": "dns-bind9", "ready": True}],
                labels={"app.kubernetes.io/component": "dns-bind9"},
            )
        ]


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Rig:
    return Rig(monkeypatch, tmp_path)


def test_no_pod_yet_right_after_an_apply_is_starting_and_heals_nothing(rig: Rig) -> None:
    rig.role_apply()
    rig.heals = 0
    rig.now += 2.0  # the next heartbeat
    assert rig.tick() == "starting"
    assert rig.heals == 0


def test_ready_pods_read_healthy_within_the_short_recheck(rig: Rig) -> None:
    rig.role_apply()
    rig.now += 2.0
    assert rig.tick() == "starting"
    rig.now += 3.0
    rig.ready_pod()
    # Still inside the short re-check: the cached verdict is not yet stale.
    rig.now += heartbeat._WATCHDOG_RECHECK_S
    assert rig.tick() == "healthy"
    assert rig.now - heartbeat._last_watchdog_at < heartbeat._WATCHDOG_INTERVAL_S
    # ...and once settled the full interval applies again.
    assert not heartbeat._watchdog_check_due()


def test_a_chart_deleted_later_is_missing_then_healed(rig: Rig) -> None:
    rig.role_apply()
    rig.ready_pod()
    rig.now += 2.0
    assert rig.tick() == "healthy"
    # Well past any grace, the chart is deleted out from under us.
    rig.now += 1000.0
    rig.pods = []
    rig.heals = 0
    assert rig.tick() == "missing"
    assert rig.heals == 1


def test_a_pod_that_never_comes_is_missing_after_the_grace(rig: Rig) -> None:
    rig.role_apply()
    rig.heals = 0
    rig.now += 2.0
    assert rig.tick() == "starting"
    rig.now += watchdog.APPLY_GRACE_S
    assert rig.tick() == "missing"
    assert rig.heals == 1
