"""The watchdog carries the kubelet's OOMKilled for this node's role
container (#2018).

The kubelet group-kills a container that reaches its memory limit, so the
DNS agent dies with named and cannot record the kill; the container's last
state is the only record. These tests drive the real pod-list parse and the
real watchdog pass from a pod document shaped like the one the issue
captured, and assert on the ``role_health`` the heartbeat sends.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from spatium_supervisor import k8s_api, watchdog


def _pod(node: str, *, oom: bool = True, running: bool = False) -> dict[str, Any]:
    state: dict[str, Any] = (
        {"running": {"startedAt": "2026-10-17T03:37:10Z"}}
        if running
        else {"waiting": {"reason": "CrashLoopBackOff"}}
    )
    last = {
        "terminated": {
            "reason": "OOMKilled" if oom else "Error",
            "exitCode": 137 if oom else 1,
            "startedAt": "2026-10-17T03:30:00Z",
            "finishedAt": "2026-10-17T03:36:40Z",
        }
    }
    return {
        "metadata": {
            "name": f"dns-bind9-{node}",
            "namespace": "spatium",
            "labels": {
                "app.kubernetes.io/part-of": "spatiumddi",
                "app.kubernetes.io/component": "dns-bind9",
            },
        },
        "spec": {
            "nodeName": node,
            "containers": [
                {
                    "name": "dns-bind9",
                    "resources": {
                        "requests": {"memory": "256Mi"},
                        "limits": {"memory": "2Gi"},
                    },
                }
            ],
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "dns-bind9",
                    "ready": running,
                    "restartCount": 13,
                    "state": state,
                    "lastState": last,
                }
            ],
        },
    }


def _serve(monkeypatch, pods: list[dict[str, Any]]) -> None:
    body = json.dumps({"items": pods}).encode()

    def fake_request(method: str, path: str, **_kw: Any) -> tuple[int, bytes]:
        assert method == "GET"
        return 200, body

    monkeypatch.setattr(k8s_api, "_request", fake_request)
    monkeypatch.setattr(k8s_api, "check_kubeapi_ready", lambda *a, **k: True)


def _env(tmp_path: Path) -> Path:
    env = tmp_path / "role-compose.env"
    env.write_text("COMPOSE_PROFILES=dns-bind9\n")
    return env


def test_list_pods_keeps_the_node_and_memory_limit(monkeypatch) -> None:
    _serve(monkeypatch, [_pod("ddi-1")])
    pods = k8s_api.list_pods()
    assert pods[0].node_name == "ddi-1"
    assert pods[0].memory_limits == {"dns-bind9": "2Gi"}


def test_an_oom_killed_container_is_reported(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NODE_NAME", "ddi-1")
    _serve(monkeypatch, [_pod("ddi-1")])
    out = watchdog.check_health(_env(tmp_path), auto_heal=False)
    runtime = out["dns-bind9"]["container"]
    assert runtime == {
        "restart_count": 13,
        "running_since": None,
        "last_termination": {
            "reason": "OOMKilled",
            "exit_code": 137,
            "finished_at": "2026-10-17T03:36:40Z",
        },
        "memory_limit": "2Gi",
    }


def test_a_restarted_container_reports_when_it_came_back(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NODE_NAME", "ddi-1")
    _serve(monkeypatch, [_pod("ddi-1", running=True)])
    out = watchdog.check_health(_env(tmp_path), auto_heal=False)
    runtime = out["dns-bind9"]["container"]
    assert runtime["running_since"] == "2026-10-17T03:37:10Z"
    assert runtime["last_termination"]["reason"] == "OOMKilled"


def test_this_nodes_pod_is_reported_not_another_nodes(
    monkeypatch, tmp_path: Path
) -> None:
    """A DaemonSet has a pod per node with the same component label. The
    other node's OOM kill must not be reported as this appliance's, and
    whichever order the API lists them in, this node's pod wins."""
    monkeypatch.setenv("NODE_NAME", "DDI-1")  # k3s lowercases the Node name
    mine = _pod("ddi-1", oom=False, running=True)
    theirs = _pod("ddi-2", oom=True)
    for order in ([mine, theirs], [theirs, mine]):
        _serve(monkeypatch, order)
        out = watchdog.check_health(_env(tmp_path), auto_heal=False)
        assert out["dns-bind9"]["container_id"] == "dns-bind9-ddi-1"
        assert out["dns-bind9"]["container"]["last_termination"]["reason"] == "Error"


def test_no_report_when_only_another_nodes_pod_is_listed(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NODE_NAME", "ddi-1")
    _serve(monkeypatch, [_pod("ddi-2", oom=True)])
    out = watchdog.check_health(_env(tmp_path), auto_heal=False)
    assert "container" not in out["dns-bind9"]
