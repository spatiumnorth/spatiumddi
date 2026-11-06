"""#3618 — the kubeapi proxy runs only what the Fleet routes build.

The proxy is on by default since #3618, and the service account behind it
can create HelmCharts in kube-system and delete nodes. These tests drive one
poll -> execute -> reply cycle and assert on what reaches the kubeapi and
what the control plane is told.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from spatium_supervisor import appliance_state, k8s_proxy
from spatium_supervisor.config import SupervisorConfig
from spatium_supervisor.identity import load_or_generate

_RESTART = json.dumps(
    {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": "2026-11-05T00:00:00+00:00"
                    }
                }
            }
        }
    }
).encode()
_SMP = {
    "Accept": "application/json",
    "Content-Type": "application/strategic-merge-patch+json",
}

# The exact requests backend/app/api/v1/appliance/supervisor.py builds.
ALLOWED = [
    (
        "pods",
        "GET",
        "/api/v1/namespaces/spatium/pods",
        {"Accept": "application/json"},
        b"",
    ),
    (
        "logs",
        "GET",
        "/api/v1/namespaces/spatium/pods/dns-bind9-abc12/log?tailLines=1200",
        {"Accept": "text/plain"},
        b"",
    ),
    (
        "logs-container",
        "GET",
        "/api/v1/namespaces/spatium/pods/dns-bind9-abc12/log?tailLines=1200&container=agent",
        {"Accept": "text/plain"},
        b"",
    ),
    ("deployments", "GET", "/apis/apps/v1/namespaces/spatium/deployments", {}, b""),
    ("daemonsets", "GET", "/apis/apps/v1/namespaces/spatium/daemonsets", {}, b""),
    ("statefulsets", "GET", "/apis/apps/v1/namespaces/spatium/statefulsets", {}, b""),
    (
        "restart",
        "PATCH",
        "/apis/apps/v1/namespaces/spatium/daemonsets/dns-bind9",
        _SMP,
        _RESTART,
    ),
]

REFUSED = [
    (
        "helmchart-create",
        "POST",
        "/apis/helm.cattle.io/v1/namespaces/kube-system/helmcharts",
        {"Content-Type": "application/json"},
        b"{}",
    ),
    ("node-delete", "DELETE", "/api/v1/nodes/node-1", {}, b""),
    ("secrets", "GET", "/api/v1/namespaces/spatium/secrets", {}, b""),
    ("other-namespace-pods", "GET", "/api/v1/namespaces/kube-system/pods", {}, b""),
    ("pods-query", "GET", "/api/v1/namespaces/spatium/pods?watch=true", {}, b""),
    ("pod-delete", "DELETE", "/api/v1/namespaces/spatium/pods/x", {}, b""),
    ("pod-exec", "GET", "/api/v1/namespaces/spatium/pods/x/exec", {}, b""),
    ("log-follow", "GET", "/api/v1/namespaces/spatium/pods/x/log?follow=true", {}, b""),
    ("log-traversal", "GET", "/api/v1/namespaces/spatium/pods/../secrets/log", {}, b""),
    (
        "log-dup-key",
        "GET",
        "/api/v1/namespaces/spatium/pods/x/log?tailLines=1&tailLines=2",
        {},
        b"",
    ),
    (
        "workload-get",
        "GET",
        "/apis/apps/v1/namespaces/spatium/deployments/api",
        {},
        b"",
    ),
    (
        "restart-other-field",
        "PATCH",
        "/apis/apps/v1/namespaces/spatium/deployments/api",
        _SMP,
        json.dumps({"spec": {"replicas": 0}}).encode(),
    ),
    (
        "restart-json-patch",
        "PATCH",
        "/apis/apps/v1/namespaces/spatium/deployments/api",
        {"Content-Type": "application/json-patch+json"},
        _RESTART,
    ),
    (
        "restart-extra-annotation",
        "PATCH",
        "/apis/apps/v1/namespaces/spatium/deployments/api",
        _SMP,
        json.dumps(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": "x",
                                "other": "y",
                            }
                        }
                    }
                }
            }
        ).encode(),
    ),
    ("replicasets", "GET", "/apis/apps/v1/namespaces/spatium/replicasets", {}, b""),
    (
        "absolute-url",
        "GET",
        "https://evil.example/api/v1/namespaces/spatium/pods",
        {},
        b"",
    ),
]


class _Resp:
    def __init__(self, body: dict[str, Any]) -> None:
        self.status_code = 200
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


def _run_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
    response: bytes = b'{"items": []}',
) -> tuple[list[tuple[str, str, bytes, dict[str, str]]], dict[str, Any]]:
    monkeypatch.setattr(appliance_state, "is_control_plane_member", lambda: False)
    monkeypatch.setattr(k8s_proxy, "load_appliance_id", lambda _d: "app-1")
    monkeypatch.setattr(k8s_proxy, "load_cert", lambda _d: "CERT")
    monkeypatch.setattr(k8s_proxy, "build_auth_headers", lambda *a, **k: {})
    executed: list[tuple[str, str, bytes, dict[str, str]]] = []

    def _kubeapi(m: str, p: str, b: bytes, h: dict[str, str]) -> tuple[int, bytes]:
        executed.append((m, p, b, h))
        return 200, response

    monkeypatch.setattr(k8s_proxy, "_call_local_kubeapi", _kubeapi)
    replies: list[dict[str, Any]] = []
    queued = {
        "request_id": "r1",
        "method": method,
        "path": path,
        "headers": headers,
        "body_b64": base64.b64encode(body).decode() if body else "",
    }

    class _Client:
        def post(self, url: str, **kw: Any) -> _Resp:
            if url.endswith("/poll"):
                return _Resp(queued)
            replies.append(kw["json"])
            return _Resp({"delivered": "true"})

    cfg = SupervisorConfig(
        control_plane_url="https://cp.example",
        hostname="node",
        state_dir=tmp_path,
        bootstrap_pairing_code="",
        heartbeat_interval_seconds=30,
        k8s_proxy_enabled=True,
        in_pod_firewall_enabled=True,
    )
    identity, _ = load_or_generate(tmp_path)
    k8s_proxy._proxy_once(cfg, identity, _Client())  # type: ignore[arg-type]
    assert len(replies) == 1
    return executed, replies[0]


@pytest.mark.parametrize(
    ("method", "path", "headers", "body"),
    [case[1:] for case in ALLOWED],
    ids=[case[0] for case in ALLOWED],
)
def test_the_fleet_requests_reach_the_kubeapi(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> None:
    executed, reply = _run_once(tmp_path, monkeypatch, method, path, headers, body)
    assert [(m, p) for m, p, _b, _h in executed] == [(method, path)]
    assert reply["status"] == 200


@pytest.mark.parametrize(
    ("method", "path", "headers", "body"),
    [case[1:] for case in REFUSED],
    ids=[case[0] for case in REFUSED],
)
def test_anything_else_is_refused_unexecuted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> None:
    executed, reply = _run_once(tmp_path, monkeypatch, method, path, headers, body)
    assert executed == []
    assert reply["status"] == 403
    assert b"refused" in base64.b64decode(reply["body_b64"])


def test_control_plane_headers_beyond_content_negotiation_are_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executed, _reply = _run_once(
        tmp_path,
        monkeypatch,
        "GET",
        "/api/v1/namespaces/spatium/pods",
        {
            "Accept": "application/json",
            "Authorization": "Bearer forged",
            "Impersonate-User": "system:admin",
        },
        b"",
    )
    assert executed[0][3] == {"Accept": "application/json"}


_LOG = (
    "/api/v1/namespaces/spatium/pods/dns-bind9-abc12/log?tailLines=1200&container=agent"
)


@pytest.mark.parametrize("sent", ["text/plain", "application/json", "*/*"])
def test_pod_logs_always_ask_the_kubeapi_for_any_media_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sent: str
) -> None:
    """kubeapi answers a text/plain Accept on pod logs with 406 (#3618)."""
    executed, reply = _run_once(
        tmp_path, monkeypatch, "GET", _LOG, {"Accept": sent}, b""
    )
    assert executed[0][1] == _LOG  # container= selection untouched
    assert executed[0][3] == {"Accept": "*/*"}
    assert reply["status"] == 200


def test_pod_log_text_body_is_relayed_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = b"line one\nnot json {\xff\xfe\n"
    _executed, reply = _run_once(
        tmp_path, monkeypatch, "GET", _LOG, {"Accept": "*/*"}, b"", response=raw
    )
    assert base64.b64decode(reply["body_b64"]) == raw


@pytest.mark.parametrize(
    ("method", "path", "headers", "body"),
    [case[1:] for case in ALLOWED if case[0] not in ("logs", "logs-container")],
    ids=[case[0] for case in ALLOWED if case[0] not in ("logs", "logs-container")],
)
def test_other_routes_forward_accept_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> None:
    executed, _reply = _run_once(tmp_path, monkeypatch, method, path, headers, body)
    assert executed[0][3].get("Accept") == headers.get("Accept")
