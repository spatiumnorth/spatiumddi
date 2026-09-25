"""The appliance console sends the /metrics scrape token (#1159).

/metrics refuses a request without a bearer token, and the console's API
panel scrapes it every few seconds. The console reads the token from the
chart's app Secret (``metrics-token``) with the kubectl it already uses for
the svc lookup, caches it, and looks it up again after a 401.

The console imports rich and psutil at load time, which this suite does not
install, so these tests lift the scrape functions out of the shipped script
and run exactly those bytes.
"""

from __future__ import annotations

import __future__
import ast
import base64
import io
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

CONSOLE = Path(__file__).resolve().parents[1] / "mkosi.extra/usr/local/bin/spatium-console"
_NAMES = {
    "_API_REQ_PREV",
    "_METRICS_TOKEN_CACHE",
    "_metrics_scrape_token",
    "_get_api_metrics",
    "fetch_api_metrics",
}
_METRICS = (
    b'spatiumddi_api_requests_total{method="GET",path_template="/x",status_code="200"} 5.0\n'
    b"spatiumddi_api_active_requests 2.0\n"
)


def _console() -> dict[str, Any]:
    tree = ast.parse(CONSOLE.read_text(encoding="utf-8"))
    body = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _NAMES:
            body.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in _NAMES for t in targets):
                body.append(node)
    namespace: dict[str, Any] = {
        "base64": base64,
        "json": json,
        "os": os,
        "subprocess": subprocess,
        "time": time,
        "urllib": urllib,
    }
    code = compile(
        ast.Module(body=body, type_ignores=[]),
        str(CONSOLE),
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    exec(code, namespace)  # noqa: S102 — the shipped console's own functions
    missing = _NAMES - set(namespace)
    assert not missing, f"not found in spatium-console: {sorted(missing)}"
    return namespace


class _Kubectl:
    """Stands in for ``k3s kubectl get secret``: returns each token in turn."""

    def __init__(self, *tokens: str | None) -> None:
        self.tokens = list(tokens)
        self.calls = 0

    def __call__(self, argv: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        assert argv[:4] == ["/usr/local/bin/k3s", "kubectl", "get", "secret"], argv
        token = self.tokens[min(self.calls, len(self.tokens) - 1)]
        self.calls += 1
        data = {"metrics-token": base64.b64encode(token.encode()).decode()} if token else {}
        stdout = json.dumps({"items": [{"metadata": {"name": "x-app"}, "data": data}]})
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


class _Api:
    """Stands in for the api: accepts only ``accepted`` (or anything, if None)."""

    def __init__(self, accepted: str | None) -> None:
        self.accepted = accepted
        self.seen: list[str | None] = []

    def __call__(self, request: urllib.request.Request, timeout: float = 0) -> io.BytesIO:
        auth = request.get_header("Authorization")
        self.seen.append(auth)
        if self.accepted is not None and auth != f"Bearer {self.accepted}":
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]
        return io.BytesIO(_METRICS)


def _wire(monkeypatch: pytest.MonkeyPatch, kubectl: _Kubectl, api: _Api) -> None:
    monkeypatch.setattr(subprocess, "run", kubectl)
    monkeypatch.setattr(urllib.request, "urlopen", api)


def test_the_scrape_token_from_the_secret_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    console = _console()
    kubectl, api = _Kubectl("tok-1159"), _Api(accepted="tok-1159")
    _wire(monkeypatch, kubectl, api)
    result = console["fetch_api_metrics"]("10.43.0.10")
    assert api.seen == ["Bearer tok-1159"]
    assert result["total"] == 5 and result["active"] == 2


def test_the_token_is_cached_between_scrapes(monkeypatch: pytest.MonkeyPatch) -> None:
    console = _console()
    kubectl, api = _Kubectl("tok-1159"), _Api(accepted="tok-1159")
    _wire(monkeypatch, kubectl, api)
    console["fetch_api_metrics"]("10.43.0.10")
    console["fetch_api_metrics"]("10.43.0.10")
    assert kubectl.calls == 1, "the Secret must not be read on every scrape"


def test_a_rotated_token_is_looked_up_again_after_a_401(monkeypatch: pytest.MonkeyPatch) -> None:
    console = _console()
    kubectl, api = _Kubectl("old-token", "new-token"), _Api(accepted="new-token")
    _wire(monkeypatch, kubectl, api)
    result = console["fetch_api_metrics"]("10.43.0.10")
    assert api.seen == ["Bearer old-token", "Bearer new-token"]
    assert kubectl.calls == 2
    assert result["total"] == 5


def test_no_token_in_the_secret_scrapes_without_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """An api from before #1159 has no token and needs none."""
    console = _console()
    kubectl, api = _Kubectl(None), _Api(accepted=None)
    _wire(monkeypatch, kubectl, api)
    result = console["fetch_api_metrics"]("10.43.0.10")
    assert api.seen == [None]
    assert result["total"] == 5


def test_a_refused_scrape_renders_as_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Still refused after the lookup: the panel shows n/a, it doesn't crash."""
    console = _console()
    kubectl, api = _Kubectl("wrong"), _Api(accepted="right")
    _wire(monkeypatch, kubectl, api)
    assert console["fetch_api_metrics"]("10.43.0.10") == {}
