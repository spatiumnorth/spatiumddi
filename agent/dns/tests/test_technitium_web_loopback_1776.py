"""The Technitium web console + API bind to loopback only (#1776).

Technitium listens on 0.0.0.0 / [::]:5380 by default. A fresh ``/etc/dns``
takes the bind from ``DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES``; an existing
one needs a one-time ``settings/set webServiceLocalAddresses``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import technitium as mod
from spatium_dns_agent.drivers.technitium import TechnitiumDriver


class _Resp:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.status_code = 200
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


def _apply(tmp_path: Path, bound: list[str] | None) -> list[tuple[str, dict[str, Any]]]:
    sent: list[tuple[str, dict[str, Any]]] = []

    def request(_t: str, _m: str, path: str, params: dict[str, Any]) -> _Resp:
        sent.append((path, dict(params)))
        if path == "settings/get":
            resp: dict[str, Any] = {} if bound is None else {"webServiceLocalAddresses": bound}
            return _Resp({"status": "ok", "response": resp})
        if path == "zones/records/get":
            return _Resp({"status": "ok", "response": {"records": []}})
        return _Resp({"status": "ok"})

    d = TechnitiumDriver(state_dir=tmp_path)
    d.daemon_running = lambda: True  # type: ignore[method-assign]
    d._wait_for_api_up = lambda **_: None  # type: ignore[method-assign]
    d._get_api_token = lambda: "tok"  # type: ignore[method-assign]
    d._reprovision_token = lambda stale: None  # type: ignore[method-assign]
    d._request = request  # type: ignore[method-assign]
    d.render({"zones": [], "options": {}, "tsig_keys": []})
    d.swap_and_reload()
    return sent


def _bind_sets(sent: list[tuple[str, dict[str, Any]]]) -> list[Any]:
    return [
        p["webServiceLocalAddresses"]
        for path, p in sent
        if path == "settings/set" and "webServiceLocalAddresses" in p
    ]


def test_existing_config_listening_everywhere_is_pinned(tmp_path: Path) -> None:
    sent = _apply(tmp_path, ["0.0.0.0", "[::]"])
    assert _bind_sets(sent) == ["127.0.0.1"]


def test_unreadable_bind_is_pinned_too(tmp_path: Path) -> None:
    assert _bind_sets(_apply(tmp_path, None)) == ["127.0.0.1"]


def test_already_pinned_is_not_resent(tmp_path: Path) -> None:
    assert _bind_sets(_apply(tmp_path, ["127.0.0.1"])) == []


def test_fresh_daemon_gets_the_loopback_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    class _P:
        pid = 4242

    def popen(cmd: list[str], **kw: Any) -> _P:
        seen["env"] = kw["env"]
        return _P()

    monkeypatch.setattr(mod.shutil, "which", lambda _n: "/usr/bin/dotnet")
    monkeypatch.setattr(mod, "find_running_daemon", lambda _n: None)
    monkeypatch.setattr(mod.subprocess, "Popen", popen)
    monkeypatch.setenv("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES", "0.0.0.0")
    d = TechnitiumDriver(state_dir=tmp_path)
    d.start_daemon()
    assert seen["env"]["DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES"] == "127.0.0.1"
