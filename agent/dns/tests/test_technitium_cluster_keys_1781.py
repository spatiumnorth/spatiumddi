"""Clustered Technitium: the TSIG sync keeps ``cluster-catalog.*`` keys (#1781).

A daemon with clustering initialised refuses a ``tsigKeys`` write that omits
its ``cluster-catalog.<domain>`` key, so every apply recorded a refusal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import TechnitiumDriver


class _Resp:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.status_code = 200
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


def _sync(
    tmp_path: Path, installed: list[dict[str, Any]], keys: list[dict[str, Any]]
) -> str:
    sent: list[dict[str, Any]] = []

    def request(_t: str, _m: str, path: str, params: dict[str, Any]) -> _Resp:
        if path == "settings/get":
            return _Resp({"status": "ok", "response": {"tsigKeys": installed}})
        if path == "settings/set" and "tsigKeys" in params:
            sent.append(dict(params))
        return _Resp({"status": "ok"})

    d = TechnitiumDriver(state_dir=tmp_path)
    d._request = request  # type: ignore[method-assign]
    d._sync_tsig_keys("tok", keys)
    return str(sent[-1]["tsigKeys"])


def test_cluster_catalog_key_is_preserved(tmp_path: Path) -> None:
    installed = [
        {
            "keyName": "cluster-catalog.example.org",
            "sharedSecret": "c2VjcmV0",
            "algorithmName": "hmac-sha256",
        },
        {
            "keyName": "stale-key",
            "sharedSecret": "eA==",
            "algorithmName": "hmac-sha256",
        },
    ]
    keys = [{"name": "spatium-default", "secret": "YWJj", "algorithm": "hmac-sha256"}]
    out = _sync(tmp_path, installed, keys).split("|")
    assert out[:3] == ["cluster-catalog.example.org", "c2VjcmV0", "hmac-sha256"]
    assert out[3:] == ["spatium-default", "YWJj", "hmac-sha256"]
    assert "stale-key" not in out


def test_no_cluster_key_keeps_empty_set_clearing(tmp_path: Path) -> None:
    assert (
        _sync(
            tmp_path,
            [
                {
                    "keyName": "old",
                    "sharedSecret": "eA==",
                    "algorithmName": "hmac-sha256",
                }
            ],
            [],
        )
        == ""
    )
