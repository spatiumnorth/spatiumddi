"""PowerDNS apex SOA + served-serial reporting (#1522).

Zones were created with only the bundle's records, so PowerDNS filled
in its default SOA: the zone's Primary NS / Admin Email were ignored,
the payload serial was never sent on create, and the reconcile never
touched the SOA afterwards. The agent then reported the BUNDLE's
serial as the server's, so per-server sync status read "in sync"
whatever pdns actually served.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.drivers import powerdns as powerdns_mod
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _soa_content
from spatium_dns_agent.sync import SyncLoop

# ── _soa_content ────────────────────────────────────────────────────────────


def test_soa_uses_zone_primary_ns_admin_email_timers_and_serial() -> None:
    zone = {
        "name": "example.com",
        "serial": 2026100401,
        "primary_ns": "ns1.example.net",
        "admin_email": "hostmaster.example.com",
        "refresh": 7200,
        "retry": 900,
        "expire": 1209600,
        "minimum": 60,
        "records": [],
    }
    assert _soa_content(zone, "example.com.") == (
        "ns1.example.net. hostmaster.example.com. 2026100401 7200 900 1209600 60"
    )


def test_soa_falls_back_to_declared_apex_ns_and_placeholder() -> None:
    zone = {
        "name": "example.com",
        "serial": 7,
        "records": [
            {"name": "@", "type": "NS", "value": "ns2.example.org."},
            {"name": "www", "type": "A", "value": "192.0.2.1"},
        ],
    }
    assert _soa_content(zone, "example.com.") == (
        "ns2.example.org. admin.example.com. 7 3600 600 86400 300"
    )
    bare = {"name": "example.com", "serial": 7, "records": []}
    assert _soa_content(bare, "example.com.") == (
        "ns1.example.com. admin.example.com. 7 3600 600 86400 300"
    )


def test_soa_unusable_timer_falls_back_per_field() -> None:
    zone = {
        "name": "example.com",
        "serial": 7,
        "refresh": "daily",
        "retry": -5,
        "expire": 1209600,
        "minimum": True,
        "records": [],
    }
    assert _soa_content(zone, "example.com.").split()[-4:] == [
        "3600",
        "600",
        "1209600",
        "300",
    ]


# ── render ──────────────────────────────────────────────────────────────────


def test_render_primary_zone_carries_synthesised_soa(tmp_path: Path) -> None:
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver.render(
        {
            "zones": [
                {
                    "name": "example.com",
                    "type": "primary",
                    "ttl": 3600,
                    "serial": 99,
                    "primary_ns": "ns1.example.net",
                    "admin_email": "hostmaster.example.com",
                    "records": [{"name": "www", "type": "A", "value": "192.0.2.1"}],
                }
            ],
            "options": {},
        }
    )
    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    rrsets = {(r["name"], r["type"]): r for r in payload[0]["rrsets"]}
    soa = rrsets[("example.com.", "SOA")]
    assert soa["records"][0]["content"] == (
        "ns1.example.net. hostmaster.example.com. 99 3600 600 86400 300"
    )


def test_render_secondary_zone_has_no_soa(tmp_path: Path) -> None:
    """A secondary's SOA arrives with the transfer; synthesising one from
    the bundle would fight the primary's."""
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver.render(
        {
            "zones": [
                {
                    "name": "example.com",
                    "type": "secondary",
                    "masters": ["192.0.2.10"],
                    "records": [],
                }
            ],
            "options": {},
        }
    )
    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    assert payload[0]["rrsets"] == []


# ── reconcile: serial on create ─────────────────────────────────────────────


class _Resp:
    def __init__(self, status: int = 200, body: Any = None) -> None:
        self.status_code = status
        self.text = ""
        self._body = body if body is not None else []

    def json(self) -> Any:
        return self._body


class _FakeClient:
    def __init__(self, calls: list, existing: Any) -> None:
        self._calls = calls
        self._existing = existing

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("GET", url, None))
        return _Resp(200, self._existing)

    def post(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("POST", url, json))
        return _Resp(201, {})

    def put(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("PUT", url, json))
        return _Resp(200, {})

    def patch(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("PATCH", url, json))
        return _Resp(200, {})

    def delete(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("DELETE", url, None))
        return _Resp(200, {})


def _install_fake_client(
    monkeypatch: pytest.MonkeyPatch, existing: Any
) -> list[tuple[str, str, Any]]:
    calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        powerdns_mod,
        "httpx",
        SimpleNamespace(Client=lambda **kw: _FakeClient(calls, existing)),
    )
    return calls


def test_reconcile_create_sends_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _install_fake_client(monkeypatch, existing=[])
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver._reconcile_zones(
        "key",
        [
            {
                "name": "example.com.",
                "kind": "Native",
                "serial": 2026100401,
                "rrsets": [],
                "update_acl": [],
                "update_tsig_keys": [],
            }
        ],
    )
    posts = [c for c in calls if c[0] == "POST" and c[1].endswith("/zones")]
    assert posts and posts[0][2]["serial"] == 2026100401


# ── served_zone_serials + sync reporting ────────────────────────────────────


def test_served_zone_serials_reads_back_live_serials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_client(
        monkeypatch,
        existing=[
            {"name": "example.com.", "serial": 1234},
            {"name": "other.example.", "serial": 5},
            {"name": "broken.example."},
        ],
    )
    driver = PowerDNSDriver(state_dir=tmp_path)
    assert driver.served_zone_serials({}) == {"example.com": 1234, "other.example": 5}


class _CPResp:
    status_code = 200
    text = ""


class _CPClient:
    def __init__(self, posts: list) -> None:
        self._posts = posts

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, url: str, headers: Any = None, json: Any = None) -> _CPResp:
        self._posts.append((url, json))
        return _CPResp()


class _HookDriver:
    """Driver stub exposing the served-serials hook."""

    def __init__(self, served: dict[str, int]) -> None:
        self._served = served

    def served_zone_serials(self, bundle: dict[str, Any]) -> dict[str, int]:
        return self._served


class _PlainDriver:
    """Driver stub with no hook — bundle serials are reported as before."""


def _report(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, driver: Any, bundle: Any
) -> list:
    posts: list = []
    monkeypatch.setattr(SyncLoop, "_client", lambda self: _CPClient(posts))
    loop = SyncLoop(agent_cfg, ["tok"], driver, SimpleNamespace())
    loop._report_zone_state(bundle)
    return posts


def test_zone_state_reports_served_serial_not_bundle_serial(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pdns serves 1234 while the bundle says 9999 — the report must carry
    1234, and the forward zone pdns never served must not be reported."""
    bundle = {
        "zones": [
            {"name": "example.com", "serial": 9999},
            {"name": "fwd.example.com", "serial": 9999},
        ]
    }
    posts = _report(agent_cfg, monkeypatch, _HookDriver({"example.com": 1234}), bundle)
    assert posts and posts[0][1] == {
        "zones": [{"zone_name": "example.com", "serial": 1234}]
    }


def test_zone_state_without_hook_reports_bundle_serials(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = {"zones": [{"name": "example.com", "serial": 9999}]}
    posts = _report(agent_cfg, monkeypatch, _PlainDriver(), bundle)
    assert posts and posts[0][1] == {
        "zones": [{"zone_name": "example.com", "serial": 9999}]
    }
