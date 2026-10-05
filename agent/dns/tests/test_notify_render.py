"""NOTIFY settings + zone allow_query reach the agents (#1523).

``notify_enabled`` / ``also_notify`` / ``allow_notify`` (server options)
and ``also_notify`` / ``notify_enabled`` / ``allow_query`` (zone
overrides) were accepted, validated (#1316) and stored, but never
shipped in the agent bundle — so a stealth primary (``notify no``)
still sent NOTIFY from BIND9, also-notify targets were never notified,
a zone-level allow_query was never enforced, and PowerDNS zones stayed
kind Native, which does not send NOTIFY at all.

These tests assert on the RENDERED config / applied metadata, per the
#899 lesson: a field that is shipped but not rendered is still broken.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from spatium_dns_agent.drivers import powerdns as powerdns_mod
from spatium_dns_agent.drivers.bind9 import (
    Bind9Driver,
    _render_notify_block,
    _zone_notify_clauses,
)
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _also_notify_targets

# ── BIND9: clause builders ──────────────────────────────────────────────────


def test_notify_block_renders_all_three_statements() -> None:
    out = _render_notify_block(
        {
            "notify_enabled": "no",
            "also_notify": ["192.0.2.53", "192.0.2.54 port 5300"],
            "allow_notify": ["192.0.2.0/24"],
        }
    )
    assert "    notify no;\n" in out
    assert "    also-notify { 192.0.2.53; 192.0.2.54 port 5300; };\n" in out
    assert "    allow-notify { 192.0.2.0/24; };\n" in out


def test_notify_block_drops_unusable_values() -> None:
    """A notify value outside the #1316 grammar, and an entry that would
    break out of the statement, are dropped — never rendered."""
    out = _render_notify_block(
        {
            "notify_enabled": "sometimes",
            "also_notify": ["192.0.2.53; }; controls { };"],
            "allow_notify": [],
        }
    )
    assert out == ""


def test_zone_clauses_only_for_zone_owned_values() -> None:
    zone = {
        "allow_query": ["192.0.2.0/24"],
        "notify_enabled": "explicit",
        "also_notify": ["192.0.2.53"],
    }
    out = _zone_notify_clauses(zone)
    assert "allow-query { 192.0.2.0/24; }; " in out
    assert "notify explicit; " in out
    assert "also-notify { 192.0.2.53; }; " in out
    # None = inherit the server options; no clause may shadow them.
    inherit = {"allow_query": None, "notify_enabled": None, "also_notify": None}
    assert _zone_notify_clauses(inherit) == ""


# ── BIND9: through a full render ────────────────────────────────────────────


def _bundle(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "auto",
            "allow_transfer": ["none"],
            "notify_enabled": "yes",
            "also_notify": [],
            "allow_notify": [],
        },
        "tsig_keys": [],
        "zones": [],
    }
    base.update(over)
    return base


def _zone(name: str, **over: Any) -> dict[str, Any]:
    z: dict[str, Any] = {
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 1,
        "dynamic_update_enabled": False,
        "update_acl": [],
        "allow_transfer": None,
        "allow_query": None,
        "also_notify": None,
        "notify_enabled": None,
        "records": [],
    }
    z.update(over)
    return z


def _render_bind9(tmp_path: Path, bundle: dict[str, Any]) -> str:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_bind9_options_block_carries_notify_settings(tmp_path: Path) -> None:
    bundle = _bundle()
    bundle["options"].update(
        {
            "notify_enabled": "no",
            "also_notify": ["192.0.2.53"],
            "allow_notify": ["192.0.2.0/24"],
        }
    )
    conf = _render_bind9(tmp_path, bundle)
    assert "    notify no;\n" in conf
    assert "    also-notify { 192.0.2.53; };\n" in conf
    assert "    allow-notify { 192.0.2.0/24; };\n" in conf


def test_bind9_zone_stanza_carries_overrides(tmp_path: Path) -> None:
    zone = _zone(
        "corp.example.",
        allow_query=["192.0.2.0/24"],
        notify_enabled="no",
        also_notify=["192.0.2.53"],
    )
    conf = _render_bind9(tmp_path, _bundle(zones=[zone]))
    stanza = [ln for ln in conf.splitlines() if 'zone "corp.example."' in ln]
    assert stanza, "zone stanza rendered"
    assert "allow-query { 192.0.2.0/24; };" in stanza[0]
    assert "notify no;" in stanza[0]
    assert "also-notify { 192.0.2.53; };" in stanza[0]


def test_bind9_zone_without_overrides_gets_no_zone_clauses(tmp_path: Path) -> None:
    conf = _render_bind9(tmp_path, _bundle(zones=[_zone("plain.example.")]))
    stanza = [ln for ln in conf.splitlines() if 'zone "plain.example."' in ln]
    assert stanza and "allow-query" not in stanza[0] and "also-notify" not in stanza[0]


# ── PowerDNS: conversion, kind, payload ─────────────────────────────────────


def test_also_notify_targets_convert_bind_grammar() -> None:
    assert _also_notify_targets(
        ["192.0.2.53", "192.0.2.54 port 5300", "192.0.2.55 port 53 key ops-xfer."]
    ) == ["192.0.2.53", "192.0.2.54:5300", "192.0.2.55:53"]
    assert _also_notify_targets(["not-an-ip", ""]) == []
    assert _also_notify_targets(None) == []


def _render_pdns(tmp_path: Path, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    PowerDNSDriver(state_dir=tmp_path).render(bundle)
    return json.loads((tmp_path / "rendered.new" / "zones.json").read_text())


def _pdns_zone(**over: Any) -> dict[str, Any]:
    z: dict[str, Any] = {
        "name": "example.com",
        "type": "primary",
        "ttl": 3600,
        "serial": 1,
        "records": [],
    }
    z.update(over)
    return z


def test_pdns_notify_no_keeps_native_and_zone_override_wins(tmp_path: Path) -> None:
    payload = _render_pdns(
        tmp_path,
        {
            "zones": [_pdns_zone()],
            "options": {"notify_enabled": "no", "also_notify": ["192.0.2.53"]},
        },
    )
    assert payload[0]["kind"] == "Native"
    # Server also-notify is inherited as the effective target list.
    assert payload[0]["also_notify"] == ["192.0.2.53"]
    assert payload[0]["notify_enabled"] == "no"

    payload = _render_pdns(
        tmp_path,
        {
            "zones": [_pdns_zone(notify_enabled="yes", also_notify=["192.0.2.99"])],
            "options": {"notify_enabled": "no", "also_notify": ["192.0.2.53"]},
        },
    )
    assert payload[0]["kind"] == "Master"
    assert payload[0]["also_notify"] == ["192.0.2.99"]


# ── PowerDNS: reconcile applies ALSO-NOTIFY ─────────────────────────────────


class _Resp:
    def __init__(self, status: int = 200, body: Any = None) -> None:
        self.status_code = status
        self.text = ""
        self._body = body if body is not None else []

    def json(self) -> Any:
        return self._body


class _FakeClient:
    def __init__(self, calls: list) -> None:
        self._calls = calls

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("GET", url, None))
        return _Resp(200, [{"name": "example.com.", "kind": "Master", "masters": []}])

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


def test_pdns_reconcile_sets_and_clears_also_notify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        powerdns_mod,
        "httpx",
        SimpleNamespace(Client=lambda **kw: _FakeClient(calls)),
    )
    driver = PowerDNSDriver(state_dir=tmp_path)
    base = {
        "name": "example.com.",
        "kind": "Master",
        "masters": [],
        "rrsets": [],
        "update_acl": [],
        "update_tsig_keys": [],
    }
    driver._reconcile_zones(
        "key", [{**base, "also_notify": ["192.0.2.53 port 5300 key k."]}]
    )
    puts = [c for c in calls if c[0] == "PUT" and c[1].endswith("ALSO-NOTIFY")]
    assert puts and puts[0][2]["metadata"] == ["192.0.2.53:5300"]

    calls.clear()
    driver._reconcile_zones("key", [{**base, "also_notify": []}])
    dels = [c for c in calls if c[0] == "DELETE" and "ALSO-NOTIFY" in c[1]]
    assert dels, "empty target list clears the metadata"
