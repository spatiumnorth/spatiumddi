"""PowerDNS agent reports DNSSEC key state to dnssec-state (#4604)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import powerdns as pdns
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver

# RFC 4034 section 5.4's example DNSKEY: its key tag is 60485.
_RFC_KEY = (
    "256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ"
    "DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbt"
    "G9DMBmADjFDc2w/rljwvFw=="
)
_CRYPTOKEYS = [
    {
        "id": 1,
        "keytype": "ksk",
        "active": True,
        "published": True,
        "dnskey": _RFC_KEY.replace("256", "257", 1),
        "ds": ["60485 5 1 aaaa", "60485 5 2 bbbb"],
    },
    {
        "id": 2,
        "keytype": "zsk",
        "active": False,
        "published": True,
        "dnskey": "256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    },
]


class _Resp:
    def __init__(self, status: int, payload: Any) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _Client:
    status = 200

    def __init__(self, *a: Any, **k: Any) -> None:
        pass

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def get(self, url: str, headers: Any = None) -> _Resp:
        assert url.endswith("/zones/example.com./cryptokeys")
        return _Resp(self.status, _CRYPTOKEYS if self.status == 200 else {})


def _driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int = 200) -> PowerDNSDriver:
    _Client.status = status
    monkeypatch.setattr(pdns.httpx, "Client", _Client)
    d = PowerDNSDriver(state_dir=tmp_path)
    monkeypatch.setattr(d, "_load_or_generate_api_key", lambda: "k")
    return d


def test_dnskey_tag_matches_rfc4034_example() -> None:
    assert PowerDNSDriver._dnskey_tag(_RFC_KEY) == 60485


def test_collect_dnssec_state_reports_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _driver(tmp_path, monkeypatch)
    bundle = {
        "zones": [
            {"name": "example.com.", "type": "primary", "dnssec_enabled": True},
            {"name": "unsigned.test.", "type": "primary", "dnssec_enabled": False},
        ]
    }
    (state,) = d.collect_dnssec_state(bundle)
    assert state["zone_name"] == "example.com."
    assert state["ds_records"] == ["60485 5 1 aaaa", "60485 5 2 bbbb"]
    by_type = {k["key_type"]: k for k in state["keys"]}
    assert set(by_type) == {"ksk", "zsk"}
    assert by_type["ksk"]["algorithm"] == 5
    assert by_type["ksk"]["key_tag"] != 0
    assert by_type["ksk"]["state"] == "active"
    assert by_type["ksk"]["ds_records"] == ["60485 5 1 aaaa", "60485 5 2 bbbb"]
    assert by_type["zsk"]["algorithm"] == 13
    assert by_type["zsk"]["state"] == "published"
    assert isinstance(by_type["zsk"]["key_tag"], int)


def test_collect_dnssec_state_skips_an_unreadable_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = _driver(tmp_path, monkeypatch, status=500)
    out = d.collect_dnssec_state(
        {"zones": [{"name": "example.com.", "type": "primary", "dnssec_enabled": True}]}
    )
    assert out == []
    assert d.dnssec_incomplete is True


def test_sign_op_report_carries_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _driver(tmp_path, monkeypatch)
    monkeypatch.setattr(d, "_dnssec_sign", lambda api_key, zone: ["60485 5 1 aaaa"])
    res = d.apply_record_op({"op": "dnssec_sign", "zone_name": "example.com"})
    assert res is not None
    state = res["dnssec_state"]
    assert {k["key_type"] for k in state["keys"]} == {"ksk", "zsk"}


def test_unsign_op_report_clears_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = _driver(tmp_path, monkeypatch)
    monkeypatch.setattr(d, "_dnssec_unsign", lambda api_key, zone: None)
    res = d.apply_record_op({"op": "dnssec_unsign", "zone_name": "example.com"})
    assert res is not None
    assert res["dnssec_state"]["keys"] == []


def test_unparseable_key_list_omits_keys_not_empties_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "keys": [] would wipe the control plane's rows; absent leaves them.
    monkeypatch.setattr(
        sys.modules[__name__],
        "_CRYPTOKEYS",
        [{"keytype": "ksk", "active": True, "ds": ["1 13 2 aa"]}],
    )
    d = _driver(tmp_path, monkeypatch)
    (state,) = d.collect_dnssec_state(
        {"zones": [{"name": "example.com.", "type": "primary", "dnssec_enabled": True}]}
    )
    assert "keys" not in state
    assert state["ds_records"] == ["1 13 2 aa"]
