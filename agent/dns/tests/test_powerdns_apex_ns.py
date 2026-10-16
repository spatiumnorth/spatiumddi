"""A PowerDNS primary zone serves an apex NS rrset (#1985).

The agent rendered an apex SOA but never an NS, and PowerDNS does not make one,
so a BIND9 secondary refused every transfer ("has no NS records"). The rule is
the BIND9 renderer's: the operator's own apex NS records win, else the Primary
NS when it can resolve, else the ``ns1.<zone>`` placeholder.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver
from tests.test_powerdns_serial_owner import FakePdns, _install
from tests.test_powerdns_soa import _install_fake_client


def _render(tmp_path: Path, zone: dict[str, Any]) -> list[dict[str, Any]]:
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver.render(
        {
            "zones": [{"type": "primary", "ttl": 3600, "serial": 5, **zone}],
            "options": {},
        }
    )
    payload = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    return payload[0]["rrsets"]


def _ns(rrsets: list[dict[str, Any]]) -> list[str]:
    return [
        r["content"]
        for rs in rrsets
        if rs["type"] == "NS" and rs["name"] == "example.com."
        for r in rs["records"]
    ]


def test_primary_ns_outside_zone_is_the_apex_ns(tmp_path: Path) -> None:
    rr = _render(
        tmp_path,
        {"name": "example.com", "primary_ns": "ns1.example.net", "records": []},
    )
    assert _ns(rr) == ["ns1.example.net."]


def test_no_primary_ns_uses_placeholder(tmp_path: Path) -> None:
    assert _ns(_render(tmp_path, {"name": "example.com", "records": []})) == ["ns1.example.com."]


def test_primary_ns_inside_zone_needs_an_address(tmp_path: Path) -> None:
    zone = {"name": "example.com", "primary_ns": "ns.example.com", "records": []}
    assert _ns(_render(tmp_path, zone)) == ["ns1.example.com."]
    zone["records"] = [{"name": "ns", "type": "A", "value": "192.0.2.1"}]
    assert _ns(_render(tmp_path, zone)) == ["ns.example.com."]


def test_operator_apex_ns_is_used_alone(tmp_path: Path) -> None:
    zone = {
        "name": "example.com",
        "primary_ns": "ns1.example.net",
        "records": [
            {"name": "@", "type": "NS", "value": "ns2.example.org."},
            {"name": "@", "type": "NS", "value": "ns3.example.org."},
        ],
    }
    assert sorted(_ns(_render(tmp_path, zone))) == [
        "ns2.example.org.",
        "ns3.example.org.",
    ]


def test_secondary_gets_no_synthesised_ns(tmp_path: Path) -> None:
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
    assert json.loads((tmp_path / "rendered.new" / "zones.json").read_text())[0]["rrsets"] == []


def test_create_sends_the_ns_rrset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_fake_client(monkeypatch, existing=[])
    driver = PowerDNSDriver(state_dir=tmp_path)
    rrsets = _render(tmp_path, {"name": "example.com", "records": []})
    driver._reconcile_zones(
        "key",
        [{"name": "example.com.", "kind": "Native", "serial": 5, "rrsets": rrsets}],
    )
    post = next(c for c in calls if c[0] == "POST")[2]
    assert _ns(post["rrsets"]) == ["ns1.example.com."]


def test_existing_zone_without_ns_gets_it_and_a_held_ns_is_not_swept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The upgrade: PowerDNS holds the zone with no apex NS."""
    calls = _install_fake_client(monkeypatch, existing=[{"name": "example.com.", "kind": "Native"}])
    driver = PowerDNSDriver(state_dir=tmp_path)
    rrsets = _render(
        tmp_path,
        {"name": "example.com", "primary_ns": "ns1.example.net", "records": []},
    )
    driver._reconcile_zones(
        "key",
        [{"name": "example.com.", "kind": "Native", "serial": 5, "rrsets": rrsets}],
    )
    patch = next(c for c in calls if c[0] == "PATCH")[2]
    replaced = [r for r in patch["rrsets"] if r["type"] == "NS" and r["changetype"] == "REPLACE"]
    assert [x["content"] for r in replaced for x in r["records"]] == ["ns1.example.net."]
    assert not [r for r in patch["rrsets"] if r["type"] == "NS" and r["changetype"] == "DELETE"]


def test_an_apex_ns_record_spelled_as_the_zone_name_is_never_overwritten(
    tmp_path: Path,
) -> None:
    """The operator's NS is detected by what PowerDNS will serve, not by a
    second reading of the record name: ``example.com`` is the apex to the
    renderer, so the default must not replace that rrset."""
    zone = {
        "name": "example.com",
        "records": [{"name": "example.com", "type": "NS", "value": "ns9.example.org."}],
    }
    assert _ns(_render(tmp_path, zone)) == ["ns9.example.org."]


def test_primary_ns_at_the_apex_needs_an_apex_address(tmp_path: Path) -> None:
    zone: dict[str, Any] = {
        "name": "example.com",
        "primary_ns": "example.com.",
        "records": [],
    }
    assert _ns(_render(tmp_path, zone)) == ["ns1.example.com."]
    zone["records"] = [{"name": "@", "type": "AAAA", "value": "2001:db8::1"}]
    assert _ns(_render(tmp_path, zone)) == ["example.com."]


# ── against the stateful fake (serial ownership, record ops) ────────────────


def _payload(tmp_path: Path, zone: dict[str, Any]) -> list[dict[str, Any]]:
    """Render, and make it the APPLIED render (``rendered/``) as a swap would."""
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver.render({"zones": [{"type": "primary", "ttl": 300, "serial": 7, **zone}], "options": {}})
    live = tmp_path / "rendered"
    if live.exists():
        shutil.rmtree(live)
    (tmp_path / "rendered.new").rename(live)
    return json.loads((live / "zones.json").read_text())


def test_reconciling_the_ns_again_moves_no_serial_and_sends_no_notify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = PowerDNSDriver(state_dir=tmp_path)
    payload = _payload(tmp_path, {"name": "example.com", "primary_ns": "ns1.example.net"})
    drv._reconcile_zones("k", payload)
    assert fake.zones["example.com."]["rrsets"][("example.com.", "NS")] == ["ns1.example.net."]
    fake.calls.clear()
    drv._reconcile_zones("k", payload)
    drv._reconcile_zones("k", payload)
    assert fake.serial("example.com.") == 7
    assert not [c for c in fake.calls if c[1].endswith("/notify")]


def test_deleting_the_last_operator_ns_restores_the_default_in_the_same_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = PowerDNSDriver(state_dir=tmp_path)
    zone = {
        "name": "example.com",
        "primary_ns": "ns1.example.net",
        "records": [{"name": "@", "type": "NS", "value": "ns2.example.org."}],
    }
    drv._reconcile_zones("k", _payload(tmp_path, zone))
    assert fake.zones["example.com."]["rrsets"][("example.com.", "NS")] == ["ns2.example.org."]
    fake.calls.clear()
    drv.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "target_serial": 8,
            "record": {
                "name": "@",
                "type": "NS",
                "value": "ns2.example.org.",
                "rrset": {"ttl": 3600, "members": []},
            },
        }
    )
    (patch,) = [c for c in fake.calls if c[0] == "PATCH"]
    ns = [r for r in patch[2]["rrsets"] if r["type"] == "NS"]
    assert [r["changetype"] for r in ns] == ["REPLACE"], "never a DELETE: no gap"
    assert ns[0]["ttl"] == 300
    assert fake.zones["example.com."]["rrsets"][("example.com.", "NS")] == ["ns1.example.net."]
    assert fake.serial("example.com.") == 8


def test_legacy_delete_without_an_applied_render_falls_back_to_the_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    fake.seed("example.com.", 7, edit_api="")
    fake.zones["example.com."]["rrsets"][("example.com.", "NS")] = ["ns2.example.org."]
    _install(monkeypatch, fake)
    PowerDNSDriver(state_dir=tmp_path).apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {"name": "@", "type": "NS", "value": "ns2.example.org."},
        }
    )
    assert fake.zones["example.com."]["rrsets"][("example.com.", "NS")] == ["ns1.example.com."]


def test_deleting_a_delegation_ns_below_the_apex_is_still_a_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    fake.seed("example.com.", 7, edit_api="")
    fake.zones["example.com."]["rrsets"][("sub.example.com.", "NS")] = ["ns.sub.example.com."]
    _install(monkeypatch, fake)
    PowerDNSDriver(state_dir=tmp_path).apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {"name": "sub", "type": "NS", "value": "ns.sub.example.com."},
        }
    )
    assert ("sub.example.com.", "NS") not in fake.zones["example.com."]["rrsets"]
