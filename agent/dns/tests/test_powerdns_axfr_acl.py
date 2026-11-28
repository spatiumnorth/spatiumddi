"""A secondary on another host can transfer a zone from a PowerDNS primary (#1967).

``primary=yes`` makes PowerDNS send the NOTIFY, but it answers an AXFR only to
``allow-axfr-ips`` (loopback by default), a zone's ``ALLOW-AXFR-FROM`` subnets
or a TSIG key in its ``TSIG-ALLOW-AXFR``. Neither per-zone grant was rendered,
so a BIND9 (or second PowerDNS) secondary was told about every change and then
REFUSED the transfer (``NOTAUTH``) — checked against a live pdns-auth 5.0.7
and BIND 9.20 secondary. The grants come from the same source the BIND9 agent
renders ``allow-transfer`` from (#734): the zone's ``allow_transfer`` override,
else the server options'. A TSIG key is granted only when that list names it
(#4568): PowerDNS signs its outgoing NOTIFY with the first key in
``TSIG-ALLOW-AXFR``, so granting every bundle key made a secondary without the
key reject each NOTIFY and catch up only at its SOA refresh.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _axfr_grants

KEY = {"name": "spatium-xfr", "algorithm": "hmac-sha256", "secret": "c2VjcmV0"}


def _render(tmp_path: Path, bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    PowerDNSDriver(state_dir=tmp_path).render(bundle)
    zones = json.loads((tmp_path / "rendered.new" / "zones.json").read_text())
    return {z["name"]: z for z in zones}


def _zone(name: str, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 42,
        "records": [{"name": "www", "type": "A", "value": "192.0.2.1"}],
        **extra,
    }


def test_the_server_transfer_policy_reaches_the_payload(tmp_path: Path) -> None:
    zones = _render(
        tmp_path,
        {
            "zones": [_zone("a.test")],
            "options": {"allow_transfer": ["198.51.100.0/24", "any", "key spatium-xfr"]},
            "tsig_keys": [KEY],
        },
    )
    a = zones["a.test."]
    assert a["axfr_from"] == ["198.51.100.0/24", "0.0.0.0/0", "::/0"]
    assert [k["name"] for k in a["axfr_tsig_keys"]] == ["spatium-xfr"]


def test_a_secondary_granted_by_address_gets_an_unsigned_notify(tmp_path: Path) -> None:
    # #4568: PowerDNS signs NOTIFY with the first TSIG-ALLOW-AXFR key. A zone
    # whose transfer policy names no key must carry none, or a secondary that
    # does not hold the group key rejects every NOTIFY.
    zones = _render(
        tmp_path,
        {
            "zones": [
                _zone("a.test", allow_transfer=["192.0.2.53"], also_notify=["192.0.2.53"]),
                _zone("b.test"),
                _zone("c.test", allow_transfer=["192.0.2.53", "key spatium-xfr"]),
            ],
            "options": {"allow_transfer": ["none"]},
            "tsig_keys": [KEY, {**KEY, "name": "other"}],
        },
    )
    assert zones["a.test."]["axfr_from"] == ["192.0.2.53/32"]
    assert zones["a.test."]["axfr_tsig_keys"] == []
    assert zones["b.test."]["axfr_tsig_keys"] == []
    # Only the key the zone names, not every key in the bundle.
    assert [k["name"] for k in zones["c.test."]["axfr_tsig_keys"]] == ["spatium-xfr"]


def test_the_catalog_zone_carries_no_key_the_server_policy_does_not_name(
    tmp_path: Path,
) -> None:
    zones = _render(
        tmp_path,
        {
            "zones": [_zone("a.test")],
            "options": {"allow_transfer": ["198.51.100.7"]},
            "tsig_keys": [KEY],
            "catalog": {"mode": "producer", "zone_name": "catalog.test", "members": []},
        },
    )
    assert zones["catalog.test."]["axfr_from"] == ["198.51.100.7/32"]
    assert zones["catalog.test."]["axfr_tsig_keys"] == []


def test_a_zone_override_shadows_the_server_policy(tmp_path: Path) -> None:
    zones = _render(
        tmp_path,
        {
            "zones": [_zone("a.test", allow_transfer=["192.0.2.53"]), _zone("b.test")],
            "options": {"allow_transfer": ["any"]},
            "tsig_keys": [KEY],
        },
    )
    assert zones["a.test."]["axfr_from"] == ["192.0.2.53/32"]
    assert zones["b.test."]["axfr_from"] == ["0.0.0.0/0", "::/0"]


def test_none_grants_nothing() -> None:
    assert _axfr_grants(["none"], {"spatium-xfr": KEY}, "a.test.") == ([], [])
    assert _axfr_grants(None, {"spatium-xfr": KEY}, "a.test.") == ([], [])


def test_a_negated_entry_drops_every_address_grant_rather_than_widening() -> None:
    # Dropping only "!10.0.0.5" would grant 10.0.0.5 through the /8 — the
    # opposite of what the operator wrote.
    cidrs, keys = _axfr_grants(
        ["!10.0.0.5", "10.0.0.0/8", "key spatium-xfr"], {"spatium-xfr": KEY}, "a.test."
    )
    assert cidrs == []
    assert [k["name"] for k in keys] == ["spatium-xfr"]


def test_named_acls_and_unknown_keys_are_not_granted() -> None:
    cidrs, keys = _axfr_grants(
        ["trusted-secondaries", "key ghost", 'key "spatium-xfr"', "203.0.113.9"],
        {"spatium-xfr": KEY},
        "a.test.",
    )
    assert cidrs == ["203.0.113.9/32"]
    assert [k["name"] for k in keys] == ["spatium-xfr"]


class _Pdns:
    def __init__(self) -> None:
        self.zones: set[str] = set()
        self.metadata: dict[tuple[str, str], list[str]] = {}
        self.tsigkeys: dict[str, dict[str, Any]] = {}

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path.removeprefix("/api/v1/servers/localhost")
        parts = path.split("/")
        if path == "/zones" and request.method == "GET":
            return httpx.Response(200, json=[{"name": n, "kind": "Master"} for n in self.zones])
        if path == "/zones" and request.method == "POST":
            self.zones.add(body["name"].lower())
            return httpx.Response(201, json={})
        if path == "/tsigkeys" and request.method == "POST":
            self.tsigkeys[body["name"]] = body
            return httpx.Response(201, json={})
        if len(parts) == 3 and parts[1] == "zones" and request.method == "GET":
            return httpx.Response(
                200,
                json={"name": parts[2], "kind": "Master", "soa_edit_api": "", "rrsets": []},
            )
        if len(parts) == 3 and parts[1] == "zones" and request.method in ("PUT", "PATCH"):
            return httpx.Response(204)
        if len(parts) >= 5 and parts[1] == "zones" and parts[3] == "metadata":
            key = (parts[2].lower(), parts[4])
            if request.method == "PUT":
                self.metadata[key] = body["metadata"]
                return httpx.Response(200, json=body)
            if request.method == "DELETE":
                self.metadata.pop(key, None)
                return httpx.Response(204)
        if len(parts) >= 4 and parts[1] == "zones" and parts[3] in ("notify", "axfr-retrieve"):
            return httpx.Response(200, json={})
        return httpx.Response(404, json={"error": f"unhandled {request.method} {path}"})


def _install(monkeypatch: pytest.MonkeyPatch, fake: _Pdns) -> None:
    real_client = httpx.Client

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(fake.handle), **kwargs)

    monkeypatch.setattr(powerdns.httpx, "Client", client)


def test_the_reconcile_writes_the_grants_and_imports_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _Pdns()
    _install(monkeypatch, fake)
    payload = {
        "name": "a.test.",
        "kind": "Master",
        "rrsets": [],
        "update_acl": [],
        "update_tsig_keys": [],
        "axfr_from": ["198.51.100.0/24"],
        "axfr_tsig_keys": [KEY],
    }
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones("k", [payload])
    assert fake.metadata[("a.test.", "ALLOW-AXFR-FROM")] == ["198.51.100.0/24"]
    assert fake.metadata[("a.test.", "TSIG-ALLOW-AXFR")] == ["spatium-xfr"]
    assert "spatium-xfr" in fake.tsigkeys

    # Granting nothing clears the grants a previous render wrote.
    fake.metadata[("a.test.", "ALLOW-AXFR-FROM")] = ["0.0.0.0/0"]
    PowerDNSDriver(state_dir=tmp_path)._reconcile_zones(
        "k", [{**payload, "axfr_from": [], "axfr_tsig_keys": []}]
    )
    assert ("a.test.", "ALLOW-AXFR-FROM") not in fake.metadata
    assert ("a.test.", "TSIG-ALLOW-AXFR") not in fake.metadata
