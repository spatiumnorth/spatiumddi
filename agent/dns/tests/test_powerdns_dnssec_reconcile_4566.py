"""A zone flagged signed is signed by every PowerDNS reconcile (#4566).

Signing only happened in answer to the one-shot ``dnssec_sign`` op, so a zone
re-created by the reconcile (a lost LMDB volume, a replaced node, a new
server) was served unsigned while the control plane still showed it signed
under the old DS. The reconcile now signs a flagged zone that has no active
key, and ``collect_dnssec_state`` hands the sync loop the resulting DS.

Driven against an in-memory stand-in for the pdns REST API that keeps zones
and cryptokeys, so "signed, then the volume is lost" can be played through.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


class FakePdns:
    """Zones + cryptokeys, as much of the API as the driver touches."""

    def __init__(self) -> None:
        self.zones: set[str] = set()
        self.keys: dict[str, list[dict[str, Any]]] = {}
        self.generation = 0
        self.calls: list[tuple[str, str]] = []
        self.cryptokeys_status = 200

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.split("/zones", 1)[1]
        self.calls.append((request.method, path))
        if path == "" and request.method == "GET":
            return httpx.Response(200, json=[{"name": z, "kind": "Native"} for z in self.zones])
        if path == "" and request.method == "POST":
            self.zones.add(json.loads(request.content)["name"])
            return httpx.Response(201, json={})
        zone, _, rest = path.lstrip("/").partition("/")
        if rest == "cryptokeys":
            if self.cryptokeys_status != 200:
                return httpx.Response(self.cryptokeys_status, json={"error": "backend down"})
            if request.method == "GET":
                return httpx.Response(200, json=self.keys.get(zone, []))
            body = json.loads(request.content)
            self.generation += 1
            key = {"id": self.generation, "keytype": body["keytype"], "active": body["active"]}
            if body["keytype"] == "ksk":
                key["ds"] = [f"{1000 + self.generation} 13 2 {'ab' * 32}"]
            self.keys.setdefault(zone, []).append(key)
            return httpx.Response(201, json=key)
        if request.method == "GET":
            return httpx.Response(200, json={"name": zone, "kind": "Native", "rrsets": []})
        if request.method == "DELETE":
            return httpx.Response(404)
        return httpx.Response(204)

    def lose_volume(self) -> None:
        self.zones.clear()
        self.keys.clear()

    def key_posts(self) -> int:
        return sum(1 for m, p in self.calls if m == "POST" and p.endswith("/cryptokeys"))


@pytest.fixture
def pdns(monkeypatch: pytest.MonkeyPatch) -> FakePdns:
    fake = FakePdns()
    real_client = httpx.Client

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(fake.handle), **kwargs)

    monkeypatch.setattr(powerdns.httpx, "Client", client)
    return fake


def _bundle(*zones: dict[str, Any]) -> dict[str, Any]:
    return {"options": {}, "zones": [{"type": "primary", "records": [], **z} for z in zones]}


def _payload(tmp_path: Path, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    PowerDNSDriver(state_dir=tmp_path).render(bundle)
    payload: list[dict[str, Any]] = json.loads(
        (tmp_path / "rendered.new" / "zones.json").read_text()
    )
    return payload


SIGNED = _bundle({"name": "t1.example", "dnssec_enabled": True})


def test_the_render_carries_the_flag_for_a_primary_only(tmp_path: Path) -> None:
    payload = _payload(
        tmp_path,
        _bundle(
            {"name": "signed.example", "dnssec_enabled": True},
            {"name": "plain.example"},
            {
                "name": "sec.example",
                "type": "secondary",
                "masters": ["192.0.2.1"],
                "dnssec_enabled": True,
            },
        ),
    )
    assert {z["name"]: z["dnssec_enabled"] for z in payload} == {
        "signed.example.": True,
        "plain.example.": False,
        "sec.example.": False,
    }


def test_a_recreated_signed_zone_is_signed_again(tmp_path: Path, pdns: FakePdns) -> None:
    """The issue's reproduction: signed, the zone is lost, the reconcile
    re-creates it. It must come back with active keys, and a new DS."""
    drv = PowerDNSDriver(state_dir=tmp_path)
    payload = _payload(tmp_path, SIGNED)

    drv._reconcile_zones("k", payload)
    first = drv.collect_dnssec_state(SIGNED)
    assert first == [{"zone_name": "t1.example.", "ds_records": [f"1001 13 2 {'ab' * 32}"]}]

    pdns.lose_volume()
    drv._reconcile_zones("k", payload)

    assert "t1.example." in pdns.zones
    assert sorted(k["keytype"] for k in pdns.keys["t1.example."] if k["active"]) == ["ksk", "zsk"]
    assert ("PUT", "/t1.example./rectify") in pdns.calls
    second = drv.collect_dnssec_state(SIGNED)
    assert second and second != first
    assert drv.dnssec_incomplete is False


def test_a_zone_with_an_active_key_is_left_alone(tmp_path: Path, pdns: FakePdns) -> None:
    drv = PowerDNSDriver(state_dir=tmp_path)
    payload = _payload(tmp_path, SIGNED)
    drv._reconcile_zones("k", payload)
    assert pdns.key_posts() == 2

    drv._reconcile_zones("k", payload)

    assert pdns.key_posts() == 2  # no second key set, so the DS did not move


def test_an_unflagged_zone_is_not_signed(tmp_path: Path, pdns: FakePdns) -> None:
    bundle = _bundle({"name": "plain.example"})
    drv = PowerDNSDriver(state_dir=tmp_path)

    drv._reconcile_zones("k", _payload(tmp_path, bundle))

    assert not [c for c in pdns.calls if c[1].endswith("/cryptokeys")]
    assert drv.collect_dnssec_state(bundle) == []


def test_a_zone_that_cannot_be_signed_fails_the_apply(tmp_path: Path, pdns: FakePdns) -> None:
    """Not a silent skip: the apply fails, so the sync loop retries it and
    the server does not report the bundle as applied."""
    pdns.cryptokeys_status = 500
    drv = PowerDNSDriver(state_dir=tmp_path)

    with pytest.raises(RuntimeError, match=r"t1\.example\. DNSSEC"):
        drv._reconcile_zones("k", _payload(tmp_path, SIGNED))


def test_collect_leaves_out_a_flagged_zone_with_no_active_key(
    tmp_path: Path, pdns: FakePdns
) -> None:
    """An empty DS report would clear the control plane's copy as if the zone
    had been unsigned on purpose; the zone is held back and re-read soon."""
    pdns.zones.add("t1.example.")
    pdns.keys["t1.example."] = [{"id": 1, "keytype": "ksk", "active": False, "ds": ["1 13 2 aa"]}]
    drv = PowerDNSDriver(state_dir=tmp_path)

    assert drv.collect_dnssec_state(SIGNED) == []
    assert drv.dnssec_incomplete is True


def test_the_sign_op_signs_a_zone_whose_keys_are_all_inactive(
    tmp_path: Path, pdns: FakePdns
) -> None:
    pdns.zones.add("t1.example.")
    pdns.keys["t1.example."] = [{"id": 1, "keytype": "ksk", "active": False, "ds": ["1 13 2 aa"]}]

    PowerDNSDriver(state_dir=tmp_path)._dnssec_sign("k", "t1.example.")

    assert sum(1 for k in pdns.keys["t1.example."] if k["active"]) == 2
