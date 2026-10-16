"""A PowerDNS zone serves the control plane's SOA serial, and never a lower one
than it already served; NOTIFY goes out and a secondary transfers (#1965,
#1967, #1968).

ddi-pg's drill of #1611 on PowerDNS 5.0.7:

* #1965 — the agent created zones with no ``soa_edit_api``, so PowerDNS's API
  default (``SOA-EDIT-API: DEFAULT``) rewrote the serial of every change made
  through it. A serial of 1 was served as ``2026101601``, a record add as
  ``…02``, an SOA-only edit under the serial already held. The zone never read
  in sync and a secondary saw no new serial for an SOA edit.
* #1968 — the reconcile replaced the SOA with the control plane's serial, which
  can be BELOW what PowerDNS served (the upgrade from a pre-#1611 build; any
  record add on the new one), so the served serial went backwards.
* #1967 — ``pdns.conf`` left ``primary`` and ``secondary`` at ``no``, so no
  NOTIFY was sent and a secondary zone was never transferred.

``FakePdns`` is a small stateful stand-in for the pdns REST API that keeps the
real semantics those bugs depend on (the DEFAULT rewrite, ``soa_edit_api``
cleared by an empty string, a lower serial accepted as sent). Its behaviours
were checked against ``pdns-auth`` 5.0.7 (see the PR).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import commit_config, ensure_layout, save_config
from spatium_dns_agent.drivers import powerdns
from spatium_dns_agent.drivers.powerdns import (
    PowerDNSDriver,
    _floor_soa_content,
    _soa_serial,
)
from tests.test_sync_partial_apply import _bundle, _Driver, _loop, _poll

TODAY = 2026101600  # PowerDNS's "YYYYMMDD00" base for the DEFAULT rewrite
BASE = "http://127.0.0.1:8081/api/v1/servers/localhost"


class FakePdns:
    def __init__(self) -> None:
        self.zones: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str, Any]] = []

    # -- seeding ----------------------------------------------------------
    def seed(
        self,
        name: str,
        serial: int,
        *,
        edit_api: str = "DEFAULT",
        kind: str = "Native",
        soa: str | None = None,
    ) -> None:
        self.zones[name.lower()] = {
            "kind": kind,
            "soa_edit_api": edit_api,
            "soa": soa
            or f"a.misconfigured.dns.server.invalid. hostmaster.{name} {serial} 10800 3600 604800 3600",
            "ttl": 3600,
            "rrsets": {},
            "masters": [],
        }

    def serial(self, name: str) -> int:
        return int(self.zones[name.lower()]["soa"].split()[2])

    # -- semantics --------------------------------------------------------
    def _default_edit(self, serial: int) -> int:
        return TODAY + 1 if serial < TODAY + 1 else serial + 1

    def _set_soa(self, z: dict[str, Any], content: str, *, edited: bool) -> None:
        parts = content.split()
        if z["soa_edit_api"] == "DEFAULT" and edited:
            parts[2] = str(self._default_edit(int(parts[2])))
        z["soa"] = " ".join(parts)

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path.removeprefix("/api/v1/servers/localhost")
        self.calls.append(
            (
                request.method,
                path + (f"?{request.url.query.decode()}" if request.url.query else ""),
                body,
            )
        )
        if path == "/zones" and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {"name": n, "kind": z["kind"], "masters": z["masters"]}
                    for n, z in self.zones.items()
                ],
            )
        if path == "/zones" and request.method == "POST":
            name = body["name"].lower()
            z = {
                "kind": body["kind"],
                # The API default when the key is absent — the #1965 defect.
                "soa_edit_api": body.get("soa_edit_api", "DEFAULT"),
                "soa": None,
                "ttl": 3600,
                "rrsets": {},
                "masters": body.get("masters", []),
            }
            self.zones[name] = z
            for rs in body.get("rrsets", []):
                self._apply_rrset(z, name, rs, edited=False)
            if z["soa"] is None:
                z["soa"] = (
                    f"a.misconfigured.dns.server.invalid. hostmaster.{name} {body.get('serial', 1)} 1 1 1 1"
                )
            self._set_soa(z, z["soa"], edited=True)  # creation edits once too
            return httpx.Response(201, json={})
        parts = path.split("/")
        if len(parts) >= 3 and parts[1] == "zones":
            name = parts[2].lower()
            z = self.zones.get(name)
            if z is None:
                return httpx.Response(404, json={"error": "not found"})
            tail = "/".join(parts[3:])
            if tail == "" and request.method == "GET":
                rrsets = [
                    {
                        "name": name,
                        "type": "SOA",
                        "ttl": z["ttl"],
                        "records": [{"content": z["soa"], "disabled": False}],
                    }
                ]
                if "rrset_type=SOA" not in request.url.query.decode():
                    rrsets += [
                        {
                            "name": n,
                            "type": t,
                            "ttl": 60,
                            "records": [{"content": c, "disabled": False} for c in cs],
                        }
                        for (n, t), cs in z["rrsets"].items()
                    ]
                return httpx.Response(
                    200,
                    json={
                        "name": name,
                        "kind": z["kind"],
                        "soa_edit_api": z["soa_edit_api"],
                        "rrsets": rrsets,
                    },
                )
            if tail == "" and request.method == "PUT":
                if "soa_edit_api" in body:
                    z["soa_edit_api"] = body["soa_edit_api"]
                if "kind" in body:
                    z["kind"] = body["kind"]
                if "masters" in body:
                    z["masters"] = body["masters"]
                return httpx.Response(204)
            if tail == "" and request.method == "PATCH":
                soa_in_patch = False
                for rs in body["rrsets"]:
                    if rs["type"] == "SOA":
                        soa_in_patch = True
                        self._apply_rrset(z, name, rs, edited=True)
                    else:
                        self._apply_rrset(z, name, rs, edited=False)
                if not soa_in_patch and z["soa_edit_api"] == "DEFAULT":
                    # PowerDNS edits the stored SOA on any change made through
                    # the API.
                    self._set_soa(z, z["soa"], edited=True)
                return httpx.Response(204)
            if tail.startswith("metadata"):
                return httpx.Response(204 if request.method == "PUT" else 404)
            if tail in ("notify", "axfr-retrieve") and request.method == "PUT":
                return httpx.Response(200, json={"result": "queued"})
        return httpx.Response(404, json={"error": f"unhandled {request.method} {path}"})

    def _apply_rrset(
        self, z: dict[str, Any], zone: str, rs: dict[str, Any], *, edited: bool
    ) -> None:
        key = (rs["name"].lower(), rs["type"])
        if rs["type"] == "SOA" and rs["name"].lower() == zone:
            if rs.get("changetype", "REPLACE") == "REPLACE":
                z["ttl"] = rs.get("ttl", 3600)
                self._set_soa(z, rs["records"][0]["content"], edited=edited)
                if not edited:
                    z["soa"] = rs["records"][0]["content"]
            return
        if rs.get("changetype") == "DELETE":
            z["rrsets"].pop(key, None)
        else:
            z["rrsets"][key] = [r["content"] for r in rs["records"]]


def _install(monkeypatch: pytest.MonkeyPatch, fake: FakePdns) -> None:
    real_client = httpx.Client

    def client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_client(*args, transport=httpx.MockTransport(fake.handle), **kwargs)

    monkeypatch.setattr(powerdns.httpx, "Client", client)


def _soa_rrset(
    zone: str, serial: int, *, ns: str = "ns1.example.com.", refresh: int = 3600
) -> dict[str, Any]:
    return {
        "name": zone,
        "type": "SOA",
        "ttl": 3600,
        "records": [
            {
                "content": f"{ns} hostmaster.example.com. {serial} {refresh} 600 86400 300",
                "disabled": False,
            }
        ],
    }


def _zone(name: str, serial: int, **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "kind": extra.pop("kind", "Master"),
        "serial": serial,
        "rrsets": [_soa_rrset(name, serial, **extra.pop("soa", {}))],
        "update_acl": [],
        "update_tsig_keys": [],
        **extra,
    }


def _driver(tmp_path: Path) -> PowerDNSDriver:
    return PowerDNSDriver(state_dir=tmp_path)


# ── #1965: the zone serves the control plane's serial ────────────────────────


def test_a_new_zone_is_created_with_soa_edit_api_cleared_and_serves_our_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    _driver(tmp_path)._reconcile_zones("k", [_zone("example.com.", 1)])
    (post,) = [c for c in fake.calls if c[0] == "POST"]
    assert post[2]["soa_edit_api"] == ""
    assert (
        fake.serial("example.com.") == 1
    ), "not PowerDNS's DEFAULT rewrite to YYYYMMDD01"


def test_an_soa_only_edit_serves_the_new_serial_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1965 case 7: the SOA edit's serial must be what is served, so a
    secondary sees the new MNAME / timers."""
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101600)])
    drv._reconcile_zones(
        "k",
        [
            _zone(
                "example.com.",
                2026101601,
                soa={"ns": "ns9.example.com.", "refresh": 7200},
            )
        ],
    )
    z = fake.zones["example.com."]
    assert fake.serial("example.com.") == 2026101601
    assert z["soa"].startswith(
        "ns9.example.com. hostmaster.example.com. 2026101601 7200 "
    )


def test_a_zone_still_on_default_is_cleared_before_its_soa_is_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    fake.seed("example.com.", 2026101600)
    _install(monkeypatch, fake)
    _driver(tmp_path)._reconcile_zones("k", [_zone("example.com.", 2026101700)])
    assert fake.zones["example.com."]["soa_edit_api"] == ""
    methods = [(m, p) for m, p, _ in fake.calls]
    assert methods.index(("PUT", "/zones/example.com.")) < methods.index(
        ("PATCH", "/zones/example.com.")
    )
    assert fake.serial("example.com.") == 2026101700


# ── #1968: never backwards ───────────────────────────────────────────────────


def test_the_upgrade_never_serves_a_serial_below_the_one_pdns_served(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reproduced upgrade: zone A served 2026101604 (PowerDNS's default
    SOA, bumped by SOA-EDIT-API); the control plane still says 2026101600."""
    fake = FakePdns()
    fake.seed("a.test.", 2026101604)
    fake.seed("b.test.", 2026101608)
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones(
        "k", [_zone("a.test.", 2026101600), _zone("b.test.", 2026101605)]
    )
    assert fake.serial("a.test.") == 2026101605, "forward of what was served"
    assert fake.serial("b.test.") == 2026101609
    assert fake.zones["a.test."]["soa"].startswith(
        "ns1.example.com. hostmaster.example.com."
    ), "and it is the zone's own SOA now"
    # A later full reconcile (the control plane has not caught up yet) must not
    # creep: same SOA fields, so nothing to publish.
    drv._reconcile_zones(
        "k", [_zone("a.test.", 2026101600), _zone("b.test.", 2026101605)]
    )
    assert fake.serial("a.test.") == 2026101605
    assert fake.serial("b.test.") == 2026101609
    # Once the control plane has adopted the served serial, it is sent as is.
    drv._reconcile_zones("k", [_zone("a.test.", 2026101605)])
    assert fake.serial("a.test.") == 2026101605


def test_a_full_reconcile_after_a_record_add_does_not_step_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The new-build-only case from #1968: a record add raised the served
    serial; the next full reconcile carried the control plane's older one."""
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("d.test.", 2026101600)])
    drv.apply_record_op(
        {
            "zone_name": "d.test.",
            "op": "create",
            "target_serial": 2026101601,
            "record": {"name": "www", "type": "A", "value": "192.0.2.1", "ttl": 60},
        }
    )
    assert fake.serial("d.test.") == 2026101601
    drv._reconcile_zones("k", [_zone("d.test.", 2026101601)])
    assert fake.serial("d.test.") == 2026101601
    # even when the bundle's serial is behind (the op raced the render)
    drv._reconcile_zones("k", [_zone("d.test.", 2026101600)])
    assert fake.serial("d.test.") == 2026101601


def test_floor_uses_rfc1982_arithmetic() -> None:
    soa = "ns. a. {} 1 2 3 4"
    assert _soa_serial(_floor_soa_content(soa.format(5), soa.format(4))) == 5
    # Wrap-around: 1 is LATER than 4294967295.
    assert _soa_serial(_floor_soa_content(soa.format(1), soa.format(4294967295))) == 1
    # Behind with different fields: served + 1, wrapping.
    assert (
        _soa_serial(
            _floor_soa_content("ns2. a. 4294967290 1 2 3 4", soa.format(4294967295))
        )
        == 0
    )


# ── the record-op path ───────────────────────────────────────────────────────


def _op(target: Any, zone: str = "example.com.", name: str = "www") -> dict[str, Any]:
    return {
        "zone_name": zone,
        "op": "create",
        "target_serial": target,
        "record": {
            "name": name,
            "type": "A",
            "value": "192.0.2.1",
            "ttl": 60,
            "rrset": {"ttl": 60, "members": [{"value": "192.0.2.1"}]},
        },
    }


def test_a_record_op_carries_the_zone_to_the_control_planes_serial_and_notifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101600)])
    fake.calls.clear()
    drv.apply_record_op(_op(2026101601))
    assert fake.serial("example.com.") == 2026101601
    assert drv.reached_serial("example.com.") == 2026101601
    (patch,) = [c for c in fake.calls if c[0] == "PATCH"]
    assert [r["type"] for r in patch[2]["rrsets"]] == ["A", "SOA"], "one transaction"
    assert ("PUT", "/zones/example.com./notify", None) in fake.calls


def test_a_record_op_made_before_adoption_moves_the_serial_past_the_served_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control plane is still behind the served serial (the op was made
    before it adopted it). Leaving the SOA alone would publish the new record
    under 2026101605, which every secondary already holds: they would never
    transfer it. The zone moves to served + 1 and a NOTIFY goes out."""
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101605)])
    fake.calls.clear()
    drv.apply_record_op(_op(2026101601))
    assert fake.serial("example.com.") == 2026101606, "forward of the served serial"
    served = fake.zones["example.com."]["rrsets"]
    assert served[("www.example.com.", "A")] == ["192.0.2.1"]
    assert drv.reached_serial("example.com.") == 2026101606, "reported as what it is"
    (patch,) = [c for c in fake.calls if c[0] == "PATCH"]
    assert [r["type"] for r in patch[2]["rrsets"]] == ["A", "SOA"], "one transaction"
    assert ("PUT", "/zones/example.com./notify", None) in fake.calls


def test_a_retried_op_whose_change_is_already_served_leaves_the_soa(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same op again (its ack was lost): the record is already served, so
    moving the serial would only make every secondary transfer the same data."""
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101600)])
    drv.apply_record_op(_op(2026101601))
    assert fake.serial("example.com.") == 2026101601
    fake.calls.clear()
    drv.apply_record_op(_op(2026101601))
    assert fake.serial("example.com.") == 2026101601, "no creep"
    assert drv.reached_serial("example.com.") == 2026101601
    assert not [c for c in fake.calls if c[1].endswith("/notify")]


def test_a_stale_delete_of_a_record_still_served_moves_the_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101600)])
    drv.apply_record_op(_op(2026101601))
    delete = _op(2026101601)
    delete["op"] = "delete"
    delete["record"]["rrset"] = {"ttl": 60, "members": []}
    fake.calls.clear()
    drv.apply_record_op(delete)
    assert ("www.example.com.", "A") not in fake.zones["example.com."]["rrsets"]
    assert fake.serial("example.com.") == 2026101602
    assert ("PUT", "/zones/example.com./notify", None) in fake.calls
    # and once it is gone, the same delete again changes nothing
    fake.calls.clear()
    drv.apply_record_op(delete)
    assert fake.serial("example.com.") == 2026101602
    assert not [c for c in fake.calls if c[1].endswith("/notify")]


def test_a_stale_op_without_an_rrset_payload_moves_the_serial_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The merge path (DNS-pool ops, older control planes) takes the same rule."""
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101605)])
    op = _op(2026101601)
    del op["record"]["rrset"]
    fake.calls.clear()
    drv.apply_record_op(op)
    assert fake.serial("example.com.") == 2026101606
    assert ("PUT", "/zones/example.com./notify", None) in fake.calls


def test_an_op_without_a_target_serial_moves_the_serial_forward_by_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("example.com.", 2026101605)])
    drv.apply_record_op(_op(None))
    assert fake.serial("example.com.") == 2026101606


def test_an_op_on_a_zone_not_yet_cleared_clears_it_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    fake.seed("example.com.", 2026101604)
    _install(monkeypatch, fake)
    _driver(tmp_path).apply_record_op(_op(2026101605))
    assert fake.zones["example.com."]["soa_edit_api"] == ""
    assert fake.serial("example.com.") == 2026101605, "not DEFAULT's 2026101606"


def test_an_op_on_a_secondary_zone_leaves_the_soa_to_the_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    fake.seed("s.test.", 7, edit_api="", kind="Slave")
    _install(monkeypatch, fake)
    _driver(tmp_path).apply_record_op(_op(99, zone="s.test."))
    assert fake.serial("s.test.") == 7


def test_the_sync_loop_reports_the_serial_the_zone_actually_reached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Driver(_Driver):
        def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
            super().apply_record_op(op)
            return None

        def reached_serial(self, zone_name: str) -> int | None:
            return 2026101605  # PowerDNS already served this

    driver = Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    posted: list[Any] = []
    monkeypatch.setattr(
        loop, "_post_zone_state", lambda entries: posted.extend(entries)
    )
    bundle = _bundle("e1", structural="s1", ops=["op-1"])
    bundle["pending_record_ops"][0]["target_serial"] = 2026101601
    _poll(loop, monkeypatch, bundle)
    assert {"zone_name": "ok.test", "serial": 2026101605} in posted
    assert {"zone_name": "ok.test", "serial": 2026101601} not in posted


# ── #1968: the startup apply reports what it left served ─────────────────────


class _ServingDriver(_Driver):
    """A driver that reads back what it serves, like PowerDNS: the startup
    apply floored the zone above the cached bundle's serial."""

    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        self.served = {"ok.test": 2026101605}
        self.readable = True

    def served_zone_serials(self, bundle: dict[str, Any]) -> dict[str, int]:
        return dict(self.served) if self.readable else {}


class _NotModified:
    def __init__(self) -> None:
        self.status_code = 304
        self.headers: dict[str, str] = {}
        self.text = ""


class _Client304:
    def __enter__(self) -> _Client304:  # noqa: PYI034 - a test double
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, *args: Any, **kwargs: Any) -> _NotModified:
        return _NotModified()


def _cached_loop(
    tmp_path: Path, driver: _Driver, monkeypatch: pytest.MonkeyPatch
) -> tuple[Any, list[dict[str, Any]], list[bool]]:
    """A loop booted from a cached bundle (the slot upgrade), whose control
    plane then answers 304: nothing structural is pending."""
    ensure_layout(tmp_path)
    bundle = _bundle("e1", structural="s1")
    bundle["zones"] = [{"name": "ok.test.", "serial": 2026101600}]
    save_config(tmp_path, bundle, "e1")
    commit_config(tmp_path, "e1")
    loop = _loop(tmp_path, driver, monkeypatch)
    posted: list[dict[str, Any]] = []
    outcomes: list[bool] = []

    def post(entries: list[dict[str, Any]]) -> bool:
        ok = outcomes.pop(0) if outcomes else True
        if ok:
            posted.extend(entries)
        return ok

    monkeypatch.setattr(loop, "_post_zone_state", post)
    monkeypatch.setattr(loop, "_client", lambda: _Client304())
    return loop, posted, outcomes


def test_the_startup_apply_reports_the_served_serials_on_the_first_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case 3 of the walk: after the slot upgrade the agent applied its cached
    bundle and reported nothing, so the control plane did not adopt the served
    serial until the next structural change."""
    loop, posted, _ = _cached_loop(tmp_path, _ServingDriver(tmp_path), monkeypatch)
    loop._poll_once()
    assert posted == [{"zone_name": "ok.test.", "serial": 2026101605}]
    loop._poll_once()
    loop._poll_once()
    assert len(posted) == 1, "reported once, not on every poll"


def test_the_startup_report_is_retried_until_it_lands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _ServingDriver(tmp_path)
    driver.readable = False  # PowerDNS still starting
    loop, posted, outcomes = _cached_loop(tmp_path, driver, monkeypatch)
    loop._poll_once()
    assert posted == []
    driver.readable = True
    outcomes.append(False)  # control plane not reachable yet
    loop._poll_once()
    assert posted == []
    loop._poll_once()
    assert posted == [{"zone_name": "ok.test.", "serial": 2026101605}]


def test_the_startup_report_gives_up_after_a_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _ServingDriver(tmp_path)
    driver.readable = False
    loop, posted, _ = _cached_loop(tmp_path, driver, monkeypatch)
    calls: list[int] = []
    real = driver.served_zone_serials
    monkeypatch.setattr(
        driver, "served_zone_serials", lambda b: calls.append(1) or real(b)
    )
    for _ in range(sync_mod.BOOT_REPORT_MAX_ATTEMPTS + 5):
        loop._poll_once()
    assert len(calls) == sync_mod.BOOT_REPORT_MAX_ATTEMPTS
    assert posted == []


def test_a_driver_serving_the_bundles_serials_sends_no_startup_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BIND9 serves the serials it was sent, which the control plane has."""
    loop, posted, _ = _cached_loop(tmp_path, _Driver(tmp_path), monkeypatch)
    loop._poll_once()
    assert posted == []


# ── #1967: NOTIFY and transfers ──────────────────────────────────────────────


def test_pdns_conf_declares_primary_and_secondary(tmp_path: Path) -> None:
    conf = _driver(tmp_path)._render_conf(api_key="k", log_level=4).splitlines()
    assert "primary=yes" in conf
    assert "secondary=yes" in conf


def test_a_new_secondary_is_asked_to_transfer_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    _driver(tmp_path)._reconcile_zones(
        "k",
        [
            {
                "name": "sec.test.",
                "kind": "Slave",
                "masters": ["192.0.2.10"],
                "serial": 0,
                "rrsets": [],
                "update_acl": [],
                "update_tsig_keys": [],
            }
        ],
    )
    (post,) = [c for c in fake.calls if c[0] == "POST"]
    assert "soa_edit_api" not in post[2], "a secondary's SOA is the transfer's"
    assert ("PUT", "/zones/sec.test./axfr-retrieve", None) in fake.calls


def test_a_reconcile_that_changes_the_serial_notifies_a_primary_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    drv = _driver(tmp_path)
    drv._reconcile_zones("k", [_zone("m.test.", 1), _zone("n.test.", 1, kind="Native")])
    fake.calls.clear()
    drv._reconcile_zones("k", [_zone("m.test.", 2), _zone("n.test.", 2, kind="Native")])
    assert ("PUT", "/zones/m.test./notify", None) in fake.calls
    assert ("PUT", "/zones/n.test./notify", None) not in fake.calls
    fake.calls.clear()
    drv._reconcile_zones("k", [_zone("m.test.", 2)])
    assert not [c for c in fake.calls if c[1].endswith("/notify")], "nothing changed"


def test_the_catalog_zone_keeps_pdns_serial_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakePdns()
    _install(monkeypatch, fake)
    _driver(tmp_path)._reconcile_zones(
        "k",
        [
            {
                "name": "catalog.invalid.",
                "kind": "Native",
                "serial": 1792000000,
                "serial_managed": False,
                "rrsets": [_soa_rrset("catalog.invalid.", 1792000000)],
                "update_acl": [],
                "update_tsig_keys": [],
            }
        ],
    )
    (post,) = [c for c in fake.calls if c[0] == "POST"]
    assert "soa_edit_api" not in post[2]
