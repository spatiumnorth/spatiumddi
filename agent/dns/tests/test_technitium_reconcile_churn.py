"""Technitium structural reconcile: no churn, no lost PTRs (#1768).

A stateful fake daemon that normalises the way Technitium 15.4 does:
one TTL per RRset (AuthZone.AddRecord), CAA tags lower-cased, URIs read
back as ``Uri.AbsoluteUri``, IDN targets stored as punycode with a derived
``*Idn`` key, and an A/AAAA delete that also deletes the matching PTR in a
reverse zone on the same server (WebServiceZonesApi.DeleteRecord).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from spatium_dns_agent.drivers.technitium import TechnitiumDriver

from .test_technitium_render import _install_fake_request, _seed_token

_VALUE_KEYS = {
    "A": ("ipAddress",),
    "AAAA": ("ipAddress",),
    "CNAME": ("cname",),
    "PTR": ("ptrName",),
    "MX": ("preference", "exchange"),
    "CAA": ("flags", "tag", "value"),
    "URI": ("uriPriority", "uriWeight", "uri"),
}


def _reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


class FakeTechnitium:
    def __init__(self, zones: list[str]) -> None:
        # zone -> list of {name, type, ttl, disabled, rdata}
        self.zones: dict[str, list[dict[str, Any]]] = {z: [] for z in zones}
        self.writes: list[tuple[str, dict[str, Any]]] = []

    # -- helpers --
    @staticmethod
    def _idna(name: str) -> str:
        try:
            return name.encode("idna").decode("ascii")
        except UnicodeError:
            return name

    def _stored(self, rtype: str, p: dict[str, Any]) -> dict[str, Any]:
        r: dict[str, Any] = {}
        if rtype in ("A", "AAAA"):
            r["ipAddress"] = p["ipAddress"]
        elif rtype == "CNAME":
            r["cname"] = self._idna(p["cname"])
        elif rtype == "PTR":
            r["ptrName"] = self._idna(p["ptrName"])
        elif rtype == "MX":
            r["preference"] = int(p["preference"])
            r["exchange"] = self._idna(p["exchange"])
        elif rtype == "CAA":
            r["flags"] = int(p["flags"])
            r["tag"] = str(p["tag"]).lower()  # DnsCAARecordData
            r["value"] = p["value"]
        elif rtype == "URI":
            u = urlsplit(p["uri"])
            host = (u.hostname or "").lower()
            default = {"http": 80, "https": 443}.get(u.scheme.lower())
            port = f":{u.port}" if u.port and u.port != default else ""
            r["priority"] = int(p["uriPriority"])
            r["weight"] = int(p["uriWeight"])
            r["uri"] = f"{u.scheme.lower()}://{host}{port}{u.path or '/'}"
        for k in ("cname", "ptrName", "exchange"):
            if k in r and "xn--" in r[k]:
                # The derived Unicode twin the GET adds (WriteRecordAsJson).
                r[k + "Idn"] = r[k].encode("ascii").decode("idna")
        return r

    @staticmethod
    def _same(rec: dict[str, Any], rtype: str, stored: dict[str, Any]) -> bool:
        return rec["type"] == rtype and {
            k: v for k, v in rec["rdata"].items() if not k.endswith("Idn")
        } == {k: v for k, v in stored.items() if not k.endswith("Idn")}

    def _rrset(self, zone: str, name: str, rtype: str) -> list[dict[str, Any]]:
        return [r for r in self.zones[zone] if r["name"] == name and r["type"] == rtype]

    def _add(self, p: dict[str, Any], disabled: bool = False) -> dict[str, Any]:
        zone, rtype = p["zone"], p["type"]
        name = self._idna(p["domain"])
        stored = self._stored(rtype, p)
        ttl = int(p["ttl"])
        for r in self._rrset(zone, name, rtype):
            # AuthZone.AddRecord: same rdata at the same TTL returns the
            # existing record untouched, disabled or not, and the web API
            # answers "already exists".
            if self._same(r, rtype, stored) and r["ttl"] == ttl:
                return {
                    "status": "error",
                    "errorMessage": "Cannot add record: record already exists.",
                }
        sibs = self._rrset(zone, name, rtype)
        for r in sibs:
            r["ttl"] = ttl  # AuthZone.AddRecord: one TTL per RRset
        for r in sibs:
            if self._same(r, rtype, stored):
                # Same rdata, other TTL: replaced by the new record.
                r["disabled"] = disabled
                return {"status": "ok"}
        self.zones[zone].append(
            {
                "name": name,
                "type": rtype,
                "ttl": ttl,
                "disabled": disabled,
                "rdata": stored,
            }
        )
        return {"status": "ok"}

    def _delete(self, p: dict[str, Any]) -> dict[str, Any]:
        zone, rtype = p["zone"], p["type"]
        name = self._idna(p["domain"])
        stored = self._stored(rtype, p)
        for r in self._rrset(zone, name, rtype):
            if self._same(r, rtype, stored):
                self.zones[zone].remove(r)
                if rtype in ("A", "AAAA"):
                    # The web API's implicit PTR cleanup.
                    for rz, recs in self.zones.items():
                        if rz.endswith(".arpa"):
                            for ptr in list(recs):
                                if (
                                    ptr["type"] == "PTR"
                                    and ptr["rdata"]["ptrName"] == name
                                    and ptr["name"] == _reverse_name(p["ipAddress"])
                                ):
                                    recs.remove(ptr)
                return {"status": "ok"}
        return {
            "status": "error",
            "errorMessage": "Cannot delete record: no such record exists.",
        }

    def _update(self, p: dict[str, Any]) -> dict[str, Any]:
        zone, rtype = p["zone"], p["type"]
        name = self._idna(p["domain"])
        stored = self._stored(rtype, p)
        for r in self._rrset(zone, name, rtype):
            if self._same(r, rtype, stored):
                # AuthZone.UpdateRecord: delete + add, no PTR cleanup. The
                # new record's state comes from ``disable`` (default false).
                self.zones[zone].remove(r)
                self._add(p, disabled=str(p.get("disable", "false")).lower() == "true")
                return {"status": "ok"}
        return {
            "status": "error",
            "errorMessage": "Cannot update record: the old record does not exists.",
        }

    # -- the API --
    def respond(self, path: str, params: dict[str, Any], _n: int) -> dict[str, Any]:
        if path == "zones/records/get":
            zone = params["zone"]
            return {
                "status": "ok",
                "response": {
                    "records": [
                        {
                            "name": r["name"],
                            "type": r["type"],
                            "ttl": r["ttl"],
                            "disabled": r["disabled"],
                            "rData": dict(r["rdata"]),
                        }
                        for r in self.zones[zone]
                    ]
                },
            }
        if path in (
            "zones/records/add",
            "zones/records/delete",
            "zones/records/update",
        ):
            self.writes.append((path, dict(params)))
            op = path.rsplit("/", 1)[1]
            return getattr(self, "_" + op)(params)
        return {"status": "ok"}


def _driver(tmp_path: Path, fake: FakeTechnitium) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    _install_fake_request(d, fake.respond)
    # The zones exist already; no create/options traffic matters here.
    d._ensure_zone_exists = lambda *_a, **_k: None  # type: ignore[method-assign]
    d._apply_zone_options = lambda *_a, **_k: None  # type: ignore[method-assign]
    d._reconcile_zone_apex = lambda *_a, **_k: None  # type: ignore[method-assign]
    return d


def _payload(
    d: TechnitiumDriver, tmp_path: Path, zones: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    import json

    d.render({"zones": zones})
    return json.loads((d.state_dir / "rendered.new" / "zones.json").read_text())


def _z(name: str, records: list[dict[str, Any]], ttl: int = 3600) -> dict[str, Any]:
    return {"name": name, "type": "primary", "ttl": ttl, "records": records}


FORWARD = _z(
    "example.com.",
    [
        {"name": "www", "type": "A", "value": "10.0.0.1", "ttl": 3600},
        {"name": "www", "type": "A", "value": "10.0.0.2", "ttl": 300},
        {"name": "web", "type": "CNAME", "value": "bücher.example.net."},
        {"name": "@", "type": "CAA", "value": '0 Issue "letsencrypt.org"'},
        {"name": "@", "type": "URI", "value": '10 1 "https://Example.COM:443/a"'},
        {"name": "@", "type": "URI", "value": '10 2 "https://Other.test"'},
        {"name": "@", "type": "MX", "value": "mail.example.com.", "priority": 10},
    ],
)
REVERSE = _z(
    "0.0.10.in-addr.arpa.",
    [
        {"name": "1", "type": "PTR", "value": "www.example.com."},
        {"name": "2", "type": "PTR", "value": "www.example.com."},
    ],
)


def test_second_structural_pass_writes_nothing(tmp_path: Path) -> None:
    fake = FakeTechnitium(["example.com", "0.0.10.in-addr.arpa"])
    d = _driver(tmp_path, fake)
    payload = _payload(d, tmp_path, [FORWARD, REVERSE])

    d._reconcile_zones("tok-1", payload)
    assert fake.writes, "first pass must create the records"
    first = len(fake.writes)

    d._reconcile_zones("tok-1", payload)
    assert fake.writes[first:] == [], "unchanged bundle must issue zero writes"
    # The mixed TTL set is stored at its minimum, as the op path does.
    ttls = {r["ttl"] for r in fake.zones["example.com"] if r["type"] == "A"}
    assert ttls == {300}


def test_ptr_survives_an_a_record_change(tmp_path: Path) -> None:
    fake = FakeTechnitium(["example.com", "0.0.10.in-addr.arpa"])
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, tmp_path, [FORWARD, REVERSE]))

    # Re-address one A record: the delete of 10.0.0.2 takes its PTR with it.
    changed = _z(
        "example.com.",
        [
            r if r["value"] != "10.0.0.2" else {**r, "value": "10.0.0.9"}
            for r in FORWARD["records"]
        ],
    )
    # Reverse zone listed FIRST in the bundle: it must still be reconciled last.
    d._reconcile_zones("tok-1", _payload(d, tmp_path, [REVERSE, changed]))

    ptrs = {
        (r["name"], r["rdata"]["ptrName"])
        for r in fake.zones["0.0.10.in-addr.arpa"]
        if r["type"] == "PTR"
    }
    assert ("1.0.0.10.in-addr.arpa", "www.example.com") in ptrs
    assert ("2.0.0.10.in-addr.arpa", "www.example.com") in ptrs


def test_ttl_only_change_is_an_update_and_keeps_the_ptr(tmp_path: Path) -> None:
    fake = FakeTechnitium(["example.com", "0.0.10.in-addr.arpa"])
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, tmp_path, [FORWARD, REVERSE]))
    n = len(fake.writes)

    faster = _z(
        "example.com.",
        [{**r, "ttl": 60} if r["type"] == "A" else r for r in FORWARD["records"]],
    )
    d._reconcile_zones("tok-1", _payload(d, tmp_path, [faster, REVERSE]))

    new = fake.writes[n:]
    assert new and all(p == "zones/records/update" for p, _ in new)
    assert {r["ttl"] for r in fake.zones["example.com"] if r["type"] == "A"} == {60}
    assert (
        len([r for r in fake.zones["0.0.10.in-addr.arpa"] if r["type"] == "PTR"]) == 2
    )
    # Technitium rewrites the whole set's TTL on the first update, so the
    # set has converged: the next pass writes nothing.
    n = len(fake.writes)
    d._reconcile_zones("tok-1", _payload(d, tmp_path, [faster, REVERSE]))
    assert fake.writes[n:] == []


def test_record_disabled_in_the_console_is_re_enabled(tmp_path: Path) -> None:
    fake = FakeTechnitium(["example.com"])
    d = _driver(tmp_path, fake)
    payload = _payload(d, tmp_path, [FORWARD])
    d._reconcile_zones("tok-1", payload)
    victim = next(r for r in fake.zones["example.com"] if r["type"] == "MX")
    victim["disabled"] = True
    n = len(fake.writes)

    d._reconcile_zones("tok-1", payload)

    assert [p for p, _ in fake.writes[n:]] == ["zones/records/update"]
    assert [r["disabled"] for r in fake.zones["example.com"] if r["type"] == "MX"] == [
        False
    ]


def test_render_stamps_min_ttl_per_rrset_for_technitium_only(tmp_path: Path) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    payload = _payload(d, tmp_path, [FORWARD])
    a = {r["ttl"] for r in payload[0]["records"] if r["type"] == "A"}
    assert a == {300}
    # A different RRset keeps its own TTL.
    mx = [r for r in payload[0]["records"] if r["type"] == "MX"]
    assert mx[0]["ttl"] == 3600


def test_apex_ns_ttl_is_carried_and_converges(tmp_path: Path) -> None:
    from spatium_dns_agent.drivers.technitium import _zone_apex

    zone = _z(
        "example.com.",
        [
            {"name": "@", "type": "NS", "value": "ns1.example.com.", "ttl": 86400},
            {"name": "@", "type": "NS", "value": "ns2.example.com.", "ttl": 7200},
        ],
    )
    apex = _zone_apex("example.com", zone)
    assert apex is not None and apex["ns_ttl"] == 7200

    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    calls = _install_fake_request(
        d,
        lambda path, params, n: (
            {
                "status": "ok",
                "response": {
                    "records": [
                        {
                            "name": "example.com",
                            "type": "NS",
                            "ttl": 3600,
                            "rData": {"nameServer": "ns1.example.com"},
                        },
                        {
                            "name": "example.com",
                            "type": "NS",
                            "ttl": 3600,
                            "rData": {"nameServer": "ns2.example.com"},
                        },
                    ]
                },
            }
            if path == "zones/records/get"
            else {"status": "ok"}
        ),
    )
    d._reconcile_zone_apex("tok-1", "example.com", apex)
    upd = [c[3] for c in calls if c[2] == "zones/records/update"]
    assert {u["nameServer"] for u in upd} == {"ns1.example.com", "ns2.example.com"}
    assert all(u["ttl"] == 7200 for u in upd)
    assert not [
        c for c in calls if c[2] in ("zones/records/add", "zones/records/delete")
    ]


def test_equivalent_uri_spellings_do_not_churn(tmp_path: Path) -> None:
    from spatium_dns_agent.drivers.technitium import _normalize_uri

    # Percent-escapes of unreserved characters decode and the rest
    # upper-case (RFC 3986 6.2.2), as System.Uri reads them back.
    assert _normalize_uri("https://x.test/%41%2f") == _normalize_uri(
        "https://x.test/A%2F"
    )
    assert (
        _normalize_uri("HTTP://X.test:80/a/./b/../c?q=a%7e") == "http://x.test/a/c?q=a~"
    )
    # A path's trailing slash stays significant.
    assert _normalize_uri("https://x.test/a/") != _normalize_uri("https://x.test/a")


class _ZoneTypedFake(FakeTechnitium):
    """FakeTechnitium plus what the full per-zone pass touches before the
    record diff: ``zones/create`` of an existing zone ("Zone already exists"),
    ``zones/options/get`` (type, #1457), ``zones/options/set`` and a
    Forwarder's apex FWD records (#1764), kept as Technitium keeps them."""

    def __init__(self, zones: dict[str, str]) -> None:
        super().__init__(list(zones))
        self.types = dict(zones)
        self.option_sets: list[dict[str, Any]] = []

    def _fwd(self, zone: str, p: dict[str, Any]) -> dict[str, Any] | None:
        for r in self.zones[zone]:
            d = r["rdata"]
            if (
                r["type"] == "FWD"
                and d["protocol"] == p.get("protocol", "Udp")
                and d["forwarder"].lower() == str(p["forwarder"]).lower()
            ):
                return r
        return None

    def _fwd_record(self, zone: str, p: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": zone,
            "type": "FWD",
            "ttl": 0,
            "disabled": False,
            "rdata": {
                "protocol": p.get("protocol", "Udp"),
                "forwarder": p["forwarder"],
                "priority": int(p.get("forwarderPriority", 0)),
                "dnssecValidation": p.get("dnssecValidation") == "true",
            },
        }

    def respond(self, path: str, params: dict[str, Any], _n: int) -> dict[str, Any]:
        zone = params.get("zone")
        if path == "zones/create":
            if zone in self.zones:
                return {"status": "error", "errorMessage": f"Zone already exists: {zone}"}
            self.writes.append((path, dict(params)))
            self.zones[zone] = []
            self.types[zone] = params["type"]
            if params["type"] == "Forwarder":
                self.zones[zone].append(self._fwd_record(zone, params))
            return {"status": "ok"}
        if path == "zones/options/get":
            return {"status": "ok", "response": {"name": zone, "type": self.types[zone]}}
        if path == "zones/options/set":
            self.option_sets.append(dict(params))
            return {"status": "ok"}
        if path.startswith("zones/records/") and params.get("type") == "FWD":
            self.writes.append((path, dict(params)))
            have = self._fwd(zone, params)
            if path == "zones/records/add":
                if have is not None:
                    return {
                        "status": "error",
                        "errorMessage": "Cannot add record: record already exists.",
                    }
                self.zones[zone].append(self._fwd_record(zone, params))
            elif have is None:
                return {
                    "status": "error",
                    "errorMessage": "Cannot delete record: no such record exists.",
                }
            elif path == "zones/records/delete":
                self.zones[zone].remove(have)
            else:
                have["rdata"].update(self._fwd_record(zone, params)["rdata"])
            return {"status": "ok"}
        return super().respond(path, params, _n)


def test_second_full_pass_over_every_zone_type_writes_no_records(tmp_path: Path) -> None:
    """The zero-writes property through the whole per-zone pass, not just
    the record diff: zone create/type check (#1457), a Forwarder's upstream
    reconcile (#1764) and a Secondary's upstream + TSIG (#1765) issue no
    record or zone write on a second pass over an unchanged bundle."""
    fake = _ZoneTypedFake({"example.com": "Primary", "0.0.10.in-addr.arpa": "Primary"})
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    _install_fake_request(d, fake.respond)
    d._reconcile_zone_apex = lambda *_a, **_k: None  # type: ignore[method-assign]
    zones = [
        FORWARD,
        REVERSE,
        {
            "name": "fwd.test.",
            "type": "forward",
            "forwarders": ["https://dns.quad9.net/dns-query", "9.9.9.9"],
            "records": [],
        },
        {
            "name": "sec.test.",
            "type": "secondary",
            "masters": ["192.0.2.1"],
            "records": [],
        },
    ]
    payload = _payload(d, tmp_path, zones)

    d._reconcile_zones("tok-1", payload)
    assert fake.writes, "first pass must create zones and records"
    assert len([r for r in fake.zones["fwd.test"] if r["type"] == "FWD"]) == 2
    first, first_opts = len(fake.writes), len(fake.option_sets)

    d._reconcile_zones("tok-1", payload)
    assert fake.writes[first:] == [], "unchanged bundle must issue zero writes"
    # ``zones/options/set`` (zone options, a Secondary's primaries + TSIG
    # key) is re-sent each pass: an idempotent set, as on main. It must at
    # least be the same set every time, never a drifting one.
    second = fake.option_sets[first_opts:]
    d._reconcile_zones("tok-1", payload)
    assert fake.option_sets[first_opts + len(second) :] == second
    assert {"zone": "sec.test", "primaryNameServerAddresses": "192.0.2.1",
            "primaryZoneTransferTsigKeyName": ""} in second
