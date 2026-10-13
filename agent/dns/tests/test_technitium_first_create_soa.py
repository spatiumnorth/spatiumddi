"""A Technitium zone never answers under the daemon's default SOA (#1758).

``zones/create`` takes no SOA, so a new Primary answers with Technitium's
default (``hostadmin@<zone>``, TTL and minimum 900 s, the negative-cache
TTL) until the zone's own SOA lands. On a group move that window was 8-11 s
and a resolver could cache an NXDOMAIN from it for 15 minutes.

The fix HOLDS the zone straight after the create: ``queryAccess=Deny``,
which ``AuthZoneManager.QueryAsync`` answers with REFUSED (15.4.0), and
restores the bundle's query access once records and apex are reconciled.
It deliberately does not ``zones/disable``: a disabled zone is not
authoritative, so on a resolving group the query RECURSES (to the root's
NXDOMAIN for an internal TLD, or a public zone's public answers), which is
cached far longer than the 900 s being fixed.

The fake daemon checks the invariant after EVERY request: a Primary that
answers queries must not carry the default SOA, and no zone is ever disabled.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.technitium import _HELD_ZONES_FILE, TechnitiumDriver

from .test_technitium_reconcile_churn import FORWARD, REVERSE, _ZoneTypedFake
from .test_technitium_render import _install_fake_request, _seed_token

DEFAULT_MINIMUM = 900


class _SoaFake(_ZoneTypedFake):
    def __init__(self, zones: dict[str, str]) -> None:
        super().__init__(zones)
        self.access: dict[str, str] = {z: "Allow" for z in zones}
        self.acl: dict[str, str] = {z: "" for z in zones}
        self.soa: dict[str, dict[str, Any]] = {z: self._default_soa(z) for z in zones}
        self.ns: dict[str, list[str]] = {z: ["pod-1.local"] for z in zones}
        self.soa_ttl: dict[str, int] = {z: 900 for z in zones}
        self.violations: list[str] = []
        self.holds: list[str] = []
        self.fail_release = 0
        self.gap = False

    @staticmethod
    def _default_soa(zone: str, rp: str | None = None) -> dict[str, Any]:
        return {
            "primaryNameServer": "pod-1.local",
            "responsiblePerson": rp or f"hostadmin.{zone}",
            "serial": 1,
            "refresh": 900,
            "retry": 300,
            "expire": 604800,
            "minimum": DEFAULT_MINIMUM,
        }

    def respond(self, path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        self.gap = False
        out = self._respond(path, params, n)
        if path == "zones/create" or self.gap:
            # The one request-sized gap left: the create (or, for a
            # converted Forwarder, the #1461 placeholder replacement) is
            # followed at once by the hold, with nothing between them.
            return out
        for zone, access in self.access.items():
            # Negative TTL = min(SOA TTL, minimum) (RFC 2308 §5). A
            # Forwarder's placeholder has TTL 0, so it is never cached.
            negative_ttl = min(self.soa_ttl[zone], self.soa[zone]["minimum"])
            if (
                self.types.get(zone) == "Primary"
                and access != "Deny"
                and negative_ttl == DEFAULT_MINIMUM
            ):
                self.violations.append(f"{zone} answered under the default SOA after {path}")
        return out

    def _respond(self, path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        zone = params.get("zone")
        if path in ("zones/disable", "zones/enable"):
            self.violations.append(f"{path} {zone}: a disabled zone recurses")
            return {"status": "ok"}
        if path == "zones/create" and zone not in self.zones:
            out = super().respond(path, params, n)
            self.access[zone] = "Allow"  # ApexZone ctor
            self.acl[zone] = ""
            self.soa[zone] = self._default_soa(zone)
            self.ns[zone] = ["pod-1.local"]
            self.soa_ttl[zone] = 900
            return out
        if path == "zones/convert":
            self.writes.append((path, dict(params)))
            self.types[zone] = params["type"]
            return {"status": "ok"}
        if path == "zones/options/set" and "queryAccess" in params:
            if params["queryAccess"] == "Deny" and set(params) == {"zone", "queryAccess"}:
                self.holds.append(zone)
            elif self.fail_release:
                self.fail_release -= 1
                self.option_sets.append(dict(params))
                return {"status": "error", "errorMessage": "boom"}
            self.access[zone] = params["queryAccess"]
            if "queryAccessNetworkACL" in params:
                self.acl[zone] = params["queryAccessNetworkACL"]
        if path == "zones/records/get" and zone in self.soa:
            base = super().respond(path, params, n)
            extra = [
                {
                    "name": zone,
                    "type": "SOA",
                    "ttl": self.soa_ttl[zone],
                    "rData": dict(self.soa[zone]),
                },
                *[
                    {"name": zone, "type": "NS", "ttl": 3600, "rData": {"nameServer": t}}
                    for t in self.ns[zone]
                ],
            ]
            base["response"]["records"] = extra + base["response"]["records"]
            return base
        if path.startswith("zones/records/") and params.get("type") == "SOA":
            self.writes.append((path, dict(params)))
            self.gap = self.soa[zone]["responsiblePerson"] == "invalid"
            for k in ("primaryNameServer", "responsiblePerson"):
                self.soa[zone][k] = params[k]
            for k in ("refresh", "retry", "expire", "minimum"):
                self.soa[zone][k] = int(params[k])
            self.soa_ttl[zone] = int(params["ttl"])
            self.soa[zone]["serial"] += 1
            return {"status": "ok"}
        if path.startswith("zones/records/") and params.get("type") == "NS":
            self.writes.append((path, dict(params)))
            target = params["nameServer"]
            if path.endswith("/add") and target not in self.ns[zone]:
                self.ns[zone].append(target)
            elif path.endswith("/delete") and target in self.ns[zone]:
                self.ns[zone].remove(target)
            return {"status": "ok"}
        return super().respond(path, params, n)


def _driver(tmp_path: Path, fake: _SoaFake) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    _install_fake_request(d, fake.respond)
    return d


def _zones() -> list[dict[str, Any]]:
    fwd = {
        **FORWARD,
        "primary_ns": "ns1.example.com.",
        "admin_email": "hostmaster@example.com",
        "minimum": 300,
    }
    rev = {**REVERSE, "primary_ns": "ns1.example.com.", "minimum": 300}
    return [fwd, rev]


def _payload(d: TechnitiumDriver, options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    d.render({"zones": _zones(), "options": options or {}})
    return json.loads((d.state_dir / "rendered.new" / "zones.json").read_text())


def _marker(tmp_path: Path) -> Path:
    return tmp_path / _HELD_ZONES_FILE


def test_new_zone_never_answers_under_the_default_soa(tmp_path: Path) -> None:
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)

    d._reconcile_zones("tok-1", _payload(d))

    assert fake.violations == []
    assert sorted(fake.holds) == ["0.0.10.in-addr.arpa", "example.com"]
    assert fake.access == {"example.com": "Allow", "0.0.10.in-addr.arpa": "Allow"}
    assert fake.soa["example.com"]["minimum"] == 300
    assert not _marker(tmp_path).exists()


def test_release_applies_the_bundles_query_access(tmp_path: Path) -> None:
    """The hold is released to the group's ``allow_query``, not to Allow,
    and the body's own options call does not release it early (the
    invariant would catch a zone answering before its SOA)."""
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)

    d._reconcile_zones("tok-1", _payload(d, {"allow_query": ["10.0.0.0/8"]}))

    assert fake.violations == []
    assert fake.access["example.com"] == "UseSpecifiedNetworkACL"
    assert fake.acl["example.com"] == "10.0.0.0/8"


def test_second_pass_writes_nothing_and_never_holds(tmp_path: Path) -> None:
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d)
    d._reconcile_zones("tok-1", payload)
    first_writes, first_holds = len(fake.writes), len(fake.holds)

    d._reconcile_zones("tok-1", payload)

    assert fake.writes[first_writes:] == []
    assert fake.holds[first_holds:] == []
    assert fake.violations == []


def test_existing_zone_is_never_held(tmp_path: Path) -> None:
    fake = _SoaFake({"example.com": "Primary", "0.0.10.in-addr.arpa": "Primary"})
    for z in fake.soa:
        fake.soa[z]["minimum"] = 300
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d))
    assert fake.holds == []
    assert fake.violations == []


def test_forwarder_converted_to_primary_is_held(tmp_path: Path) -> None:
    """#1457/#1461: ``zones/convert`` keeps the Forwarder's placeholder SOA
    (TTL 0, so uncacheable), which ``_replace_placeholder_soa`` swaps for
    Technitium's create default (900 s). From there it is the create window
    again, so the converted zone is held the same way."""
    fake = _SoaFake({"example.com": "Forwarder", "0.0.10.in-addr.arpa": "Primary"})
    fake.soa["example.com"] = fake._default_soa("example.com", rp="invalid")
    fake.soa_ttl["example.com"] = 0
    fake.soa["0.0.10.in-addr.arpa"]["minimum"] = 300
    d = _driver(tmp_path, fake)

    d._reconcile_zones("tok-1", _payload(d))

    assert fake.types["example.com"] == "Primary"
    assert fake.holds == ["example.com"]
    assert fake.violations == []
    assert fake.access["example.com"] == "Allow"
    assert fake.soa["example.com"]["minimum"] == 300


def test_failed_release_is_finished_by_the_next_pass(tmp_path: Path) -> None:
    fake = _SoaFake({})
    # Each zone's release is refused twice: its options call, then the
    # query-access-only fallback.
    fake.fail_release = 4
    d = _driver(tmp_path, fake)
    payload = _payload(d, {"allow_query": ["10.0.0.0/8"]})

    d._reconcile_zones("tok-1", payload)
    assert fake.access["example.com"] == "Deny"
    assert json.loads(_marker(tmp_path).read_text()) == ["0.0.10.in-addr.arpa", "example.com"]

    d2 = _driver(tmp_path, fake)
    d2._reconcile_zones("tok-1", payload)
    assert fake.access["example.com"] == "UseSpecifiedNetworkACL"
    assert fake.acl["example.com"] == "10.0.0.0/8"
    assert not _marker(tmp_path).exists()
    assert fake.violations == []


def test_killed_pass_is_released_by_the_next_pass(tmp_path: Path) -> None:
    """The release sits in a ``finally``; a hard kill skips it. The marker,
    written before the body runs, is what the next pass finishes from."""
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d)

    class Killed(BaseException):
        pass

    def kill(*_a: Any, **_k: Any) -> None:
        raise Killed

    d._reconcile_zone_apex = kill  # type: ignore[method-assign]
    d._release_zone = kill  # type: ignore[method-assign]
    # The agent dies mid-pass, after the hold and before the release.
    with pytest.raises(Killed):
        d._reconcile_zones("tok-1", payload)
    assert fake.access["example.com"] == "Deny"
    assert d._load_held_zones() == {"example.com"}

    d2 = _driver(tmp_path, fake)
    d2._reconcile_zones("tok-1", payload)
    assert fake.access["example.com"] == "Allow"
    assert fake.soa["example.com"]["minimum"] == 300
    assert d2._load_held_zones() == set()
    assert fake.violations == []


def test_marker_is_tolerant_and_scoped_to_the_bundle(tmp_path: Path) -> None:
    """A corrupt marker is ignored, and a marker naming a zone the bundle
    no longer carries touches nothing on the daemon."""
    fake = _SoaFake({"example.com": "Primary", "0.0.10.in-addr.arpa": "Primary"})
    for z in fake.soa:
        fake.soa[z]["minimum"] = 300
    d = _driver(tmp_path, fake)
    payload = _payload(d)

    for junk in ("{not json", '"example.com"', '{"example.com": 1}', "42"):
        _marker(tmp_path).write_text(junk)
        assert d._load_held_zones() == set()
        d._reconcile_zones("tok-1", payload)

    _marker(tmp_path).write_text(json.dumps(["gone.test"]))
    d._reconcile_zones("tok-1", payload)
    assert all(o.get("zone") != "gone.test" for o in fake.option_sets)
    assert not _marker(tmp_path).exists()
    assert fake.holds == []
    assert fake.violations == []
