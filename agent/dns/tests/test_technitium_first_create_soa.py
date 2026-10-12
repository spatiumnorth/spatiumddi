"""A Technitium zone is never served under the daemon's default SOA (#1758).

``zones/create`` takes no SOA, so a new Primary answers with Technitium's
default (``hostadmin@<zone>``, 900 s minimum = negative-cache TTL) until the
zone's own SOA lands. On a group move that window was 8-11 s and a resolver
could cache an NXDOMAIN from it for 15 minutes. The fix creates the zone,
disables it (``zones/disable``; ``AuthZoneManager`` skips a zone whose
``IsActive`` is false when answering, 15.4.0) and enables it only once the
apex is reconciled.

The fake daemon checks the invariant after EVERY request: a zone that is
enabled must not carry the default SOA.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import TechnitiumDriver

from .test_technitium_reconcile_churn import FORWARD, REVERSE, _payload, _ZoneTypedFake
from .test_technitium_render import _install_fake_request, _seed_token

DEFAULT_MINIMUM = 900


class _SoaFake(_ZoneTypedFake):
    def __init__(self, zones: dict[str, str]) -> None:
        super().__init__(zones)
        self.enabled: dict[str, bool] = {z: True for z in zones}
        self.soa: dict[str, dict[str, Any]] = {z: self._default_soa(z) for z in zones}
        self.ns: dict[str, list[str]] = {z: ["pod-1.local"] for z in zones}
        self.soa_ttl: dict[str, int] = {z: 900 for z in zones}
        self.violations: list[str] = []
        self.toggles: list[tuple[str, str]] = []

    @staticmethod
    def _default_soa(zone: str) -> dict[str, Any]:
        return {
            "primaryNameServer": "pod-1.local",
            "responsiblePerson": f"hostadmin.{zone}",
            "serial": 1,
            "refresh": 900,
            "retry": 300,
            "expire": 604800,
            "minimum": DEFAULT_MINIMUM,
        }

    def respond(self, path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        out = self._respond(path, params, n)
        if path == "zones/create":
            # The one request-sized gap left: create is followed at once by
            # disable, with nothing between them. Every later request must
            # find the zone disabled or carrying its own SOA.
            return out
        for zone, on in self.enabled.items():
            if on and zone in self.soa and self.soa[zone]["minimum"] == DEFAULT_MINIMUM:
                self.violations.append(f"{zone} served under default SOA after {path}")
        return out

    def _respond(self, path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        zone = params.get("zone")
        if path == "zones/create" and zone not in self.zones:
            out = super().respond(path, params, n)
            self.enabled[zone] = True
            self.soa[zone] = self._default_soa(zone)
            self.ns[zone] = ["pod-1.local"]
            self.soa_ttl[zone] = 900
            return out
        if path in ("zones/enable", "zones/disable"):
            self.toggles.append((path, zone))
            self.enabled[zone] = path == "zones/enable"
            return {"status": "ok"}
        if path == "zones/records/get" and zone in self.soa:
            base = super().respond(path, params, n)
            apex = zone
            extra = [
                {
                    "name": apex,
                    "type": "SOA",
                    "ttl": self.soa_ttl[zone],
                    "rData": dict(self.soa[zone]),
                },
                *[
                    {
                        "name": apex,
                        "type": "NS",
                        "ttl": 3600,
                        "rData": {"nameServer": t},
                    }
                    for t in self.ns[zone]
                ],
            ]
            base["response"]["records"] = extra + base["response"]["records"]
            return base
        if path.startswith("zones/records/") and params.get("type") == "SOA":
            self.writes.append((path, dict(params)))
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


def test_new_zone_is_never_enabled_under_the_default_soa(tmp_path: Path) -> None:
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d, tmp_path, _zones())

    d._reconcile_zones("tok-1", payload)

    assert fake.violations == []
    assert fake.enabled == {"example.com": True, "0.0.10.in-addr.arpa": True}
    assert fake.soa["example.com"]["minimum"] == 300
    # Disabled straight after the create, enabled at the end, once each.
    assert fake.toggles.count(("zones/disable", "example.com")) == 1
    assert fake.toggles.count(("zones/enable", "example.com")) == 1
    assert fake.toggles.index(("zones/disable", "example.com")) < fake.toggles.index(
        ("zones/enable", "example.com")
    )
    assert not (tmp_path / "zones-held-disabled.json").exists()


def test_second_pass_writes_nothing_and_never_toggles(tmp_path: Path) -> None:
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d, tmp_path, _zones())
    d._reconcile_zones("tok-1", payload)
    first_writes, first_toggles = len(fake.writes), len(fake.toggles)

    d._reconcile_zones("tok-1", payload)

    assert fake.writes[first_writes:] == []
    assert fake.toggles[first_toggles:] == []
    assert fake.violations == []


def test_existing_zone_is_never_disabled(tmp_path: Path) -> None:
    fake = _SoaFake({"example.com": "Primary", "0.0.10.in-addr.arpa": "Primary"})
    for z in fake.soa:
        fake.soa[z]["minimum"] = 300
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, tmp_path, _zones()))
    assert fake.toggles == []


def test_zone_left_disabled_by_a_killed_pass_is_enabled_next_pass(
    tmp_path: Path,
) -> None:
    fake = _SoaFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d, tmp_path, _zones())

    def boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("agent killed")

    d._reconcile_zone_apex = boom  # type: ignore[method-assign]
    # The enable sits in a finally, so even a failed pass re-enables; to
    # model a hard kill, make the enable itself fail the first time.
    real = d._set_zone_enabled
    d._set_zone_enabled = (  # type: ignore[method-assign]
        lambda t, z, on: False if on else real(t, z, on)
    )
    try:
        d._reconcile_zones("tok-1", payload)
    except RuntimeError:
        pass
    assert fake.enabled["example.com"] is False
    assert "example.com" in d._load_held_zones()

    d2 = _driver(tmp_path, fake)
    d2._reconcile_zones("tok-1", payload)
    assert fake.enabled["example.com"] is True
    assert fake.soa["example.com"]["minimum"] == 300
    assert d2._load_held_zones() == set()
