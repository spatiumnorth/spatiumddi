"""A Technitium zone's serial is driven from the control plane's and read back (#1779).

Technitium owns the SOA serial: it starts at 1 on create and moves on with
every write, so two servers of one zone serve different numbers and a
re-created zone restarts at 1. A SOA update carrying a serial HIGHER than the
stored one is adopted as given, otherwise the stored one is bumped by one
(``ApexZone.GetNewSerial``, 15.4.0) — the fake daemon below does the same.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import TechnitiumDriver

from .test_technitium_first_create_soa import _SoaFake
from .test_technitium_reconcile_churn import FORWARD
from .test_technitium_render import _install_fake_request, _seed_token


class _SerialFake(_SoaFake):
    def _respond(self, path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        zone = params.get("zone")
        if path == "zones/records/get" and zone not in self.zones:
            return {"status": "error", "errorMessage": f"No such zone was found: {zone}"}
        if path.startswith("zones/records/") and params.get("type") == "SOA":
            wanted = int(params["serial"])
            stored = self.soa[zone]["serial"]
            out = super()._respond(path, params, n)
            # ``_SoaFake`` always adds one; Technitium adopts a higher serial.
            self.soa[zone]["serial"] = wanted if wanted > stored else stored + 1
            return out
        return super()._respond(path, params, n)


def _driver(tmp_path: Path, fake: _SerialFake) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    _install_fake_request(d, fake.respond)
    return d


def _zone(serial: int | None) -> dict[str, Any]:
    z = {
        **FORWARD,
        "primary_ns": "ns1.example.com.",
        "admin_email": "hostmaster@example.com",
        "minimum": 300,
    }
    if serial is not None:
        z["serial"] = serial
    return z


def _payload(d: TechnitiumDriver, serial: int | None) -> list[dict[str, Any]]:
    import json

    d.render({"zones": [_zone(serial)], "options": {}})
    return json.loads((d.state_dir / "rendered.new" / "zones.json").read_text())


def test_a_new_zone_is_created_at_the_control_planes_serial(tmp_path: Path) -> None:
    fake = _SerialFake({})
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, 50))
    assert fake.soa["example.com"]["serial"] == 50


def test_a_zone_re_created_at_one_is_raised_to_it(tmp_path: Path) -> None:
    fake = _SerialFake({"example.com": "Primary"})
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, 9000))
    assert fake.soa["example.com"]["serial"] == 9000


def test_a_zone_already_ahead_is_never_lowered_or_rewritten(tmp_path: Path) -> None:
    fake = _SerialFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d, 50)
    d._reconcile_zones("tok-1", payload)
    fake.soa["example.com"]["serial"] = 143  # records written since moved it on
    before = len(fake.writes)
    d._reconcile_zones("tok-1", payload)
    assert fake.soa["example.com"]["serial"] == 143
    assert [w for w in fake.writes[before:] if w[1].get("type") == "SOA"] == []


def test_no_serial_in_the_bundle_leaves_the_daemons_alone(tmp_path: Path) -> None:
    """An older control plane ships none: nothing is driven."""
    fake = _SerialFake({"example.com": "Primary"})
    for k in ("primaryNameServer",):
        fake.soa["example.com"][k] = "ns1.example.com"
    fake.soa["example.com"].update(
        responsiblePerson="hostmaster@example.com", minimum=300, serial=77
    )
    fake.soa_ttl["example.com"] = FORWARD.get("ttl", 3600)
    d = _driver(tmp_path, fake)
    d._reconcile_zones("tok-1", _payload(d, None))
    assert fake.soa["example.com"]["serial"] == 77


def test_the_reported_serial_is_what_the_daemon_serves(tmp_path: Path) -> None:
    fake = _SerialFake({"example.com": "Primary"})
    fake.soa["example.com"]["serial"] = 143
    d = _driver(tmp_path, fake)
    bundle = {"zones": [{"name": "example.com.", "serial": 50}]}
    assert d.served_zone_serials(bundle) == {"example.com": 143}


def test_a_zone_the_daemon_lacks_is_not_reported(tmp_path: Path) -> None:
    """A skipped or refused-at-create zone must not read as converged."""
    fake = _SerialFake({"example.com": "Primary"})
    d = _driver(tmp_path, fake)
    bundle = {
        "zones": [
            {"name": "example.com.", "serial": 50},
            {"name": "never-created.example.org.", "serial": 50},
        ]
    }
    assert d.served_zone_serials(bundle) == {"example.com": 1}


def test_the_between_changes_read_follows_the_rendered_zones(tmp_path: Path) -> None:
    fake = _SerialFake({})
    d = _driver(tmp_path, fake)
    payload = _payload(d, 50)
    d._reconcile_zones("tok-1", payload)
    (tmp_path / "rendered").mkdir(exist_ok=True)
    (tmp_path / "rendered.new" / "zones.json").rename(tmp_path / "rendered" / "zones.json")
    fake.soa["example.com"]["serial"] = 61
    assert d.periodic_served_serials() == {"example.com": 61}
