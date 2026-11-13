"""A same-named zone the agent did not create is never taken over (#1775).

``zones/create`` on an existing zone answers "Zone already exists". The agent
used to treat that as its own zone: the record diff then deleted every record
the bundle did not list, and the zone entered the managed ledger so a later
retire deleted the zone itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.technitium import (
    _MANAGED_ZONES_FILE,
    _OWNER_MARKER,
    TechnitiumDriver,
)

from .test_technitium_first_create_soa import _SoaFake
from .test_technitium_render import _install_fake_request, _seed_token, _zone

FORWARD = "corp.test"


def _run(tmp_path: Path, fake: _SoaFake, ledger: list[str] | None) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    if ledger is not None:
        (tmp_path / _MANAGED_ZONES_FILE).write_text(json.dumps(ledger))
    _seed_token(d)
    d.daemon_running = lambda: True  # type: ignore[method-assign]
    d._wait_for_api_up = lambda **_: None  # type: ignore[method-assign]
    _install_fake_request(d, fake.respond)
    d.render({"zones": [_zone(FORWARD, "primary")], "options": {}, "tsig_keys": []})
    d.validate()
    d.swap_and_reload()
    return d


def _deletes(fake: _SoaFake) -> list[str]:
    return [p for p, _ in fake.writes if "delete" in p]


def _foreign() -> _SoaFake:
    fake = _SoaFake({FORWARD: "Primary"})
    fake.zones[FORWARD] = [
        {
            "name": f"keep.{FORWARD}",
            "type": "A",
            "ttl": 60,
            "disabled": False,
            "rdata": {"ipAddress": "192.0.2.77"},
        }
    ]
    return fake


def test_a_zone_the_agent_never_created_keeps_its_records(tmp_path: Path) -> None:
    fake = _foreign()
    d = _run(tmp_path, fake, ledger=[])
    assert [r["name"] for r in fake.zones[FORWARD]] == [f"keep.{FORWARD}"]
    assert not _deletes(fake)
    assert any(FORWARD in r and "did not create" in r for r in d._refused_zones)
    # ...and is not recorded as ours, or the next pass would wipe it.
    assert FORWARD not in json.loads((tmp_path / _MANAGED_ZONES_FILE).read_text())
    _run_again = _run(tmp_path, fake, ledger=None)
    assert [r["name"] for r in fake.zones[FORWARD]] == [f"keep.{FORWARD}"]
    assert _run_again._refused_zones


def test_the_adopt_flag_takes_the_zone_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TECHNITIUM_ADOPT_EXISTING_ZONES", "true")
    fake = _foreign()
    d = _run(tmp_path, fake, ledger=[])
    assert not d._refused_zones
    assert f"keep.{FORWARD}" not in [r["name"] for r in fake.zones[FORWARD]]
    assert FORWARD in json.loads((tmp_path / _MANAGED_ZONES_FILE).read_text())


def test_a_zone_in_the_ledger_is_still_reconciled(tmp_path: Path) -> None:
    fake = _foreign()
    d = _run(tmp_path, fake, ledger=[FORWARD])
    assert not d._refused_zones
    assert f"keep.{FORWARD}" not in [r["name"] for r in fake.zones[FORWARD]]


def test_a_lost_ledger_with_the_marker_is_still_ours(tmp_path: Path) -> None:
    fake = _foreign()
    fake.soa_comments[FORWARD] = _OWNER_MARKER
    d = _run(tmp_path, fake, ledger=[])  # state dir wiped: empty ledger
    assert not d._refused_zones
    assert f"keep.{FORWARD}" not in [r["name"] for r in fake.zones[FORWARD]]
    assert FORWARD in json.loads((tmp_path / _MANAGED_ZONES_FILE).read_text())
    assert fake.soa_comments[FORWARD] == _OWNER_MARKER


def test_a_zone_in_the_ledger_without_the_marker_is_stamped(tmp_path: Path) -> None:
    fake = _foreign()
    _run(tmp_path, fake, ledger=[FORWARD])
    assert fake.soa_comments[FORWARD] == _OWNER_MARKER
    stamps = [p for p, q in fake.writes if q.get("type") == "SOA"]
    _run(tmp_path, fake, ledger=None)
    # Stamped once: the second pass writes no further SOA.
    assert [p for p, q in fake.writes if q.get("type") == "SOA"] == stamps


def test_a_new_zone_is_stamped_at_creation(tmp_path: Path) -> None:
    fake = _SoaFake({})
    _run(tmp_path, fake, ledger=[])
    assert fake.soa_comments[FORWARD] == _OWNER_MARKER
