"""A target the booted slot already is is never fired (#3026).

The slot write goes to the inactive slot, the only rollback. A nightly's
release tag (``nightly-YYYY.MM.DD``) never equalled the slot's version
(``0.0.0-nightly-YYYYMMDD+<sha>``), so a finished upgrade was fired again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state

NIGHTLY = "0.0.0-nightly-20261028+623cc9f"
URL = "https://cp.local/x.raw.xz#n1"


@pytest.fixture
def trigger(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    t = tmp_path / "slot-upgrade-pending"
    monkeypatch.setattr(appliance_state, "_TRIGGER_FILE", t)
    monkeypatch.setattr(appliance_state, "_FIRED_URL_MARKER", tmp_path / "fired")
    monkeypatch.setattr(appliance_state, "_HOST_SLOT_STATE", tmp_path / "state")
    monkeypatch.setattr(appliance_state, "_SLOT_UPGRADE_PROGRESS", tmp_path / "progress")
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    return t


def _installed(monkeypatch: pytest.MonkeyPatch, version: str) -> None:
    monkeypatch.setattr(appliance_state, "read_installed_version", lambda: version)


def test_nightly_tag_for_the_booted_nightly_does_not_fire(
    trigger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, NIGHTLY)
    assert appliance_state.maybe_fire_fleet_upgrade("nightly-2026.10.28", URL) is False
    assert not trigger.exists()


def test_a_newer_nightly_still_fires(trigger: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(monkeypatch, NIGHTLY)
    assert appliance_state.maybe_fire_fleet_upgrade("nightly-2026.10.29", URL) is True
    assert trigger.exists()


def test_release_tag_equal_to_installed_does_not_fire(
    trigger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, "2026.10.03-1")
    assert appliance_state.maybe_fire_fleet_upgrade("2026.10.03-1", URL) is False
    assert not trigger.exists()


def test_a_different_release_still_fires(trigger: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _installed(monkeypatch, "2026.10.03-1")
    assert appliance_state.maybe_fire_fleet_upgrade("2026.10.04-1", URL) is True


@pytest.mark.parametrize(
    ("installed", "target", "expected"),
    [
        (NIGHTLY, "nightly-2026.10.28", True),
        (NIGHTLY, "nightly-20261028", True),
        (NIGHTLY, "nightly-2026.10.27", False),
        ("1.0.0", "1.0.0", True),
        ("1.0.0", "1.0.1", False),
        (None, "nightly-2026.10.28", False),
    ],
)
def test_installed_is_target(installed: str | None, target: str, expected: bool) -> None:
    assert appliance_state.installed_is_target(installed, target) is expected
