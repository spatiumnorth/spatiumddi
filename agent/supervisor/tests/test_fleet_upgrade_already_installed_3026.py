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
    monkeypatch.setattr(
        appliance_state, "_SLOT_UPGRADE_PROGRESS", tmp_path / "progress"
    )
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


def test_a_newer_nightly_still_fires(
    trigger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, NIGHTLY)
    assert appliance_state.maybe_fire_fleet_upgrade("nightly-2026.10.29", URL) is True
    assert trigger.exists()


def test_release_tag_equal_to_installed_does_not_fire(
    trigger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, "2026.10.03-1")
    assert appliance_state.maybe_fire_fleet_upgrade("2026.10.03-1", URL) is False
    assert not trigger.exists()


def test_a_different_release_still_fires(
    trigger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _installed(monkeypatch, "2026.10.03-1")
    assert appliance_state.maybe_fire_fleet_upgrade("2026.10.04-1", URL) is True


# Kept identical to CASES in backend/tests/test_nightly_upgrade_cleared_3026.py,
# which also runs this module's copy over its list.
CASES: list[tuple[str | None, str | None, bool]] = [
    # A nightly tag names a night: any build of that night is it.
    (NIGHTLY, "nightly-2026.10.28", True),
    (NIGHTLY, "nightly-20261028", True),
    (NIGHTLY, "0.0.0-nightly-20261028", True),
    (NIGHTLY, " nightly-2026.10.28 ", True),
    ("0.0.0-nightly-20261028", "nightly-2026.10.28", True),
    # A full nightly version names one build: only that build is it.
    (NIGHTLY, NIGHTLY, True),
    (NIGHTLY, "0.0.0-nightly-20261028+deadbee", False),
    (NIGHTLY, "nightly-2026.10.27", False),
    (NIGHTLY, "nightly-2026.10.29", False),
    ("0.0.0-nightly-20261018+4be23dc", "nightly-2026.10.28", False),
    # Not real dates, and malformed tags, never match.
    ("0.0.0-nightly-20261399+623cc9f", "nightly-2026.13.99", False),
    (NIGHTLY, "nightly-2026.10.28-1", False),
    (NIGHTLY, "nightly-2026-10-28", False),
    (NIGHTLY, "nightly", False),
    # Releases: tag == version.
    ("2026.10.03-1", "2026.10.03-1", True),
    ("2026.10.03-1", "2026.10.03-2", False),
    ("1.0.0", "1.0.0", True),
    ("1.0.0", "1.0.1", False),
    ("1.0.0-rc.1", "1.0.0", False),
    # A release tag never matches a nightly, and unknowns never match.
    (NIGHTLY, "2026.10.28-1", False),
    ("2026.10.28-1", "nightly-2026.10.28", False),
    ("dev", "nightly-2026.10.28", False),
    ("nightly-2026.10.28", "nightly-2026.10.28", True),
    (None, "nightly-2026.10.28", False),
    (NIGHTLY, None, False),
    (NIGHTLY, "", False),
    ("", "", False),
]


@pytest.mark.parametrize(("installed", "target", "expected"), CASES)
def test_installed_is_target(
    installed: str | None, target: str | None, expected: bool
) -> None:
    assert appliance_state.installed_is_target(installed, target) is expected


def test_a_trial_boot_of_the_target_does_not_fire(
    trigger: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a trial boot the booted slot IS the target and the durable default
    is still the old slot — the inactive slot is the only way back, so
    writing it would destroy the rollback before firstboot even commits."""
    _installed(monkeypatch, NIGHTLY)
    assert appliance_state.maybe_fire_fleet_upgrade("nightly-2026.10.28", URL) is False
    assert not trigger.exists()


def test_a_retry_after_a_failed_write_still_fires(
    trigger: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed apply leaves the node on the old slot: a fresh Apply (new
    nonce) of the same nightly target must fire, the guard is not in its way."""
    _installed(monkeypatch, "0.0.0-nightly-20261018+4be23dc")
    (tmp_path / "fired").write_text(URL + "\n", encoding="utf-8")
    assert appliance_state.maybe_fire_fleet_upgrade("nightly-2026.10.28", URL) is False
    assert (
        appliance_state.maybe_fire_fleet_upgrade(
            "nightly-2026.10.28", "https://cp.local/x.raw.xz#n2"
        )
        is True
    )


def test_shared_chart_hold_recognises_a_node_on_the_nightly_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1710's hold, for a nightly rolling upgrade: the run's target is the
    release tag, the node reports the slot version. A string compare let a
    node already on the target write the shared chart mid-roll."""
    from spatium_supervisor import service_lifecycle

    _installed(monkeypatch, NIGHTLY)
    hold = {
        "run_id": "r",
        "from_tag": "nightly-20261018",
        "target_version": "nightly-2026.10.28",
    }
    assert service_lifecycle.shared_chart_hold_refusal(hold) is not None
    _installed(monkeypatch, "0.0.0-nightly-20261018+4be23dc")
    assert service_lifecycle.shared_chart_hold_refusal(hold) is None
