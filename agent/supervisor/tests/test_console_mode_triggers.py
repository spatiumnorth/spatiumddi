"""Supervisor console-mode trigger writer (#393).

``maybe_fire_console_mode`` maps platform_settings.console_mode →
the grubenv ``spatium_verbose`` numeric the host runner + grub.cfg
consume (dashboard→0 / text_console→1 / verbose_dashboard→2), and
writes the verbose-boot trigger only on a real change (idempotent via
the applied sidecar). Replaces the pre-#393 boolean verbose_boot path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture
def cm_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    monkeypatch.setattr(
        appliance_state, "_VERBOSE_TRIGGER_FILE", tmp_path / "verbose-boot-pending"
    )
    monkeypatch.setattr(
        appliance_state, "_VERBOSE_APPLIED_FILE", tmp_path / "verbose-boot-applied"
    )
    return tmp_path


def _trigger(p: Path) -> str:
    return (p / "verbose-boot-pending").read_text().strip()


def test_text_console_maps_to_1(cm_paths: Path) -> None:
    assert appliance_state.maybe_fire_console_mode("text_console") is True
    assert _trigger(cm_paths) == "1"


def test_verbose_dashboard_maps_to_2(cm_paths: Path) -> None:
    assert appliance_state.maybe_fire_console_mode("verbose_dashboard") is True
    assert _trigger(cm_paths) == "2"


def test_dashboard_is_default_no_fire_from_fresh(cm_paths: Path) -> None:
    # Fresh box: applied sidecar missing → treated as "0"; dashboard → "0",
    # so there's nothing to change.
    assert appliance_state.maybe_fire_console_mode("dashboard") is False
    assert not (cm_paths / "verbose-boot-pending").exists()


def test_unknown_mode_falls_back_to_dashboard(cm_paths: Path) -> None:
    # Fail-closed: an unknown / None mode maps to "0" (dashboard).
    assert appliance_state.maybe_fire_console_mode("bogus") is False
    assert appliance_state.maybe_fire_console_mode(None) is False


def test_idempotent_against_applied_sidecar(cm_paths: Path) -> None:
    (cm_paths / "verbose-boot-applied").write_text("1\n")
    # Already applied text_console (1) → no re-fire.
    assert appliance_state.maybe_fire_console_mode("text_console") is False
    assert not (cm_paths / "verbose-boot-pending").exists()
    # But switching to verbose_dashboard (2) fires.
    assert appliance_state.maybe_fire_console_mode("verbose_dashboard") is True
    assert _trigger(cm_paths) == "2"


def test_non_appliance_no_op(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    monkeypatch.setattr(
        appliance_state, "_VERBOSE_TRIGGER_FILE", tmp_path / "verbose-boot-pending"
    )
    assert appliance_state.maybe_fire_console_mode("text_console") is False
    assert not (tmp_path / "verbose-boot-pending").exists()


# ── #882 audit: the plane now rides the shared bounded-retry guard ────────
#
# Pre-#882 this writer bypassed ``_fire_host_config`` entirely, so it had
# none of the #387 protections. A runner that could not apply left the
# applied sidecar unchanged, and the next heartbeat rewrote the trigger —
# whose rename re-fires the .path unit — so a failing console-mode apply
# repeated every ~30 s forever, with nothing reported upward.


@pytest.fixture
def guarded(cm_paths: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``cm_paths`` plus the plane registered for health reporting."""
    monkeypatch.setattr(
        appliance_state,
        "_HOST_CONFIG_PLANES",
        [
            (
                "console_mode",
                cm_paths / "verbose-boot-pending",
                cm_paths / "verbose-boot-applied",
            )
        ],
    )
    return cm_paths


def test_does_not_stack_a_second_trigger(guarded: Path) -> None:
    """An unconsumed trigger means the runner has not run yet."""
    assert appliance_state.maybe_fire_console_mode("text_console") is True
    # The trigger is still sitting there — do not rewrite it. The rewrite is
    # what re-fired the .path unit on every heartbeat.
    assert appliance_state.maybe_fire_console_mode("text_console") is False


def test_failing_apply_backs_off_instead_of_flooding(guarded: Path) -> None:
    """Simulate the runner failing: it consumes the trigger but never
    updates the applied sidecar."""
    fires = 0
    for _ in range(10):
        if appliance_state.maybe_fire_console_mode("text_console"):
            fires += 1
            (guarded / "verbose-boot-pending").unlink()  # runner consumed it
    # Without the guard this fired 10/10. With it, the backoff window means
    # only the first attempt goes out within the same instant.
    assert fires == 1


def test_failing_apply_is_reported_on_the_heartbeat(guarded: Path) -> None:
    assert appliance_state.maybe_fire_console_mode("text_console") is True
    (guarded / "verbose-boot-pending").unlink()  # runner ran and failed
    health = appliance_state.read_host_config_health()
    assert "console_mode" in health
    assert health["console_mode"]["state"] in ("retrying", "failing")


def test_successful_apply_clears_the_health_entry(guarded: Path) -> None:
    assert appliance_state.maybe_fire_console_mode("text_console") is True
    (guarded / "verbose-boot-pending").unlink()
    (guarded / "verbose-boot-applied").write_text("1\n")  # runner succeeded
    assert appliance_state.read_host_config_health() == {}


def test_reverting_after_a_failed_apply_clears_the_health_entry(guarded: Path) -> None:
    """(#2053) text_console fails on a fresh box; the operator goes back to
    dashboard, which the box already runs. Nothing fires again for "1", so
    its ledger must not leave the plane 'retrying' forever."""
    assert appliance_state.maybe_fire_console_mode("text_console") is True
    (guarded / "verbose-boot-pending").unlink()  # runner ran and failed
    assert "console_mode" in appliance_state.read_host_config_health()
    assert appliance_state.maybe_fire_console_mode("dashboard") is False
    assert appliance_state.read_host_config_health() == {}
