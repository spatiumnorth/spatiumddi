"""#786 — the operator-driven "make the host forget a failed upgrade" command.

The visible failure state is re-published from these host sidecars on
every heartbeat, so clearing the DB alone never worked: the next
heartbeat restored it, and rebooting didn't help because release-state
lives on the persistent /var a slot write never touches.

The passive heal (``clear_fleet_upgrade_marker``) can't cover the wedged
case either — it returns early whenever a trigger file is present, which
is exactly the state a stranded apply leaves behind, and that same guard
also blocks ``maybe_fire_fleet_upgrade``. So a box could neither clear
nor re-apply.

``apply_clear_upgrade_command`` is the explicit counterpart: the operator
asked, so the stranded trigger goes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "slot-upgrade-pending.state"
    trigger = tmp_path / "slot-upgrade-pending"
    progress = tmp_path / "slot-upgrade.progress"
    marker = tmp_path / "slot-upgrade-fired-url"
    monkeypatch.setattr(appliance_state, "_HOST_SLOT_STATE", state)
    monkeypatch.setattr(appliance_state, "_TRIGGER_FILE", trigger)
    monkeypatch.setattr(appliance_state, "_SLOT_UPGRADE_PROGRESS", progress)
    monkeypatch.setattr(appliance_state, "_FIRED_URL_MARKER", marker)
    # The command is appliance-only; every other deployment kind no-ops.
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "appliance")
    return {"state": state, "trigger": trigger, "progress": progress, "marker": marker}


def _wedged(paths: dict[str, Path]) -> None:
    """The shape a stranded failure leaves on disk."""
    paths["state"].write_text("failed 2026-08-01T00:00:00+00:00\n", encoding="utf-8")
    paths["progress"].write_text(json.dumps({"step": "failed", "pct": 40}), encoding="utf-8")
    paths["trigger"].write_text("https://cp.local/x.raw.xz\n", encoding="utf-8")
    paths["marker"].write_text("https://cp.local/x.raw.xz\n", encoding="utf-8")


def test_clear_resets_every_sidecar_and_removes_the_trigger(paths: dict[str, Path]) -> None:
    _wedged(paths)

    assert appliance_state.apply_clear_upgrade_command() is True

    assert not paths["trigger"].exists(), "a stranded trigger must be removed, not deferred to"
    assert not paths["marker"].exists()
    # Overwritten, not unlinked: release-state is sticky and this file is
    # root-owned, so a non-owner can never unlink it.
    assert paths["progress"].read_text(encoding="utf-8").strip() == "{}"
    assert paths["state"].read_text(encoding="utf-8").startswith("ready ")


def test_clear_leaves_a_live_in_flight_apply_alone(paths: dict[str, Path]) -> None:
    """Cancelling mid-apply must not stamp `ready` over `in-flight`: both
    crash detectors — the runner's exit trap and the stale-in-flight reaper
    — key on that literal, so clobbering it would let a killed `dd` leave a
    truncated image with nothing recording the failure."""
    paths["state"].write_text("in-flight 2026-08-01T00:00:00+00:00\n", encoding="utf-8")

    appliance_state.apply_clear_upgrade_command()

    assert paths["state"].read_text(encoding="utf-8").startswith("in-flight")


def test_clear_removes_the_trigger_the_passive_heal_refuses_to_touch(
    paths: dict[str, Path],
) -> None:
    """The regression this exists for: with a trigger on disk the passive
    heal returns early and the box stays wedged forever."""
    _wedged(paths)

    appliance_state.clear_fleet_upgrade_marker()
    assert paths["state"].read_text(encoding="utf-8").startswith("failed"), (
        "passive heal is expected to bail while a trigger exists"
    )

    appliance_state.apply_clear_upgrade_command()
    assert paths["state"].read_text(encoding="utf-8").startswith("ready ")


def test_clear_prunes_every_failed_sidecar(paths: dict[str, Path]) -> None:
    """#386's runaway re-fire left piles of these; an explicit clear takes
    them all, not all-but-five."""
    for ts in range(9):
        (paths["trigger"].parent / f"slot-upgrade-pending.failed.{ts}").write_text("x")

    appliance_state.apply_clear_upgrade_command()

    assert list(paths["trigger"].parent.glob("slot-upgrade-pending.failed.*")) == []


def test_clear_is_idempotent_on_an_already_clean_host(paths: dict[str, Path]) -> None:
    """Nothing to reset → False, so the heartbeat doesn't log a reset that
    didn't happen. A `ready` state file is the norm on any appliance that
    has ever applied an upgrade, so it must not by itself count as a reset."""
    paths["state"].write_text("ready 2026-08-01T00:00:00+00:00\n", encoding="utf-8")

    assert appliance_state.apply_clear_upgrade_command() is False


def test_clear_is_a_noop_off_appliance(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(appliance_state, "detect_deployment_kind", lambda: "docker")
    _wedged(paths)

    assert appliance_state.apply_clear_upgrade_command() is False
    assert paths["trigger"].exists()
    assert paths["state"].read_text(encoding="utf-8").startswith("failed")


def test_clear_reports_failure_when_the_trigger_survives(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Field-observed on ddi1: the sticky directory means a trigger the
    supervisor does not own can never be unlinked. The state/progress
    resets still succeed, so the command used to report success while the
    box stayed exactly as wedged — the trigger keeps blocking both the
    passive heal and `maybe_fire_fleet_upgrade`."""
    _wedged(paths)
    real_unlink = Path.unlink

    def _refuse_trigger(self, *a, **kw):
        if self.name == "slot-upgrade-pending":
            raise PermissionError(1, "Operation not permitted")
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", _refuse_trigger)

    assert appliance_state.apply_clear_upgrade_command() is False
    assert paths["trigger"].exists()


# --- #2021: a clear that lost the race must not blind the running apply ----


def _set_mtime(path: Path, seconds: float) -> None:
    import os

    os.utime(path, (seconds, seconds))


def test_clear_keeps_the_progress_of_an_apply_the_runner_has_claimed(
    paths: dict[str, Path],
) -> None:
    """The cancel arrived after the runner took the trigger. The apply keeps
    going, so its progress is the only thing showing what it is doing; the
    runner rewrites it only at its next step, minutes away during a dd."""
    paths["trigger"].write_text("https://cp.local/x.raw.xz\n", encoding="utf-8")
    paths["state"].write_text("in-flight 2026-10-17T04:03:08+00:00\n", encoding="utf-8")
    live = {"step": "writing", "pct": None, "detail": "writing image to root-b"}
    paths["progress"].write_text(json.dumps(live), encoding="utf-8")
    _set_mtime(paths["trigger"], 1_000)
    _set_mtime(paths["state"], 1_001)  # claimed: the runner stamped after the trigger

    appliance_state.apply_clear_upgrade_command()

    assert json.loads(paths["progress"].read_text(encoding="utf-8")) == live
    assert paths["state"].read_text(encoding="utf-8").startswith("in-flight")


def test_clear_still_resets_an_unclaimed_trigger(paths: dict[str, Path]) -> None:
    """Before the runner claims it, the clear wins: trigger gone, and the
    previous run's leftover progress is reset as before (#786)."""
    paths["state"].write_text("ready 2026-10-01T00:00:00+00:00\n", encoding="utf-8")
    paths["progress"].write_text(json.dumps({"step": "reboot-pending"}), encoding="utf-8")
    paths["trigger"].write_text("https://cp.local/x.raw.xz\n", encoding="utf-8")
    _set_mtime(paths["state"], 1_000)
    _set_mtime(paths["trigger"], 1_001)  # newer than .state: not claimed

    appliance_state.apply_clear_upgrade_command()

    assert not paths["trigger"].exists()
    assert paths["progress"].read_text(encoding="utf-8").strip() == "{}"


def test_clear_keeps_a_staged_slots_breadcrumb(paths: dict[str, Path]) -> None:
    """A clear does not disarm next-boot, and the #2007 settle keys on the
    ``reboot-pending`` progress: wiping it left the node at ``done`` forever."""
    paths["state"].write_text("done 2026-10-17T04:05:00+00:00\n", encoding="utf-8")
    staged = {"step": "reboot-pending", "staged_slot": "slot_b", "staged_boot_id": "abc"}
    paths["progress"].write_text(json.dumps(staged), encoding="utf-8")

    appliance_state.apply_clear_upgrade_command()

    assert json.loads(paths["progress"].read_text(encoding="utf-8")) == staged
