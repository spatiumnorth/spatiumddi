"""#2007 — a staged upgrade the node has rebooted past stops reading
``done`` / ``reboot-pending``.

Asserts on the settled state AND the sidecars, and on every case that must
NOT settle. "Rebooted" is the kernel boot_id the runner recorded, never a
clock; a node that came back on the slot it did not stage is a rollback and
reads ``failed``, not ``ready``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st

NOW = datetime.now(UTC)
STAGED_BOOT = "11111111-2222-3333-4444-555555555555"
OTHER_BOOT = "99999999-8888-7777-6666-555555555555"


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "slot-upgrade-pending.state"
    progress = tmp_path / "slot-upgrade.progress"
    grubenv = tmp_path / "grubenv"
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", state)
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", progress)
    monkeypatch.setattr(st, "_HOST_GRUBENV", grubenv)
    monkeypatch.setattr(st, "_TRIGGER_FILE", tmp_path / "slot-upgrade-pending")
    monkeypatch.setattr(st, "read_boot_id", lambda: OTHER_BOOT)
    state.write_text(f"done {NOW.isoformat()}\n")
    return {"state": state, "progress": progress, "grubenv": grubenv, "dir": tmp_path}


def _stage(paths: dict[str, Path], **extra: object) -> None:
    body = {"step": "reboot-pending", "at": NOW.isoformat(), **extra}
    paths["progress"].write_text(json.dumps(body))


def _settle(current: str | None, trial: bool | None) -> str | None:
    return st._settle_staged_upgrade("done", NOW, current, trial)[0]


def test_committed_boot_on_the_staged_slot_settles_ready(paths: dict[str, Path]) -> None:
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert _settle("slot_b", False) == "ready"
    assert paths["state"].read_text().startswith("ready ")


def test_boot_on_the_other_slot_is_a_rollback_not_a_success(paths: dict[str, Path]) -> None:
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert _settle("slot_a", False) == "failed"
    assert paths["state"].read_text().startswith("failed ")
    progress = json.loads(paths["progress"].read_text())
    assert progress["step"] == "failed"
    assert progress["reverted"] is True
    assert "rolled back" in progress["detail"]


def test_same_boot_is_still_pending_whatever_the_clock_says(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The boot that staged it: no reboot has happened, regardless of uptime
    # or how far the wall clock was stepped since the stamp.
    monkeypatch.setattr(st, "read_boot_id", lambda: STAGED_BOOT)
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert _settle("slot_a", False) == "done"
    assert paths["state"].read_text().startswith("done ")


def test_unreadable_boot_id_is_left_alone(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(st, "read_boot_id", lambda: None)
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert _settle("slot_b", False) == "done"


@pytest.mark.parametrize("trial", [True, None])
def test_trial_or_unknown_boot_is_left_alone(paths: dict[str, Path], trial: bool | None) -> None:
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert _settle("slot_b", trial) == "done"


def test_unknown_current_slot_is_left_alone(paths: dict[str, Path]) -> None:
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert _settle(None, False) == "done"


def test_a_new_trigger_owns_the_sidecars(paths: dict[str, Path]) -> None:
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    (paths["dir"] / "slot-upgrade-pending").write_text("https://x/img.raw.xz\n")
    assert _settle("slot_b", False) == "done"
    assert paths["state"].read_text().startswith("done ")


def test_legacy_runner_waits_for_grub_to_consume_next_entry(paths: dict[str, Path]) -> None:
    # A pre-#2007 runner records neither field: grubenv still arming the
    # one-shot means the reboot has not happened.
    _stage(paths)
    paths["grubenv"].write_text(
        "# GRUB Environment Block\nsaved_entry=slot_a\nnext_entry=slot_b\n####\n"
    )
    assert _settle("slot_a", False) == "done"
    paths["grubenv"].write_text("# GRUB Environment Block\nsaved_entry=slot_b\nnext_entry=\n####\n")
    assert _settle("slot_b", False) == "ready"


def test_legacy_runner_with_unreadable_grubenv_is_left_alone(paths: dict[str, Path]) -> None:
    _stage(paths)
    assert _settle("slot_b", False) == "done"


def test_other_progress_or_state_is_untouched(paths: dict[str, Path]) -> None:
    _stage(paths, staged_slot="slot_b", staged_boot_id=STAGED_BOOT)
    assert st._settle_staged_upgrade("failed", NOW, "slot_b", False)[0] == "failed"
    assert st._settle_staged_upgrade("in-flight", NOW, "slot_b", False)[0] == "in-flight"
    paths["progress"].write_text(json.dumps({"step": "arming", "staged_boot_id": STAGED_BOOT}))
    assert _settle("slot_b", False) == "done"
