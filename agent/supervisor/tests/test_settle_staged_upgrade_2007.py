"""#2007 — a staged upgrade the node has rebooted past stops reading
``done`` / ``reboot-pending``. Asserts on the settled state and the
sidecar, and on the cases that must NOT settle."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st

NOW = datetime.now(UTC)


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "slot-upgrade-pending.state"
    progress = tmp_path / "slot-upgrade.progress"
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", state)
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", progress)
    state.write_text(f"done {NOW.isoformat()}\n")
    return {"state": state, "progress": progress}


def _stage(paths: dict[str, Path], at: datetime, step: str = "reboot-pending") -> None:
    paths["progress"].write_text(json.dumps({"step": step, "at": at.isoformat()}))


def test_committed_boot_after_staging_settles(paths: dict[str, Path]) -> None:
    _stage(paths, NOW - timedelta(hours=1))
    state, at = st._settle_staged_upgrade(
        "done", NOW, False, boot_started=NOW - timedelta(minutes=5)
    )
    assert state == "ready" and at is not None
    assert paths["state"].read_text().startswith("ready ")


def test_rollback_boot_settles_too(paths: dict[str, Path]) -> None:
    # Auto-revert: running slot == durable default again, boot is newer.
    _stage(paths, NOW - timedelta(hours=1))
    state, _ = st._settle_staged_upgrade("done", NOW, False, boot_started=NOW)
    assert state == "ready"


def test_staged_and_not_rebooted_stays_pending(paths: dict[str, Path]) -> None:
    _stage(paths, NOW)
    state, _ = st._settle_staged_upgrade("done", NOW, False, boot_started=NOW - timedelta(days=3))
    assert state == "done"
    assert paths["state"].read_text().startswith("done ")


@pytest.mark.parametrize("trial", [True, None])
def test_trial_or_unknown_boot_is_left_alone(paths: dict[str, Path], trial: bool | None) -> None:
    _stage(paths, NOW - timedelta(hours=1))
    state, _ = st._settle_staged_upgrade("done", NOW, trial, boot_started=NOW)
    assert state == "done"


def test_other_progress_or_state_is_untouched(paths: dict[str, Path]) -> None:
    _stage(paths, NOW - timedelta(hours=1), step="failed")
    assert st._settle_staged_upgrade("done", NOW, False, boot_started=NOW)[0] == "done"
    _stage(paths, NOW - timedelta(hours=1))
    assert st._settle_staged_upgrade("failed", NOW, False, boot_started=NOW)[0] == "failed"
