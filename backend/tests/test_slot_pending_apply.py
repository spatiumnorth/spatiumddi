"""#1825 / #1288 — an apply the host runner has not started.

A trigger that lands during a systemd ``daemon-reload`` is never seen by the
``PathChanged=`` watch, so the runner never starts. The reader must (a) read
an unclaimed trigger as in-flight WITH a stamp so #421's heal can age it out,
(b) re-fire the watcher after a pickup grace, and (c) not read a previous
run's ``done`` as the new apply's state.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import pytest

from app.services.appliance import slot


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "slot-upgrade-pending.state"
    trigger = tmp_path / "slot-upgrade-pending"
    monkeypatch.setattr(slot, "_STATE_FILE", state)
    monkeypatch.setattr(slot, "_TRIGGER_FILE", trigger)
    monkeypatch.setattr(slot, "_last_rearm_at", 0.0)
    return {"state": state, "trigger": trigger}


def _age(path: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(path, (t, t))


def _spy_open(monkeypatch: pytest.MonkeyPatch, trigger: Path, deny: bool = False) -> list[str]:
    opened: list[str] = []
    real_open = open

    def spy(file: Any, mode: str = "r", *a: Any, **kw: Any) -> Any:
        if str(file) == str(trigger) and "a" in mode:
            opened.append(mode)
            if deny:
                raise PermissionError("EPERM")
        return real_open(file, mode, *a, **kw)

    monkeypatch.setattr("builtins.open", spy)
    return opened


def test_unclaimed_trigger_ages_out_to_failed(paths: dict[str, Path]) -> None:
    paths["trigger"].write_text("https://example/img.raw.xz\n")
    _age(paths["trigger"], slot._STALE_INFLIGHT_SECONDS + 60)
    state, stamp = slot._upgrade_state_now()
    assert state == "failed"
    assert stamp is not None
    assert slot.is_apply_in_flight() is False  # apply/rollback no longer 409


def test_fresh_unclaimed_trigger_is_inflight_with_stamp(paths: dict[str, Path]) -> None:
    paths["trigger"].write_text("x\n")
    state, stamp = slot._upgrade_state_now()
    assert state == "in-flight"
    assert stamp is not None


def test_previous_done_does_not_mask_new_apply(paths: dict[str, Path]) -> None:
    paths["state"].write_text("done 2026-10-01T00:00:00+00:00\n")
    _age(paths["state"], 3600)
    paths["trigger"].write_text("x\n")
    assert slot._upgrade_state_now()[0] == "in-flight"


def test_runner_state_newer_than_trigger_reads_normally(paths: dict[str, Path]) -> None:
    paths["trigger"].write_text("x\n")
    _age(paths["trigger"], 20)
    paths["state"].write_text("done 2026-10-01T00:00:00+00:00\n")
    assert slot._upgrade_state_now()[0] == "done"


def test_rearm_after_grace_keeps_mtime(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    paths["trigger"].write_text("x\n")
    _age(paths["trigger"], slot._PICKUP_GRACE_SECONDS + 5)
    before = paths["trigger"].stat().st_mtime
    opened = _spy_open(monkeypatch, paths["trigger"])
    slot._upgrade_state_now()
    slot._upgrade_state_now()  # rate-limited: no second re-arm
    assert opened == ["ab"]
    assert paths["trigger"].stat().st_mtime == before
    assert paths["trigger"].read_text() == "x\n"


def test_no_rearm_within_grace(paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    paths["trigger"].write_text("x\n")
    opened = _spy_open(monkeypatch, paths["trigger"])
    slot._upgrade_state_now()
    assert opened == []


def test_unopenable_trigger_is_left_to_the_heal(
    paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    paths["trigger"].write_text("x\n")
    _age(paths["trigger"], slot._PICKUP_GRACE_SECONDS + 5)
    _spy_open(monkeypatch, paths["trigger"], deny=True)
    assert slot._upgrade_state_now()[0] == "in-flight"
