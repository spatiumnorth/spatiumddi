"""#4707 — firstboot's "control plane not converged" record reaches the heartbeat."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state


def test_reads_the_record_firstboot_wrote(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = tmp_path / "control-plane-not-converged"
    body = {"version": "1.0.2", "at": "2026-11-21T10:00:00+00:00", "detail": "x\x00y"}
    f.write_text(json.dumps(body))
    monkeypatch.setattr(appliance_state, "_CONTROL_NOT_CONVERGED_FILE", f)
    rec = appliance_state.read_control_plane_not_converged()
    assert rec == {"version": "1.0.2", "at": "2026-11-21T10:00:00+00:00", "detail": "xy"}


@pytest.mark.parametrize("body", [None, "", "\x00\x00", "[1]", "not json"])
def test_absent_or_garbled_record_reads_as_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str | None
) -> None:
    f = tmp_path / "control-plane-not-converged"
    if body is not None:
        f.write_text(body)
    monkeypatch.setattr(appliance_state, "_CONTROL_NOT_CONVERGED_FILE", f)
    assert appliance_state.read_control_plane_not_converged() is None
