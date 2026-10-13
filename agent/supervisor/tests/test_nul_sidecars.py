"""#1747 — a power loss right after a slot apply leaves NUL bytes in the
host's slot-upgrade files. Postgres refuses U+0000, so a NUL in the
heartbeat's ``last_upgrade_log_tail`` made the api 422 every heartbeat.
The readers must scrub / treat such a file as unknown."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st


def test_log_tail_never_carries_nul(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = tmp_path / "slot-upgrade.log"
    log.write_bytes(
        b"line one\napply succeeded - calling set-next-boot\n" + b"\x00" * 410
    )
    monkeypatch.setattr(st, "_SLOT_UPGRADE_LOG", log)
    tail = st._read_slot_upgrade_log_tail()
    assert "\x00" not in tail
    assert "apply succeeded" in tail


def test_log_tail_keeps_newline_and_tab(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = tmp_path / "slot-upgrade.log"
    log.write_bytes(b"a\tb\x01\x1b[0m\nc\x00\n")
    monkeypatch.setattr(st, "_SLOT_UPGRADE_LOG", log)
    assert st._read_slot_upgrade_log_tail() == "a\tb[0m\nc"


def test_all_nul_state_file_reads_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "slot-upgrade-pending.state"
    f.write_bytes(b"\x00" * 64)
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", f)
    assert st._last_upgrade_state_from_sidecar() == (None, None)


def test_state_with_nul_tail_still_parses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "slot-upgrade-pending.state"
    f.write_bytes(b"done 2026-10-11T16:01:54+00:00\n\x00\x00\x00")
    monkeypatch.setattr(st, "_HOST_SLOT_STATE", f)
    state, stamp = st._last_upgrade_state_from_sidecar()
    assert state == "done" and stamp is not None


@pytest.mark.parametrize("raw", [b"\x00" * 50, b'{"step":"arming","de\x00\x00'])
def test_nul_or_truncated_progress_is_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: bytes
) -> None:
    f = tmp_path / "slot-upgrade.progress"
    f.write_bytes(raw)
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", f)
    assert st._read_slot_upgrade_progress() is None


def test_progress_strings_are_scrubbed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "slot-upgrade.progress"
    f.write_text(json.dumps({"step": "writing", "detail": "a\u0000b", "pct": 3}))
    monkeypatch.setattr(st, "_SLOT_UPGRADE_PROGRESS", f)
    assert st._read_slot_upgrade_progress() == {
        "step": "writing",
        "detail": "ab",
        "pct": 3,
    }
