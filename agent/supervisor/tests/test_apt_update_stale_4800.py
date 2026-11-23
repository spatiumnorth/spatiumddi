"""#4800 — the apt timers succeed while ``apt-get update`` cannot reach any
mirror. The host's apt hook stamps the last attempt / success and the
supervisor folds a stale one into ``apt_state`` as ``update-stale``."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state as st

DAY = 24 * 3600


def _stamp(path: Path, age_s: float) -> Path:
    path.write_text("")
    t = time.time() - age_s
    os.utime(path, (t, t))
    return path


def test_recent_success_is_not_stale(tmp_path: Path) -> None:
    ok = _stamp(tmp_path / "ok", DAY)
    assert st.apt_update_stale(ok, tmp_path / "attempt") is False


def test_old_success_is_stale(tmp_path: Path) -> None:
    ok = _stamp(tmp_path / "ok", 5 * DAY)
    assert st.apt_update_stale(ok, tmp_path / "attempt") is True


def test_attempt_without_success_is_stale(tmp_path: Path) -> None:
    attempt = _stamp(tmp_path / "attempt", 60)
    assert st.apt_update_stale(tmp_path / "ok", attempt) is True


def test_no_stamps_is_unknown_not_stale(tmp_path: Path) -> None:
    assert st.apt_update_stale(tmp_path / "ok", tmp_path / "attempt") is False


def test_stale_update_overrides_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(st, "read_apt_state", lambda: "synced")
    monkeypatch.setattr(st, "apt_update_stale", lambda: True)
    assert st.read_apt_state_with_update() == "update-stale"
    monkeypatch.setattr(st, "apt_update_stale", lambda: False)
    assert st.read_apt_state_with_update() == "synced"
    monkeypatch.setattr(st, "read_apt_state", lambda: None)
    monkeypatch.setattr(st, "apt_update_stale", lambda: True)
    assert st.read_apt_state_with_update() is None
