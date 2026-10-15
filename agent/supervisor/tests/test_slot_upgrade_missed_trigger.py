"""#1825 — a fleet slot-upgrade trigger the host's watcher never started.

The supervisor writes ``slot-upgrade-pending`` for a fleet upgrade; the host's
``PathChanged=`` unit misses it if systemd is reloading as it lands. Before,
the heartbeat reported the previous run's ``.state`` (or ``ready``), nothing
aged it, and the fire-once marker plus the trigger-present guard kept
``maybe_fire_fleet_upgrade`` from ever writing it again. Now an unclaimed
trigger reads ``in-flight`` stamped with its write time (so the #421 reaper
ends it), and is re-armed after a pickup grace. The re-arm is observed with a
real inotify watch for IN_CLOSE_WRITE, the event ``PathChanged=`` fires on.
"""

from __future__ import annotations

import ctypes
import os
import select
import struct
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state

IN_CLOSE_WRITE = 0x00000008
linux_only = pytest.mark.skipif(sys.platform != "linux", reason="inotify is Linux-only")


@pytest.fixture
def paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    state = tmp_path / "slot-upgrade-pending.state"
    trigger = tmp_path / "slot-upgrade-pending"
    progress = tmp_path / "slot-upgrade.progress"
    monkeypatch.setattr(appliance_state, "_HOST_SLOT_STATE", state)
    monkeypatch.setattr(appliance_state, "_TRIGGER_FILE", trigger)
    monkeypatch.setattr(appliance_state, "_SLOT_UPGRADE_PROGRESS", progress)
    # raising=False: a no-op on a tree without the re-arm, where the tests
    # then fail on their assertions rather than erroring here.
    monkeypatch.setattr(appliance_state, "_last_rearm_at", 0.0, raising=False)
    return {"state": state, "trigger": trigger, "progress": progress}


def _write(path: Path, body: str, age_seconds: float) -> float:
    path.write_text(body)
    t = time.time() - age_seconds
    os.utime(path, (t, t))
    return t


def _heartbeat_state() -> tuple[str | None, datetime | None]:
    """What collect() ships: the sidecar read, then the #421 reaper."""
    return appliance_state._reap_stale_inflight(
        *appliance_state._last_upgrade_state_from_sidecar()
    )


def _close_writes(path: Path, act: Callable[[], object], timeout: float = 0.5) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK)
    assert fd >= 0
    try:
        assert libc.inotify_add_watch(fd, os.fsencode(path), IN_CLOSE_WRITE) >= 0
        act()
        count = 0
        while True:
            ready, _, _ = select.select([fd], [], [], timeout)
            if not ready:
                return count
            buf = os.read(fd, 4096)
            off = 0
            while off < len(buf):
                _wd, mask, _cookie, length = struct.unpack_from("iIII", buf, off)
                count += bool(mask & IN_CLOSE_WRITE)
                off += 16 + length
            timeout = 0.1
    finally:
        os.close(fd)


def test_unclaimed_trigger_beside_a_previous_done_reads_in_flight(
    paths: dict[str, Path],
) -> None:
    _write(paths["state"], "done 2026-10-01T00:00:00+00:00\n", 3600)
    written = _write(paths["trigger"], "https://example/img.raw.xz\n", 5)
    state, when = _heartbeat_state()
    assert state == "in-flight"
    assert when is not None and abs(when.timestamp() - written) < 1


def test_unclaimed_trigger_is_reaped_to_failed_and_moved_aside(
    paths: dict[str, Path],
) -> None:
    # main: reports "ready" (no .state) with the trigger stranded for good.
    _write(
        paths["trigger"],
        "https://example/img.raw.xz\n",
        appliance_state._STALE_INFLIGHT_SECONDS + 60,
    )
    state, _ = _heartbeat_state()
    assert state == "failed"
    assert paths["state"].read_text().startswith("failed ")
    assert not paths["trigger"].exists()
    assert list(paths["trigger"].parent.glob("slot-upgrade-pending.failed.*"))


def test_claimed_trigger_reads_the_runners_state(paths: dict[str, Path]) -> None:
    _write(paths["trigger"], "x\n", 120)
    stamp = datetime.now(UTC).isoformat()
    paths["state"].write_text(f"in-flight {stamp}\n")
    state, when = _heartbeat_state()
    assert state == "in-flight"
    assert when == datetime.fromisoformat(stamp)


@linux_only
def test_unclaimed_trigger_is_rearmed_once_after_the_grace(paths: dict[str, Path]) -> None:
    body = "https://example/img.raw.xz\n"
    _write(paths["trigger"], body, 45)
    before = paths["trigger"].stat().st_mtime_ns

    def two_heartbeats() -> None:
        _heartbeat_state()
        _heartbeat_state()

    assert _close_writes(paths["trigger"], two_heartbeats) == 1
    assert paths["trigger"].stat().st_mtime_ns == before
    assert paths["trigger"].read_text() == body


@linux_only
def test_trigger_inside_the_grace_is_not_rearmed(paths: dict[str, Path]) -> None:
    _write(paths["trigger"], "x\n", 2)
    assert _close_writes(paths["trigger"], _heartbeat_state, timeout=0.2) == 0


@linux_only
def test_claimed_trigger_is_not_rearmed(paths: dict[str, Path]) -> None:
    _write(paths["trigger"], "x\n", 120)
    paths["state"].write_text(f"in-flight {datetime.now(UTC).isoformat()}\n")
    assert _close_writes(paths["trigger"], _heartbeat_state, timeout=0.2) == 0
