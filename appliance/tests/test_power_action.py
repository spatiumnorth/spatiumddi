"""#2974 — the web-UI reboot and the console's reboot / poweroff run the
PostgreSQL primary handoff (#2849) first, through one wrapper,
spatium-power-action. The wrapper is run for real against a stub handoff
and a stub systemctl, and the assertions are on the order of what they
were called with."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
EXTRA = REPO / "appliance" / "mkosi.extra"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-power-action"
CONSOLE = EXTRA / "usr" / "local" / "bin" / "spatium-console"
WEB_UNIT = EXTRA / "etc" / "systemd" / "system" / "spatiumddi-reboot.service"
POSTINST = REPO / "appliance" / "mkosi.postinst"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="appliance tree not present")


TEMPLATE_UNIT = EXTRA / "etc" / "systemd" / "system" / "spatium-power-action@.service"


def _run(tmp_path: Path, action: str, *, systemctl_rc: int = 0, handoff: str = "ok",
         systemctl_sleep: float = 0, cap_s: int = 240):
    log = tmp_path / "calls.log"
    handoff_sh = tmp_path / "handoff"
    # --undo always returns at once; only --before-reboot takes the body
    body = {"ok": "exit 0", "crash": "exit 7", "hang": "exec sleep 30"}[handoff]
    handoff_sh.write_text(
        f'#!/bin/bash\necho "handoff $*" >> {log}\n'
        f'[ "$1" = --undo ] && exit 0\n{body}\n'
    )
    handoff_sh.chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    sc = bindir / "systemctl"
    sc.write_text(
        f'#!/bin/bash\necho "systemctl $*" >> {log}\nsleep {systemctl_sleep}\n'
        f'exit {systemctl_rc}\n'
    )
    sc.chmod(0o755)
    (tmp_path / "state").mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SPATIUM_REBOOT_HANDOFF": str(handoff_sh),
           "SPATIUM_POWER_ACTION_MARKER": str(tmp_path / "marker"),
           "SPATIUM_POWER_ACTION_LOCK": str(tmp_path / "state"),
           "SPATIUM_POWER_ACTION_HANDOFF_CAP_S": str(cap_s)}
    proc = subprocess.Popen([str(SCRIPT), action], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    return proc, log


def _calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("action", ["reboot", "poweroff"])
def test_the_handoff_runs_before_systemctl(tmp_path: Path, action: str) -> None:
    proc, log = _run(tmp_path, action)
    assert proc.wait(30) == 0
    assert _calls(log) == ["handoff --before-reboot", f"systemctl {action}"]


@pytest.mark.parametrize("action", ["reboot", "poweroff"])
def test_a_failing_handoff_still_reboots(tmp_path: Path, action: str) -> None:
    proc, log = _run(tmp_path, action, handoff="crash")
    assert proc.wait(30) == 0
    assert _calls(log) == ["handoff --before-reboot", f"systemctl {action}"]


def test_a_failed_systemctl_undoes_the_cordon(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", systemctl_rc=1)
    assert proc.wait(30) == 1
    assert _calls(log) == ["handoff --before-reboot", "systemctl reboot", "handoff --undo"]


def _wait_for(pred, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while not pred():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.05)


def test_a_stop_during_the_handoff_undoes_the_cordon_and_never_reboots(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    marker = tmp_path / "marker"
    assert marker.read_text().split() == [str(proc.pid), "reboot"]
    started = time.monotonic()
    proc.terminate()
    assert proc.wait(20) == 1
    # acted on at once, not once the 30 s handoff has run out
    assert time.monotonic() - started < 10
    calls = _calls(log)
    assert calls == ["handoff --before-reboot", "handoff --undo"]
    assert not marker.exists()


def test_a_stop_once_systemctl_was_issued_leaves_the_cordon(tmp_path: Path) -> None:
    """The shutdown stops the unit as it goes down: undoing the cordon then
    would hand the node pods back mid-shutdown (#2974)."""
    proc, log = _run(tmp_path, "reboot", systemctl_sleep=3)
    _wait_for(lambda: "systemctl reboot" in _calls(log))
    proc.terminate()
    assert proc.wait(20) == 0
    assert _calls(log) == ["handoff --before-reboot", "systemctl reboot"]


def test_a_handoff_past_the_cap_is_stopped_and_the_reboot_goes_on(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", handoff="hang", cap_s=1)
    assert proc.wait(30) == 0
    assert _calls(log) == ["handoff --before-reboot", "systemctl reboot"]
    assert "did not finish within 1 s" in proc.stdout.read()


def test_an_unknown_action_does_nothing(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "halt")
    assert proc.wait(10) == 2
    assert _calls(log) == []


def test_the_web_ui_unit_goes_through_the_wrapper() -> None:
    text = WEB_UNIT.read_text()
    assert "ExecStart=/usr/local/bin/spatium-power-action reboot" in text
    assert "ExecStart=/usr/bin/systemctl" not in text
    # a start timeout would stop the wrapper, which is a cancel: no reboot
    assert re.search(r"^TimeoutStartSec=infinity$", text, re.M)


def test_the_console_unit_runs_the_wrapper_without_a_start_timeout() -> None:
    text = TEMPLATE_UNIT.read_text()
    assert "ExecStart=/usr/local/bin/spatium-power-action %i" in text
    assert "Type=oneshot" in text
    assert re.search(r"^TimeoutStartSec=infinity$", text, re.M)
    assert "[Install]" not in text


def test_the_console_reboot_and_poweroff_start_the_unit_without_waiting() -> None:
    """systemd owns the run: the dashboard keeps rendering through the
    handoff, and a console restart cannot kill it mid-handoff (#2974)."""
    text = CONSOLE.read_text()
    assert 'POWER_ACTION_UNIT = "spatium-power-action@{}.service"' in text
    assert '["systemctl", "start", "--no-block", unit]' in text
    assert '_start_power_action(console, state, "reboot", "Rebooting")' in text
    assert '_start_power_action(console, state, "poweroff", "Powering off")' in text
    assert '["systemctl", "reboot"]' not in text
    assert '["systemctl", "poweroff"]' not in text
    assert "/usr/local/bin/spatium-power-action" not in text


def test_the_console_cancel_stops_the_console_runs_too() -> None:
    text = CONSOLE.read_text()
    assert 'POWER_ACTION_UNIT.format("reboot"), POWER_ACTION_UNIT.format("poweroff")' in text


def test_the_image_makes_the_wrapper_executable() -> None:
    text = POSTINST.read_text()
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-power-action"' in text
    assert 'chmod 0644 "$BUILDROOT/etc/systemd/system/spatium-power-action@.service"' in text
    assert os.access(SCRIPT, os.X_OK)


def _lock_held(path: Path) -> bool:
    """The api's probe (backend/app/services/appliance/system.py)."""
    import fcntl
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def test_the_lock_the_api_reads_is_held_while_it_runs_and_freed_after(tmp_path: Path) -> None:
    """#3008 — the api's flock probe of the release-state directory."""
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    assert _lock_held(tmp_path / "state")
    proc.terminate()
    assert proc.wait(20) == 1
    assert not _lock_held(tmp_path / "state")


def test_a_killed_wrapper_leaves_no_lock_even_with_the_handoff_alive(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    proc.kill()
    proc.wait(10)
    assert not _lock_held(tmp_path / "state")


def test_the_lock_creates_nothing_and_follows_no_planted_symlink(tmp_path: Path) -> None:
    """#3008 — the api and the supervisor can write in release-state and the
    wrapper runs as root: a lock FILE there could be a symlink planted to make
    root create or truncate any host path. The directory itself is locked,
    opened read-only."""
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "power-action-active").symlink_to(victim)
    proc, log = _run(tmp_path, "reboot")
    assert proc.wait(30) == 0
    assert victim.read_text() == "precious\n"
    assert sorted(p.name for p in (tmp_path / "state").iterdir()) == ["power-action-active"]
    text = SCRIPT.read_text()
    assert 'exec 9<"$LOCK"' in text and 'exec 9>' not in text
    assert 'LOCK="${SPATIUM_POWER_ACTION_LOCK:-/var/lib/spatiumddi/release-state}"' in text


def test_a_probe_holding_the_lock_for_an_instant_does_not_cost_the_wrapper_it(
    tmp_path: Path,
) -> None:
    """#3008 — the api's shared probe can coincide with the wrapper's start;
    with ``flock -n`` that ran the whole action unlocked, the web UI's button
    enabled throughout. The wrapper waits briefly instead."""
    import fcntl
    (tmp_path / "state").mkdir()
    fd = os.open(tmp_path / "state", os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        proc, log = _run(tmp_path, "reboot", handoff="hang")
        time.sleep(1)
    finally:
        os.close(fd)
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    _wait_for(lambda: _lock_held(tmp_path / "state"))
    proc.terminate()
    assert proc.wait(20) == 1
    assert "going on regardless" not in (proc.stdout.read() if proc.stdout else "")
