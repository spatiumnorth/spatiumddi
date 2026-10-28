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


def _run(tmp_path: Path, action: str, *, systemctl_rc: int = 0, handoff: str = "ok"):
    log = tmp_path / "calls.log"
    handoff_sh = tmp_path / "handoff"
    body = {"ok": "exit 0", "crash": "exit 7", "hang": "sleep 30"}[handoff]
    handoff_sh.write_text(f'#!/bin/bash\necho "handoff $*" >> {log}\n{body}\n')
    handoff_sh.chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    sc = bindir / "systemctl"
    sc.write_text(f'#!/bin/bash\necho "systemctl $*" >> {log}\nexit {systemctl_rc}\n')
    sc.chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SPATIUM_REBOOT_HANDOFF": str(handoff_sh)}
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


def test_a_stop_during_the_handoff_undoes_the_cordon_and_never_reboots(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    for _ in range(50):
        if _calls(log):
            break
        time.sleep(0.1)
    proc.terminate()
    assert proc.wait(60) == 1
    calls = _calls(log)
    assert "handoff --undo" in calls
    assert not any(c.startswith("systemctl") for c in calls)


def test_an_unknown_action_does_nothing(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "halt")
    assert proc.wait(10) == 2
    assert _calls(log) == []


def test_the_web_ui_unit_goes_through_the_wrapper() -> None:
    text = WEB_UNIT.read_text()
    assert "ExecStart=/usr/local/bin/spatium-power-action reboot" in text
    assert "ExecStart=/usr/bin/systemctl" not in text
    # the handoff can take ~2 min; systemd's 90 s default would kill it
    m = re.search(r"^TimeoutStartSec=(\d+)", text, re.M)
    assert m and int(m.group(1)) >= 180


def test_the_console_reboot_and_poweroff_go_through_the_wrapper() -> None:
    text = CONSOLE.read_text()
    assert 'POWER_ACTION = "/usr/local/bin/spatium-power-action"' in text
    assert '[POWER_ACTION, "reboot"]' in text
    assert '[POWER_ACTION, "poweroff"]' in text
    assert '["systemctl", "reboot"]' not in text
    assert '["systemctl", "poweroff"]' not in text


def test_the_image_makes_the_wrapper_executable() -> None:
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-power-action"' in POSTINST.read_text()
    assert os.access(SCRIPT, os.X_OK)
