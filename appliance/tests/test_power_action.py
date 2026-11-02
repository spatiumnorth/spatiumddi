"""#2974 — the web-UI reboot and the console's reboot / poweroff run the
PostgreSQL primary handoff (#2849) first, through one wrapper,
spatium-power-action. The wrapper is run for real against a stub handoff
and a stub systemctl, and the assertions are on the order of what they
were called with."""

from __future__ import annotations

import os
import re
import signal
import stat
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
BOOT = "11111111-2222-3333-4444-555555555555"


def _run(tmp_path: Path, action: str, *, systemctl_rc: int = 0, handoff: str = "ok",
         systemctl_sleep: float = 0, cap_s: int = 240, extra_env: dict | None = None):
    log = tmp_path / "calls.log"
    handoff_sh = tmp_path / "handoff"
    # --undo always returns at once; only --before-reboot takes the body
    # "switch": the handoff got as far as asking CNPG for the switchover (it
    # notes that just before its cordon, #3162), then waits for it
    body = {"ok": "exit 0", "crash": "exit 7", "hang": "exec sleep 30",
            "switch": 'echo "spatium/pg pg-1" > "$SPATIUM_HANDOFF_SWITCHOVER_FILE"\n'
                      "exec sleep 30",
            "noted": 'echo x > "$SPATIUM_HANDOFF_SWITCHOVER_FILE"\nexit 0'}[handoff]
    handoff_sh.write_text(
        f'#!/bin/bash\necho "handoff $*" >> {log}\n'
        f'[ "$1" = --undo ] && exit 0\n{body}\n'
    )
    handoff_sh.chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    sc = bindir / "systemctl"
    issued = tmp_path / "state" / "power-action-issued"
    # records what the issued marker held at the moment systemctl ran
    sc.write_text(
        f'#!/bin/bash\necho "systemctl $*" >> {log}\n'
        f'cat {issued} > {tmp_path}/issued-at-systemctl 2>/dev/null\n'
        f'sleep {systemctl_sleep}\nexit {systemctl_rc}\n'
    )
    sc.chmod(0o755)
    (tmp_path / "state").mkdir(exist_ok=True)
    (tmp_path / "boot_id").write_text(BOOT + "\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           **(extra_env or {}),
           "SPATIUM_REBOOT_HANDOFF": str(handoff_sh),
           "SPATIUM_POWER_ACTION_MARKER": str(tmp_path / "marker"),
           "SPATIUM_POWER_ACTION_LOCK": str(tmp_path / "state"),
           "SPATIUM_POWER_ACTION_ISSUED": str(issued),
           "SPATIUM_BOOT_ID_FILE": str(tmp_path / "boot_id"),
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
    assert proc.wait(20) == -signal.SIGTERM
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
    assert proc.wait(20) == -signal.SIGTERM
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
    # the only name it leaves is the issued marker, written under a fresh
    # name and renamed into place
    assert sorted(p.name for p in (tmp_path / "state").iterdir()) == [
        "power-action-active", "power-action-issued"]
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
    assert proc.wait(20) == -signal.SIGTERM
    assert "going on regardless" not in (proc.stdout.read() if proc.stdout else "")


# ---- #3008 (QA case 3): the issued marker -----------------------------------

@pytest.mark.parametrize("action", ["reboot", "poweroff"])
def test_the_issued_marker_is_up_before_systemctl_and_stays(tmp_path: Path, action: str) -> None:
    """The lock ends with the wrapper, moments after systemctl and before the
    node is down; the marker, stamped with the boot id, outlives it until the
    reboot changes the boot id."""
    proc, log = _run(tmp_path, action)
    assert proc.wait(30) == 0
    assert (tmp_path / "issued-at-systemctl").read_text().split() == [action, BOOT]
    issued = tmp_path / "state" / "power-action-issued"
    assert issued.read_text().split() == [action, BOOT]
    assert oct(issued.stat().st_mode & 0o777) == oct(0o644)
    assert not _lock_held(tmp_path / "state")


def test_a_failed_systemctl_takes_the_issued_marker_down(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", systemctl_rc=1)
    assert proc.wait(30) == 1
    assert (tmp_path / "issued-at-systemctl").read_text().split() == ["reboot", BOOT]
    assert not (tmp_path / "state" / "power-action-issued").exists()


def test_a_stop_during_the_handoff_writes_no_issued_marker(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    proc.terminate()
    assert proc.wait(20) == -signal.SIGTERM
    assert not (tmp_path / "state" / "power-action-issued").exists()


def test_the_issued_marker_never_writes_through_a_planted_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("precious\n")
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "power-action-issued").symlink_to(victim)
    proc, log = _run(tmp_path, "reboot")
    assert proc.wait(30) == 0
    assert victim.read_text() == "precious\n"
    issued = tmp_path / "state" / "power-action-issued"
    assert not issued.is_symlink() and issued.read_text().split() == ["reboot", BOOT]


# ---- #3008 (QA case 2): the console sees the Fleet grace, and F9 cancels it ---

AGENT = EXTRA / "usr" / "local" / "bin" / "spatiumddi-reboot-agent"
_CONSOLE_NAMES = {
    "_RELEASE_STATE_DIR", "FLEET_GRACE_MARKER", "BOOT_ID_FILE", "POWER_ACTION_MARKER",
    "POWER_ACTION_UNIT", "reboot_pending", "fleet_reboot_in_grace",
    "power_action_in_progress", "do_cancel_reboot", "REBOOT_CANCEL_MARKER",
    "_record_reboot_cancel", "POWER_ACTION_SWITCHOVER",
}


def _console(state: Path, boot_id: Path, run) -> dict:
    """The console's reboot functions, lifted out of the shipped script (it
    imports rich and psutil at load time, which this suite does not install)."""
    import __future__
    import ast
    tree = ast.parse(CONSOLE.read_text(encoding="utf-8"))
    body = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in _CONSOLE_NAMES:
            body.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in _CONSOLE_NAMES for t in targets):
                body.append(node)
    assert {getattr(n, "name", None) for n in body} >= {
        "reboot_pending", "fleet_reboot_in_grace", "do_cancel_reboot"}

    class _Sub:
        @staticmethod
        def run(argv, **kw):
            return run(argv)

    class _Time:
        @staticmethod
        def sleep(_s):
            return None

        time = staticmethod(time.time)

    ns: dict = {"Path": Path, "os": os, "subprocess": _Sub, "time": _Time,
                "confirm_modal": lambda _c, _q: True}
    mod = ast.Module(body=body, type_ignores=[])
    exec(compile(mod, str(CONSOLE), "exec",
                 flags=__future__.annotations.compiler_flag, dont_inherit=True), ns)
    ns["_RELEASE_STATE_DIR"] = state
    ns["FLEET_GRACE_MARKER"] = state / "reboot-fleet-grace"
    ns["BOOT_ID_FILE"] = boot_id
    ns["REBOOT_CANCEL_MARKER"] = state / "reboot-cancelled"
    ns["POWER_ACTION_MARKER"] = state.parent / "no-power-action-marker"
    ns["POWER_ACTION_SWITCHOVER"] = state.parent / "no-power-action-switchover"
    return ns


class _FakeConsole:
    def __init__(self) -> None:
        self.out: list[str] = []

    def clear(self) -> None:
        return None

    def print(self, s: str = "") -> None:
        self.out.append(str(s))


def _agent(tmp_path: Path, grace_s: int):
    state = tmp_path / "state"
    state.mkdir()
    (state / "reboot-pending-fleet").write_text("stamp\n")
    (tmp_path / "boot_id").write_text(BOOT + "\n")
    wrapper = tmp_path / "wrapper"
    wrapper.write_text(f'#!/bin/bash\necho "wrapper $*" >> {tmp_path}/wrapper-calls\n')
    wrapper.chmod(0o755)
    src = (AGENT.read_text().replace("/var/lib/spatiumddi/release-state", str(state))
           .replace("/var/log/spatiumddi", str(tmp_path / "log")))
    script = tmp_path / "agent"
    script.write_text(src)
    script.chmod(0o755)
    proc = subprocess.Popen(
        [str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "SPATIUM_POWER_ACTION": str(wrapper),
             "SPATIUM_REBOOT_AGENT_GRACE_S": str(grace_s),
             "SPATIUM_BOOT_ID_FILE": str(tmp_path / "boot_id")})
    _wait_for(lambda: (state / "reboot-pending-fleet.done").exists())
    return proc, state


def test_f9_during_the_fleet_grace_cancels_the_reboot(tmp_path: Path) -> None:
    """QA case 2: F9 1.5 s into the agent's grace answered "No reboot is
    currently pending" and the node rebooted. The console now sees the grace
    marker, and its cancel (systemctl stop of the agent's unit, simulated by
    TERM to the agent) ends the run before the wrapper is called."""
    proc, state = _agent(tmp_path, grace_s=30)
    stopped: list[list[str]] = []

    def run(argv):
        stopped.append(argv)
        if argv[:2] == ["systemctl", "stop"] and "spatiumddi-reboot-agent.service" in argv:
            proc.terminate()
            proc.wait(10)

    try:
        con = _console(state, tmp_path / "boot_id", run)
        assert not (state / "reboot-pending-fleet").exists()  # renamed before the grace
        assert con["reboot_pending"]() is True
        fc = _FakeConsole()
        con["do_cancel_reboot"](fc)
        assert any("Reboot cancelled" in line for line in fc.out), fc.out
        assert proc.returncode == -signal.SIGTERM
        assert not (tmp_path / "wrapper-calls").exists()
        assert not (state / "reboot-fleet-grace").exists()
        assert con["reboot_pending"]() is False
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(10)


def test_a_grace_marker_of_a_dead_runner_or_another_boot_is_nothing(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    con = _console(state, boot, lambda argv: None)
    marker = state / "reboot-fleet-grace"
    marker.write_text(f"{os.getpid()} {BOOT}\n")
    assert con["reboot_pending"]() is True
    marker.write_text(f"{os.getpid()} 99999999-0000-0000-0000-000000000000\n")
    assert con["reboot_pending"]() is False
    dead = subprocess.Popen(["true"])
    dead.wait()
    marker.write_text(f"{dead.pid} {BOOT}\n")
    assert con["reboot_pending"]() is False
    marker.write_text("garbage\n")
    assert con["reboot_pending"]() is False


def test_the_console_names_the_handoff_only_on_a_multi_node_cluster() -> None:
    """On one node there is no primary to hand off (QA case 3)."""
    text = CONSOLE.read_text()
    assert 'handoff = " — handing off DB primary" if len(state.nodes) > 1 else ""' in text
    assert "if state is not None and len(state.nodes) > 1:" in text


def test_the_console_unit_gives_a_grace_so_the_api_outlives_the_confirm() -> None:
    """#3008 defect A — on one node nothing else delayed systemctl, and the api
    answered for ~1 s, less than the Maintenance tab's 5 s poll."""
    assert re.search(r"^Environment=SPATIUM_POWER_ACTION_GRACE_S=(\d+)$",
                     TEMPLATE_UNIT.read_text(), re.M)
    n = int(re.search(r"GRACE_S=(\d+)", TEMPLATE_UNIT.read_text()).group(1))
    assert n >= 10


def test_the_grace_holds_lock_and_marker_before_systemctl(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", extra_env={"SPATIUM_POWER_ACTION_GRACE_S": "3"})
    _wait_for(lambda: (tmp_path / "marker").exists())
    time.sleep(0.5)
    assert _calls(log) == []  # nothing issued during the grace
    assert _lock_held(tmp_path / "state")  # the api reads the reboot under way
    assert proc.wait(30) == 0
    assert _calls(log) == ["handoff --before-reboot", "systemctl reboot"]


def test_a_stop_during_the_grace_never_reboots(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", extra_env={"SPATIUM_POWER_ACTION_GRACE_S": "30"})
    _wait_for(lambda: (tmp_path / "marker").exists())
    time.sleep(0.3)
    started = time.monotonic()
    proc.terminate()
    assert proc.wait(20) == -signal.SIGTERM
    assert time.monotonic() - started < 10
    assert "systemctl reboot" not in _calls(log)
    assert not (tmp_path / "marker").exists()
    assert not _lock_held(tmp_path / "state")


def test_the_console_cancel_leaves_a_marker_for_the_supervisor(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    (state / "reboot-pending").write_text("x")
    con = _console(state, boot, lambda argv: None)
    fc = _FakeConsole()
    con["do_cancel_reboot"](fc)
    marker = state / "reboot-cancelled"
    assert marker.read_text().strip() == BOOT
    # Group-writable to release-state's shared gid: the sticky dir lets the
    # unprivileged supervisor empty it once acknowledged, never unlink it.
    assert stat.S_IMODE(marker.stat().st_mode) == 0o660
    assert marker.stat().st_gid == state.stat().st_gid


class _FlashRecorder:
    def __init__(self) -> None:
        self.flashes: list[str] = []

    def flash(self, msg: str, ttl: float = 3.0) -> None:
        self.flashes.append(msg)


def test_a_console_cancel_replaces_the_reboot_flash(tmp_path: Path) -> None:
    # The F5 / F6 flash ("Rebooting · F9 cancels") runs 20 s; the cancel must
    # replace it, or the footer goes on announcing a reboot that will not come.
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    (state / "reboot-pending").write_text("x")
    con = _console(state, boot, lambda argv: None)
    dash = _FlashRecorder()
    con["do_cancel_reboot"](_FakeConsole(), dash)
    assert dash.flashes and dash.flashes[-1] == "Reboot cancelled"


def test_cancelling_a_power_off_says_power_off_not_reboot(tmp_path: Path) -> None:
    # #3101 — the modal, the printed note and the flash named a reboot while
    # the pending action was a power-off.
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    marker = tmp_path / "power-action"
    marker.write_text(f"{os.getpid()} poweroff\n")
    con = _console(state, boot, lambda argv: None)
    con["POWER_ACTION_MARKER"] = marker
    asked: list[str] = []
    con["confirm_modal"] = lambda _c, q: asked.append(q) or True
    dash, fc = _FlashRecorder(), _FakeConsole()
    con["do_cancel_reboot"](fc, dash)
    assert asked == ["Cancel the pending power-off?"]
    assert dash.flashes[-1] == "Power-off cancelled"
    assert any("Power-off cancelled." in line for line in fc.out), fc.out
    assert not any("eboot" in line for line in fc.out), fc.out


def _dashboard_state_class(clock):
    """DashboardState's flash helpers, lifted out of the shipped script."""
    import __future__
    import ast
    tree = ast.parse(CONSOLE.read_text(encoding="utf-8"))
    cls = next(n for n in tree.body
               if isinstance(n, ast.ClassDef) and n.name == "DashboardState")
    keep = [n for n in cls.body
            if isinstance(n, ast.FunctionDef) and n.name in ("flash", "status_for_draw")]
    assert {n.name for n in keep} == {"flash", "status_for_draw"}
    cls.body = keep
    cls.bases = []
    mod = ast.Module(body=[cls], type_ignores=[])
    ns: dict = {"time": clock}
    exec(compile(mod, str(CONSOLE), "exec",
                 flags=__future__.annotations.compiler_flag, dont_inherit=True), ns)
    return ns["DashboardState"]


def test_a_flash_is_drawn_once_even_when_the_redraw_is_late() -> None:
    # #3101 — the ttl counts from the first frame that draws the flash, so a
    # footer redraw several seconds after the call cannot swallow it.
    class Clock:
        now = 1000.0

        @classmethod
        def time(cls) -> float:
            return cls.now

    st = _dashboard_state_class(Clock)()
    st.status_message, st.status_expires = "", 0.0
    st.flash("Reboot cancelled", ttl=5)
    Clock.now += 8.0  # slow redraw, past the ttl
    assert st.status_for_draw() == "Reboot cancelled"
    Clock.now += 4.0
    assert st.status_for_draw() == "Reboot cancelled"
    Clock.now += 1.5  # 5.5 s after the first draw
    assert st.status_for_draw() == ""


# ---- #3162: a cancel after the handoff asked for the switchover ---------------

def test_a_cancelled_power_action_ends_by_the_signal_not_as_a_failure(tmp_path: Path) -> None:
    """An exit 1 left spatium-power-action@reboot.service "failed" after the
    console's F9 (#3162). Death by the stop's signal is clean only because the
    units list it in SuccessExitStatus= (see the unit test below). A caller
    (the Fleet agent) still reads a non-zero status: no reboot."""
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    proc.terminate()
    assert proc.wait(20) == -signal.SIGTERM
    out = proc.stdout.read()
    assert "reboot cancelled" in out
    assert "systemctl reboot" not in _calls(log)


def test_a_failed_systemctl_still_fails(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", systemctl_rc=1)
    assert proc.wait(30) == 1


def test_a_cancel_inside_the_grace_never_reaches_the_handoff(tmp_path: Path) -> None:
    """The console's 10 s grace runs before the handoff, so F9 inside it asks
    CNPG for nothing: no switchover, and nothing to report."""
    proc, log = _run(tmp_path, "reboot", handoff="switch",
                     extra_env={"SPATIUM_POWER_ACTION_GRACE_S": "30"})
    _wait_for(lambda: (tmp_path / "marker").exists())
    time.sleep(0.3)
    proc.terminate()
    assert proc.wait(20) == -signal.SIGTERM
    # only the undo, which finds no cordon of its own to take off
    assert _calls(log) == ["handoff --undo"]
    assert not (tmp_path / "marker-switchover").exists()
    assert "switchover" not in proc.stdout.read()


def test_a_cancel_once_the_switchover_was_asked_for_says_it_completes(tmp_path: Path) -> None:
    proc, log = _run(tmp_path, "reboot", handoff="switch")
    switchover = tmp_path / "marker-switchover"
    _wait_for(switchover.exists)
    proc.terminate()
    assert proc.wait(20) == -signal.SIGTERM
    assert _calls(log) == ["handoff --before-reboot", "handoff --undo"]
    out = proc.stdout.read()
    assert "switchover the handoff had asked of CloudNativePG still completes" in out
    # kept for the console, which reads it once its stop has returned
    assert switchover.read_text().split() == ["spatium/pg", "pg-1"]
    assert not (tmp_path / "marker").exists()


def test_a_cancel_before_the_switchover_was_asked_for_says_nothing_of_one(
        tmp_path: Path) -> None:
    (tmp_path / "marker-switchover").write_text("left by an earlier run\n")
    proc, log = _run(tmp_path, "reboot", handoff="hang")
    _wait_for(lambda: _calls(log) == ["handoff --before-reboot"])
    # an earlier run's note is gone as soon as this one starts
    assert not (tmp_path / "marker-switchover").exists()
    proc.terminate()
    assert proc.wait(20) == -signal.SIGTERM
    assert "switchover" not in proc.stdout.read()


def test_a_failed_systemctl_takes_the_switchover_note_down(tmp_path: Path) -> None:
    """Else a later cancel of a web-UI reboot still in its grace (no wrapper
    yet) would read a switchover that is long over."""
    proc, log = _run(tmp_path, "reboot", systemctl_rc=1, handoff="noted")
    assert proc.wait(30) == 1
    assert _calls(log) == ["handoff --before-reboot", "systemctl reboot", "handoff --undo"]
    assert not (tmp_path / "marker-switchover").exists()


def test_the_console_cancel_says_a_begun_switchover_completes(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    (state / "reboot-pending").write_text("x")
    note = tmp_path / "switchover"
    stops: list[list[str]] = []

    def run(argv):
        # the wrapper, stopped, leaves the handoff's note behind
        stops.append(argv)
        note.write_text("spatium/pg pg-1\n")

    con = _console(state, boot, run)
    con["POWER_ACTION_SWITCHOVER"] = note
    dash, fc = _FlashRecorder(), _FakeConsole()
    con["do_cancel_reboot"](fc, dash)
    assert stops and stops[0][:2] == ["systemctl", "stop"]
    assert any("Reboot cancelled." in line for line in fc.out), fc.out
    assert any("completes the switchover it started" in line for line in fc.out), fc.out
    assert "switchover" in dash.flashes[-1]
    assert not note.exists()


def test_the_console_cancel_mentions_no_switchover_when_none_was_asked_for(
        tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    (state / "reboot-pending").write_text("x")
    con = _console(state, boot, lambda argv: None)
    con["POWER_ACTION_SWITCHOVER"] = tmp_path / "switchover"
    dash, fc = _FlashRecorder(), _FakeConsole()
    con["do_cancel_reboot"](fc, dash)
    assert not any("switchover" in line for line in fc.out), fc.out
    assert dash.flashes[-1] == "Reboot cancelled"


def test_the_console_reads_the_note_the_wrapper_keeps() -> None:
    """The console's path and the wrapper's default are one file."""
    assert 'POWER_ACTION_SWITCHOVER = Path("/run/spatium-power-action-switchover")' in \
        CONSOLE.read_text()
    text = SCRIPT.read_text()
    assert 'MARKER="${SPATIUM_POWER_ACTION_MARKER:-/run/spatium-power-action}"' in text
    assert 'SWITCHOVER="${SPATIUM_POWER_ACTION_SWITCHOVER:-${MARKER}-switchover}"' in text


def _cancel_with_note(tmp_path: Path, *, note_age_s: float, wrapper_running: bool):
    """F9 with a switchover note already on disk before the stop (the stop
    itself writes nothing)."""
    state = tmp_path / "state"
    state.mkdir()
    boot = tmp_path / "boot_id"
    boot.write_text(BOOT + "\n")
    (state / "reboot-pending").write_text("x")
    note = tmp_path / "switchover"
    note.write_text("spatium/pg pg-1\n")
    old = time.time() - note_age_s
    os.utime(note, (old, old))
    con = _console(state, boot, lambda argv: None)
    con["POWER_ACTION_SWITCHOVER"] = note
    if wrapper_running:
        marker = tmp_path / "power-action-marker"
        marker.write_text(f"{os.getpid()} reboot\n")  # a live pid
        con["POWER_ACTION_MARKER"] = marker
    dash, fc = _FlashRecorder(), _FakeConsole()
    con["do_cancel_reboot"](fc, dash)
    return note, dash, fc


def test_the_console_cancel_ignores_a_note_left_by_an_earlier_run(tmp_path: Path) -> None:
    """#3162 validation — a run stopped some other way (a manual systemctl stop)
    keeps its note; F9 on a later web-UI / Fleet reboot still in its grace (no
    wrapper yet, so nothing removed it) must not report that old switchover."""
    note, dash, fc = _cancel_with_note(tmp_path, note_age_s=3600, wrapper_running=False)
    assert not any("switchover" in line for line in fc.out), fc.out
    assert dash.flashes[-1] == "Reboot cancelled"
    assert not note.exists()


def test_the_console_cancel_reports_the_running_wrappers_note(tmp_path: Path) -> None:
    """The handoff noted the switchover a while before F9: the wrapper was
    running when it was stopped, so the note is this run's."""
    note, dash, fc = _cancel_with_note(tmp_path, note_age_s=60, wrapper_running=True)
    assert any("completes the switchover it started" in line for line in fc.out), fc.out
    assert "switchover" in dash.flashes[-1]
    assert not note.exists()


def test_the_console_cancel_does_not_claim_the_node_is_uncordoned(tmp_path: Path) -> None:
    """--undo leaves a cordon it did not set (an operator's, an upgrade's) and
    can run out of time on a slow API, so the console promises only that the
    node stays up."""
    _, _, fc = _cancel_with_note(tmp_path, note_age_s=1, wrapper_running=True)
    assert any("This node stays up." in line for line in fc.out), fc.out
    assert not any("uncordoned" in line for line in fc.out), fc.out


_UNITS = EXTRA / "etc" / "systemd" / "system"


@pytest.mark.parametrize("unit", [
    "spatium-power-action@.service",
    "spatiumddi-reboot.service",
    "spatiumddi-reboot-agent.service",
])
def test_a_cancelled_run_leaves_its_unit_inactive_not_failed(unit: str) -> None:
    """#3162 validation — for Type=oneshot, systemd counts the main process
    dying by SIGTERM / SIGINT / SIGHUP as a FAILURE (result 'signal'): only
    Type=simple and friends treat those as clean. Ending by the stop's signal
    therefore leaves the unit failed just as the old exit 1 did, unless the
    unit lists the signals in SuccessExitStatus= (checked on systemd 257)."""
    lines = [ln.strip() for ln in (_UNITS / unit).read_text().splitlines()]
    assert "Type=oneshot" in lines
    listed: set[str] = set()
    for ln in lines:
        if ln.startswith("SuccessExitStatus="):
            listed |= set(ln.split("=", 1)[1].split())
    assert {"TERM", "INT", "HUP"} <= listed, listed
    # a failed systemctl reboot (exit 1) must still fail the unit
    assert "1" not in listed
