"""#4549 — the interactive installer runs on the serial console too.

Before this, ``spatium-install.service`` owned ``/dev/tty1`` alone and no
getty ran on the serial port in install mode, so on IPMI Serial-over-LAN, a
headless server or a serial-only VM the operator saw GRUB and the kernel and
then nothing. The fix is a serial twin (``spatium-install@.service``) and an
arbitration step in the wizard so only one console installs.

The arbitration functions are run for real under bash (the script ends in
``main "$@"`` so it cannot be sourced; ``extract_fn`` slices them out, as the
rest of this suite does). The unit wiring is asserted structurally, because
systemd cannot run here.
"""

from __future__ import annotations

import configparser
import re
import subprocess
from pathlib import Path

from _installer_source import INSTALLER, SRC, extract_fn

ROOT = Path(__file__).parent.parent
UNITS = ROOT / "mkosi.extra" / "etc" / "systemd" / "system"
POSTINST = (ROOT / "mkosi.postinst").read_text(encoding="utf-8")

FNS = ["_this_console", "claim_console", "release_console", "_serial_may_run"]


def _bash(tmp_path: Path, script: str, env_extra: dict | None = None):
    funcs = "\n".join(extract_fn(n) for n in FNS)
    prelude = f"""
log() {{ :; }}
clear() {{ :; }}
INSTALL_LOCK={tmp_path}/lock
INSTALL_OWNER={tmp_path}/owner
PRESEED_VERDICT={tmp_path}/verdict
{funcs}
"""
    env = {"PATH": "/usr/bin:/bin"}
    env.update(env_extra or {})
    return subprocess.run(
        ["bash", "-c", prelude + script],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_second_console_is_told_where_the_install_runs(tmp_path):
    # Two real processes, as with two units: the first takes the lock and
    # keeps holding it while the second tries.
    funcs = "\n".join(extract_fn(n) for n in FNS)
    prelude = f"""
log() {{ :; }}
clear() {{ :; }}
INSTALL_LOCK={tmp_path}/lock
INSTALL_OWNER={tmp_path}/owner
{funcs}
"""
    env = {"PATH": "/usr/bin:/bin"}
    winner = subprocess.Popen(
        ["bash", "-c", prelude + "_this_console() { echo tty1; }\nclaim_console\necho held\nsleep 20"],
        stdout=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        assert winner.stdout.readline().strip() == "held"
        loser = subprocess.run(
            [
                "bash",
                "-c",
                prelude + "_this_console() { echo ttyS0; }\nclaim_console\necho LOSER-CONTINUED",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
    finally:
        winner.kill()
        winner.wait()
    assert "already running on tty1" in loser.stdout, loser.stderr
    assert "LOSER-CONTINUED" not in loser.stdout, "the second console must exit, not carry on"
    assert loser.returncode == 0


def test_claim_is_idempotent_and_release_frees_the_lock(tmp_path):
    # Back-navigation re-enters the welcome step; a second claim by the
    # owner must not lock itself out. After release the other console can
    # take over (the wizard dropped to a shell).
    script = """
_this_console() { echo tty1; }
claim_console
claim_console
echo "again-ok"
release_console
( _this_console() { echo ttyS0; }; claim_console; echo "TAKEN-OVER owner=$(cat "$INSTALL_OWNER")" )
"""
    r = _bash(tmp_path, script)
    assert "again-ok" in r.stdout, r.stderr
    assert "TAKEN-OVER owner=ttyS0" in r.stdout


def test_serial_console_runs_only_when_tty1_found_no_preseed(tmp_path):
    verdict = tmp_path / "verdict"
    for text, expect in (("none\n", 0), ("preseed\n", 1)):
        verdict.write_text(text)
        r = _bash(tmp_path, "_serial_may_run")
        assert r.returncode == expect, (text, r.stderr)
    # tty1 never answered (halted, or died): stand down rather than guess.
    verdict.unlink()
    r = _bash(tmp_path, "_serial_may_run", {"SPATIUM_INSTALL_VERDICT_WAIT": "1"})
    assert r.returncode == 1


def test_main_wires_serial_gate_before_preseed_and_claim_at_welcome():
    main = extract_fn("main")
    serial_gate = main.index('SPATIUM_INSTALL_CONSOLE:-}" = "serial"')
    load = main.index("        load_preseed")
    assert serial_gate < load, "the serial instance must not run discovery itself"
    # tty1 writes the verdict the serial instance waits on.
    assert "PRESEED_VERDICT" in main
    welcome_case = re.search(r"welcome\)\n(.*?)\n\s+confirm\)", main, re.S).group(1)
    assert "claim_console" in welcome_case
    # the claim comes after the welcome screen is answered / skipped
    assert welcome_case.index("welcome\n") < welcome_case.index("claim_console")


def test_recovery_shells_release_the_lock():
    # fd 8 would otherwise ride into the shell and hold the other console out.
    for fn in ("on_cancel", "on_failure"):
        body = extract_fn(fn)
        assert body.index("release_console") < body.index("exec /bin/bash --login"), fn


def _unit(name: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # type: ignore[assignment]
    raw = "\n".join(
        ln for ln in (UNITS / name).read_text().splitlines() if not ln.lstrip().startswith("#")
    )
    cp.read_string(raw)
    return cp


def test_serial_install_unit_shape():
    text = (UNITS / "spatium-install@.service").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "TTYPath=/dev/%I" in code
    assert "ConditionKernelCommandLine=spatium-mode=install" in code
    # No device behind the node is a skip, not a failed unit (#994).
    assert re.search(r"^ExecCondition=.*: > /dev/%I", code, re.M)
    assert "Environment=SPATIUM_INSTALL_CONSOLE=serial" in code
    assert "SPATIUM_INSTALL_TRACE_LOG=/var/log/spatium-install-trace-%I.log" in code
    assert "Environment=TERM=vt220" in code
    # Same hazard as the tty1 unit: a load-time Conflicts= leaks onto the
    # installed system and drops the serial getty from its boot.
    assert not re.search(r"^Conflicts=", code, re.M)
    assert "Restart=no" in code
    # tty1 is untouched.
    tty1 = (UNITS / "spatium-install.service").read_text()
    assert "TTYPath=/dev/tty1" in tty1
    assert "SPATIUM_INSTALL_CONSOLE" not in tty1


def test_serial_banner_unit_and_postinst_enable_ttyS0_instances():
    assert "TTYPath=/dev/%I" in (UNITS / "spatium-live-banner@.service").read_text()
    for tmpl in ("spatium-install", "spatium-live-banner"):
        assert f"{tmpl}@.service" in POSTINST
        assert f"chmod 0644 \"$BUILDROOT/etc/systemd/system/{tmpl}@.service\"" in POSTINST
    assert "multi-user.target.wants/${tmpl}@ttyS0.service" in POSTINST


def test_serial_tty_sizes_fall_back_to_80x24():
    # The kernel reports 0x0 for a serial line; the dialog helpers must read
    # that as the smallest supported console, not as "no room".
    assert "term=24" in extract_fn("_whiptail_height")
    assert "term=80" in extract_fn("_whiptail_width")
    assert INSTALLER.exists() and SRC
