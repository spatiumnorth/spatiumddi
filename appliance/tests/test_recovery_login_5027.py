"""The GRUB recovery entry opens a shell for the admin account (#5027).

rescue.target's stock shell is sulogin, which wants ROOT's password. Root is
locked on a default install (#995 item 12), so the entry printed "Cannot open
access to console, the root account is locked." and gave no shell.
rescue.service is now overridden by a drop-in that runs
spatium-recovery-login: a username + password prompt on each enabled console,
PAM through login(1), root and `sudo` group members only.

    python3 -m pytest appliance/tests/test_recovery_login_5027.py -v

login, id, setsid, pkill and systemctl are stubbed; no root, no console.
"""

from __future__ import annotations

import configparser
import os
import re
import subprocess
from pathlib import Path

import pytest

APPLIANCE = Path(__file__).parent.parent
SCRIPT = APPLIANCE / "mkosi.extra/usr/local/bin/spatium-recovery-login"
DROPIN_DIR = APPLIANCE / "mkosi.extra/etc/systemd/system/rescue.service.d"
SYSTEMD = APPLIANCE / "mkosi.extra/etc/systemd/system"
RENDERER = APPLIANCE / "mkosi.extra/usr/local/bin/spatium-grub-render"


def _dropin() -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False, allow_no_value=True)
    cp.optionxform = str
    cp.read_string("\n".join(
        ln for ln in (DROPIN_DIR / "spatium-recovery-login.conf").read_text().splitlines()
        if not ln.startswith("#")
    ))
    return cp


def test_dropin_replaces_the_sulogin_execstart() -> None:
    execs = [ln.split("=", 1)[1] for ln in
             (DROPIN_DIR / "spatium-recovery-login.conf").read_text().splitlines()
             if ln.startswith("ExecStart=")]
    # An empty ExecStart= clears sulogin-shell, then ours; `-` so a failure
    # never fails the unit (the script itself continues the boot).
    assert execs == ["", "-/usr/local/bin/spatium-recovery-login"]
    assert _dropin()["Service"]["StandardInput"] == "null"


def test_only_rescue_service_is_overridden() -> None:
    """Normal boots never run rescue.service; no other unit's login is touched."""
    assert sorted(p.name for p in DROPIN_DIR.iterdir()) == ["spatium-recovery-login.conf"]
    for d in SYSTEMD.glob("*.d"):
        for f in d.glob("*.conf"):
            if d.name != "rescue.service.d":
                assert "spatium-recovery-login" not in f.read_text(), f


def test_script_is_executable_and_chmodded_in_postinst() -> None:
    assert os.access(SCRIPT, os.X_OK)
    post = (APPLIANCE / "mkosi.postinst").read_text()
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-recovery-login"' in post


def test_grub_rescue_entry_describes_the_login() -> None:
    import sys
    out = subprocess.run(
        [sys.executable, str(RENDERER), "--print", "--root-a-uuid", "a", "--root-b-uuid", "b"],
        capture_output=True, text=True, check=True,
    ).stdout
    start = out.index("--id=rescue {")
    blk = out[start : out.index("\n}", start)]
    assert "spatium-recovery-login.conf" in blk
    assert "username + password" in blk
    assert "systemd.unit=rescue.target" in blk
    assert "root shell only" not in blk and "cannot open a shell:" not in blk
    assert "recovery login)" in out


# ── the script ────────────────────────────────────────────────────────────────

def _run(tmp_path: Path, consoles: str, inputs: dict[str, str], logins: dict[str, int]):
    """Run the script. logins maps username -> exit status of the stubbed login."""
    bindir = tmp_path / "bin"
    dev = tmp_path / "dev"
    bindir.mkdir()
    dev.mkdir()
    log = tmp_path / "calls.log"
    (tmp_path / "consoles").write_text(consoles)
    for name, text in inputs.items():
        (dev / name).write_text(text)
    # id -nG: root -> root; alice -> sudo; bob -> users; others unknown.
    (bindir / "id").write_text(
        '#!/bin/sh\nfor a; do u=$a; done\ncase "$u" in root) echo root;; alice) echo "alice sudo";;'
        ' bob) echo "bob users";; *) exit 1;; esac\n')
    cases = "".join(f"{u}) echo login {u} >>{log}; exit {rc};; " for u, rc in logins.items())
    (bindir / "login").write_text(f'#!/bin/sh\ncase "$2" in {cases}esac; exit 1\n')
    # setsid -w -c login -- USER  ->  login -- USER
    (bindir / "setsid").write_text('#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do shift; done\nexec "$@"\n')
    # never signal by tty on the machine running the tests
    (bindir / "pkill").write_text('#!/bin/sh\n[ "$1" = -t ] && exit 0\nexec /usr/bin/pkill "$@"\n')
    (bindir / "systemctl").write_text(f"#!/bin/sh\necho systemctl $* >>{log}\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "SPATIUM_RECOVERY_PROC_CONSOLES": str(tmp_path / "consoles"),
        "SPATIUM_RECOVERY_DEV": str(dev),
        "SPATIUM_RECOVERY_DELAY": "0",
        "SPATIUM_RECOVERY_OUT_SUFFIX": ".out",
    }
    r = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True,
                       timeout=60)
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls


TTY = "tty0 -WU (E  p  )  4:1\nttyS0 -W- (EC p a)  4:64\n"


def test_sudo_member_gets_a_shell_and_boot_continues(tmp_path) -> None:
    r, calls = _run(tmp_path, TTY, {"tty1": "alice\n"}, {"alice": 0})
    assert calls == ["login alice", "systemctl --no-block default"], r.stderr


def test_root_is_offered_the_same_login(tmp_path) -> None:
    r, calls = _run(tmp_path, TTY, {"ttyS0": "root\n"}, {"root": 0})
    assert calls[0] == "login root"


def test_account_outside_sudo_is_refused_before_login(tmp_path) -> None:
    # bob is refused, unknown is refused; alice on the next lines still works.
    r, calls = _run(tmp_path, TTY, {"tty1": "bob\nnobody\nalice\n"},
                    {"bob": 0, "nobody": 0, "alice": 0})
    assert calls == ["login alice", "systemctl --no-block default"]
    assert "Login incorrect" in (tmp_path / "dev" / "tty1.out").read_text()


def test_wrong_password_is_refused_and_prompts_again(tmp_path) -> None:
    # alice's first login fails (login exits 1), the second is not stubbed to
    # differ, so feed a user whose login fails, then one that succeeds.
    r, calls = _run(tmp_path, TTY, {"tty1": "root\nalice\n"}, {"root": 1, "alice": 0})
    assert calls == ["login root", "login alice", "systemctl --no-block default"]


def test_only_enabled_consoles_are_prompted(tmp_path) -> None:
    consoles = "tty0 -WU (E  p  )  4:1\nttyS1 -W- (C p a)  4:65\n"
    r, calls = _run(tmp_path, consoles, {"tty1": "alice\n", "ttyS1": "root\n"},
                    {"alice": 0, "root": 0})
    assert calls == ["login alice", "systemctl --no-block default"]


def test_nothing_is_accepted_without_a_password_check(tmp_path) -> None:
    """The group filter only narrows: every accepted name still goes through login."""
    text = SCRIPT.read_text()
    assert re.search(r"setsid -w -c login -- ", text)
    assert "autologin" not in text.lower() and "login -f" not in text
