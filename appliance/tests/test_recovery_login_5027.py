"""The GRUB recovery entry and emergency mode open a shell for the admin account (#5027).

rescue.target's stock shell is sulogin, which wants ROOT's password. Root is
locked on a default install (#995 item 12), so the entry printed "Cannot open
access to console, the root account is locked." and gave no shell.
rescue.service is now overridden by a drop-in that runs
spatium-recovery-login: a username + password prompt on each enabled console,
PAM through login(1), root and `sudo` group members only. emergency.service
has the same drop-in; emergency.target mounts only the root filesystem, so the
script mounts /var and a read-only /etc overlay for the session (never a
password-free shell), and unmounts them before the boot continues.

    python3 -m pytest appliance/tests/test_recovery_login_5027.py -v

login, id, setsid, pkill, mount, umount, mountpoint and systemctl are stubbed; no root, no console.
"""

from __future__ import annotations

import configparser
import os
import re
import signal
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


EMERGENCY_DIR = SYSTEMD / "emergency.service.d"


def test_emergency_dropin_runs_the_same_login() -> None:
    text = (EMERGENCY_DIR / "spatium-recovery-login.conf").read_text()
    execs = [ln.split("=", 1)[1] for ln in text.splitlines() if ln.startswith("ExecStart=")]
    assert execs == ["", "-/usr/local/bin/spatium-recovery-login --emergency"]
    assert "StandardInput=null" in text
    assert "SYSTEMD_SULOGIN_FORCE" not in "\n".join(
        ln for ln in text.splitlines() if not ln.startswith("#")
    )


def test_old_sulogin_dropin_sorts_before_ours() -> None:
    """An install made before this change keeps 10-spatium-sulogin.conf; systemd
    merges drop-ins by filename, so ours (the ExecStart reset) is applied last."""
    assert "10-spatium-sulogin.conf" < "spatium-recovery-login.conf"


def test_only_rescue_and_emergency_services_are_overridden() -> None:
    """Normal boots never run either; no other unit's login is touched."""
    for d in (DROPIN_DIR, EMERGENCY_DIR):
        assert sorted(p.name for p in d.iterdir()) == ["spatium-recovery-login.conf"]
    for d in SYSTEMD.glob("*.d"):
        for f in d.glob("*.conf"):
            if d.name not in ("rescue.service.d", "emergency.service.d"):
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

def _run(tmp_path: Path, consoles: str, inputs: dict[str, str], logins: dict[str, int],
         nologin: bool = True, args: tuple[str, ...] = (), etc_mounted: bool = True,
         var_mounted: bool = False, mount_ok: bool = True, accounts: bool = True,
         lower_exists: bool = True, timeout: int = 60):
    """Run the script. logins maps username -> exit status of the stubbed login.

    mountpoint/mount/umount are stubs recording to calls.log: /etc is a mount point
    when etc_mounted (rescue: etc.mount ran), /var when var_mounted; mount fails
    unless mount_ok. accounts: whether the bare /etc has someone who can log in.
    """
    bindir = tmp_path / "bin"
    dev = tmp_path / "dev"
    bindir.mkdir()
    dev.mkdir()
    log = tmp_path / "calls.log"
    (tmp_path / "consoles").write_text(consoles)
    if nologin:
        (tmp_path / "nologin").write_text("System is booting up.\n")
    for name, text in inputs.items():
        (dev / name).write_text(text)
    # id -nG: root -> root; alice -> sudo; bob -> users; others unknown.
    (bindir / "id").write_text(
        '#!/bin/sh\nfor a; do u=$a; done\ncase "$u" in root) echo root;; alice) echo "alice sudo";;'
        ' bob) echo "bob users";; *) exit 1;; esac\n')
    cases = "".join(f"{u}) echo login {u} >>{log}; exit {rc};; " for u, rc in logins.items())
    # pam_nologin: while the file exists login refuses everyone (here: exit 1, no log line).
    (bindir / "login").write_text(
        f'#!/bin/sh\n[ -e {tmp_path / "nologin"} ] && exit 1\ncase "$2" in {cases}esac; exit 1\n')
    # setsid -w -c login -- USER  ->  login -- USER
    (bindir / "setsid").write_text('#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do shift; done\nexec "$@"\n')
    # never signal by tty on the machine running the tests
    (bindir / "pkill").write_text('#!/bin/sh\n[ "$1" = -t ] && exit 0\nexec /usr/bin/pkill "$@"\n')
    state = tmp_path / "state"
    state.mkdir()
    for name, on in (("etc", etc_mounted), ("var", var_mounted)):
        if on:
            (state / name).touch()
    if lower_exists:
        (tmp_path / "lower").mkdir()
    (tmp_path / "var" / "persist" / "etc").mkdir(parents=True)
    # mountpoint -q DIR: "mounted" once its state file exists
    (bindir / "mountpoint").write_text(
        f'#!/bin/sh\ncase "$2" in {tmp_path}/etc) [ -e {state}/etc ];; *) [ -e {state}/var ];; esac\n')
    (bindir / "mount").write_text(
        f'#!/bin/sh\necho mount $* >>{log}\n' + ('' if mount_ok else 'echo boom >&2; exit 32\n')
        + f'for a; do t=$a; done\ncase "$t" in {tmp_path}/etc) touch {state}/etc;; *) touch {state}/var;; esac\n')
    (bindir / "umount").write_text(
        f'#!/bin/sh\necho umount $* >>{log}\nfor a; do t=$a; done\n'
        f'case "$t" in {tmp_path}/etc) rm -f {state}/etc;; *) rm -f {state}/var;; esac\n')
    (bindir / "passwd").write_text(f'#!/bin/sh\necho "root {"P" if accounts else "L"} x"\n')
    (bindir / "getent").write_text(f'#!/bin/sh\necho "sudo:x:27:{"alice" if accounts else ""}"\n')
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
        "SPATIUM_RECOVERY_NOLOGIN": str(tmp_path / "nologin"),
        "SPATIUM_RECOVERY_ETC": str(tmp_path / "etc"),
        "SPATIUM_RECOVERY_VAR": str(tmp_path / "var"),
        "SPATIUM_RECOVERY_ETC_LOWER": str(tmp_path / "lower"),
    }
    # A new session, so a timeout can kill the console loops it leaves behind.
    p = subprocess.Popen(["bash", str(SCRIPT), *args], env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        raise
    r = subprocess.CompletedProcess(p.args, p.returncode, out, err)
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


def test_run_nologin_is_cleared_so_the_admin_can_log_in(tmp_path) -> None:
    """/run/nologin (tmpfiles, boot) makes pam_nologin refuse every non-root
    login; rescue.target never starts systemd-user-sessions to remove it."""
    r, calls = _run(tmp_path, TTY, {"tty1": "alice\n"}, {"alice": 0}, nologin=True)
    assert calls == ["login alice", "systemctl --no-block default"], r.stderr
    assert not (tmp_path / "nologin").exists()


def test_nologin_is_removed_only_after_the_group_check() -> None:
    """A refused name must not lift the boot-time restriction."""
    text = SCRIPT.read_text()
    assert text.index("if ! allowed") < text.index('rm -f -- "$NOLOGIN"') < text.index("setsid -w -c login")


def test_only_run_nologin_is_touched_by_default() -> None:
    """systemd-user-sessions start removes /run/nologin only; /etc/nologin is
    the operator's and keeps applying."""
    text = SCRIPT.read_text()
    assert "${SPATIUM_RECOVERY_NOLOGIN:-/run/nologin}" in text
    assert "/etc/nologin" not in text.replace("/etc/nologin stays", "")


def test_pkill_comes_from_procps_which_the_image_lists() -> None:
    """The script uses pkill; procps must be in the image on purpose, not by
    accident of openssh-server / cloud-init depending on it."""
    pkgs = (APPLIANCE / "mkosi.conf").read_text().split()
    assert "procps" in pkgs


def test_installer_writes_no_sulogin_drop_in() -> None:
    """The installer's SYSTEMD_SULOGIN_FORCE drop-in (a password-free root shell)
    reached only the slot it wrote, because it lands in the /etc overlay that is
    mounted after systemd loads its units. Both rescue and emergency now use the
    image's own drop-ins; the installer writes neither."""
    installer = (APPLIANCE / "mkosi.extra/usr/local/bin/spatium-install").read_text()
    assert "SYSTEMD_SULOGIN_FORCE=1" not in installer
    assert "10-spatium-sulogin" not in installer
    assert "$_u.service.d" not in installer
    assert "mkdir -p \"$MOUNT/etc/systemd/system/emergency.service.d\"" not in installer


# ── emergency mode: the account store ─────────────────────────────────────────

def test_emergency_mounts_var_and_a_readonly_overlay_then_undoes_them(tmp_path) -> None:
    r, calls = _run(tmp_path, TTY, {"tty1": "alice\n"}, {"alice": 0},
                    args=("--emergency",), etc_mounted=False)
    t = str(tmp_path)
    assert calls == [
        f"mount -o ro -L var {t}/var",
        f"mount -t overlay overlay -o ro,lowerdir={t}/var/persist/etc:{t}/lower {t}/etc",
        "login alice",
        f"umount -- {t}/etc",
        f"umount -- {t}/var",
        "systemctl --no-block default",
    ], r.stderr
    assert "emergency mode" in (tmp_path / "dev" / "tty1.out").read_text()


def test_nothing_is_mounted_when_etc_is_already_the_overlay(tmp_path) -> None:
    """rescue.target, or emergency reached after etc.mount ran: no mounts, and
    nothing of systemd's own is unmounted."""
    r, calls = _run(tmp_path, TTY, {"tty1": "alice\n"}, {"alice": 0}, etc_mounted=True)
    assert calls == ["login alice", "systemctl --no-block default"], r.stderr


def test_an_already_mounted_var_is_left_alone(tmp_path) -> None:
    r, calls = _run(tmp_path, TTY, {"tty1": "alice\n"}, {"alice": 0},
                    etc_mounted=False, var_mounted=True)
    t = str(tmp_path)
    assert [c.split()[0] for c in calls] == ["mount", "login", "umount", "systemctl"], calls
    assert calls[0].endswith(f"{t}/etc") and calls[2] == f"umount -- {t}/etc"


def test_fallback_notice_names_the_reason_and_the_way_out(tmp_path) -> None:
    out = _run_fallback(tmp_path, accounts=False)
    assert "did not mount: boom" in out
    assert "No account here can log in" in out
    assert "Ctrl-Alt-Del" in out and 'labelled "var"' in out
    assert "recovery login:" not in out


def test_fallback_with_a_bare_etc_account_still_asks_for_a_password(tmp_path) -> None:
    out = _run_fallback(tmp_path, accounts=True)
    assert "did not mount: boom" in out
    assert "recovery login:" in out
    assert "No account here can log in" not in out


def _run_fallback(tmp_path: Path, accounts: bool) -> str:
    """Run in emergency mode with /var failing to mount; stop it after a moment
    (with no account it waits for a reboot) and return what the console showed."""
    try:
        _run(tmp_path, TTY, {"tty1": "alice\n"}, {"alice": 0}, args=("--emergency",),
             etc_mounted=False, mount_ok=False, accounts=accounts, timeout=3)
    except subprocess.TimeoutExpired:
        pass
    return (tmp_path / "dev" / "tty1.out").read_text()
