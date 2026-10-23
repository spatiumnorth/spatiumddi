"""Host-portable pytest for the #549 preseed installer's security guards.

Issue #581 — the security half of the salvage from the closed PR #579.
PR #582 landed the offline ``--check-preseed`` linter + its suite and
explicitly deferred these items back to #581; this file covers them.

#549 is a disk-*wiping* feature, so each guard here is the thing standing
between an unattended run and an irreversible mistake:

  * ``_preseed_url_allowed`` / ``_preseed_url_verified`` — a kernel-cmdline
    preseed URL is the one answer-file transport that arrives over the
    network from an unauthenticated party, and the file it delivers
    authorises a full disk wipe. Plain http with no integrity pin is
    refused; https, or any scheme with a matching ``spatium.preseed.sha256=``
    pin, is accepted.
  * ``_live_boot_disks`` / ``_assert_safe_wipe_target`` — the interactive
    picker excludes the live install medium (#554), but the preseed path
    returns early from ``pick_disk`` and never ran that check. The pre-wipe
    guard re-validates for BOTH paths, immediately before ``wipefs``.
  * ``admin_user`` shape — flows into ``useradd`` and into the
    ``user:password`` line piped to ``chpasswd``; a colon or a reserved
    account name breaks the install *after* the disk is already gone.

The shell guards are exercised by extracting the function under test out
of the installer and running it in a stub harness — the script ends in
``main "$@"``, so it cannot simply be sourced. ``/proc/cmdline`` and
``/proc/mounts`` are redirected through the ``SPATIUM_CMDLINE_FILE`` /
``SPATIUM_MOUNTS_FILE`` seams (inert on a real install, same idea as
``spatium-preseed-parse``'s ``SPATIUM_FAKE_DISK_BYTES``).

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_preseed_security.py -v

No database, no Docker, no root, no block devices, no appliance ISO.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

INSTALLER = (
    Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin" /
    "spatium-install"
)

_SRC = INSTALLER.read_text(encoding="utf-8")


def extract_fn(name: str) -> str:
    """Pull one shell function definition out of the installer.

    The installer ends in ``main "$@"``, so sourcing it would run a real
    install. Every function in the file opens with ``name() {`` at column
    0 and closes with ``}`` at column 0, so a line-anchored slice is
    exact.
    """
    m = re.search(
        rf"^{re.escape(name)}\(\) \{{$.*?^\}}$",
        _SRC,
        re.MULTILINE | re.DOTALL,
    )
    assert m, f"function {name}() not found in {INSTALLER}"
    return m.group(0)


# Stubs for everything the extracted functions reach for. `log` is a
# no-op sink, and the two abort paths echo a marker + exit non-zero so a
# test can assert WHICH way the guard bailed.
HARNESS_PRELUDE = """
set -uo pipefail
log() { :; }
preseed_halt() { echo "PRESEED_HALT: $1"; exit 1; }
on_cancel() { echo "ON_CANCEL: $1"; exit 1; }
whiptail() { return 0; }
clear() { :; }
BACKTITLE="test"
MIN_DISK_GIB=32
FULLY_UNATTENDED=0
TARGET_DISK=""
"""


def run_fn(fns, body: str, *, cmdline: str = "", mounts: str = "",
           tmp_path: Path, extra: str = "") -> subprocess.CompletedProcess:
    """Run `body` with `fns` (list of installer function names) in scope."""
    cmdline_file = tmp_path / "cmdline"
    cmdline_file.write_text(cmdline, encoding="utf-8")
    mounts_file = tmp_path / "mounts"
    mounts_file.write_text(mounts, encoding="utf-8")

    script = "\n".join([
        HARNESS_PRELUDE,
        f'PROC_CMDLINE="{cmdline_file}"',
        f'PROC_MOUNTS="{mounts_file}"',
        extra,
        *(extract_fn(f) for f in fns),
        body,
    ])
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60,
    )


# ── Preseed URL integrity gate ────────────────────────────────────────
# A cmdline URL delivers an answer file carrying confirm_wipe + the admin
# password + the pairing code. Whoever controls those bytes controls the
# install, so the transport has to be authenticated (https) or the
# content pinned (sha256).

URL_FNS = ["_preseed_url_sha256", "_preseed_url_allowed"]


@pytest.mark.parametrize("url", [
    "https://boot.example.com/spatium-preseed.yaml",
    "https://10.0.0.5/preseed.yaml",
    "https://[2001:db8::1]/preseed.yaml",
])
def test_https_url_allowed_without_pin(url, tmp_path):
    """TLS authenticates the origin — no pin required."""
    r = run_fn(URL_FNS, f'_preseed_url_allowed "{url}" && echo ALLOW || echo REFUSE',
               cmdline=f"spatium-mode=install spatium.preseed={url}",
               tmp_path=tmp_path)
    assert "ALLOW" in r.stdout


@pytest.mark.parametrize("url", [
    "http://boot.example.com/spatium-preseed.yaml",
    "http://10.0.0.5/preseed.yaml",
])
def test_plain_http_url_refused_without_pin(url, tmp_path):
    """The MITM case: an on-path attacker rewrites the answer file and
    drives a disk wipe. Refused."""
    r = run_fn(URL_FNS, f'_preseed_url_allowed "{url}" && echo ALLOW || echo REFUSE',
               cmdline=f"spatium-mode=install spatium.preseed={url}",
               tmp_path=tmp_path)
    assert "REFUSE" in r.stdout


def test_plain_http_url_allowed_with_sha256_pin(tmp_path):
    """Content-pinning is the documented escape hatch for air-gapped /
    internal-CA PXE where https isn't practical."""
    pin = "a" * 64
    r = run_fn(URL_FNS, '_preseed_url_allowed "http://pxe/preseed.yaml" '
                        '&& echo ALLOW || echo REFUSE',
               cmdline=f"spatium.preseed=http://pxe/preseed.yaml "
                       f"spatium.preseed.sha256={pin}",
               tmp_path=tmp_path)
    assert "ALLOW" in r.stdout


def test_sha256_pin_is_case_insensitive(tmp_path):
    """Operators paste digests from tools that emit upper-case hex."""
    r = run_fn(URL_FNS, '_preseed_url_sha256',
               cmdline="spatium.preseed.sha256=" + "AB" * 32,
               tmp_path=tmp_path)
    assert r.stdout.strip() == "ab" * 32


def test_no_pin_on_cmdline_yields_empty(tmp_path):
    r = run_fn(URL_FNS, '_preseed_url_sha256; echo "END"',
               cmdline="spatium-mode=install quiet",
               tmp_path=tmp_path)
    assert r.stdout.strip() == "END"


VERIFY_FNS = ["_preseed_url_sha256", "_preseed_url_verified"]


def test_verify_passes_with_no_pin(tmp_path):
    """No pin supplied — nothing to check, don't invent a failure."""
    f = tmp_path / "preseed.yaml"
    f.write_text("spatium_preseed: {}\n", encoding="utf-8")
    r = run_fn(VERIFY_FNS, f'_preseed_url_verified "{f}" && echo OK || echo BAD',
               cmdline="spatium-mode=install", tmp_path=tmp_path)
    assert "OK" in r.stdout


def test_verify_passes_on_matching_digest(tmp_path):
    import hashlib
    f = tmp_path / "preseed.yaml"
    content = "spatium_preseed:\n  role: control-plane\n"
    f.write_text(content, encoding="utf-8")
    digest = hashlib.sha256(content.encode()).hexdigest()
    r = run_fn(VERIFY_FNS, f'_preseed_url_verified "{f}" && echo OK || echo BAD',
               cmdline=f"spatium.preseed.sha256={digest}", tmp_path=tmp_path)
    assert "OK" in r.stdout


def test_verify_fails_on_tampered_content(tmp_path):
    """The whole point: a modified answer file must not be acted on."""
    import hashlib
    f = tmp_path / "preseed.yaml"
    original = "spatium_preseed:\n  role: control-plane\n"
    digest = hashlib.sha256(original.encode()).hexdigest()
    # What actually landed on disk is the attacker's version.
    f.write_text("spatium_preseed:\n  role: control-plane\n  confirm_wipe: true\n",
                 encoding="utf-8")
    r = run_fn(VERIFY_FNS, f'_preseed_url_verified "{f}" && echo OK || echo BAD',
               cmdline=f"spatium.preseed.sha256={digest}", tmp_path=tmp_path)
    assert "BAD" in r.stdout


def test_verify_fails_closed_when_file_unreadable(tmp_path):
    """A pin that cannot be checked is not a pin that passed."""
    r = run_fn(VERIFY_FNS,
               f'_preseed_url_verified "{tmp_path}/missing.yaml" && echo OK || echo BAD',
               cmdline="spatium.preseed.sha256=" + "b" * 64, tmp_path=tmp_path)
    assert "BAD" in r.stdout


# ── Live-boot-medium detection ────────────────────────────────────────

LIVE_FNS = ["_live_boot_disks"]


def test_live_boot_disks_finds_run_live_mounts(tmp_path):
    mounts = (
        "sysfs /sys sysfs rw 0 0\n"
        "/dev/sdb1 /run/live/medium vfat ro 0 0\n"
        "tmpfs /run tmpfs rw 0 0\n"
    )
    r = run_fn(LIVE_FNS, "_live_boot_disks", mounts=mounts, tmp_path=tmp_path)
    # lsblk can't resolve a fake device on the test host, so the basename
    # fallback in _live_boot_disks is what answers here.
    assert "/dev/sdb1" in r.stdout or "/dev/sdb" in r.stdout


def test_live_boot_disks_covers_lib_live_layout(tmp_path):
    """`boot=live toram` / older live-boot mount the medium under
    /lib/live/mount — the #554 case that findmnt alone missed."""
    mounts = "/dev/sdc1 /lib/live/mount/medium iso9660 ro 0 0\n"
    r = run_fn(LIVE_FNS, "_live_boot_disks", mounts=mounts, tmp_path=tmp_path)
    assert "sdc" in r.stdout


def test_live_boot_disks_ignores_unrelated_mounts(tmp_path):
    mounts = (
        "/dev/sda1 / ext4 rw 0 0\n"
        "/dev/sda2 /home ext4 rw 0 0\n"
        "proc /proc proc rw 0 0\n"
    )
    r = run_fn(LIVE_FNS, '_live_boot_disks; echo "END"',
               mounts=mounts, tmp_path=tmp_path)
    assert r.stdout.strip() == "END"


def test_live_boot_disks_skips_non_dev_sources(tmp_path):
    """A tmpfs/overlay source under /run/live has no parent disk."""
    mounts = (
        "tmpfs /run/live/overlay tmpfs rw 0 0\n"
        "overlay /run/live/rootfs overlay rw 0 0\n"
    )
    r = run_fn(LIVE_FNS, '_live_boot_disks; echo "END"',
               mounts=mounts, tmp_path=tmp_path)
    assert r.stdout.strip() == "END"


# ── Pre-wipe guard ────────────────────────────────────────────────────

GUARD_FNS = ["_live_boot_disks", "_assert_safe_wipe_target"]


def test_wipe_guard_refuses_empty_target(tmp_path):
    r = run_fn(GUARD_FNS, "_assert_safe_wipe_target; echo REACHED_WIPE",
               tmp_path=tmp_path, extra='TARGET_DISK=""')
    assert "REACHED_WIPE" not in r.stdout
    assert "ON_CANCEL" in r.stdout


def test_wipe_guard_refuses_non_block_device(tmp_path):
    """A preseed pointing at a regular file (or a path that stopped being
    a device between parse and wipe) must not reach wipefs."""
    decoy = tmp_path / "not-a-disk"
    decoy.write_text("", encoding="utf-8")
    r = run_fn(GUARD_FNS, "_assert_safe_wipe_target; echo REACHED_WIPE",
               tmp_path=tmp_path, extra=f'TARGET_DISK="{decoy}"')
    assert "REACHED_WIPE" not in r.stdout
    assert "ON_CANCEL" in r.stdout


def test_wipe_guard_explains_why_it_refused(tmp_path):
    """The refusal reason has to reach the operator, not just the log —
    on the unattended path preseed_halt is what prints it.
    """
    decoy = tmp_path / "not-a-disk"
    decoy.write_text("", encoding="utf-8")
    r = run_fn(GUARD_FNS, "_assert_safe_wipe_target; echo REACHED_WIPE",
               tmp_path=tmp_path,
               extra=f'TARGET_DISK="{decoy}"\nFULLY_UNATTENDED=1')
    assert "not a block device" in r.stdout


def test_wipe_guard_halts_loudly_when_unattended(tmp_path):
    """Unattended runs get preseed_halt (non-zero, no console prompt),
    never a whiptail box nobody is there to answer."""
    decoy = tmp_path / "not-a-disk"
    decoy.write_text("", encoding="utf-8")
    r = run_fn(GUARD_FNS, "_assert_safe_wipe_target; echo REACHED_WIPE",
               tmp_path=tmp_path,
               extra=f'TARGET_DISK="{decoy}"\nFULLY_UNATTENDED=1')
    assert "REACHED_WIPE" not in r.stdout
    assert "PRESEED_HALT" in r.stdout
    assert r.returncode != 0


def test_wipe_guard_rejects_the_live_install_medium(tmp_path):
    """The #554 regression the preseed path reopened: pick_disk excludes
    the boot USB, but a preseeded target_disk skips pick_disk entirely.

    Uses /dev/null — a real device node that is not a whole disk — as the
    stand-in target, and declares it as the live medium. The guard must
    refuse either way; what must never happen is falling through to the
    wipe.
    """
    mounts = "/dev/null /run/live/medium vfat ro 0 0\n"
    r = run_fn(GUARD_FNS, "_assert_safe_wipe_target; echo REACHED_WIPE",
               mounts=mounts, tmp_path=tmp_path,
               extra='TARGET_DISK="/dev/null"\nFULLY_UNATTENDED=1')
    assert "REACHED_WIPE" not in r.stdout
    assert "PRESEED_HALT" in r.stdout


def test_wipe_guard_rejects_a_partition(tmp_path):
    """target_disk must be a whole disk; the layout repartitions it."""
    # /dev/console is a char device: not a block device, so the guard
    # bails at the earlier arm. Assert only that it refuses.
    r = run_fn(GUARD_FNS, "_assert_safe_wipe_target; echo REACHED_WIPE",
               tmp_path=tmp_path,
               extra='TARGET_DISK="/dev/console"\nFULLY_UNATTENDED=1')
    assert "REACHED_WIPE" not in r.stdout


# ── admin_user shape validation (parser rule, via --check-preseed) ────

def lint(content: str, tmp_path: Path) -> subprocess.CompletedProcess:
    f = tmp_path / "spatium-preseed.yaml"
    f.write_text(content, encoding="utf-8")
    return subprocess.run(
        ["bash", str(INSTALLER), "--check-preseed", str(f)],
        capture_output=True, text=True, timeout=120,
    )


def preseed_with_user(user: str) -> str:
    return (
        "spatium_preseed:\n"
        "  role: control-plane\n"
        "  hostname: spatium-cp-1\n"
        f"  admin_user: {user}\n"
        '  admin_password: "ChangeMe!12345"\n'
        "  network:\n"
        "    mode: dhcp\n"
    )


@pytest.mark.parametrize("user", ["admin", "ops", "ops-user", "_svc", "a", "spatium1"])
def test_valid_admin_users_accepted(user, tmp_path):
    r = lint(preseed_with_user(user), tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("user,why", [
    ("Admin", "uppercase is not a portable useradd name"),
    ("1admin", "must not start with a digit"),
    ("-admin", "must not start with a hyphen"),
    ("ad min", "spaces break the useradd argv"),
    ("ad:min", "a colon splits the chpasswd user:password line"),
    ("admin$(id)", "command substitution must never reach a shell"),
    ("admin;reboot", "shell metacharacters"),
    ("admin\\ttab", "control characters"),
    ("a" * 33, "over useradd's 32-character limit"),
])
def test_invalid_admin_users_rejected(user, why, tmp_path):
    r = lint(preseed_with_user(f'"{user}"'), tmp_path)
    assert r.returncode != 0, f"{why}: {user!r} was accepted\n{r.stdout}"


@pytest.mark.parametrize("user", ["root", "daemon", "www-data", "nobody", "sshd"])
def test_reserved_system_accounts_rejected(user, tmp_path):
    """`useradd -m root` fails mid-install — after the disk is wiped."""
    r = lint(preseed_with_user(user), tmp_path)
    assert r.returncode != 0, f"reserved account {user!r} was accepted\n{r.stdout}"
    assert "reserved" in (r.stdout + r.stderr).lower()


def test_admin_user_error_names_the_field(tmp_path):
    """The linter's whole job is telling the operator what to fix — so
    assert it FAILED and that the message names both the field and the
    offending value."""
    r = lint(preseed_with_user('"Bad:User"'), tmp_path)
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert "admin_user" in out
    assert "Bad:User" in out


def test_absent_admin_user_is_not_an_error(tmp_path):
    """admin_user is optional — absent means the "admin" default."""
    r = lint(
        "spatium_preseed:\n"
        "  role: control-plane\n"
        "  hostname: spatium-cp-1\n"
        '  admin_password: "ChangeMe!12345"\n'
        "  network:\n"
        "    mode: dhcp\n",
        tmp_path,
    )
    assert r.returncode == 0, r.stdout + r.stderr


# ── Secrets must not reach the trace log ──────────────────────────────

def _xtrace_is_off_at(fn: str, needle: str) -> bool:
    """Is xtrace off at every line of ``fn`` containing ``needle``?

    Walks the function tracking the last `set +x` / `set -x` seen, rather
    than slicing at the first loop keyword. The slice version anchored on
    "everything before the first ``while true; do``", which silently
    stopped testing anything the day #995 item 4 put a username-validation
    loop ahead of the password loop: the property still held, the test no
    longer looked at the right half of the function, and it reported that
    as a failure. Track the state and the assertion survives the next
    refactor too.

    ``|| { set -x; return 1; }`` does NOT count as re-enabling for the
    lines that follow it: it restores tracing on the way OUT of the
    function, and the next statement is only reached when it did not run.
    Counting it flags the second --passwordbox in a two-prompt loop, which
    is a false positive — and was the first thing this helper got wrong.
    """
    off = False
    seen = False
    for line in fn.splitlines():
        # Match the needle against CODE, not the raw line: the prose above
        # ask_application_config's prompt says "Pairing code" too, and it
        # sits before the `set +x` it is describing.
        code = line.split("#", 1)[0]
        if needle in code:
            seen = True
            if not off:
                return False
        if "set +x" in code:
            off = True
        elif "set -x" in code:
            after = code.split("set -x", 1)[1]
            if "return" not in after and "exit" not in after:
                off = False
    assert seen, f"{needle!r} not found — the anchor moved, fix the test"
    return True


def test_interactive_password_prompt_disables_xtrace():
    """`on_failure` tails 30 lines of the trace log to the console on any
    non-zero exit. The preseed path already suppressed xtrace around the
    secret env and around chpasswd; the INTERACTIVE prompt did not, so
    `ADMIN_PASSWORD="$p1"` and `[ "$p1" = "$p2" ]` — both argv — wrote the
    operator's plaintext password into that log.
    """
    fn = extract_fn("ask_user_password")
    assert _xtrace_is_off_at(fn, "--passwordbox"), (
        "every --passwordbox in ask_user_password must run with xtrace "
        "off, or the plaintext lands in the trace log on_failure prints"
    )


def test_pairing_code_prompt_disables_xtrace():
    """Same hole, same file, missed by #581 (issue #995 item 1).

    The pairing code is typed into an inputbox and then assigned — both
    argv — so `set -x` wrote it to the trace log that on_failure tails to
    the console, and that #995 item 1 now copies onto the installed
    system. A single-use code is spent on first boot; a PERSISTENT
    multi-claim code is a standing fleet-join credential.
    """
    fn = extract_fn("ask_application_config")
    assert _xtrace_is_off_at(fn, "BOOTSTRAP_PAIRING_CODE=\"$code_val\""), (
        "the pairing-code assignment must run with xtrace off"
    )
    assert _xtrace_is_off_at(fn, "Pairing code"), (
        "the pairing-code prompt must run with xtrace off"
    )


def test_pairing_code_prompt_restores_xtrace_on_every_exit():
    """A leaked `set +x` blinds the trace log for the rest of the install,
    which is the diagnostic the whole file exists for."""
    fn = extract_fn("ask_application_config")
    marker = "{ set +x; } 2>/dev/null"
    # Named, not indexed: without this the pre-fix script raises
    # IndexError instead of saying what is missing, and a harness whose
    # failure mode is a stack trace is a harness nobody reads.
    assert marker in fn, "ask_application_config never disables xtrace"
    tail = fn.split(marker, 1)[1]
    # One Back path out of the prompt, plus the fall-through at the end.
    assert tail.count("{ set -x; return 1; }") == 1, tail
    assert "\n    set -x\n" in tail, tail[-400:]


def _xtrace_state_at_end(fn: str) -> bool:
    """Is xtrace ON when this function returns normally?

    Walks the same way _xtrace_is_off_at does, ignoring the `set -x` that
    is part of an early `{ set -x; return 1; }` — those restore on the way
    out and say nothing about the fall-through path.
    """
    off = False
    for line in fn.splitlines():
        code = line.split("#", 1)[0]
        if "set +x" in code:
            off = True
        elif "set -x" in code:
            after = code.split("set -x", 1)[1]
            if "return" not in after and "exit" not in after:
                off = False
    return not off


def test_password_prompt_restores_xtrace_on_every_exit():
    """A leaked `set +x` would silently blind the trace log for the rest
    of the install, which is the diagnostic the whole file exists for.

    Anchored on the STATE at the end rather than on the last line being
    literally `set -x`: #995 item 12 appended a root-password prompt after
    the password loop, and the line-anchored version reported that as a
    failure while the property it cares about still held.
    """
    fn = extract_fn("ask_user_password")
    # Both early returns inside the loop restore before returning.
    assert fn.count("{ set -x; return 1; }") == 2, fn
    assert _xtrace_state_at_end(fn), fn[-400:]


def test_the_root_password_prompt_is_not_inside_the_blind_region():
    """It carries no secret, and leaving it under `set +x` would mean the
    trace log stops just before the most consequential branch in the
    function."""
    fn = extract_fn("ask_user_password")
    assert not _xtrace_is_off_at(fn, "SET_ROOT_PASSWORD=\"yes\"")


def test_chpasswd_still_runs_with_xtrace_off():
    """Regression guard on the shipped #549 protection.

    Anchors on the real command, not the word — do_install's prose
    mentions chpasswd well before the code that runs it.
    """
    fn = extract_fn("do_install")
    idx = fn.find('| chroot "$MOUNT" chpasswd')
    assert idx > 0, "could not find the chpasswd invocation in do_install"
    assert "set +x" in fn[:idx], "chpasswd must not be traced"


def test_secret_env_sourced_with_xtrace_off():
    """Regression guard: PRESEED_SECRET_ENV carries the admin password
    hash and the pairing code."""
    fn = extract_fn("load_preseed")
    # Anchor on the SOURCE of the secret env, not the first mention of the
    # name — that one is the parser argv, which is fine to trace.
    src_idx = fn.find('. "$PRESEED_SECRET_ENV"')
    assert src_idx > 0
    assert "set +x" in fn[:src_idx], "secret env must be sourced with xtrace off"


def test_trace_log_is_excluded_from_the_installed_system():
    """/var/log/* must not be rsynced onto the target — otherwise every
    guard above is undone by shipping the trace log to the installed
    machine."""
    # The live-root rsync moved into _copy_live_root (#2256), and
    # do_install calls it.
    assert "_copy_live_root" in extract_fn("do_install")
    fn = extract_fn("_copy_live_root")
    assert '--exclude="/var/log/*"' in fn
