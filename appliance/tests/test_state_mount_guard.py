"""A STATE that is present is mounted before spatium-etc-render touches it (#1910).

STATE is mounted ``nofail``. After a power-off, a QA seed's STATE check was
stopped mid journal recovery, its mount never ran, and the boot went on with
``/var/lib/spatium-state`` as the empty mountpoint directory on /var. The
render then wrote the node's identity paths into that directory, the
supervisor's symlink resolved into it, and the supervisor minted a new
identity: a stranger to its own control plane that never heartbeat again.

The render's guard, run here against stubbed ``blkid`` / ``mountpoint`` /
``systemctl``:

* no ``state`` label: nothing happens, the render goes on (a box without STATE
  degrades exactly as before);
* the label and the mount: nothing happens;
* the label without the mount: the STATE mount (its check included) is started
  again, up to three times, and the render goes on once it is mounted;
* still not mounted: the render stops (exit 1) before it reads or writes
  STATE, says so on the kernel log, and keeps the hostname the last good boot
  rendered into /etc.

The console's Identity row then reads "Held — STATE not mounted" instead of
"Bootstrapping…".

    python3 -m pytest appliance/tests/test_state_mount_guard.py -v
"""

from __future__ import annotations

import __future__
import ast
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from _installer_source import BIN

ETC_RENDER = BIN / "spatium-etc-render"
GUARD_START = "# ── STATE is mounted before anything reads or writes it"
GUARD_END = "# ── Hostname"

STUBS = {
    "blkid": '[ -n "${STUB_LABEL:-}" ] && { echo "$STUB_LABEL"; exit 0; }\nexit 2\n',
    "mountpoint": '[ -e "$STUB_DIR/mounted" ] && exit 0\nexit 1\n',
    "systemd-escape": (
        '[ "$1" = --path ] && [ "$2" = --suffix=mount ] || exit 9\n'
        'echo "escaped($3).mount"\n'
    ),
    "timeout": 'shift\nexec "$@"\n',
    "sleep": "exit 0\n",
    "systemctl": (
        'echo "$*" >> "$STUB_DIR/calls"\n'
        'n=$(grep -c "^start " "$STUB_DIR/calls")\n'
        'if [ -n "${STUB_MOUNT_ON:-}" ] && [ "$n" -ge "$STUB_MOUNT_ON" ]; then\n'
        '    : > "$STUB_DIR/mounted"; exit 0\n'
        "fi\n"
        "exit 1\n"
    ),
    "hostname": 'echo "$1" > "$STUB_DIR/hostname-set"\n',
}


def _guard() -> str:
    src = ETC_RENDER.read_text(encoding="utf-8")
    return src[src.index(GUARD_START) : src.index(GUARD_END)]


def _run(tmp_path: Path, *, label: str = "", mounted: bool = False,
         mount_on: int | None = None, etc_hostname: str = "ddi1") -> tuple[int, str, Path]:
    stub_dir = tmp_path / "stub"
    bin_dir = tmp_path / "bin"
    state = tmp_path / "state"
    for d in (stub_dir, bin_dir, state):
        d.mkdir()
    for name, body in STUBS.items():
        p = bin_dir / name
        p.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        p.chmod(0o755)
    (stub_dir / "calls").write_text("", encoding="utf-8")
    if mounted:
        (stub_dir / "mounted").write_text("", encoding="utf-8")
    (tmp_path / "etc-hostname").write_text(etc_hostname + "\n", encoding="utf-8")
    guard = _guard()
    for literal in ("/dev/kmsg", "/etc/hostname"):
        assert literal in guard, f"the guard no longer names {literal}"
    guard = guard.replace("/dev/kmsg", f"{tmp_path}/kmsg").replace(
        "/etc/hostname", f"{tmp_path}/etc-hostname"
    )
    script = f"set -eu\nSTATE_DIR={state}\n{guard}\necho CONTINUED\n"
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "STUB_DIR": str(stub_dir),
        "STUB_LABEL": label,
        "STUB_MOUNT_ON": "" if mount_on is None else str(mount_on),
    }
    proc = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr, stub_dir


def _starts(stub_dir: Path) -> list[str]:
    calls = (stub_dir / "calls").read_text(encoding="utf-8").splitlines()
    return [c for c in calls if c.startswith("start ")]


def test_no_state_label_degrades_as_before(tmp_path: Path) -> None:
    rc, out, stub = _run(tmp_path, label="")
    assert rc == 0 and "CONTINUED" in out
    assert _starts(stub) == []


def test_a_mounted_state_is_left_alone(tmp_path: Path) -> None:
    rc, out, stub = _run(tmp_path, label="/dev/vda3", mounted=True)
    assert rc == 0 and "CONTINUED" in out
    assert _starts(stub) == []


@pytest.mark.parametrize("mount_on", [1, 2, 3])
def test_an_unmounted_state_is_checked_and_mounted_again(tmp_path: Path, mount_on: int) -> None:
    rc, out, stub = _run(tmp_path, label="/dev/vda3", mount_on=mount_on)
    assert rc == 0 and "CONTINUED" in out, out
    assert _starts(stub) == [f"start escaped({tmp_path}/state).mount"] * mount_on
    assert "STATE mounted on" in out
    assert not (tmp_path / "kmsg").exists()


def test_a_state_that_never_mounts_stops_the_render_loudly(tmp_path: Path) -> None:
    rc, out, stub = _run(tmp_path, label="/dev/vda3", mount_on=None, etc_hostname="ddipg-seed")
    assert rc == 1, out
    assert "CONTINUED" not in out
    assert len(_starts(stub)) == 3
    kmsg = (tmp_path / "kmsg").read_text(encoding="utf-8")
    assert kmsg.startswith("<3>spatium-etc-render: ERROR: STATE (/dev/vda3) is present but did not mount")
    # The kernel hostname comes from the overlay's /etc/hostname, not PID1's
    # slot baseline (empty, i.e. ``localhost``, on an upgrade-written slot).
    assert (stub / "hostname-set").read_text(encoding="utf-8").strip() == "ddipg-seed"
    # Nothing was written into the empty mountpoint directory.
    assert list((tmp_path / "state").iterdir()) == []


def test_the_guard_runs_before_anything_reads_or_writes_state() -> None:
    src = ETC_RENDER.read_text(encoding="utf-8")
    absent_exit = src.index('echo "STATE dir $STATE_DIR absent')
    guard = src.index(GUARD_START)
    first_reader = src.index(GUARD_END)
    assert absent_exit < guard < first_reader
    # Every read or write of STATE comes after the guard.
    for use in ('get_cfg hostname', 'SSH_STATE="$STATE_DIR/ssh"',
                'mkdir -p "$STATE_DIR/spatium-supervisor"', '"$STATE_DIR/machine-id"'):
        assert src.index(use) > guard, use


@pytest.mark.skipif(shutil.which("systemd-escape") is None, reason="systemd-escape not installed")
def test_the_started_unit_is_the_fstab_mount_of_state() -> None:
    """The fstab generator names the STATE mount after its path; the guard
    starts that unit, which pulls in the STATE check
    (systemd-fsck@dev-disk-by\\x2dlabel-state.service) through its Requires=."""
    name = subprocess.run(
        ["systemd-escape", "--path", "--suffix=mount", "/var/lib/spatium-state"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert name == "var-lib-spatium\\x2dstate.mount"


# ── the console's Identity row ──────────────────────────────────────────

CONSOLE = BIN / "spatium-console"
_CONSOLE_NAMES = {"_state_not_mounted", "pairing_status"}
HELD = ("Held — STATE not mounted (see /var/log/spatiumddi/etc-render.log)", "bold red")


def _console(root: Path, *, state_mounted: bool) -> dict[str, Any]:
    """Lift the two functions out of the shipped console (it imports rich and
    psutil at load, which this suite does not install) and run them against a
    fake root: every absolute path is read under ``root``."""
    tree = ast.parse(CONSOLE.read_text(encoding="utf-8"))
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in _CONSOLE_NAMES]
    namespace: dict[str, Any] = {
        "Path": lambda p: root / str(p).lstrip("/"),
        "os": SimpleNamespace(path=SimpleNamespace(
            ismount=lambda p: state_mounted and p == "/var/lib/spatium-state")),
    }
    code = compile(
        ast.Module(body=body, type_ignores=[]),
        str(CONSOLE),
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    exec(code, namespace)  # noqa: S102 — the shipped console's own functions
    missing = _CONSOLE_NAMES - set(namespace)
    assert not missing, f"not found in spatium-console: {sorted(missing)}"
    return namespace


def _box(root: Path, *, label: bool = True, approved: bool = False,
         cmdline: str = "root=PARTLABEL=root_A ro") -> Path:
    (root / "proc").mkdir(parents=True)
    (root / "proc/cmdline").write_text(cmdline + "\n", encoding="utf-8")
    if label:
        (root / "dev/disk/by-label").mkdir(parents=True)
        (root / "dev/disk/by-label/state").write_text("", encoding="utf-8")
    if approved:
        (root / "var/persist/spatium-supervisor/tls").mkdir(parents=True)
        (root / "var/persist/spatium-supervisor/tls/cert.pem").write_text("PEM", encoding="utf-8")
    return root


def test_identity_row_says_held_when_state_did_not_mount(tmp_path: Path) -> None:
    ns = _console(_box(tmp_path, approved=True), state_mounted=False)
    assert ns["_state_not_mounted"]() is True
    assert ns["pairing_status"]({}, "appliance", []) == HELD


def test_identity_row_is_unchanged_with_state_mounted(tmp_path: Path) -> None:
    ns = _console(_box(tmp_path, approved=True), state_mounted=True)
    assert ns["pairing_status"]({}, "appliance", []) == ("Approved ●", "bold green")


def test_a_box_without_state_is_never_held(tmp_path: Path) -> None:
    ns = _console(_box(tmp_path, label=False), state_mounted=False)
    assert ns["_state_not_mounted"]() is False
    assert ns["pairing_status"]({}, "appliance", []) == ("Bootstrapping…", "bold yellow")


def test_the_live_iso_is_never_held(tmp_path: Path) -> None:
    ns = _console(_box(tmp_path, cmdline="boot=live components quiet"), state_mounted=False)
    assert ns["_state_not_mounted"]() is False
