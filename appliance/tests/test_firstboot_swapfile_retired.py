"""#2400 — firstboot no longer creates a swapfile, and retires the old one.

Every boot without active swap used to create a 2 GiB
``/var/lib/spatiumddi/swapfile`` and append it to ``/etc/fstab``. That line
went into the /etc overlay's upper layer, which mounts after PID1 has run
systemd-fstab-generator over the underlying rootfs /etc, so the swap was
active until the first reboot and never again — and the creation guard
skipped an existing file. 2 GiB of /var held nothing, on the volume the
kubelet evicts the control plane on.

These run the real ``retire_inactive_swapfile`` under ``sh`` (dash on the
appliance and on CI) with a stub ``swapon``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-firstboot"
)
SHELL = shutil.which("dash") or "sh"


def _run(tmp_path: Path, *, active: bool) -> subprocess.CompletedProcess[str]:
    swapfile = tmp_path / "var" / "swapfile"
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    swapon = stub / "swapon"
    swapon.write_text(f"#!/bin/sh\n{'echo ' + str(swapfile) if active else ':'}\n")
    swapon.chmod(0o755)
    return subprocess.run(
        [SHELL, "-c", f'set -eu\n. "{SCRIPT}"\nretire_inactive_swapfile\n'],
        env={
            **os.environ,
            "SPATIUM_FIRSTBOOT_LIB": "1",
            "SPATIUM_SWAPFILE": str(swapfile),
            "SPATIUM_SWAP_FSTAB": str(tmp_path / "fstab"),
            "PATH": f"{stub}:{os.environ['PATH']}",
        },
        capture_output=True,
        text=True,
        check=False,
    )


def _seed(tmp_path: Path) -> tuple[Path, Path]:
    swapfile = tmp_path / "var" / "swapfile"
    swapfile.parent.mkdir(parents=True)
    swapfile.write_bytes(b"\0" * 4096)
    fstab = tmp_path / "fstab"
    fstab.write_text(
        "LABEL=var /var ext4 defaults 0 2\n"
        f"{swapfile} none swap sw 0 0\n"
        "tmpfs /tmp tmpfs nosuid,nodev,noexec,mode=1777 0 0\n"
    )
    return swapfile, fstab


def test_an_inactive_swapfile_and_its_fstab_line_are_removed(tmp_path: Path) -> None:
    swapfile, fstab = _seed(tmp_path)
    proc = _run(tmp_path, active=False)
    assert proc.returncode == 0, proc.stderr
    assert not swapfile.exists()
    assert fstab.read_text() == (
        "LABEL=var /var ext4 defaults 0 2\n"
        "tmpfs /tmp tmpfs nosuid,nodev,noexec,mode=1777 0 0\n"
    )


def test_an_active_swapfile_is_left_alone(tmp_path: Path) -> None:
    """Swapping off a live file under memory pressure could OOM the node."""
    swapfile, fstab = _seed(tmp_path)
    before = fstab.read_text()
    proc = _run(tmp_path, active=True)
    assert proc.returncode == 0, proc.stderr
    assert swapfile.exists()
    assert fstab.read_text() == before


def test_nothing_to_retire_is_a_no_op(tmp_path: Path) -> None:
    fstab = tmp_path / "fstab"
    fstab.write_text("LABEL=var /var ext4 defaults 0 2\n")
    proc = _run(tmp_path, active=False)
    assert proc.returncode == 0, proc.stderr
    assert fstab.read_text() == "LABEL=var /var ext4 defaults 0 2\n"


def test_firstboot_no_longer_creates_swap() -> None:
    src = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in src.splitlines() if not line.lstrip().startswith("#")
    )
    for creator in ("mkswap", "fallocate", "none swap sw"):
        assert creator not in code, creator
    # ...and the retirement runs on the boot path, past the lib guard.
    guard = code.index('if [ "${SPATIUM_FIRSTBOOT_LIB:-}" = "1" ]')
    assert code.index("\nretire_inactive_swapfile", guard) > guard
