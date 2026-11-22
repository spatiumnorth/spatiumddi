"""A control-plane install below REC_CP_DISK_GIB logs a warning (#4661).

The interactive path prompts (_control_plane_sizing_ok); the preseed path
skips that screen, so the pre-wipe guard calls _warn_control_plane_disk_size.
Drives the real function with a stubbed blockdev; run it under the target
shell (bash).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from _installer_source import SRC

GIB = 1024**3


def _fn() -> str:
    m = re.search(r"^_warn_control_plane_disk_size\(\) \{.*?^\}\n", SRC, re.S | re.M)
    assert m, "_warn_control_plane_disk_size is missing"
    return m.group(0)


def _run(tmp: Path, role: str, gib: int) -> str:
    (tmp / "blockdev").write_text(f"#!/bin/sh\necho {gib * GIB}\n")
    (tmp / "blockdev").chmod(0o755)
    script = (
        f"PATH={tmp}:$PATH\nREC_CP_DISK_GIB=40\nROLE={role}\n"
        'log() { echo "LOG: $*"; }\n'
        + _fn()
        + "\n_warn_control_plane_disk_size /dev/x\n"
        'echo "rc=$?"\n'
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout


def test_warns_for_control_plane_below_recommended(tmp_path):
    out = _run(tmp_path, "control-plane", 32)
    assert "WARN" in out and "32 GiB" in out and "40 GiB" in out
    assert "rc=0" in out


def test_silent_at_recommended_and_for_agent_role(tmp_path):
    assert "WARN" not in _run(tmp_path, "control-plane", 40)
    assert "WARN" not in _run(tmp_path, "appliance", 32)


def test_pre_wipe_guard_calls_it():
    assert re.search(r'_warn_control_plane_disk_size "\$real"', SRC)
