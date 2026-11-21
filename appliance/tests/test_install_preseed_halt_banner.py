"""#4589 — a deliberate preseed halt keeps its banner on screen.

Runs the real ``preseed_halt`` under the real ``on_failure`` EXIT trap with
``clear`` stubbed to a marker, and asserts nothing clears after the banner.
"""

from __future__ import annotations

import os
import subprocess
import textwrap

from _installer_source import extract_fn


def _run(tmp_path, *, halt: bool):
    live = tmp_path / "live"
    live.mkdir()
    for n in ("install.log", "trace.log", "launch.log"):
        (live / n).write_text(f"content of {n}\n")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "clear").write_text("#!/bin/sh\necho '<<CLEAR>>'\n")
    (stubs / "mountpoint").write_text("#!/bin/sh\nexit 1\n")
    for f in stubs.iterdir():
        f.chmod(0o755)
    on_failure = extract_fn("on_failure").split('    echo "Press Enter')[0] + "}\n"
    launch = str(live / "launch.log")
    trigger = 'preseed_halt "Preseed validation failed: bad key"' if halt else "exit 3"
    script = textwrap.dedent(
        f"""
        set -uo pipefail
        MOUNT={tmp_path}/target
        INSTALL_LOG={live}/install.log
        TRACE_LOG={live}/trace.log
        PRESEED_SOURCE=/x/answers.yaml
        log() {{ echo "[x] $*" >> "$INSTALL_LOG"; }}
        {extract_fn("preseed_halt")}
        {on_failure.replace("/var/log/spatium-install-launch.log", launch)}
        trap on_failure EXIT
        {trigger}
        """
    )
    env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}")
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30
    ).stdout


def test_halt_banner_is_not_cleared_by_failure_screen(tmp_path):
    out = _run(tmp_path, halt=True)
    assert "PRESEED ERROR" in out
    # Only preseed_halt's own clear, which comes before the banner.
    assert out.count("<<CLEAR>>") == 1
    assert out.index("<<CLEAR>>") < out.index("PRESEED ERROR")
    assert "Installer exited with status" not in out
    assert "Last 20 lines" not in out
    assert "install.log" in out  # the log path is still named


def test_real_crash_keeps_generic_failure_screen(tmp_path):
    out = _run(tmp_path, halt=False)
    assert "Installer exited with status 3" in out
    assert "Last 20 lines" in out
