"""The chrony sync-state sidecar is refreshed on a timer (#4825).

It used to be written only when a config was applied, so chrony syncing (or
losing sync) afterwards left the NTP tab on the stale state.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_chrony_status_refresh_4825.py -v
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from _installer_source import BIN

RUNNER = BIN / "spatiumddi-chrony-reload"
UNITS = BIN.parent.parent.parent / "etc" / "systemd" / "system"


def _run(tmp_path: Path, leap: str) -> str:
    state = tmp_path / "state"
    src = (
        RUNNER.read_text(encoding="utf-8")
        .replace("/var/lib/spatiumddi/release-state", str(state))
        .replace("/var/log/spatiumddi", str(tmp_path / "log"))
        .replace("/etc/nftables.d", str(tmp_path / "nft"))
    )
    script = tmp_path / "runner.sh"
    script.write_text(src)
    stub = tmp_path / "bin"
    stub.mkdir()
    chronyc = stub / "chronyc"
    chronyc.write_text(f"#!/bin/sh\necho 'Leap status     : {leap}'\n")
    chronyc.chmod(0o755)
    env = {"PATH": f"{stub}:/usr/bin:/bin"}
    r = subprocess.run(
        ["bash", str(script), "--status-only"], env=env, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
    return (state / "ntp-status").read_text().strip()


def test_status_only_refreshes_sidecar_without_trigger(tmp_path: Path) -> None:
    assert _run(tmp_path, "Normal") == "synchronized"


def test_status_only_reports_unsynchronized(tmp_path: Path) -> None:
    assert _run(tmp_path, "Not synchronised") == "unsynchronized"


def test_timer_drives_status_only() -> None:
    svc = (UNITS / "spatiumddi-chrony-status.service").read_text()
    assert "spatiumddi-chrony-reload --status-only" in svc
    assert "OnUnitActiveSec" in (UNITS / "spatiumddi-chrony-status.timer").read_text()


def _run_stub(tmp_path: Path, chronyc_body: str) -> str:
    state = tmp_path / "state"
    src = (
        RUNNER.read_text(encoding="utf-8")
        .replace("/var/lib/spatiumddi/release-state", str(state))
        .replace("/var/log/spatiumddi", str(tmp_path / "log"))
        .replace("/etc/nftables.d", str(tmp_path / "nft"))
    )
    script = tmp_path / "runner.sh"
    script.write_text(src)
    stub = tmp_path / "bin"
    stub.mkdir()
    chronyc = stub / "chronyc"
    chronyc.write_text("#!/bin/sh\n" + chronyc_body)
    chronyc.chmod(0o755)
    r = subprocess.run(
        ["bash", str(script), "--status-only"],
        env={"PATH": f"{stub}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    return (state / "ntp-status").read_text().strip()


def test_falls_back_to_unix_socket_when_udp_refused(tmp_path: Path) -> None:
    # chronyd-restricted opens no 127.0.0.1 command socket: -h reads fail.
    body = (
        'if [ "$1" = "-h" ]; then echo "506 Cannot talk to daemon" >&2; exit 1; fi\n'
        "echo 'Leap status     : Normal'\n"
    )
    assert _run_stub(tmp_path, body) == "synchronized"


def test_unreadable_chrony_writes_unknown_and_exits_zero(tmp_path: Path) -> None:
    body = 'echo "506 Cannot talk to daemon" >&2\nexit 1\n'
    assert _run_stub(tmp_path, body) == "unknown"
