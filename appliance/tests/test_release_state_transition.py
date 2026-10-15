"""#1661 — the outgoing api pod must keep working across the #1621 tightening.

Upgrading from a build older than #1621 leaves release-state at 1777; the
booted slot re-owns it to root:2770 at sysinit while the OLD api (uid 1000,
no gid 2770) still serves, so every status read 500s until the booted chart
replaces it. ``spatium-release-state-transition`` bridges that window and
must close again on every path. The script is EXECUTED against a temp
directory with ``chown`` and ``kubectl`` stubbed (ownership is recorded, not
applied, so no root is needed).

NOT PROVABLE HERE: systemd ordering (Before=systemd-tmpfiles-setup,
Before=k3s) and that tmpfiles re-owns the directory on the next boot.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
EXTRA = REPO / "appliance" / "mkosi.extra"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-release-state-transition"
UNITS = EXTRA / "etc" / "systemd" / "system"
POSTINST = REPO / "appliance" / "mkosi.postinst"


def _env(tmp: Path, pods: str = "", tag: str = "nightly-1") -> dict[str, str]:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    chown_log = tmp / "chown.log"
    (bindir / "chown").write_text(f'#!/bin/sh\necho "$@" >> {chown_log}\n')
    (bindir / "chown").chmod(0o755)
    kube = tmp / "kubectl"
    kube.write_text(f"#!/bin/sh\nprintf '%s' '{pods}'\n")
    kube.chmod(0o755)
    ver = tmp / "version"
    ver.write_text(tag + "\n")
    rs = tmp / "release-state"
    rs.mkdir(exist_ok=True)
    return {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "SPATIUM_RS_DIR": str(rs),
        "SPATIUM_RS_STAMP": str(tmp / "stamp"),
        "SPATIUM_RS_VERSION_FILE": str(ver),
        "SPATIUM_RS_KUBECTL": str(kube),
        "SPATIUM_RS_DEADLINE": "2",
        "SPATIUM_RS_POLL": "1",
    }


def _run(mode: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), mode], env=env, capture_output=True, text=True
    )


def _chowns(tmp: Path) -> list[str]:
    p = tmp / "chown.log"
    return p.read_text().splitlines() if p.exists() else []


def test_pre_1621_world_writable_dir_is_stamped_and_opened(tmp_path: Path) -> None:
    env = _env(tmp_path)
    rs = Path(env["SPATIUM_RS_DIR"])
    rs.chmod(0o1777)
    (rs / "slot-upgrade-pending.state").write_text("x")
    assert _run("detect", env).returncode == 0
    assert Path(env["SPATIUM_RS_STAMP"]).exists()
    rs.chmod(0o1770)  # what tmpfiles does next
    assert _run("open", env).returncode == 0
    log = _chowns(tmp_path)
    assert f"1000:2770 {rs}" in log
    assert f"1000:2770 {rs}/slot-upgrade-pending.state" in log
    # never looser than 1770, even while open
    assert stat.S_IMODE(rs.stat().st_mode) == 0o1770


def test_already_tight_or_fresh_install_never_opens(tmp_path: Path) -> None:
    env = _env(tmp_path)
    Path(env["SPATIUM_RS_DIR"]).chmod(0o1770)
    _run("detect", env)
    assert not Path(env["SPATIUM_RS_STAMP"]).exists()
    _run("open", env)
    assert _chowns(tmp_path) == []


def test_wait_closes_when_every_api_pod_runs_the_booted_tag(tmp_path: Path) -> None:
    env = _env(tmp_path, pods="spatiumddi-api:nightly-1\n", tag="nightly-1")
    Path(env["SPATIUM_RS_STAMP"]).write_text("")
    assert _run("wait", env).returncode == 0
    assert f"0:2770 {env['SPATIUM_RS_DIR']}" in _chowns(tmp_path)
    assert not Path(env["SPATIUM_RS_STAMP"]).exists()


def test_wait_stays_open_while_the_outgoing_api_runs_then_closes_at_deadline(
    tmp_path: Path,
) -> None:
    env = _env(
        tmp_path,
        pods="spatiumddi-api:old\nspatiumddi-api:nightly-1\n",
        tag="nightly-1",
    )
    Path(env["SPATIUM_RS_STAMP"]).write_text("")
    r = _run("wait", env)
    assert "deadline" in r.stderr  # did not close early
    assert f"0:2770 {env['SPATIUM_RS_DIR']}" in _chowns(tmp_path)  # bounded


def test_units_and_install_wiring() -> None:
    detect = (UNITS / "spatium-release-state-detect.service").read_text()
    assert "Before=systemd-tmpfiles-setup.service" in detect
    trans = (UNITS / "spatium-release-state-transition.service").read_text()
    assert "After=systemd-tmpfiles-setup.service" in trans
    assert "Before=k3s.service" in trans
    assert "ExecStopPost=/usr/local/bin/spatium-release-state-transition close" in trans
    assert "RuntimeMaxSec=" in trans
    post = POSTINST.read_text()
    assert "spatium-release-state-transition.service" in post
    assert "spatium-release-state-detect.service" in post
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-release-state-transition"' in post
