"""``make trivy`` must not report a scan that never ran as a finding (#1272).

``scripts/trivy-scan.sh`` used to treat every non-zero exit from ``docker run``
as FINDINGS. So a Docker error (125 — a refused mount, a pull failure, the
daemon down) or a Trivy error (a DB download failure, which Trivy reports as
exit 1) printed "✗ Trivy found HIGH/CRITICAL vulnerabilities" with nothing
under it, for images that scanned clean — seen 2026-09-28 when Docker Desktop
refused the checkout-relative cache mount on an external volume.

The shipped script is executed against a stubbed ``docker`` on ``PATH``, so
these test the bytes ``make trivy`` runs. Three properties:

* a scan that did not run reads as SCAN FAILED, with its log tail, and never
  as FINDINGS;
* a real finding still reads as FINDINGS and still fails — the fix must not
  turn the guard's own failure into a pass;
* scanning nothing is not "clean": an ``IMAGE=`` that matches no spec fails.
"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess
import textwrap

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "trivy-scan.sh"

pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="trivy scan script not present in this checkout",
)

# What ``docker`` does, per image name: the ``build`` exit code, and the
# ``run`` (scanner) exit code + output. Read from files the test writes.
_DOCKER_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    set -u
    cmd="$1"
    for last; do :; done
    name="${last#spatiumddi-trivy-}"
    if [ "$cmd" = build ]; then
      while [ $# -gt 0 ]; do
        if [ "$1" = -t ]; then name="${2#spatiumddi-trivy-}"; fi
        shift
      done
      name="${name%:scan}"
      d="$STUB_DIR/$name"
      [ -f "$d.build-out" ] && cat "$d.build-out"
      exit "$(cat "$d.build-rc" 2>/dev/null || echo 0)"
    fi
    name="${name%:scan}"
    d="$STUB_DIR/$name"
    [ -f "$d.run-out" ] && cat "$d.run-out"
    exit "$(cat "$d.run-rc" 2>/dev/null || echo 0)"
    """)

_MOUNT_ERROR = (
    "docker: Error response from daemon: error while creating mount source "
    "path '/host_mnt/Volumes/ext1/x/.trivy-cache': mkdir /host_mnt/Volumes/ext1: "
    "file exists.\n"
)

_FINDINGS_REPORT = textwrap.dedent("""\
    spatiumddi-trivy-bind9:scan (alpine 3.23.2)

    Total: 2 (HIGH: 2, CRITICAL: 0)

    │ libssl3 │ CVE-2026-1234 │ HIGH │ fixed │ 3.5.1-r0 │ 3.5.2-r0 │
    │ libcrypto3 │ CVE-2026-1234 │ HIGH │ fixed │ 3.5.1-r0 │ 3.5.2-r0 │

    usr/bin/gobgpd (gobinary)

    Total: 0 (HIGH: 0, CRITICAL: 0)
    """)

_DB_ERROR = (
    "2026-09-28T10:00:00Z\tFATAL\tFatal error\trun error: init error: DB error: "
    "failed to download vulnerability DB\n"
)


class _Rig:
    def __init__(self, tmp: pathlib.Path) -> None:
        self.stub_dir = tmp / "stub"
        self.stub_dir.mkdir()
        bindir = tmp / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(_DOCKER_STUB)
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        self.env = {
            **os.environ,
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "STUB_DIR": str(self.stub_dir),
            "TRIVY_CACHE": str(tmp / "cache"),
            "TRIVY_LOG_DIR": str(tmp / "logs"),
        }
        self.env.pop("IMAGE", None)

    def image(self, name: str, *, run_rc: int = 0, run_out: str = "", build_rc: int = 0) -> str:
        (self.stub_dir / f"{name}.run-rc").write_text(str(run_rc))
        (self.stub_dir / f"{name}.run-out").write_text(run_out)
        (self.stub_dir / f"{name}.build-rc").write_text(str(build_rc))
        if build_rc:
            (self.stub_dir / f"{name}.build-out").write_text("ERROR: failed to solve\n")
        return f"agent/{name}/Dockerfile:.:{name}"

    def run(self, *specs: str, only: str | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(self.env)
        if only is not None:
            env["IMAGE"] = only
        return subprocess.run(
            ["bash", str(_SCRIPT), *specs],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )


@pytest.fixture
def rig(tmp_path: pathlib.Path) -> _Rig:
    return _Rig(tmp_path)


def test_a_docker_error_is_scan_failed_not_findings(rig: _Rig) -> None:
    """The reported case: docker exits 125 on a refused mount."""
    proc = rig.run(rig.image("bind9", run_rc=125, run_out=_MOUNT_ERROR))
    assert "SCAN FAILED (exit 125)" in proc.stdout
    assert "FINDINGS" not in proc.stdout
    assert "found HIGH/CRITICAL" not in proc.stdout
    # The reason is on screen, not only in a log nobody opens.
    assert "file exists" in proc.stdout
    # Still not a pass: nothing was verified.
    assert proc.returncode == 2
    assert "safe to push" not in proc.stdout


def test_a_trivy_error_with_no_findings_is_scan_failed(rig: _Rig) -> None:
    """Trivy reports its own errors as exit 1 — the same code as a finding."""
    proc = rig.run(rig.image("kea", run_rc=1, run_out=_DB_ERROR))
    assert "SCAN FAILED (exit 1)" in proc.stdout
    assert "FINDINGS" not in proc.stdout
    assert "failed to download vulnerability DB" in proc.stdout
    assert proc.returncode == 2


def test_a_real_finding_still_fails_and_is_printed(rig: _Rig) -> None:
    """The negative control: the fix must not turn a finding into a pass."""
    proc = rig.run(rig.image("bind9", run_rc=1, run_out=_FINDINGS_REPORT))
    assert "FINDINGS" in proc.stdout
    assert "SCAN FAILED" not in proc.stdout
    assert "CVE-2026-1234" in proc.stdout
    assert "found HIGH/CRITICAL vulnerabilities in 1 image(s)" in proc.stdout
    assert proc.returncode == 1


def test_a_clean_scan_passes(rig: _Rig) -> None:
    proc = rig.run(rig.image("bind9"), rig.image("kea"))
    assert proc.stdout.count("scanning… clean\n") == 2
    assert "safe to push" in proc.stdout
    assert proc.returncode == 0


def test_a_build_failure_is_not_a_finding(rig: _Rig) -> None:
    proc = rig.run(rig.image("dnsdist", build_rc=1))
    assert "BUILD FAILED" in proc.stdout
    assert "failed to solve" in proc.stdout
    assert "FINDINGS" not in proc.stdout
    assert proc.returncode == 2


def test_findings_win_over_failures_and_both_are_reported(rig: _Rig) -> None:
    proc = rig.run(
        rig.image("bind9", run_rc=1, run_out=_FINDINGS_REPORT),
        rig.image("powerdns", run_rc=125, run_out=_MOUNT_ERROR),
    )
    assert "found HIGH/CRITICAL vulnerabilities in 1 image(s)" in proc.stdout
    assert "1 more image(s) could not be scanned" in proc.stdout
    assert proc.returncode == 1


def test_image_selects_one_spec(rig: _Rig) -> None:
    proc = rig.run(
        rig.image("bind9"),
        rig.image("kea", run_rc=125, run_out=_MOUNT_ERROR),
        only="bind9",
    )
    assert "bind9" in proc.stdout
    assert "kea" not in proc.stdout
    assert proc.returncode == 0


def test_an_image_that_matches_nothing_is_not_clean(rig: _Rig) -> None:
    """``make trivy IMAGE=bnid9`` used to print "✓ Trivy clean"."""
    proc = rig.run(rig.image("bind9"), only="bnid9")
    assert "matched no image" in proc.stdout
    assert "safe to push" not in proc.stdout
    assert proc.returncode == 2


def test_the_makefile_runs_this_script_with_a_cache_outside_the_checkout() -> None:
    """The cache mount is what failed on 2026-09-28: a checkout on an external
    volume Docker Desktop would not mount. Its default must not live there."""
    makefile = (_REPO_ROOT / "Makefile").read_text()
    assert "scripts/trivy-scan.sh $(TRIVY_IMAGES)" in makefile
    assert "TRIVY_CACHE ?= $(HOME)/" in makefile
    assert "TRIVY_CACHE ?= $(CURDIR)" not in makefile
