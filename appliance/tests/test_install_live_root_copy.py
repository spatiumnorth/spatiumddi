"""The live-root rsync tolerates vanished files and skips k3s runtime state (#2256).

An unattended install aborted ~1 minute in: k3s unpacks its bundled tools
into ``/var/lib/rancher/k3s/data/<hash>-tmp/`` on any invocation, the files
vanished under the copy, rsync exited 24, and ``pipefail`` + ``set -e``
turned that into a dead install and a root shell.

``_copy_live_root`` is extracted from the shipped script and run under
bash with ``set -e -o pipefail`` piped into a consumer (exactly how
``do_install`` uses it), against a stub ``rsync``. Asserts on the exit
status the pipeline yields and on the argv rsync was given.

HOW TO RUN: python3 -m pytest appliance/tests/test_install_live_root_copy.py -v
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from _installer_source import extract_fn as _extract

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="bash required")


def _run(tmp: Path, rsync_rc: int):
    bindir = tmp / "bin"
    bindir.mkdir()
    argv_file = tmp / "argv"
    stub = bindir / "rsync"
    stub.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$@" > {argv_file}\n'
        f'echo "file has vanished: x" >&2\nexit {rsync_rc}\n'
    )
    stub.chmod(0o755)
    log = tmp / "install.log"
    script = textwrap.dedent(
        f"""
        set -e -o pipefail
        export PATH="{bindir}:$PATH"
        INSTALL_LOG="{log}"
        MOUNT="{tmp}/mnt"
        log() {{ echo "$*" >> "$INSTALL_LOG"; }}
        {_extract("_copy_live_root")}
        _copy_live_root | {{ while read -r _l; do :; done; }}
        echo AFTER_COPY
        """
    )
    p = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    argv = argv_file.read_text().splitlines() if argv_file.exists() else []
    return p, argv, log.read_text() if log.exists() else ""


def test_exit_24_is_success_and_logged(tmp_path):
    p, _, log = _run(tmp_path, 24)
    assert p.returncode == 0, p.stderr
    assert "AFTER_COPY" in p.stdout
    assert "exit 24" in log


@pytest.mark.parametrize("rc", [1, 11, 12, 23, 30])
def test_every_other_failure_still_aborts(tmp_path, rc):
    p, _, _ = _run(tmp_path, rc)
    assert p.returncode == rc
    assert "AFTER_COPY" not in p.stdout


def test_clean_copy_succeeds(tmp_path):
    p, _, log = _run(tmp_path, 0)
    assert p.returncode == 0
    assert "AFTER_COPY" in p.stdout
    assert "exit 24" not in log


def test_k3s_runtime_state_is_excluded_but_baked_images_are_not(tmp_path):
    _, argv, _ = _run(tmp_path, 0)
    excludes = [a.split("=", 1)[1] for a in argv if a.startswith("--exclude=")]
    # covers the <hash>-tmp extraction dirs (and the renamed <hash> trees)
    assert "/var/lib/rancher/k3s/data/*" in excludes
    # the baked air-gap image tarballs live under agent/ and MUST be copied
    assert not any(e.startswith("/var/lib/rancher/k3s/agent") for e in excludes)
    assert "/var/lib/rancher/k3s" not in excludes
    assert argv[-2:] == ["/", f"{tmp_path}/mnt/"]
