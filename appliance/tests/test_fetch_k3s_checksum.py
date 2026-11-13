"""#1260 — fetch-k3s.sh verifies the k3s artifacts against the release's
own sha256sum-<arch>.txt before baking them into the image.

Runs the shipped script in a scratch copy of the appliance tree with a
stub ``curl`` serving canned bytes, so no network is touched.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from _installer_source import SCRIPTS  # noqa: E402 - sibling module

BIN = b"fake-k3s-binary"
AIR = b"fake-airgap-tarball"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def rig(tmp_path: Path):
    app = tmp_path / "appliance"
    (app / "scripts").mkdir(parents=True)
    script = app / "scripts" / "fetch-k3s.sh"
    shutil.copy(Path(SCRIPTS) / "fetch-k3s.sh", script)
    stub = tmp_path / "bin"
    stub.mkdir()
    serve = tmp_path / "serve"
    serve.mkdir()
    curl = stub / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        'out=""; url=""\n'
        'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; '
        '-*) shift;; *) url="$1"; shift;; esac; done\n'
        'f="$SERVE/$(basename "$url")"\n'
        '[ -f "$f" ] || exit 22\n'
        'cp "$f" "$out"\n'
    )
    curl.chmod(0o755)

    def run(bin_hash=None, air_hash=None, sums=True):
        (serve / "k3s").write_bytes(BIN)
        (serve / "k3s-airgap-images-amd64.tar.zst").write_bytes(AIR)
        for n in ("k3s-images.txt", "LICENSE", "NOTICE"):
            (serve / n).write_text("x")
        if sums:
            (serve / "sha256sum-amd64.txt").write_text(
                f"{bin_hash or _sha(BIN)}  k3s\n"
                f"{air_hash or _sha(AIR)}  k3s-airgap-images-amd64.tar.zst\n"
            )
        else:
            (serve / "sha256sum-amd64.txt").unlink(missing_ok=True)
        env = dict(
            os.environ,
            PATH=f"{stub}:{os.environ['PATH']}",
            SERVE=str(serve),
            ARCH="x86_64",
            K3S_VERSION="v0.0.0+k3s1",
        )
        return subprocess.run(
            ["bash", str(script)], env=env, capture_output=True, text=True
        ), app / "mkosi.extra"

    return run


def test_good_checksums_bake_the_artifacts(rig):
    r, extra = rig()
    assert r.returncode == 0, r.stderr
    assert (extra / "usr/local/bin/k3s").read_bytes() == BIN
    assert "sha256 verified: k3s" in r.stdout


def test_bad_binary_checksum_fails_and_bakes_nothing(rig):
    r, extra = rig(bin_hash="0" * 64)
    assert r.returncode != 0
    assert "mismatch" in r.stderr
    assert not (extra / "usr/local/bin/k3s").exists()


def test_bad_airgap_checksum_fails(rig):
    r, extra = rig(air_hash="f" * 64)
    assert r.returncode != 0
    assert "mismatch" in r.stderr
    assert not (extra / "var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst").exists()
    assert not (extra / "usr/share/doc/k3s/.version").exists()


def test_missing_checksum_file_fails(rig):
    r, _ = rig(sums=False)
    assert r.returncode != 0
