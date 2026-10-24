"""The bake must not ship an index-only image archive (#2393).

With Docker's containerd image store a platform-less ``docker save`` of a
freshly pulled multi-arch image can write the index and manifests but no
config and no layers. The bake reported success; air-gapped k3s imported
the index and then tried to pull the image at pod start.

These tests execute the REAL ``bake-images.sh`` (copied into a scratch
tree so it writes its archives there) against a stubbed ``docker`` and
``zstd``. The stubs record their argv and replay a tar chosen per test, so
the assertions are on what the script did with the archive and what it
passed to ``docker save``, not on its internals.

The script's own ``set`` options are read from the script, never
hardcoded: a harness that drops ``-e`` hides exactly the bugs this file
exists to catch (#1029).

HOW TO RUN:
    python3 -m pytest appliance/tests/test_bake_archive_complete.py -v
No Docker, zstd, root or ISO required; python3 is.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from _installer_source import SCRIPTS  # noqa: E402 - sibling module

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def _digest(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _j(o) -> bytes:
    return json.dumps(o).encode()


def _blob(digest: str) -> str:
    return "blobs/sha256/" + digest.split(":", 1)[1]


def oci_archive(*, with_layers: bool, arch: str = "amd64") -> bytes:
    """A containerd-store archive: index -> manifest -> config + layer."""
    layer = b"layer-bytes-" + arch.encode()
    config = _j({"architecture": arch, "os": "linux"})
    manifest = _j(
        {
            "mediaType": OCI_MANIFEST,
            "config": {"digest": _digest(config), "size": len(config)},
            "layers": [{"digest": _digest(layer), "size": len(layer)}],
        }
    )
    other = _j({"mediaType": OCI_MANIFEST, "config": {"digest": "sha256:" + "0" * 64}})
    index = _j(
        {
            "mediaType": OCI_INDEX,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": _digest(manifest),
                    "platform": {"os": "linux", "architecture": arch},
                },
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": _digest(other),
                    "platform": {"os": "linux", "architecture": "s390x"},
                },
            ],
        }
    )
    members = {
        "index.json": _j(
            {"manifests": [{"mediaType": OCI_INDEX, "digest": _digest(index)}]}
        ),
        _blob(_digest(index)): index,
        _blob(_digest(manifest)): manifest,
    }
    if with_layers:
        members[_blob(_digest(config))] = config
        members[_blob(_digest(layer))] = layer
    return _tar(members)


def classic_archive(*, with_layers: bool) -> bytes:
    members = {
        "manifest.json": _j(
            [{"Config": "abc.json", "Layers": ["l1/layer.tar"], "RepoTags": ["x:1"]}]
        )
    }
    if with_layers:
        members["abc.json"] = b"{}"
        members["l1/layer.tar"] = b"x"
    return _tar(members)


DOCKER_STUB = """#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
case "$1" in
  image) exit 0 ;;
  rmi)
    # STUB_RMI_FAILS=1: rmi's own output must reach the log, not /dev/null.
    if [ -n "${STUB_RMI_FAILS:-}" ]; then echo "Error: stub rmi refused" >&2; exit 1; fi
    exit 0 ;;
  pull|tag) exit 0 ;;
  run)
    # The skopeo fallback: ``docker run ... -v DIR:/out IMG copy ...`` writes
    # DIR/image.tar (from archive.tar.skopeo when the test supplies one).
    # STUB_SKOPEO_FAILS=1 makes the copy fail too.
    [ -n "${STUB_SKOPEO_FAILS:-}" ] && { echo "skopeo: stub copy failed" >&2; exit 1; }
    prev=""; dir=""
    for a in "$@"; do [ "$prev" = "-v" ] && dir="${a%%:*}"; prev="$a"; done
    src="$STUB_ARCHIVE"; [ -f "$STUB_ARCHIVE.skopeo" ] && src="$STUB_ARCHIVE.skopeo"
    cat "$src" > "$dir/image.tar" ;;
  save)
    # STUB_SAVE_FAILS=N: the first N saves fail like a containerd store that
    # lost the platform's layer blobs ("no suitable export target found").
    if [ -n "${STUB_SAVE_FAILS:-}" ]; then
      n=$(cat "$STUB_LOG.saves" 2>/dev/null || echo 0)
      if [ "$n" -lt "$STUB_SAVE_FAILS" ]; then
        echo $((n + 1)) > "$STUB_LOG.saves"
        echo "no suitable export target found: does not provide the specified platform" >&2
        exit 1
      fi
    fi
    cat "$STUB_ARCHIVE" ;;
esac
"""

# ``-o FILE`` compresses (here: copies); ``-dc FILE`` decompresses.
ZSTD_STUB = """#!/bin/sh
case " $* " in
  *" -dc "*) for a in "$@"; do f="$a"; done; cat "$f" ;;
  *) while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done; cat > "$out" ;;
esac
"""


def _shell_opts(script: Path) -> str:
    m = re.search(r"^set -[a-z]+ ?[a-z]*$", script.read_text(), re.M)
    assert m, "no 'set -...' line in the shipped script"
    return m.group(0)


@pytest.fixture()
def rig(tmp_path):
    root = tmp_path / "repo" / "appliance"
    (root / "scripts").mkdir(parents=True)
    for n in ("bake-images.sh", "verify-image-archive.py"):
        shutil.copy(SCRIPTS / n, root / "scripts" / n)
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in (("docker", DOCKER_STUB), ("zstd", ZSTD_STUB)):
        p = stubs / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "docker.log"
    log.write_text("")

    def run(archive: bytes, skopeo_archive: bytes | None = None, **env):
        arch = tmp_path / "archive.tar"
        arch.write_bytes(archive)
        if skopeo_archive is not None:
            (tmp_path / "archive.tar.skopeo").write_bytes(skopeo_archive)
        e = {
            "PATH": f"{stubs}:{os.environ['PATH']}",
            "HOME": str(tmp_path),
            "STUB_LOG": str(log),
            "STUB_ARCHIVE": str(arch),
            "BAKE_SOURCE": "ghcr",
            "SPATIUMDDI_VERSION": "t",
        }
        e.update(env)
        r = subprocess.run(
            ["bash", str(root / "scripts" / "bake-images.sh")],
            env=e,
            capture_output=True,
            text=True,
        )
        return r, log.read_text(), root

    return run


def test_harness_reads_the_scripts_own_set_options():
    assert "e" in _shell_opts(SCRIPTS / "bake-images.sh").split()[1]


def test_complete_oci_archive_bakes_every_image(rig):
    r, log, root = rig(oci_archive(with_layers=True), BAKE_SAVE_PLATFORM="linux/amd64")
    assert r.returncode == 0, r.stderr
    assert "images baked" in r.stdout
    images = list((root / "mkosi.extra/var/lib/rancher/k3s/agent/images").glob("*.tar.zst"))
    assert len(images) > 10


def test_index_only_archive_fails_naming_the_image(rig):
    r, log, root = rig(oci_archive(with_layers=False), BAKE_SAVE_PLATFORM="linux/amd64")
    assert r.returncode != 0
    assert "ghcr.io/spatiumnorth/spatium-supervisor:t" in r.stderr
    assert "missing" in r.stderr
    # The torn archive is not left behind to be baked into the ISO.
    d = root / "mkosi.extra/var/lib/rancher/k3s/agent/images"
    assert not list(d.glob("spatium-supervisor.tar.zst*"))


def test_archive_without_the_target_platform_fails(rig):
    r, _, _ = rig(oci_archive(with_layers=True, arch="arm64"), BAKE_SAVE_PLATFORM="linux/amd64")
    assert r.returncode != 0
    assert "no manifest for linux/amd64" in r.stderr


def test_classic_layout_complete_passes_and_incomplete_fails(rig):
    ok, _, _ = rig(classic_archive(with_layers=True), BAKE_SAVE_PLATFORM="linux/amd64")
    assert ok.returncode == 0, ok.stderr
    bad, _, _ = rig(classic_archive(with_layers=False), BAKE_SAVE_PLATFORM="linux/amd64")
    assert bad.returncode != 0
    assert "abc.json is missing" in bad.stderr


def test_unset_platform_still_passes_platform_to_docker_save(rig):
    r, log, _ = rig(oci_archive(with_layers=True, arch="arm64"), APPLIANCE_ARCH="linux/arm64")
    assert r.returncode == 0, r.stderr
    saves = [ln for ln in log.splitlines() if ln.startswith("docker save")]
    assert saves and all("--platform linux/arm64" in ln for ln in saves)
    pulls = [ln for ln in log.splitlines() if ln.startswith("docker pull")]
    assert pulls and all("--platform linux/arm64" in ln for ln in pulls)


def test_unset_everything_defaults_to_the_host_arch(rig):
    host = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[os.uname().machine]
    r, log, _ = rig(oci_archive(with_layers=True, arch=host))
    assert r.returncode == 0, r.stderr
    assert f"--platform linux/{host}" in log


def test_failed_platform_save_recovers_with_rmi_pull_retry(rig):
    r, log, root = rig(
        oci_archive(with_layers=True),
        BAKE_SAVE_PLATFORM="linux/amd64",
        STUB_SAVE_FAILS="1",
    )
    assert r.returncode == 0, r.stderr
    lines = log.splitlines()
    first_save = next(i for i, ln in enumerate(lines) if ln.startswith("docker save"))
    after = lines[first_save + 1 :]
    # Only the failed reference is removed, then re-pulled for the platform,
    # then the save is retried.
    rmis = [ln for ln in lines if ln.startswith("docker rmi")]
    assert len(rmis) == 1 and len(rmis[0].split()) == 3
    assert not any("prune" in ln for ln in lines)
    assert after[0].startswith("docker rmi")
    assert after[1].startswith("docker pull --platform linux/amd64")
    assert any(ln.startswith("docker save") for ln in after)
    assert "recovered" in r.stdout
    assert "images baked" in r.stdout


def test_save_failing_after_the_retry_recovers_from_the_registry(rig):
    # The QA builder's shape: rmi + pull cannot repair the local store, so
    # both saves fail; the registry copy must still produce a good archive.
    r, log, root = rig(
        oci_archive(with_layers=True),
        BAKE_SAVE_PLATFORM="linux/amd64",
        STUB_SAVE_FAILS="99",
    )
    assert r.returncode == 0, r.stderr
    assert "recovered" in r.stdout and "skopeo" in r.stdout
    runs = [ln for ln in log.splitlines() if ln.startswith("docker run")]
    assert runs
    assert all("--override-os linux --override-arch amd64" in ln for ln in runs)
    assert all("quay.io/skopeo/stable:v" in ln for ln in runs)
    assert all("docker://" in ln and "docker-archive:/out/image.tar:" in ln for ln in runs)
    assert "images baked" in r.stdout
    d = root / "mkosi.extra/var/lib/rancher/k3s/agent/images"
    assert not list(d.glob("*.tar.zst.new"))


def test_registry_copy_archive_is_still_verified(rig):
    # Negative control: a skopeo archive without its layers must be refused,
    # not baked on the strength of the recovery having "succeeded".
    r, log, root = rig(
        oci_archive(with_layers=True),
        skopeo_archive=oci_archive(with_layers=False),
        BAKE_SAVE_PLATFORM="linux/amd64",
        STUB_SAVE_FAILS="99",
    )
    assert r.returncode != 0
    assert "without its layers" in r.stderr
    assert "images baked" not in r.stdout


def test_save_and_registry_copy_both_failing_refuses_naming_the_image(rig):
    r, log, root = rig(
        oci_archive(with_layers=True),
        BAKE_SAVE_PLATFORM="linux/amd64",
        STUB_SAVE_FAILS="99",
        STUB_SKOPEO_FAILS="1",
    )
    assert r.returncode != 0
    assert "ghcr.io/spatiumnorth/" in r.stderr
    assert "after re-pulling it and copying it from the registry" in r.stderr
    assert "images baked" not in r.stdout
    assert len([ln for ln in log.splitlines() if ln.startswith("docker save")]) == 2
    d = root / "mkosi.extra/var/lib/rancher/k3s/agent/images"
    assert not list(d.glob("*.tar.zst.new"))


def test_recovery_logs_rmi_and_pull_results_instead_of_discarding_them(rig):
    r, log, _ = rig(
        oci_archive(with_layers=True),
        BAKE_SAVE_PLATFORM="linux/amd64",
        STUB_SAVE_FAILS="1",
        STUB_RMI_FAILS="1",
    )
    assert r.returncode == 0, r.stderr
    assert "rmi ghcr.io/spatiumnorth/" in r.stderr and "stub rmi refused" in r.stderr
    assert "pull ghcr.io/spatiumnorth/" in r.stderr and ": ok" in r.stderr


def test_a_locally_built_image_has_no_registry_fallback(rig):
    # Negative control for the skopeo step: with no pull ref (BAKE_SOURCE
    # local) a failed save refuses outright and never runs skopeo.
    r, log, _ = rig(
        oci_archive(with_layers=True),
        BAKE_SAVE_PLATFORM="linux/amd64",
        BAKE_SOURCE="local",
        STUB_SAVE_FAILS="99",
    )
    assert r.returncode != 0
    assert not any(ln.startswith("docker run") for ln in log.splitlines())


def test_bake_logs_docker_version_and_store(rig):
    r, log, _ = rig(oci_archive(with_layers=True), BAKE_SAVE_PLATFORM="linux/amd64")
    assert r.returncode == 0, r.stderr
    assert "→ Docker:" in r.stdout and "image store:" in r.stdout
