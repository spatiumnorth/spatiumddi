"""The installer keeps the baked image tarballs on root_A itself too (#3169).

``do_install`` mounts /var at $MOUNT/var before rsyncing the live root, so the
tarballs landed only on the /var partition and root_A's own
``var/lib/rancher/k3s/agent/images`` stayed an empty mountpoint directory. A
rollback to the node's original slot then had nothing to re-copy.

``_keep_images_in_root_slot`` is extracted from the shipped script and run
under bash with ``set -e``, against stub ``mount`` / ``umount``. The stub
bind-mount makes the temp mountpoint a symlink to a directory standing for
root_A's raw filesystem, which is DIFFERENT from ``$MOUNT/var`` (the /var
partition), so the tests can tell which of the two received the files.

HOW TO RUN: python3 -m pytest appliance/tests/test_install_root_slot_images.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
import types
from pathlib import Path

import pytest

from _installer_source import CODE, extract_fn as _extract

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="bash required")

REL = "var/lib/rancher/k3s/agent/images"
MTIME = 1_650_000_000
SET = {
    "dhcp-kea.tar.zst": b"kea" * 5000,
    "dns-bind9.tar.zst": b"bind9" * 5000,
}


def _run(tmp: Path, *, avail: int | None = None, files=SET, mount_rc: int = 0, failing_cp: bool = False):
    live = tmp / "live"
    (live / REL).mkdir(parents=True)
    for name, body in files.items():
        p = live / REL / name
        p.write_bytes(body)
        os.utime(p, (MTIME, MTIME))
    root_a = tmp / "root_a_raw"  # the raw root_A filesystem
    root_a.mkdir()
    mnt = tmp / "mnt"  # what the installer sees: root_A with /var mounted over it
    (mnt / "var").mkdir(parents=True)
    var_part = tmp / "var_part"  # the /var partition's own content
    var_part.mkdir()
    bindir = tmp / "bin"
    bindir.mkdir()
    (bindir / "mount").write_text(
        f'#!/bin/sh\n[ {mount_rc} -ne 0 ] && exit {mount_rc}\n'
        f'[ "$1" = "--bind" ] || exit 0\nrmdir "$3" && ln -s "{root_a}" "$3"\n'
    )
    (bindir / "umount").write_text('#!/bin/sh\nrm -f "$1"\n')
    if avail is not None:
        (bindir / "df").write_text(f'#!/bin/sh\necho Avail\necho {avail}\n')
    if failing_cp:
        # writes one file, then dies (ENOSPC part-way through)
        (bindir / "cp").write_text('#!/bin/sh\nmkdir -p "$4"; echo part > "$4/dhcp-kea.tar.zst"; exit 1\n')
    for f in bindir.iterdir():
        f.chmod(0o755)
    log = tmp / "install.log"
    script = textwrap.dedent(
        f"""
        set -e -o pipefail
        export PATH="{bindir}:$PATH"
        INSTALL_LOG="{log}"
        MOUNT="{mnt}"
        LIVE_ROOT_SRC="{live}/"
        log() {{ echo "$*" >> "$INSTALL_LOG"; }}
        {_extract("_keep_images_in_root_slot")}
        _keep_images_in_root_slot
        echo AFTER
        """
    )
    p = subprocess.run([BASH, "-c", script], capture_output=True, text=True)
    return p, root_a, var_part, log.read_text() if log.exists() else ""


def test_tarballs_land_on_root_a_itself_with_their_mtimes(tmp_path):
    p, root_a, var_part, log = _run(tmp_path)
    assert p.returncode == 0, p.stderr
    for name, body in SET.items():
        f = root_a / REL / name
        assert f.read_bytes() == body, f"{name} is not on root_A's own filesystem"
        assert int(f.stat().st_mtime) == MTIME
    assert not any(var_part.rglob("*")), "the /var partition must be left to rsync, not written here"
    assert "Kept 2 baked image tarballs" in log


def test_the_temp_bind_mount_is_released(tmp_path):
    _run(tmp_path)
    assert not list(Path("/tmp").glob("spatium-rootA-raw.*")), "the bind mountpoint was left behind"


def test_not_enough_room_fails_loudly_and_leaves_no_set(tmp_path):
    p, root_a, _, log = _run(tmp_path, avail=1024)
    assert p.returncode == 1
    assert "AFTER" not in p.stdout
    assert "FATAL" in log and "root_A has" in log
    assert not (root_a / REL).exists(), "a truncated set was left where a rollback would trust it"


def test_a_failed_copy_removes_the_partial_set(tmp_path):
    p, root_a, _, _ = _run(tmp_path, failing_cp=True)
    assert p.returncode == 1
    assert not (root_a / REL).exists(), "a partial set was left behind"


def test_a_failed_bind_mount_fails_the_install(tmp_path):
    p, _, _, log = _run(tmp_path, mount_rc=32)
    assert p.returncode == 1
    assert "could not bind-mount root_A" in log


def test_a_live_root_with_no_tarballs_is_not_an_error(tmp_path):
    p, root_a, _, log = _run(tmp_path, files={})
    assert p.returncode == 0
    assert "AFTER" in p.stdout
    assert "keeps none of its own" in log


def test_do_install_places_them_after_the_live_root_copy_on_every_path():
    """Structural: after the rsync, before anything is built on root_A, in the
    unconditional part of do_install, so it also runs on the KEEP_VAR reinstall.
    The source is the live root, not $MOUNT/var (a kept /var holds an old set)."""
    body = CODE[CODE.index("\ndo_install() {"):]
    copy = body.index("_copy_live_root \\")
    keep = body.index("_keep_images_in_root_slot || exit 1")
    nxt = body.index('echo "60"; echo "Writing boot-critical config')
    assert copy < keep < nxt
    # not inside the `if [ "$KEEP_VAR" != "yes" ]` mkfs branches
    between = body[copy:keep]
    assert "KEEP_VAR" not in between
    fn = _extract("_keep_images_in_root_slot")
    assert "LIVE_ROOT_SRC" in fn and '"$MOUNT/var' not in fn
    assert "mount --bind" in fn and "--rbind" not in fn


def test_a_freshly_installed_slot_a_is_what_a_rollback_recopies(tmp_path, monkeypatch):
    """End to end: install lays the set on root_A, an upgrade leaves a different
    set on /var, and the rollback to A restores A's own set from root_A."""
    p, root_a, _, _ = _run(tmp_path)
    assert p.returncode == 0, p.stderr

    import test_upgrade_slot_image_copy as t

    rig = t.Rig(tmp_path / "rb", monkeypatch)
    shutil.rmtree(rig.mnt)
    shutil.copytree(root_a, rig.mnt, symlinks=True)  # mount of root_A as the rollback sees it
    monkeypatch.setattr(rig.mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(rig.mod, "detect_active_inactive", lambda: (dict(t.ACTIVE), dict(t.INACTIVE)))
    monkeypatch.setattr(rig.mod, "_sync_mirror_esp", lambda: None)
    monkeypatch.setattr(rig.mod, "_read_grubenv_default", lambda: "slot_a")
    monkeypatch.setattr(rig.mod, "host_architecture", lambda: "amd64")
    monkeypatch.setattr(rig.mod, "slot_release_fields", lambda target: {"APPLIANCE_ARCH": "amd64"})
    # /var holds the NEWER slot's set (same names and sizes, different bytes)
    for name, body in SET.items():
        rig.old_tarball(name, bytes(len(body)))

    assert rig.mod.cmd_rollback(types.SimpleNamespace()) == 0

    for name, body in SET.items():
        got = rig.dest / name
        assert got.read_bytes() == body, f"{name}: slot A's own image was not restored"
        assert int(got.stat().st_mtime) > MTIME, "mtime not fresh: k3s would skip it"
