"""A slot upgrade copies its image tarballs into k3s's images dir atomically (#1630).

``spatium-upgrade-slot apply`` runs on the OLD slot, and that slot's k3s keeps
running. Its image watcher imports, 2 s after any event in
/var/lib/rancher/k3s/agent/images, every file whose name ends in a tarball
extension or ``.txt`` (k3s v1.36 ``pkg/agent/containerd/watcher.go``,
``isFileSupported`` over wharfie's ``SupportedExtensions``).

``_refresh_baked_images`` used to copy each of the new slot's tarballs over the
old one in place (``shutil.copy2(tarball, dest / tarball.name)``), so the
watcher imported files that were still being written. Those imports fail
("short read", "window size exceeded"). One cut off inside a tarball's
``index.json`` leaves a containerd ingest under the ref ``tar-index.json``,
which every tarball's index shares. That ingest then fails every shorter
``index.json`` after it, on the next boot too. A node came up on the new slot
without its DNS and DHCP agents' images that way.

These tests drive the real ``_refresh_baked_images``. ``mount`` is stubbed,
the function's two absolute paths are remapped into tmp, and every path the
copy writes is recorded:

  * nothing is ever written under a name the watcher imports, and each tarball
    reaches its real name through one rename;
  * the result is the slot's tarballs, byte for byte, with their mtimes, and no
    temp files are left;
  * a copy that fails part-way leaves the previous tarball whole;
  * a temp file left by an apply killed part-way is removed.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_upgrade_slot_image_copy.py -v
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-upgrade-slot"
)

# The names k3s imports from its images dir: wharfie v0.7.1
# ``pkg/tarfile.SupportedExtensions`` plus ``.txt`` (a pre-pull list), as
# ``isFileSupported`` in k3s v1.36.4's watcher.go checks them.
K3S_IMPORTS = (".tar", ".tar.lz4", ".tar.bz2", ".tbz", ".tar.gz", ".tgz",
               ".tar.zst", ".tzst", ".txt")

SLOT_IMAGES = "var/lib/rancher/k3s/agent/images"
OLD_MTIME = 1_700_000_000
NEW_MTIME = 1_760_000_000


def _watched(name: str) -> bool:
    return any(name.endswith(ext) for ext in K3S_IMPORTS)


class Rig:
    """The module under test, with ``mount`` stubbed and its paths remapped."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        loader = SourceFileLoader("spatium_upgrade_slot_image_copy", str(SCRIPT))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.mod = importlib.util.module_from_spec(spec)
        loader.exec_module(self.mod)

        self.mnt = tmp_path / "slot-mnt"
        self.dest = tmp_path / "var-images"
        self.src = self.mnt / SLOT_IMAGES
        self.src.mkdir(parents=True)
        remap = {
            "/tmp/spatium-slot-mnt": self.mnt,
            "/var/lib/rancher/k3s/agent/images": self.dest,
        }
        real_path = pathlib.Path

        def fake_path(*parts):
            p = real_path(*parts)
            return real_path(remap.get(str(p), p))

        monkeypatch.setattr(self.mod, "Path", fake_path)

        self.commands: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            self.commands.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(self.mod, "subprocess", types.SimpleNamespace(run=fake_run))

        self.writes: list[Path] = []
        self.renames: list[tuple[Path, Path]] = []
        self.copy2 = shutil.copy2

        def recording_copy2(src, dst, *args, **kwargs):
            self.writes.append(Path(dst))
            return self.copy2(src, dst, *args, **kwargs)

        monkeypatch.setattr(self.mod, "shutil", types.SimpleNamespace(copy2=recording_copy2))
        real_replace = os.replace

        def recording_replace(src, dst, *args, **kwargs):
            self.renames.append((Path(src), Path(dst)))
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(self.mod.os, "replace", recording_replace)

    def slot_tarball(self, name: str, body: bytes) -> Path:
        p = self.src / name
        p.write_bytes(body)
        os.utime(p, (NEW_MTIME, NEW_MTIME))
        return p

    def old_tarball(self, name: str, body: bytes) -> Path:
        self.dest.mkdir(parents=True, exist_ok=True)
        p = self.dest / name
        p.write_bytes(body)
        os.utime(p, (OLD_MTIME, OLD_MTIME))
        return p


@pytest.fixture()
def rig(tmp_path, monkeypatch) -> Rig:
    return Rig(tmp_path, monkeypatch)


SLOT_SET = {
    "dhcp-kea.tar.zst": b"new-kea" * 4096,
    "dns-bind9.tar.zst": b"new-bind9" * 4096,
    "k3s-airgap-images-amd64.tar.zst": b"airgap" * 8192,
}


def test_no_tarball_is_ever_written_under_a_name_k3s_imports(rig: Rig, capsys) -> None:
    for name, body in SLOT_SET.items():
        rig.slot_tarball(name, body)
    rig.old_tarball("dhcp-kea.tar.zst", b"old-kea")
    rig.old_tarball("dns-bind9.tar.zst", b"old-bind9")

    rig.mod._refresh_baked_images("/dev/vda5")

    assert rig.writes, "the refresh copied nothing"
    for dst in rig.writes:
        assert not _watched(dst.name), (
            f"the slot's tarball was written in place as {dst.name}: the running k3s's "
            "image watcher imports a file of that name while it is still being written "
            "(#1630 — a failed import there leaves a stale containerd ingest that "
            "poisons every later index.json)"
        )
        assert dst.parent == rig.dest, f"{dst} is not in the images dir (the rename would cross filesystems)"
    renamed_to = {dst.name for _, dst in rig.renames}
    assert renamed_to == set(SLOT_SET), f"each tarball must land by one rename; renamed: {sorted(renamed_to)}"
    for src, dst in rig.renames:
        assert src.parent == dst.parent == rig.dest
        assert not _watched(src.name), f"renamed from {src.name}, a name k3s imports"
    assert "refreshed 3 baked tarballs" in capsys.readouterr().out


def test_the_images_dir_ends_with_the_slots_tarballs_whole(rig: Rig) -> None:
    for name, body in SLOT_SET.items():
        rig.slot_tarball(name, body)
    rig.old_tarball("dhcp-kea.tar.zst", b"old-kea")

    rig.mod._refresh_baked_images("/dev/vda5")

    left = sorted(p.name for p in rig.dest.iterdir())
    assert left == sorted(SLOT_SET), f"the images dir holds {left}"
    for name, body in SLOT_SET.items():
        p = rig.dest / name
        assert p.read_bytes() == body, f"{name} is not the slot's copy"
        # copy2's mtime is what makes k3s import the new file (its cache is keyed
        # on size and mtime), so it must survive the rename.
        assert int(p.stat().st_mtime) == NEW_MTIME
    assert [c[0] for c in rig.commands] == ["mount", "umount"]


def test_a_copy_that_fails_part_way_leaves_the_previous_tarball_whole(rig: Rig, capsys) -> None:
    rig.slot_tarball("dhcp-kea.tar.zst", SLOT_SET["dhcp-kea.tar.zst"])
    old = rig.old_tarball("dhcp-kea.tar.zst", b"old-kea-bytes")

    def disk_full_copy2(src, dst, *args, **kwargs):
        rig.writes.append(Path(dst))
        Path(dst).write_bytes(Path(src).read_bytes()[:100])
        raise OSError(28, "No space left on device")

    rig.mod.shutil.copy2 = disk_full_copy2

    rig.mod._refresh_baked_images("/dev/vda5")

    assert old.read_bytes() == b"old-kea-bytes", (
        "a copy that died part-way truncated the previous tarball: the node now has "
        "neither the old image's file nor the new one's"
    )
    assert sorted(p.name for p in rig.dest.iterdir()) == ["dhcp-kea.tar.zst"], "the partial copy was left behind"
    assert "baked-image refresh skipped" in capsys.readouterr().err
    assert rig.commands[-1][0] == "umount"


def test_a_temp_file_left_by_a_killed_apply_is_removed(rig: Rig) -> None:
    rig.slot_tarball("dhcp-kea.tar.zst", SLOT_SET["dhcp-kea.tar.zst"])
    rig.dest.mkdir(parents=True)
    leftover = rig.dest / ".dns-bind9.tar.zst.part"
    leftover.write_bytes(b"half a tarball")

    rig.mod._refresh_baked_images("/dev/vda5")

    assert not leftover.exists(), "a .part file from an earlier, killed apply is still in the images dir"
    assert sorted(p.name for p in rig.dest.iterdir()) == ["dhcp-kea.tar.zst"]
