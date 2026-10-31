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

#3169 — the same copy now also runs before a slot SWITCH (``rollback``,
``set-default`` to the other slot, ``set-next-boot`` to the other slot), with a
fresh mtime: k3s's import cache re-imports a tarball only when its size differs
or its mtime is after the cached one, so the older slot's equal-size tarball
copied with its own (older) mtime would be skipped and the rolled-back slot
would boot ErrImageNeverPull on any node whose containerd lost its images. The
switch tests drive the real subcommands with the slot pair and GRUB stubbed:

  * rollback / set-default-to-other / set-next-boot-to-other re-copy the
    target's set with fresh mtimes, BEFORE GRUB is flipped;
  * set-default to the running slot (committing a trial) copies nothing, and
    set-next-boot straight after an apply copies nothing (already in place);
  * a target slot with no tarballs, or a copy that fails, warns loudly and
    still flips GRUB — rollback is the emergency path and must not be blocked.

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


# --- #3169: slot switches re-copy the TARGET slot's set with a fresh mtime ---

ROLLBACK_SET = {
    # Same names AND sizes as the newer slot's copies already in /var: the case
    # k3s's cache skips unless the mtime moves forward.
    "dhcp-kea.tar.zst": b"OLD-kea" * 4096,
    "dns-bind9.tar.zst": b"OLD-bind9" * 4096,
}
ACTIVE = {"partlabel": "root_b", "device": "/dev/vda4", "uuid": "bbbb"}
INACTIVE = {"partlabel": "root_a", "device": "/dev/vda3", "uuid": "aaaa"}


@pytest.fixture()
def switch_rig(rig: Rig, monkeypatch) -> Rig:
    """The rig, plus the slot pair, root and GRUB helpers stubbed: running on
    root_b (the newer slot), root_a the older one being switched back to."""
    monkeypatch.setattr(rig.mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(rig.mod, "detect_active_inactive", lambda: (dict(ACTIVE), dict(INACTIVE)))
    monkeypatch.setattr(rig.mod, "_sync_mirror_esp", lambda: None)
    monkeypatch.setattr(rig.mod, "_read_grubenv_default", lambda: "slot_a")
    # The target slot's release file (#1026 arch check): same arch as the host.
    monkeypatch.setattr(rig.mod, "host_architecture", lambda: "amd64")
    rig.target_release = {"APPLIANCE_VERSION": "2026.10.02-1", "APPLIANCE_ARCH": "amd64"}
    monkeypatch.setattr(rig.mod, "slot_release_fields", lambda slot: rig.target_release)
    for name, body in ROLLBACK_SET.items():
        p = rig.src / name
        p.write_bytes(body)
        os.utime(p, (OLD_MTIME, OLD_MTIME))  # the older slot's bake time
        newer = rig.dest / name
        rig.dest.mkdir(parents=True, exist_ok=True)
        newer.write_bytes(body.replace(b"OLD", b"NEW"))  # equal size
        os.utime(newer, (NEW_MTIME, NEW_MTIME))
    return rig


def _assert_recopied_fresh(rig: Rig, started: float) -> None:
    for name, body in ROLLBACK_SET.items():
        p = rig.dest / name
        assert p.read_bytes() == body, f"{name} is still the running slot's copy, not the target's"
        assert p.stat().st_mtime >= started - 1, (
            f"{name} kept the target slot's (older) bake mtime: k3s's import cache "
            "skips an equal-size tarball whose mtime is not after the cached one, so "
            "nothing is re-imported and the rolled-back slot is ErrImageNeverPull"
        )


def _grub_after_copy(rig: Rig, grub_cmd: str) -> None:
    tools = [c[0] for c in rig.commands]
    assert "mount" in tools, f"the target slot was never mounted to copy its images: {tools}"
    assert tools.index("mount") < tools.index(grub_cmd), (
        f"GRUB was flipped before the target's images were copied: {tools}"
    )
    assert any(c[0] == "mount" and "/dev/vda3" in c for c in rig.commands), "mounted the wrong slot"


@pytest.mark.parametrize(
    "invoke, grub_cmd",
    [
        (lambda m: m.cmd_rollback(types.SimpleNamespace()), "grub-set-default"),
        (lambda m: m.cmd_set_default(types.SimpleNamespace(slot="slot_a")), "grub-set-default"),
        (lambda m: m.cmd_set_next_boot(types.SimpleNamespace(slot="slot_a")), "grub-reboot"),
    ],
    ids=["rollback", "set-default-other", "set-next-boot-other"],
)
def test_a_switch_to_the_other_slot_recopies_its_images_with_a_fresh_mtime(
    switch_rig: Rig, invoke, grub_cmd
) -> None:
    import time

    started = time.time()
    assert invoke(switch_rig.mod) == 0
    _assert_recopied_fresh(switch_rig, started)
    _grub_after_copy(switch_rig, grub_cmd)
    assert not list(switch_rig.dest.glob(".*.part")), "a temp file was left behind"
    renamed = {dst.name for _, dst in switch_rig.renames}
    assert renamed == set(ROLLBACK_SET), "each tarball must still land by one atomic rename (#1630)"


def test_set_default_to_the_running_slot_copies_nothing(switch_rig: Rig) -> None:
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in switch_rig.dest.iterdir()}

    assert switch_rig.mod.cmd_set_default(types.SimpleNamespace(slot="slot_b")) == 0

    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in switch_rig.dest.iterdir()}
    assert after == before, "committing the running slot rewrote k3s's images dir"
    assert [c[0] for c in switch_rig.commands] == ["grub-set-default"]


def test_set_next_boot_right_after_an_apply_copies_nothing(switch_rig: Rig) -> None:
    # The upgrade runner calls set-next-boot straight after apply, whose refresh
    # already copy2'd the target's set (same size and mtime). Copying it again
    # would make the running k3s import the whole set a second time.
    for name in ROLLBACK_SET:
        shutil.copy2(switch_rig.src / name, switch_rig.dest / name)
    before = {p.name: p.stat().st_mtime_ns for p in switch_rig.dest.iterdir()}

    assert switch_rig.mod.cmd_set_next_boot(types.SimpleNamespace(slot=None)) == 0

    assert not switch_rig.writes, "set-next-boot after an apply re-copied the set"
    assert {p.name: p.stat().st_mtime_ns for p in switch_rig.dest.iterdir()} == before
    assert "grub-reboot" in [c[0] for c in switch_rig.commands]


@pytest.mark.parametrize("layout", ["empty-dir", "no-dir"])
def test_a_target_with_no_tarballs_warns_and_still_rolls_back(switch_rig: Rig, capsys, layout) -> None:
    for p in switch_rig.src.iterdir():
        p.unlink()
    if layout == "no-dir":
        switch_rig.src.rmdir()
    before = {p.name: p.read_bytes() for p in switch_rig.dest.iterdir()}

    assert switch_rig.mod.cmd_rollback(types.SimpleNamespace()) == 0

    err = capsys.readouterr().err
    assert "WARNING: could not re-copy root_a's baked images" in err, err
    assert {p.name: p.read_bytes() for p in switch_rig.dest.iterdir()} == before
    assert "grub-set-default" in [c[0] for c in switch_rig.commands], "the rollback was blocked"


def test_a_failed_copy_warns_loudly_and_still_rolls_back(switch_rig: Rig, capsys) -> None:
    def disk_full_copy2(src, dst, *args, **kwargs):
        Path(dst).write_bytes(b"partial")
        raise OSError(28, "No space left on device")

    switch_rig.mod.shutil.copy2 = disk_full_copy2

    assert switch_rig.mod.cmd_rollback(types.SimpleNamespace()) == 0

    err = capsys.readouterr().err
    assert "WARNING: could not re-copy root_a's baked images" in err, err
    for name, body in ROLLBACK_SET.items():
        assert (switch_rig.dest / name).read_bytes() == body.replace(b"OLD", b"NEW"), (
            f"{name} was left half-written"
        )
    assert not list(switch_rig.dest.glob(".*.part"))
    tools = [c[0] for c in switch_rig.commands]
    assert tools[-1] == "grub-set-default", f"the rollback was blocked by a failed copy: {tools}"


def test_a_target_slot_of_another_architecture_is_not_copied(switch_rig: Rig, capsys) -> None:
    # #1026 — an apply refused at the arch gate leaves the other arch's rootfs
    # in the inactive slot. Its tarballs must not reach the RUNNING k3s, which
    # would import them and could re-point a shared tag at the wrong arch.
    switch_rig.target_release = {"APPLIANCE_VERSION": "2026.10.02-1", "APPLIANCE_ARCH": "arm64"}
    before = {p.name: p.read_bytes() for p in switch_rig.dest.iterdir()}

    assert switch_rig.mod.cmd_rollback(types.SimpleNamespace()) == 0

    assert not switch_rig.writes, "a wrong-architecture slot's tarballs were copied"
    assert {p.name: p.read_bytes() for p in switch_rig.dest.iterdir()} == before
    assert "holds an arm64 image and this node is amd64" in capsys.readouterr().err
    assert [c[0] for c in switch_rig.commands] == ["grub-set-default"]


def test_a_target_slot_with_no_release_arch_is_still_copied(switch_rig: Rig) -> None:
    # Unlabelled (older) slots are amd64 in fact; unknown never blocks.
    switch_rig.target_release = {}
    assert switch_rig.mod.cmd_rollback(types.SimpleNamespace()) == 0
    assert {dst.name for _, dst in switch_rig.renames} == set(ROLLBACK_SET)


def test_an_apply_of_a_slot_without_tarballs_still_clears_a_killed_copy(rig: Rig) -> None:
    # The apply path must keep removing a .part a killed apply left, whether or
    # not the new slot carries tarballs (#1630 cleanup, unchanged by #3169).
    rig.dest.mkdir(parents=True)
    leftover = rig.dest / ".dns-bind9.tar.zst.part"
    leftover.write_bytes(b"half a tarball")

    assert rig.mod._refresh_baked_images("/dev/vda5") is None

    assert not leftover.exists(), "a .part file from an earlier, killed apply is still in the images dir"
