"""A mirrored (#999 RAID1) appliance can slot-upgrade and roll back (#3172).

On a mirrored install the partitions carrying the ``root_A`` / ``root_B``
GPT names are raid1 MEMBERS — four of them, two per slot — and the
filesystem ``root=UUID=`` names lives on the md array lsblk lists beneath
each member. ``spatium-upgrade-slot`` collected every node with a slot
PARTLABEL, found four candidates instead of two, and every subcommand
(status / apply / rollback / set-next-boot / sync-versions) exited 2 with
"couldn't detect A/B slots". Even with two candidates the active slot would
not have matched: a member's UUID is the ARRAY's, not the filesystem's.

And once detection works, ``apply`` must write the ARRAY, never a member —
and the array is 9 MiB smaller than the 8 GiB image (metadata 1.2's data
offset), so the image goes in through a spill device and its filesystem is
shrunk into the array before anything reads it.

The lsblk fixtures are the real shape captured from a mirrored VM installed
from nightly-20261027 (the evidence on #3172): md125 / md127 appear as a
child of BOTH members of their slot.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_upgrade_slot_mirror.py -v
"""

from __future__ import annotations

import __future__
import ast
import copy
import importlib.util
import json
import re
import shutil
import subprocess
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

BIN = Path(__file__).resolve().parents[1] / "mkosi.extra" / "usr" / "local" / "bin"
SLOT_CLI = BIN / "spatium-upgrade-slot"

RAID = "a19d880f-05fc-4d3b-a006-743f0f84911e"  # fd00, Linux RAID
ROOT_X86 = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"  # 8304

# ── the mirrored VM (#3172 evidence), as `lsblk -J` emits it ──────────
ROOT_A_FS = "bad1f6f7-7eeb-40e0-a713-d9cb8d5cb6b3"  # root=UUID= on the cmdline
ROOT_B_FS = "8fb55b19-fe3d-41b1-ae57-11806a676e4d"
ROOT_A_ARRAY = "87470471-c473-569e-2115-9cad0f7b34b0"
ROOT_B_ARRAY = "9a3bc8e1-bce7-8b37-b814-d5afb79c8993"


def _md(name: str, uuid: str, label: str) -> dict:
    return {"name": name, "path": f"/dev/{name}", "uuid": uuid, "partlabel": None,
            "label": label, "parttype": None, "fstype": "ext4"}


def _member(name: str, partlabel: str, array_uuid: str, md_name: str | None,
            md_uuid: str, label: str) -> dict:
    node = {"name": name, "path": f"/dev/{name}", "uuid": array_uuid,
            "partlabel": partlabel, "label": f"any:{label}", "parttype": RAID,
            "fstype": "linux_raid_member"}
    if md_name:
        node["children"] = [_md(md_name, md_uuid, label)]
    return node


def _mirror_disk(disk: str, esp_label: str, esp_uuid: str) -> dict:
    return {
        "name": disk, "path": f"/dev/{disk}", "uuid": None, "partlabel": None,
        "label": None, "parttype": None, "fstype": None,
        "children": [
            {"name": f"{disk}1", "path": f"/dev/{disk}1", "uuid": None,
             "partlabel": "bios_boot", "label": None,
             "parttype": "21686148-6449-6e6f-744e-656564454649", "fstype": None},
            {"name": f"{disk}2", "path": f"/dev/{disk}2", "uuid": esp_uuid,
             "partlabel": "ESP", "label": esp_label,
             "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "fstype": "vfat"},
            _member(f"{disk}3", "state", "263540af-b393-d313-94f7-d8f56da6c821",
                    "md124", "6e53ee3d-99e2-4da3-bb44-84edf9490fde", "state"),
            _member(f"{disk}4", "root_A", ROOT_A_ARRAY, "md125", ROOT_A_FS, "root_a"),
            _member(f"{disk}5", "root_B", ROOT_B_ARRAY, "md127", ROOT_B_FS, "root_b"),
            _member(f"{disk}6", "var", "a574417d-6b39-d763-c92d-b9cc4d007154",
                    "md126", "a9e5cc6b-fc67-4761-ae3c-85e0b797423e", "var"),
        ],
    }


MIRROR = {"blockdevices": [
    _mirror_disk("vda", "ESP", "84B9-51BA"),
    _mirror_disk("vdb", "ESP2", "84B9-D943"),
    {"name": "vdc", "path": "/dev/vdc", "uuid": "2026-10-31-15-24-25-00",
     "partlabel": None, "label": "CIDATA", "parttype": None, "fstype": "iso9660"},
]}

SINGLE_A = "11111111-2222-4333-8444-555555555555"
SINGLE_B = "66666666-7777-4888-9999-aaaaaaaaaaaa"
SINGLE = {"blockdevices": [{
    "name": "sda", "path": "/dev/sda", "uuid": None, "partlabel": None,
    "label": None, "parttype": None, "fstype": None,
    "children": [
        {"name": "sda2", "path": "/dev/sda2", "uuid": "84B9-51BA", "partlabel": "ESP",
         "label": "ESP", "parttype": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
         "fstype": "vfat"},
        {"name": "sda4", "path": "/dev/sda4", "uuid": SINGLE_A, "partlabel": "root_A",
         "label": "root_a", "parttype": ROOT_X86, "fstype": "ext4"},
        {"name": "sda5", "path": "/dev/sda5", "uuid": SINGLE_B, "partlabel": "root_B",
         "label": "root_b", "parttype": ROOT_X86, "fstype": "ext4"},
    ],
}]}

_REAL_POPEN = subprocess.Popen
MEMBERS = {"/dev/vda4", "/dev/vdb4", "/dev/vda5", "/dev/vdb5"}
ARRAY_BYTES = 8580497408  # an 8 GiB slot as an md 1.2 array: 18432 sectors short
IMAGE_BYTES = 8 * 1024 ** 3


@pytest.fixture
def slot_cli(tmp_path, monkeypatch):
    loader = SourceFileLoader("spatium_upgrade_slot_mirror", str(SLOT_CLI))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setattr(module, "_STAGING_DIR", tmp_path / "staging")
    monkeypatch.setattr(module, "_PROGRESS_FILE", tmp_path / "progress.json")
    monkeypatch.setattr(module, "_SLOT_VERSIONS_FILE", tmp_path / "slot-versions.json")
    monkeypatch.setattr(module, "_SLOT_IMAGE_TAGS_FILE", tmp_path / "slot-image-tags.json")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    return module


class Host:
    """Stands in for every external command the slot CLI runs. Records argv;
    answers lsblk from a topology and the sizing / mapping tools from
    attributes a test can change."""

    def __init__(self, topology: dict, root_uuid: str) -> None:
        self.topology = topology
        self.root_uuid = root_uuid
        self.calls: list[list[str]] = []
        self.inputs: dict[str, str] = {}
        self.spill_stays_mapped = False
        self.popen: list[list[str]] = []
        self.blkid_uuid = "0f0f0f0f-1111-4222-8333-444444444444"
        self.labels: dict[str, str] = {}

    def run(self, argv, **kw):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        if kw.get("input") is not None:
            self.inputs[argv[0]] = kw["input"]
        out, rc = "", 0
        cmd = argv[0]
        if cmd == "lsblk":
            out = json.dumps(self.topology)
        elif cmd == "xz" and "--list" in argv:
            out = (f"name\t{argv[-1]}\nfile\t1\t2731\t337091368\t{IMAGE_BYTES}\t0.039\tCRC64\t0\n"
                   f"totals\t1\t2731\t337091368\t{IMAGE_BYTES}\t0.039\tCRC64\t0\t1\n")
        elif cmd == "blockdev":
            out = f"{ARRAY_BYTES}\n"
        elif cmd == "losetup" and "--find" in argv:
            out = "/dev/loop7\n"
        elif cmd == "dmsetup" and argv[1] == "info":
            rc = 0 if self.spill_stays_mapped else 1
        elif cmd == "tune2fs" and argv[1] == "-L":
            self.labels[argv[3]] = argv[2]
        elif cmd == "blkid" and "LABEL" in argv:
            out = self.labels.get(argv[-1], "") + "\n"
        elif cmd == "blkid" and "UUID" in argv:
            out = self.blkid_uuid + "\n"
        if kw.get("check") and rc:
            raise subprocess.CalledProcessError(rc, argv, out, "")
        return subprocess.CompletedProcess(argv, rc, out, "")

    def Popen(self, argv, **kw):  # noqa: N802 — stands in for subprocess.Popen
        self.popen.append([str(a) for a in argv])
        real = _REAL_POPEN
        if argv[0] == "xz":
            return real(["printf", "image"], **kw)
        return real(["sh", "-c", "cat >/dev/null"], **kw)

    def ran(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]

    def every_device_written(self) -> set[str]:
        """Every block device a mutating command was pointed at."""
        devs: set[str] = set()
        for argv in self.popen:
            devs |= {a[3:] for a in argv if a.startswith("of=")}
        for argv in self.calls:
            if argv[0] in ("tune2fs", "resize2fs", "e2fsck", "partprobe"):
                devs |= {a for a in argv if a.startswith("/dev/")}
        return devs


@pytest.fixture
def host(slot_cli, monkeypatch):
    def install(topology: dict, root_uuid: str) -> Host:
        h = Host(topology, root_uuid)
        monkeypatch.setattr(slot_cli.subprocess, "run", h.run)
        monkeypatch.setattr(slot_cli.subprocess, "Popen", h.Popen)
        monkeypatch.setattr(slot_cli, "parse_cmdline_root_uuid", lambda: root_uuid)
        return h
    return install


# ══════════════════════════════════════════════════════════════════════
# detection
# ══════════════════════════════════════════════════════════════════════


def test_a_mirror_resolves_each_slot_to_its_array(slot_cli, host) -> None:
    host(MIRROR, ROOT_A_FS)
    slots = sorted(slot_cli.find_slot_partitions(), key=lambda s: s["partlabel"])
    assert slots == [
        {"device": "/dev/md125", "uuid": ROOT_A_FS, "partlabel": "root_a",
         "fslabel": "root_a", "members": "/dev/vda4 /dev/vdb4"},
        {"device": "/dev/md127", "uuid": ROOT_B_FS, "partlabel": "root_b",
         "fslabel": "root_b", "members": "/dev/vda5 /dev/vdb5"},
    ]


def test_a_mirror_detects_the_booted_array_as_active(slot_cli, host) -> None:
    host(MIRROR, ROOT_A_FS)
    active, inactive = slot_cli.detect_active_inactive()
    assert (active["partlabel"], active["device"]) == ("root_a", "/dev/md125")
    assert (inactive["partlabel"], inactive["device"]) == ("root_b", "/dev/md127")


def test_a_mirror_booted_from_b_detects_b(slot_cli, host) -> None:
    host(MIRROR, ROOT_B_FS.upper())
    active, inactive = slot_cli.detect_active_inactive()
    assert (active["device"], inactive["device"]) == ("/dev/md127", "/dev/md125")


def test_the_named_array_link_is_preferred_when_it_is_this_array(
    slot_cli, host, monkeypatch
) -> None:
    host(MIRROR, ROOT_A_FS)
    links = {"/dev/md/root_a": "/dev/md125", "/dev/md/root_b": "/dev/md126"}  # stale b
    monkeypatch.setattr(slot_cli.os.path, "exists", lambda p: p in links)
    monkeypatch.setattr(slot_cli.os.path, "realpath", lambda p: links.get(p, p))
    devices = {s["partlabel"]: s["device"] for s in slot_cli.find_slot_partitions()}
    assert devices == {"root_a": "/dev/md/root_a", "root_b": "/dev/md127"}


def test_single_disk_detection_is_unchanged(slot_cli, host) -> None:
    host(SINGLE, SINGLE_A)
    assert slot_cli.find_slot_partitions() == [
        {"device": "/dev/sda4", "uuid": SINGLE_A, "partlabel": "root_a", "fslabel": "root_a"},
        {"device": "/dev/sda5", "uuid": SINGLE_B, "partlabel": "root_b", "fslabel": "root_b"},
    ]
    active, inactive = slot_cli.detect_active_inactive()
    assert (active["device"], inactive["device"]) == ("/dev/sda4", "/dev/sda5")


def _without_array(topology: dict, member: str) -> dict:
    topology = copy.deepcopy(topology)
    for disk in topology["blockdevices"]:
        for part in disk.get("children") or []:
            if part["name"] == member:
                part.pop("children", None)
    return topology


def test_a_member_kicked_out_of_a_degraded_array_does_not_hide_the_slot(
    slot_cli, host
) -> None:
    host(_without_array(MIRROR, "vdb5"), ROOT_A_FS)
    _active, inactive = slot_cli.detect_active_inactive()
    assert inactive["device"] == "/dev/md127"
    assert inactive["members"] == "/dev/vda5"


def test_a_slot_whose_array_is_not_assembled_is_never_its_member(slot_cli, host) -> None:
    host(_without_array(_without_array(MIRROR, "vda5"), "vdb5"), ROOT_A_FS)
    assert not {s["device"] for s in slot_cli.find_slot_partitions()} & MEMBERS
    assert slot_cli.detect_active_inactive() is None


def test_two_halves_assembled_separately_are_refused(slot_cli, host) -> None:
    split = copy.deepcopy(MIRROR)
    split["blockdevices"][1]["children"][4]["children"][0]["name"] = "md120"
    split["blockdevices"][1]["children"][4]["children"][0]["path"] = "/dev/md120"
    host(split, ROOT_A_FS)
    assert slot_cli.detect_active_inactive() is None


# ══════════════════════════════════════════════════════════════════════
# apply
# ══════════════════════════════════════════════════════════════════════


def _apply_args():
    return types.SimpleNamespace(image="https://cp/slot.raw.xz", checksum=None,
                                 expected_sha256=None, insecure=False)


@pytest.fixture
def applying(slot_cli, monkeypatch, tmp_path):
    def fake_fetch(src, staged, *, insecure):
        staged.write_bytes(b"xz")
        return 0
    monkeypatch.setattr(slot_cli, "_fetch_image", fake_fetch)
    monkeypatch.setattr(slot_cli, "_paced_copy",
                        lambda src, dst, **kw: dst.write(src.read()))
    monkeypatch.setattr(slot_cli, "host_architecture", lambda: "amd64")
    monkeypatch.setattr(slot_cli, "_ACTIVE_RELEASE_FILE", tmp_path / "no-release")
    monkeypatch.setattr(slot_cli, "_ACTIVE_ROOT", tmp_path / "no-root")
    monkeypatch.setattr(slot_cli, "_refresh_baked_images",
                        lambda dev: slot_cli.mounted.append(("refresh", dev)))
    slot_cli.mounted = []

    def probe(slot):
        slot_cli.mounted.append(("probe", slot["device"]))
        return {"APPLIANCE_VERSION": "2026.10.30-1", "APPLIANCE_ARCH": "amd64"}, ""
    monkeypatch.setattr(slot_cli, "slot_probe", probe)

    def has_mdadm(slot):
        slot_cli.mounted.append(("mdadm", slot["device"]))
        return slot_cli.image_has_mdadm
    slot_cli.image_has_mdadm = True
    monkeypatch.setattr(slot_cli, "_slot_has_mdadm", has_mdadm)
    return slot_cli


def test_apply_writes_the_inactive_array_never_a_member(applying, host) -> None:
    h = host(MIRROR, ROOT_A_FS)
    assert applying.cmd_apply(_apply_args()) == 0

    # The image went in through the spill mapping, which is the array first.
    assert [a for a in h.popen if a[0] == "dd"][0][1] == "of=/dev/mapper/spatium-slot-write"
    table = h.inputs["dmsetup"].splitlines()
    assert table[0] == f"0 {ARRAY_BYTES // 512} linear /dev/md127 0"
    assert table[1] == f"{ARRAY_BYTES // 512} {(IMAGE_BYTES - ARRAY_BYTES) // 512} linear /dev/loop7 0"
    # ...its filesystem was shrunk to the array, the mapping torn down, and
    # the result checked through the array alone.
    assert h.ran("resize2fs") == [["resize2fs", "/dev/mapper/spatium-slot-write",
                                   f"{ARRAY_BYTES // 1024}K"]]
    assert h.ran("dmsetup", "remove", "--retry", "spatium-slot-write")
    assert h.ran("losetup", "-d", "/dev/loop7")
    assert h.ran("e2fsck", "-f", "-n", "/dev/md127")

    # Every post-write step targets the array; nothing touched a member, the
    # active array, or a partition table.
    written = h.every_device_written()
    assert not written & MEMBERS
    assert written == {"/dev/md127", "/dev/mapper/spatium-slot-write"}
    assert ["tune2fs", "-U", "random", "/dev/md127"] in h.calls
    assert ["tune2fs", "-L", "root_b", "/dev/md127"] in h.calls
    assert not h.ran("partprobe")
    # The #1026 arch check, the version sidecar and the #3169-area image
    # refresh all mount the array.
    assert set(applying.mounted) == {
        ("probe", "/dev/md127"), ("refresh", "/dev/md127"), ("mdadm", "/dev/md127"),
    }

    # GRUB is rendered with the FILESYSTEM UUIDs, and both ESPs get it.
    render = h.ran("spatium-grub-render")[0]
    assert render[render.index("--root-a-uuid") + 1] == ROOT_A_FS
    assert render[render.index("--root-b-uuid") + 1] == h.blkid_uuid
    assert h.ran("/usr/local/bin/spatiumddi-esp-sync")
    assert h.calls.index(render) < h.calls.index(["/usr/local/bin/spatiumddi-esp-sync"])


def test_apply_refuses_when_the_spill_will_not_unmap(applying, host) -> None:
    h = host(MIRROR, ROOT_A_FS)
    h.spill_stays_mapped = True
    assert applying.cmd_apply(_apply_args()) == 4
    assert not h.ran("spatium-grub-render")
    assert not h.ran("tune2fs")
    assert json.loads(applying._PROGRESS_FILE.read_text())["step"] == "failed"


def test_apply_refuses_when_the_shrink_fails(applying, host, monkeypatch) -> None:
    h = host(MIRROR, ROOT_A_FS)
    real = h.run

    def failing(argv, **kw):
        if argv[0] == "resize2fs":
            h.calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, "", "")
        return real(argv, **kw)

    monkeypatch.setattr(applying.subprocess, "run", failing)
    assert applying.cmd_apply(_apply_args()) == 4
    assert h.ran("dmsetup", "remove", "--retry", "spatium-slot-write"), "unmapped on failure too"
    assert not h.ran("spatium-grub-render")


def test_apply_drops_the_arrays_stale_cache_before_reading_it_back(applying, host) -> None:
    h = host(MIRROR, ROOT_A_FS)
    assert applying.cmd_apply(_apply_args()) == 0
    flush = h.calls.index(["blockdev", "--flushbufs", "/dev/md127"])
    assert h.calls.index(["dmsetup", "remove", "--retry", "spatium-slot-write"]) < flush
    assert flush < h.calls.index(["e2fsck", "-f", "-n", "/dev/md127"])


def test_a_failed_write_still_tears_the_spill_down(applying, host, monkeypatch) -> None:
    h = host(MIRROR, ROOT_A_FS)
    real_popen = h.Popen

    def failing_dd(argv, **kw):
        if argv[0] == "dd":
            h.popen.append([str(a) for a in argv])
            return _REAL_POPEN(["sh", "-c", "cat >/dev/null; exit 1"], **kw)
        return real_popen(argv, **kw)

    monkeypatch.setattr(applying.subprocess, "Popen", failing_dd)
    with pytest.raises(subprocess.CalledProcessError):
        applying.cmd_apply(_apply_args())
    assert h.ran("dmsetup", "remove", "--retry", "spatium-slot-write")
    assert h.ran("losetup", "-d", "/dev/loop7")
    assert not h.ran("resize2fs") and not h.ran("spatium-grub-render")


def test_sigterm_mid_write_tears_the_spill_down(applying, host, monkeypatch) -> None:
    """The unit's stop or timeout is a SIGTERM, whose default action runs no
    ``finally``: the mapping would stay, holding the array open."""
    import os
    import signal

    h = host(MIRROR, ROOT_A_FS)

    class Unhandled(Exception):
        pass

    def unhandled(*_):
        raise Unhandled  # stands in for the default action: no teardown

    # Never the real default action: on a regression that would kill pytest.
    previous = signal.signal(signal.SIGTERM, unhandled)
    writers = []

    def popen(argv, **kw):
        proc = Host.Popen(h, argv, **kw)
        writers.append(proc)
        return proc

    monkeypatch.setattr(applying.subprocess, "Popen", popen)
    monkeypatch.setattr(applying, "_paced_copy",
                        lambda src, dst, **kw: os.kill(os.getpid(), signal.SIGTERM))
    try:
        with pytest.raises(SystemExit) as exc:
            applying.cmd_apply(_apply_args())
    finally:
        after = signal.signal(signal.SIGTERM, previous)
    assert exc.value.code == 128 + signal.SIGTERM
    assert after is unhandled, "the previous handler was restored"
    assert h.ran("dmsetup", "remove", "--retry", "spatium-slot-write")
    assert h.ran("losetup", "-d", "/dev/loop7")
    assert all(p.poll() is not None for p in writers), "the writers were stopped"
    assert not h.ran("spatium-grub-render")


def test_apply_refuses_an_image_that_cannot_assemble_the_mirror(applying, host) -> None:
    h = host(MIRROR, ROOT_A_FS)
    applying.image_has_mdadm = False
    assert applying.cmd_apply(_apply_args()) == 4
    assert not h.ran("spatium-grub-render")
    assert not h.ran("/usr/local/bin/spatiumddi-esp-sync")
    progress = json.loads(applying._PROGRESS_FILE.read_text())
    assert progress["step"] == "failed" and "mdadm" in progress["detail"]


def test_an_unmountable_slot_is_not_refused_for_mdadm(applying, host) -> None:
    host(MIRROR, ROOT_A_FS)
    applying.image_has_mdadm = None
    assert applying.cmd_apply(_apply_args()) == 0


def test_single_disk_apply_writes_the_partition_directly(applying, host) -> None:
    h = host(SINGLE, SINGLE_A)
    assert applying.cmd_apply(_apply_args()) == 0
    assert [a for a in h.popen if a[0] == "dd"][0][1] == "of=/dev/sda5"
    assert not h.ran("dmsetup") and not h.ran("resize2fs") and not h.ran("blockdev")
    assert not h.ran("xz")
    assert h.ran("partprobe")
    assert ("mdadm", "/dev/sda5") not in applying.mounted, "no mirror gate on one disk"


# ══════════════════════════════════════════════════════════════════════
# rollback / set-next-boot / sync-versions
# ══════════════════════════════════════════════════════════════════════


def test_rollback_on_a_mirror_commits_the_other_slot_on_both_esps(slot_cli, host) -> None:
    h = host(MIRROR, ROOT_A_FS)
    assert slot_cli.cmd_rollback(None) == 0
    assert h.ran("grub-set-default", "--boot-directory=/boot/efi", "slot_b")
    assert h.ran("/usr/local/bin/spatiumddi-esp-sync")


def test_set_next_boot_on_a_mirror_targets_the_inactive_slot(slot_cli, host) -> None:
    h = host(MIRROR, ROOT_B_FS)
    assert slot_cli.cmd_set_next_boot(types.SimpleNamespace(slot=None)) == 0
    assert h.ran("grub-reboot", "--boot-directory=/boot/efi", "slot_a")
    assert h.ran("/usr/local/bin/spatiumddi-esp-sync")


def test_sync_versions_on_a_mirror_probes_the_inactive_array(
    slot_cli, host, monkeypatch, tmp_path
) -> None:
    host(MIRROR, ROOT_A_FS)
    probed: list[str] = []
    monkeypatch.setattr(slot_cli, "_read_active_appliance_version", lambda: "2026.10.27-1")
    monkeypatch.setattr(slot_cli, "_ACTIVE_ROOT", tmp_path / "no-root")
    monkeypatch.setattr(
        slot_cli, "slot_probe",
        lambda slot: (probed.append(slot["device"]), ({"APPLIANCE_VERSION": "2026.10.30-1"}, ""))[1],
    )
    assert slot_cli.sync_slot_versions() == {"slot_a": "2026.10.27-1", "slot_b": "2026.10.30-1"}
    assert probed == ["/dev/md127"]


# ══════════════════════════════════════════════════════════════════════
# the booted slot, as the console and firstboot read it
# ══════════════════════════════════════════════════════════════════════


def _console_detect(topology: dict, root_uuid: str):
    console = BIN / "spatium-console"
    tree = ast.parse(console.read_text(encoding="utf-8"))
    names = {"detect_slot_info", "_slot_holding_uuid"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]

    def fake_run(argv, **kw):
        if argv[0] == "lsblk":
            return subprocess.CompletedProcess(argv, 0, json.dumps(topology), "")
        return subprocess.CompletedProcess(argv, 0, "saved_entry=slot_a\n", "")

    class FakePath:
        def __init__(self, p):
            self.p = p

        def read_text(self):
            return f"BOOT_IMAGE=/boot/vmlinuz root=UUID={root_uuid} rw\n"

    ns = {"json": json, "Path": FakePath,
          "subprocess": types.SimpleNamespace(
              run=fake_run, CalledProcessError=subprocess.CalledProcessError,
              TimeoutExpired=subprocess.TimeoutExpired)}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(console), "exec",  # noqa: S102
                 flags=__future__.annotations.compiler_flag, dont_inherit=True), ns)
    return ns["detect_slot_info"]()


def test_the_console_reads_the_booted_slot_on_a_mirror() -> None:
    assert _console_detect(MIRROR, ROOT_B_FS) == ("slot_b", "slot_a")


def test_the_console_reads_the_booted_slot_on_a_single_disk() -> None:
    assert _console_detect(SINGLE, SINGLE_A) == ("slot_a", "slot_a")


def _firstboot_partlabel(tmp_path: Path, lsblk_output: str) -> str:
    src = (BIN / "spatiumddi-firstboot").read_text(encoding="utf-8")
    m = re.search(r"^root_dev_partlabel\(\) \{$.*?^\}$", src, re.MULTILINE | re.DOTALL)
    assert m, "root_dev_partlabel() not found in spatiumddi-firstboot"
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "lsblk").write_text(
        "#!/bin/sh\n"
        'case "$1" in -*s*) cat "$LSBLK_OUT" ;; *) head -1 "$LSBLK_OUT" ;; esac\n'
    )
    (stub / "lsblk").chmod(0o755)
    out = tmp_path / "lsblk.out"
    out.write_text(lsblk_output)
    script = f"set -eu\n{m.group(0)}\ncur=$(root_dev_partlabel /dev/x)\nprintf '%s' \"$cur\"\n"
    proc = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True,
        env={"PATH": f"{stub}:/usr/bin:/bin", "LSBLK_OUT": str(out)},
    )
    return proc.stdout


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_firstboot_reads_the_booted_slot_through_the_array(tmp_path) -> None:
    """`lsblk -lsno PARTLABEL /dev/md125`, as measured against a real md
    array: the array's own (empty) name, then each member and its disk."""
    assert _firstboot_partlabel(tmp_path, "\nroot_A\n\nroot_A\n\n") == "root_a"


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_firstboot_reads_the_booted_slot_on_a_single_disk(tmp_path) -> None:
    assert _firstboot_partlabel(tmp_path, "root_B\n\n") == "root_b"


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_firstboot_reports_nothing_rather_than_failing(tmp_path) -> None:
    assert _firstboot_partlabel(tmp_path, "\n\n") == ""


def test_firstboot_resolves_both_slot_readers_through_the_helper() -> None:
    src = (BIN / "spatiumddi-firstboot").read_text(encoding="utf-8")
    code = "\n".join(ln.split("#", 1)[0] for ln in src.splitlines())
    assert "lsblk -no PARTLABEL" not in code
    assert code.count('root_dev_partlabel "$root_dev"') == 2


def test_firstboot_syncs_the_mirror_esp_after_committing_a_trial_boot() -> None:
    """Found on a real mirrored VM: firstboot's commit wrote saved_entry to
    the primary ESP only, and `spatiumddi-esp-sync --check` then reported
    grub/grubenv drifted — losing the primary disk would boot the slot just
    upgraded away from."""
    src = (BIN / "spatiumddi-firstboot").read_text(encoding="utf-8")
    m = re.search(r"^commit_slot_if_healthy\(\) \{$.*?^\}$", src, re.MULTILINE | re.DOTALL)
    assert m, "commit_slot_if_healthy() not found"
    code = "\n".join(ln.split("#", 1)[0] for ln in m.group(0).splitlines())
    commit = code.index("grub-set-default")
    sync = code.find("/usr/local/bin/spatiumddi-esp-sync", commit)
    assert sync != -1, "the commit must be followed by an ESP sync"
    assert sync < code.index("else", commit), "only on a successful commit"
