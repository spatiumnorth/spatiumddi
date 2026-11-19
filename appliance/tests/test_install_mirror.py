"""#999 Part C — RAID1 mirror + multipath install support.

The pure logic is EXECUTED against stubbed sysfs / block devices rather
than grepped, because every failure mode here is silent:

  * ``partition_node`` returning a path that does not exist makes the
    mkfs that follows create a regular FILE on the installer's tmpfs and
    report success — an install that completes and produces a disk with
    no filesystems on it;
  * a mirror member smaller than the target does not fail, it silently
    shrinks /var, because a RAID1 is the size of its smallest member;
  * a mirror member that resolves to the target is not redundancy, and
    on a multipath LUN "the same disk" can wear two different names.

A structural "the string appears in the file" test catches none of those.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_install_mirror.py -v
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from _installer_source import CODE, INSTALLER, PARSER, extract_fn

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash required"
)


def _run_fn(tmp_path: Path, fn: str, body: str, *, pre: str = "") -> str:
    """Extract one installer function and run ``body`` against it."""
    script = tmp_path / "run.sh"
    script.write_text(
        "set -uo pipefail\n"
        + pre
        + "\n"
        + extract_fn(fn)
        + "\n"
        + body
        + "\n"
    )
    r = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=30
    )
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


# ── partition_node: three naming rules, not two ──────────────────────


@pytest.mark.parametrize(
    "disk,idx,want",
    [
        ("/dev/sda", 4, "/dev/sda4"),
        ("/dev/nvme0n1", 4, "/dev/nvme0n1p4"),
        ("/dev/mmcblk0", 2, "/dev/mmcblk0p2"),
        # #999 Part C3 — kpartx names a multipath map's partitions
        # "<map>-partN". Getting this wrong yields a path that does not
        # exist, and mkfs then creates a FILE there and reports success.
        ("/dev/mapper/mpatha", 4, "/dev/mapper/mpatha-part4"),
        ("/dev/mapper/36000d31000ee5a", 2, "/dev/mapper/36000d31000ee5a-part2"),
    ],
)
def test_partition_node_naming(tmp_path: Path, disk: str, idx: int, want: str) -> None:
    out = _run_fn(
        tmp_path,
        "partition_node",
        f'TARGET_DISK={disk}\npartition_node {idx}',
    )
    assert out == want


def test_partition_node_takes_an_explicit_disk(tmp_path: Path) -> None:
    """The mirror path asks for the SECOND disk's node while
    ``$TARGET_DISK`` still names the first."""
    out = _run_fn(
        tmp_path,
        "partition_node",
        'TARGET_DISK=/dev/sda\npartition_node 4 /dev/nvme1n1',
    )
    assert out == "/dev/nvme1n1p4"


# ── md_node: named arrays, not md0..3 ────────────────────────────────


def test_md_node_uses_stable_names(tmp_path: Path) -> None:
    """Kernel md minor numbers are assigned in ASSEMBLY order, so a
    numeric name is not stable across a boot with one member missing —
    which is precisely the boot this feature exists to survive."""
    body = "\n".join(f"md_node {i}" for i in (3, 4, 5, 6))
    out = _run_fn(tmp_path, "md_node", body, pre=_md_names_decl())
    assert out.splitlines() == [
        "/dev/md/state",
        "/dev/md/root_a",
        "/dev/md/root_b",
        "/dev/md/var",
    ]


def _md_names_decl() -> str:
    # The array literal lives outside any function, so extract_fn cannot
    # reach it; take it from the source so a rename cannot silently
    # desynchronise this test from the installer.
    for line in INSTALLER.read_text().splitlines():
        if line.startswith("_MD_NAMES="):
            return line
    raise AssertionError("_MD_NAMES declaration not found in spatium-install")


def test_md_names_cover_exactly_the_mirrored_partitions() -> None:
    """Indices 1 (bios_boot) and 2 (ESP) must NOT be mirrored: firmware
    reads the ESP before any md driver exists, and grub embeds a
    disk-specific core.img in each bios_boot."""
    decl = _md_names_decl()
    assert "[3]=" in decl and "[4]=" in decl and "[5]=" in decl and "[6]=" in decl
    assert "[1]=" not in decl
    assert "[2]=" not in decl


# ── _stop_arrays_on: scoped to the target, like the dm teardown ──────


def _sysfs(tmp_path: Path, holders: dict[str, list[str]]) -> Path:
    """Build /sys/block/<dev>/holders/<md> trees."""
    root = tmp_path / "sys" / "block"
    for dev, mds in holders.items():
        for md in mds:
            (root / dev / "holders" / md).mkdir(parents=True, exist_ok=True)
        (root / dev).mkdir(parents=True, exist_ok=True)
    return root


def test_stop_arrays_only_touches_the_target(tmp_path: Path) -> None:
    """An installer must not stop an array belonging to storage it was
    not pointed at — the same rule the #995 dm teardown enforces."""
    sysroot = _sysfs(
        tmp_path,
        {"sda": [], "sda4": ["md127"], "sdb4": ["md126"]},
    )
    # sda's partitions live under /sys/block/sda/<part>/holders in the
    # real kernel layout; mirror that for the target.
    (sysroot / "sda" / "sda4" / "holders" / "md127").mkdir(parents=True)

    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "mdadm").write_text(
        "#!/bin/sh\necho \"mdadm $*\" >> %s\n" % (tmp_path / "calls.txt")
    )
    (stub / "mdadm").chmod(0o755)

    script = tmp_path / "run.sh"
    script.write_text(
        "set -uo pipefail\n"
        f'export PATH="{stub}:$PATH"\n'
        'INSTALL_LOG=/dev/null\n'
        'log() { :; }\n'
        + extract_fn("_stop_arrays_on").replace(
            '"/sys/block/$base"', f'"{sysroot}/$base"'
        )
        + "\n_stop_arrays_on /dev/sda\n"
    )
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls.txt").read_text() if (tmp_path / "calls.txt").exists() else ""
    assert "--stop /dev/md127" in calls
    # md126 belongs to sdb — a disk the installer was not pointed at.
    assert "md126" not in calls


def test_stop_arrays_is_a_noop_without_mdadm(tmp_path: Path) -> None:
    """A pre-#999 image has no mdadm; the helper must not abort the
    install under ``set -e``."""
    script = tmp_path / "run.sh"
    script.write_text(
        "set -euo pipefail\n"
        'export PATH="/nonexistent"\n'
        'INSTALL_LOG=/dev/null\n'
        'log() { :; }\n'
        + extract_fn("_stop_arrays_on")
        + "\n_stop_arrays_on /dev/sda\necho SURVIVED\n"
    )
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "SURVIVED" in r.stdout


# ── the ESP is never an md member ────────────────────────────────────


def test_esp_is_not_mirrored_and_is_labelled_distinctly() -> None:
    """Two FAT filesystems both labelled ``ESP`` would make the
    image-baseline fstab's ``LABEL=ESP`` resolve to whichever udev
    enumerated last — /boot/efi would be a different disk between boots
    and the sync would have no fixed direction."""
    assert "mkfs.fat -F32 -n ESP2" in CODE
    # The second ESP is a plain partition on the second disk, never an
    # array member.
    assert 'ESP2=$(partition_node 2 "$TARGET_DISK2")' in CODE


def test_mirror_bootloader_installed_on_both_disks() -> None:
    """A mirror whose surviving disk cannot boot has protected the data
    and lost the appliance."""
    assert '"$TARGET_DISK2" >> "$INSTALL_LOG"' in CODE  # BIOS core.img
    assert "--efi-directory=/boot/efi2" in CODE          # EFI on ESP2


def test_esp_sync_is_called_from_every_esp_mutation() -> None:
    """grub.cfg and grubenv live on the ESP, which is NOT mirrored. Every
    writer must push the change to the second ESP or the survivor boots
    an old kernel from a stale menu."""
    upgrade = (INSTALLER.parent / "spatium-upgrade-slot").read_text()
    # apply (kernel + grub.cfg), set-next-boot and set-default (grubenv).
    assert upgrade.count("_sync_mirror_esp()") >= 3


# ── preseed: mirror_disk ─────────────────────────────────────────────


def _check_preseed(tmp_path: Path, body: str, **env) -> subprocess.CompletedProcess:
    """Run the real parser over an answer file.

    Invoked directly rather than through ``spatium-install
    --check-preseed`` because the parser is what is under test here, and
    driving it straight also keeps the case where it must FAIL loud (a
    non-zero exit) unambiguous.
    """
    import os

    ans = tmp_path / "answers.yaml"
    ans.write_text(body)
    e = dict(os.environ)
    e.update(env)
    return subprocess.run(
        [
            "python3",
            str(PARSER),
            str(ans),
            str(tmp_path / "out.env"),
            str(tmp_path / "secret.env"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=e,
    )


def _env_of(tmp_path: Path) -> dict[str, str]:
    """The resolved environment the parser emitted."""
    out: dict[str, str] = {}
    path = tmp_path / "out.env"
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip("'\"")
    return out


_BASE = """\
target_disk: /dev/sda
confirm_wipe: true
hostname: ddi1
role: control-plane
admin_user: admin
timezone: UTC
"""


def test_preseed_accepts_a_valid_mirror(tmp_path: Path) -> None:
    r = _check_preseed(
        tmp_path,
        _BASE + "mirror_disk: /dev/sdb\n",
        SPATIUM_FAKE_DISK_BYTES=str(64 * 1024**3),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    env = _env_of(tmp_path)
    # The installer branches on these three; an accepted answer file that
    # emitted none of them would install single-disk in silence.
    assert env.get("MIRROR_MODE") == "yes"
    assert env.get("TARGET_DISK2") == "/dev/sdb"
    assert env.get("PRESEED_HAS_MIRROR_DISK") == "1"


def test_preseed_refuses_a_mirror_equal_to_the_target(tmp_path: Path) -> None:
    """A disk cannot mirror itself, and on a multipath LUN "the same
    disk" can wear two different names."""
    r = _check_preseed(
        tmp_path,
        _BASE + "mirror_disk: /dev/sda\n",
        SPATIUM_FAKE_DISK_BYTES=str(64 * 1024**3),
    )
    assert r.returncode != 0
    assert "mirror itself" in (r.stdout + r.stderr)


_BIG = 64 * 1024**3
_SMALL = 32 * 1024**3


def test_preseed_refuses_an_unusable_mirror(tmp_path: Path) -> None:
    """Silently installing single-disk when a mirror was asked for hands
    back an appliance the operator believes is redundant and is not."""
    r = _check_preseed(
        tmp_path,
        _BASE + "mirror_disk: /dev/nope\n",
        SPATIUM_FAKE_DISK_BYTES=f"/dev/sda={_BIG}",
    )
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    # ...and it is reported against the key the operator actually wrote,
    # not as a confusing complaint about target_disk.
    assert "mirror_disk" in out
    assert "target_disk '/dev/nope'" not in out


def test_preseed_refuses_a_smaller_mirror(tmp_path: Path) -> None:
    """A RAID1 is the size of its SMALLEST member, so a smaller mirror
    does not fail — it silently shrinks /var below the size the layout
    was just sized for. Refusing is the only honest answer."""
    r = _check_preseed(
        tmp_path,
        _BASE + "mirror_disk: /dev/sdb\n",
        SPATIUM_FAKE_DISK_BYTES=f"/dev/sda={_BIG},/dev/sdb={_SMALL}",
    )
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert "smallest member" in out


def test_preseed_accepts_a_larger_mirror(tmp_path: Path) -> None:
    """Bigger is fine — the array is just the size of the target."""
    r = _check_preseed(
        tmp_path,
        _BASE + "mirror_disk: /dev/sdb\n",
        SPATIUM_FAKE_DISK_BYTES=f"/dev/sda={_SMALL},/dev/sdb={_BIG}",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert _env_of(tmp_path).get("TARGET_DISK2") == "/dev/sdb"


def test_preseed_without_a_mirror_key_is_a_single_disk_install(
    tmp_path: Path,
) -> None:
    """The mirror is opt-in; every existing answer file keeps working."""
    r = _check_preseed(
        tmp_path, _BASE, SPATIUM_FAKE_DISK_BYTES=str(64 * 1024**3)
    )
    assert r.returncode == 0, r.stdout + r.stderr
    env = _env_of(tmp_path)
    assert "MIRROR_MODE" not in env
    assert "PRESEED_HAS_MIRROR_DISK" not in env


# ── the review findings, pinned ──────────────────────────────────────


def test_grub_can_actually_see_an_md_array(tmp_path: Path) -> None:
    """The whole of C2, dead without this.

    A mirrored install puts BOTH slot roots on /dev/md/root_*, and the
    menu reaches them with ``search --fs-uuid`` + ``linux /boot/vmlinuz``.
    GRUB cannot see an array without diskfilter + mdraid1x, so it never
    finds the root filesystem — a perfectly healthy mirror under a box
    that does not boot.

    Asserted on the RENDERED grub.cfg, not on the renderer's source: the
    first cut matched the word "menuentry" in the module docstring and
    reported the ordering backwards.
    """
    import sys

    out = subprocess.run(
        [
            sys.executable,
            str(INSTALLER.parent / "spatium-grub-render"),
            "--print",
            "--root-a-uuid",
            "11111111-1111-1111-1111-111111111111",
            "--root-b-uuid",
            "22222222-2222-2222-2222-222222222222",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    cfg = out.stdout
    assert "insmod diskfilter" in cfg
    assert "insmod mdraid1x" in cfg
    # ...and BEFORE the menuentries that depend on them: grub resolves an
    # insmod where it is written, and a module loaded after its first use
    # is an error rather than a forward declaration.
    assert cfg.index("insmod mdraid1x") < cfg.index("menuentry ")


def test_zero_superblock_is_given_a_device_not_a_sysfs_path() -> None:
    """``$holder`` is /sys/block/sda/sda4/holders/md127, so trimming the
    suffix yields a sysfs directory. mdadm errored on it every time and
    ``|| true`` swallowed that, so the ghost-array protection had never
    once run."""
    fn = extract_fn("_stop_arrays_on")
    assert 'member="/dev/$(basename "${holder%/holders/*}")"' in fn
    assert '--zero-superblock "$member"' in fn
    # And the failure is no longer swallowed silently.
    assert "could not zero the md superblock" in fn


def test_keep_var_is_refused_on_a_mirrored_layout() -> None:
    """lsblk walks holders, so a mirrored disk's md devices carry the
    five labels and the layout LOOKS reusable. Taking that path forces
    MIRROR_MODE off, so the reinstalled slot gets an initrd with no
    md_mod / raid1 / mdadm.conf — and the box does not come back."""
    fn = extract_fn("_layout_is_reusable")
    assert "_layout_is_on_md" in fn
    on_md = extract_fn("_layout_is_on_md")
    assert "holders/md" in on_md


def test_the_last_member_refusal_knows_the_raid_level() -> None:
    """``in_sync -le 1`` is right for raid1 and wrong for everything
    else: a 4-disk raid5 needs 3, so removing its second-to-last member
    passed the old test and destroyed the array."""
    runner = (INSTALLER.parent / "spatiumddi-storage-action").read_text()
    assert "raid4|raid5)    minimum=$((raid_disks - 1))" in runner
    assert "raid6)          minimum=$((raid_disks - 2))" in runner
    assert '[ "$in_sync" -le "$minimum" ]' in runner
    # An unrecognised level assumes NO redundancy — guessing generously
    # permits a remove that destroys the array.
    assert "*)              minimum=\"$raid_disks\"" in runner


def test_the_boot_disk_refusal_does_not_freeze_a_mirror() -> None:
    """On a two-disk mirror half the members sit on the booted disk, so
    an unconditional refusal makes replacing a failed disk impossible
    from the UI — for exactly the layout the feature exists to support.
    A mirrored install puts a bootloader and an ESP on BOTH disks, so the
    real question is whether another disk can boot."""
    runner = (INSTALLER.parent / "spatiumddi-storage-action").read_text()
    assert "other_esp" in runner
    assert "the only disk this appliance can boot from" in runner
    # The refusal applies to REMOVE only. Add has no boot-disk rule at
    # all — see test_add_member_does_not_refuse_the_standard_repair.
    remove = runner[
        runner.index("    fail_member|remove_member)") : runner.index("    add_member)")
    ]
    assert "other_esp" in remove


def test_esp_sync_runs_after_a_grub_re_render() -> None:
    """The #395 host-migration re-render reaches spatium-grub-render
    without going through spatium-upgrade-slot, so without this a
    re-render leaves the second ESP holding the previous menu."""
    render = (INSTALLER.parent / "spatium-grub-render").read_text()
    assert "_sync_mirror_esp" in render
    assert "spatiumddi-esp-sync" in render


def test_the_preseed_short_circuit_precedes_the_reset() -> None:
    """The other order clears the values the answer file just supplied."""
    fn = extract_fn("_ask_mirror_disk")
    assert fn.index("PRESEED_HAS_MIRROR_DISK") < fn.index('MIRROR_MODE="no"')


# ── second review pass ───────────────────────────────────────────────


def test_the_esp_mount_cannot_strand_the_survivor() -> None:
    """The label ``ESP`` exists on the PRIMARY disk only — the mirror
    member's is ``ESP2``, deliberately, so /boot/efi has a fixed
    direction. Lose the primary and the survivor boots (grub is on its
    own ESP and its own bios_boot) only for systemd to fail the
    /boot/efi mount and drop the box into emergency.target: storage
    redundant and unbootable."""
    line = next(
        ln for ln in CODE.splitlines() if ln.startswith("LABEL=ESP")
    )
    assert "nofail" in line


def test_the_mirror_members_core_img_embeds_its_own_esp() -> None:
    """grub-install embeds the fs UUID of --boot-directory into the
    core.img it writes to THAT disk. Pointing disk 2's BIOS install at
    /boot/efi (the primary's ESP) leaves it looking for a filesystem on
    the disk that just died — `grub rescue>` on the survivor."""
    i = CODE.index("Installing bootloader on the mirror member")
    blk = CODE[i : CODE.index("Cloning root_A", i)]
    assert "--boot-directory=/boot/efi2" in blk
    # ...and NOT the primary's, anywhere in that block.
    assert "--boot-directory=/boot/efi " not in blk
    assert "--boot-directory=/boot/efi\n" not in blk
    # ESP2 has to be mounted before either install, or --boot-directory
    # points at an empty directory.
    assert blk.index('mount "$ESP2"') < blk.index("--target=i386-pc")


def test_our_own_mirror_can_be_reinstalled() -> None:
    """Both members of a SpatiumDDI mirror are md members, so refusing
    md members outright made a mirrored appliance a dead end — the
    keep-/var path refused it too, and its message pointed at a full
    install that was equally impossible."""
    fn = extract_fn("_disk_hazard")
    assert "_md_array_is_ours" in fn
    ours = extract_fn("_md_array_is_ours")
    # Identified by OUR labels; somebody else's array stays refused.
    for label in ("root_a", "root_b", "var", "state"):
        assert label in ours
    # And the operator is told that both halves go, not just this disk.
    assert "mirror destroyed" in CODE


def test_a_multipath_lun_is_offered_exactly_once() -> None:
    """``/dev/dm-N`` and ``/dev/mapper/<name>`` are the same LUN and are
    NOT equivalent targets: partition_node maps the raw one to
    ``/dev/dm-N-partN``, which kpartx never creates, so mkfs writes
    regular files onto tmpfs and the install "succeeds" with no
    filesystems."""
    fn = extract_fn("pick_disk")
    assert "zram|dm-)" in fn or "|dm-)" in fn


def test_esp_sync_can_report_being_in_sync() -> None:
    """``--no-times`` makes rsync's quick check see every file as
    changed, so ``--check`` reported drift unconditionally (it could
    never say "in sync") and every sync re-copied the whole ESP. FAT
    stores mtimes at 2 s resolution, which is what the window is for."""
    sync = (INSTALLER.parent / "spatiumddi-esp-sync").read_text()
    assert "--modify-window=2" in sync
    # ``-t`` as well, and it is the half the first fix missed: ``-r``
    # does not imply ``-t``, so rsync compared times it never preserved
    # and reported the whole ESP as drifted on every run. Caught on a
    # live mirrored appliance, not by this test — which is why the test
    # now pins the flag rather than the absence of the old one.
    assert "rsync -rtin" in sync
    assert "rsync -rt " in sync
    # Comment-stripped: the fix's comment names the flag it removed, so
    # matching raw text reports the explanation as the regression (the
    # reason ``_installer_source.CODE`` exists).
    code = "\n".join(ln.split("#", 1)[0] for ln in sync.splitlines())
    assert "--no-times" not in code


def test_the_storage_trigger_is_level_triggered() -> None:
    """``PathChanged=`` on the directory is edge-triggered: a request
    written while the runner was executing produced no event and sat
    unanswered until the operator's 60 s timeout, with nothing in the
    journal."""
    unit = (
        INSTALLER.parent.parent.parent.parent
        / "etc/systemd/system/spatiumddi-storage-action.path"
    ).read_text()
    assert "PathExistsGlob=" in unit
    code = "\n".join(ln.split("#", 1)[0] for ln in unit.splitlines())
    assert "PathChanged=" not in code


def test_add_member_does_not_refuse_the_standard_repair() -> None:
    """A member of the ROOT mirror dropping out and being re-added is
    the commonest repair there is, and it happens on the disk you are
    running from — a blanket boot-disk refusal blocks the exact thing
    the feature exists to do. What must be refused is overwriting
    something in USE."""
    runner = (INSTALLER.parent / "spatiumddi-storage-action").read_text()
    add = runner[runner.index("    add_member)") : runner.index("    mpath_reinstate)")]
    assert "the disk this appliance is running from" not in add
    assert "is mounted" in add
    assert "already a member of" in add


def test_the_runner_claims_its_request_by_renaming_it() -> None:
    """Without this, Part B disables itself on the SECOND request.

    ``PathExistsGlob`` is LEVEL-triggered: when the service exits with a
    matching file still present, systemd re-triggers it immediately. The
    runner leaving the request in place therefore produced a tight
    restart loop, which trips systemd's start limit within a second and
    leaves the PATH UNIT in ``failed`` — after which no storage action
    ever fires again until an operator notices.

    Observed on a live appliance: the first request answered, and the
    next two produced no result at all with the unit dead. The pcap
    runner performs the same claim for the same reason.
    """
    runner = (INSTALLER.parent / "spatiumddi-storage-action").read_text()
    assert 'CLAIMED="$STATE_DIR/$RID.request.running"' in runner
    assert 'mv -T "$REQUEST" "$CLAIMED"' in runner
    # The claim must precede any work, or the loop window still exists.
    assert runner.index('mv -T "$REQUEST" "$CLAIMED"') < runner.index("__badreq__\" ]")


def test_the_supervisor_cleans_up_the_claimed_request() -> None:
    """The runner renames the request; the supervisor deletes. Missing
    the claimed name leaves a stub per action forever."""
    proxy = (
        Path(__file__).resolve().parents[2]
        / "agent/supervisor/spatium_supervisor/storage_proxy.py"
    ).read_text()
    assert "request.running" in proxy
    assert "claimed_path" in proxy


def _renderer_module():
    """Load spatium-grub-render as a module (it has no ``main`` guard
    side effects at import)."""
    import importlib.util
    from importlib.machinery import SourceFileLoader

    ldr = SourceFileLoader("grub_render_uut", str(INSTALLER.parent / "spatium-grub-render"))
    spec = importlib.util.spec_from_loader(ldr.name, ldr)
    mod = importlib.util.module_from_spec(spec)
    ldr.exec_module(mod)
    return mod


def _discover_with(tree: dict, monkeypatch) -> dict:
    """Run ``discover_live_uuids`` against a canned ``lsblk -J`` tree."""
    import json as _json
    import subprocess as _sp

    m = _renderer_module()

    class _R:
        stdout = _json.dumps(tree)

    monkeypatch.setattr(_sp, "run", lambda *a, **k: _R())
    return m.discover_live_uuids()


# lsblk -J as it reports a MIRRORED layout: the slot partition is an md
# member and the ext4 filesystem is on its child.
_MIRRORED_TREE = {
    "blockdevices": [
        {
            "name": "sda", "uuid": None, "partlabel": None,
            "label": None, "fstype": None,
            "children": [
                {
                    "name": "sda4", "uuid": "ARRAY-UUID-root-a",
                    "partlabel": "root_A", "label": "any:root_a",
                    "fstype": "linux_raid_member",
                    "children": [
                        {
                            "name": "md125", "uuid": "FS-UUID-root-a",
                            "partlabel": None, "label": "root_a",
                            "fstype": "ext4", "children": [],
                        }
                    ],
                },
                {
                    "name": "sda5", "uuid": "ARRAY-UUID-root-b",
                    "partlabel": "root_B", "label": "any:root_b",
                    "fstype": "linux_raid_member",
                    "children": [
                        {
                            "name": "md127", "uuid": "FS-UUID-root-b",
                            "partlabel": None, "label": "root_b",
                            "fstype": "ext4", "children": [],
                        }
                    ],
                },
            ],
        }
    ]
}

# ...and an ordinary single-disk one, where the filesystem IS the partition.
_SINGLE_TREE = {
    "blockdevices": [
        {
            "name": "sda", "uuid": None, "partlabel": None,
            "label": None, "fstype": None,
            "children": [
                {
                    "name": "sda4", "uuid": "FS-UUID-root-a",
                    "partlabel": "root_A", "label": "root_a",
                    "fstype": "ext4", "children": [],
                },
                {
                    "name": "sda5", "uuid": "FS-UUID-root-b",
                    "partlabel": "root_B", "label": "root_b",
                    "fstype": "ext4", "children": [],
                },
            ],
        }
    ]
}


def test_slot_uuids_resolve_to_the_FILESYSTEM_not_the_raid_member(
    monkeypatch,
) -> None:
    """The bug that left a live mirrored appliance unbootable.

    On a mirror the slot PARTITION is a ``linux_raid_member`` whose UUID
    is the ARRAY's; the filesystem — and the UUID ``search --fs-uuid``
    must match — lives on the md child. Taking the partition's UUID
    yields a menu that matches nothing:

        error: no such device: 8b4aa553-…
        error: file '/boot/vmlinuz' not found.

    It does not show up at install (the installer passes UUIDs
    explicitly). It shows up on FIRST BOOT, when the #395 host-migration
    re-render calls this with no arguments and overwrites a working menu
    — so the box installs, boots once, and is unbootable from then on.
    """
    assert _discover_with(_MIRRORED_TREE, monkeypatch) == {
        "root_a": "FS-UUID-root-a",
        "root_b": "FS-UUID-root-b",
    }


def test_slot_uuids_still_work_on_a_single_disk_layout(monkeypatch) -> None:
    """The ordinary case is unchanged: the filesystem IS the partition."""
    assert _discover_with(_SINGLE_TREE, monkeypatch) == {
        "root_a": "FS-UUID-root-a",
        "root_b": "FS-UUID-root-b",
    }
