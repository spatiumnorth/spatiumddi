"""The two OS slots never share a filesystem label (#1045).

``build-slot-image.sh`` builds ONE image for both slots and bakes
``mkfs.ext4 -L root_a`` into it, so every slot upgrade writes ``root_a``
onto whichever slot it targets. ``spatium-upgrade-slot`` already knew the
baked-in filesystem identity was wrong for the target and fixed half of
it — ``tune2fs -U random``, because a duplicate UUID wedges slot
detection — and left the label alone, with a comment ("PARTLABEL is
preserved because it lives in the GPT header, not the filesystem") that
shows it was never considered.

So slot B came out of its first upgrade labelled ``root_a`` and NO
partition on the disk carried ``root_b`` again, ever. Nothing on the boot
path noticed (``root=UUID=`` on the cmdline, and the image-baseline fstab
has no root entry), which is why it survived releases. What noticed was
the INSTALLER: ``_layout_is_reusable`` required a ``root_b`` label, so the
#995 item 25 "Keep /var" reinstall stopped being offered — silently, and
indistinguishably from "this disk is not ours" — on exactly the
long-lived appliances most likely to want it.

Two halves, and they are tested separately because they fail separately:

* ``spatium-upgrade-slot`` labels the target from its own GPT name, so no
  NEW disk drifts. Executed, not grepped: the point is that the label is
  read back off the device afterwards, since on a mounted filesystem
  ``tune2fs`` goes through ``FS_IOC_SETFSLABEL`` and "accepted" is not
  the same as "applied".
* ``spatium-install`` matches the two slots by GPT name, so disks ALREADY
  written by an older appliance keep working. That is the half that
  repairs the fleet, and it has to be tested against a duplicated-label
  fixture, because a correct installer and a correct upgrade script both
  pass on a freshly installed disk.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_slot_filesystem_labels.py -v

No root, no partitions, no appliance.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import textwrap
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from _installer_source import BIN, CODE, SRC as INSTALL_SRC, extract_fn as _extract

SLOT_CLI = BIN / "spatium-upgrade-slot"
SLOT_SRC = SLOT_CLI.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def slot_cli():
    loader = SourceFileLoader("spatium_upgrade_slot_labels", str(SLOT_CLI))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _needs_bash():
    if not shutil.which("bash"):
        pytest.skip("bash not available")


# ══════════════════════════════════════════════════════════════════════
# spatium-upgrade-slot — the relabel itself
# ══════════════════════════════════════════════════════════════════════


def _record(slot_cli, monkeypatch, *, label_after: str | None, tune2fs_rc: int = 0):
    """Stub tune2fs + blkid; return the list of argv lists attempted."""
    calls: list[list[str]] = []

    def _fake_run(argv, **kw):
        calls.append(list(argv))
        if argv[0] == "tune2fs":
            return subprocess.CompletedProcess(argv, tune2fs_rc, "", "tune2fs: nope")
        if argv[0] == "blkid":
            if label_after is None:
                raise subprocess.CalledProcessError(2, argv)
            return subprocess.CompletedProcess(argv, 0, label_after + "\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(slot_cli.subprocess, "run", _fake_run)
    return calls


def test_the_target_is_labelled_from_its_own_gpt_name(slot_cli, monkeypatch) -> None:
    calls = _record(slot_cli, monkeypatch, label_after="root_b")
    assert slot_cli._relabel_slot_filesystem("/dev/vda5", "root_b") is True
    assert ["tune2fs", "-L", "root_b", "/dev/vda5"] in calls


def test_a_label_that_did_not_stick_is_reported_not_assumed(
    slot_cli, monkeypatch, capsys
) -> None:
    """The whole reason the label is read back. ``tune2fs`` exiting 0 on a
    MOUNTED filesystem means the ioctl was accepted; it does not mean the
    kernel's cached superblock will not win."""
    _record(slot_cli, monkeypatch, label_after="root_a")
    assert slot_cli._relabel_slot_filesystem("/dev/vda5", "root_b") is False
    assert "still reads LABEL=root_a" in capsys.readouterr().err


def test_a_tune2fs_refusal_is_reported_with_its_own_stderr(
    slot_cli, monkeypatch, capsys
) -> None:
    _record(slot_cli, monkeypatch, label_after=None, tune2fs_rc=1)
    assert slot_cli._relabel_slot_filesystem("/dev/vda5", "root_b") is False
    err = capsys.readouterr().err
    assert "could not label" in err and "tune2fs: nope" in err


@pytest.mark.parametrize("bad", ["", "var", "root_c", "ROOT_B"])
def test_only_the_two_slot_names_are_ever_written(slot_cli, monkeypatch, bad) -> None:
    """The value comes from a GPT name read off the disk. An unexpected one
    is not a label to write — ``mkfs -L`` on the wrong filesystem is how
    the #999 mirror path describes losing a /var."""
    calls = _record(slot_cli, monkeypatch, label_after=bad)
    assert slot_cli._relabel_slot_filesystem("/dev/vda5", bad) is False
    assert not any(c[0] == "tune2fs" for c in calls)


def test_an_empty_device_writes_nothing(slot_cli, monkeypatch) -> None:
    calls = _record(slot_cli, monkeypatch, label_after="root_b")
    assert slot_cli._relabel_slot_filesystem("", "root_b") is False
    assert not any(c[0] == "tune2fs" for c in calls)


def test_the_readback_bypasses_blkids_cache(slot_cli, monkeypatch) -> None:
    """The cache is stale by construction here — a ``dd`` plus a relabel is
    exactly the sequence that invalidates it, so reading it would confirm
    the value we are checking has changed."""
    calls = _record(slot_cli, monkeypatch, label_after="root_b")
    slot_cli._relabel_slot_filesystem("/dev/vda5", "root_b")
    blkid = next(c for c in calls if c[0] == "blkid")
    assert "-p" in blkid


# ── where the relabel sits in cmd_apply ──────────────────────────────


def _apply_body() -> str:
    m = re.search(r"^def cmd_apply\(.*?(?=^def )", SLOT_SRC, re.M | re.S)
    assert m, "cmd_apply not found"
    return m.group(0)


def test_the_relabel_is_between_the_write_and_the_bootloader() -> None:
    """Before the ``dd`` there is nothing to label; after the grub render
    the disk has already been advertised as bootable with the wrong
    identity. Anchored on the render, not on the ``"bootloader"`` progress
    label, which is emitted several steps earlier (#1026's lesson).
    """
    body = _apply_body()
    write = body.index('"dd"')
    relabel = body.index("_relabel_slot_filesystem")
    render = body.index('"spatium-grub-render"')
    assert write < relabel < render, (write, relabel, render)


def test_the_target_relabel_is_not_conditional() -> None:
    """Every applied image carries ``root_a``, so the target always needs
    this — a guard comparing the label to the partlabel first would skip
    precisely slot A, whose baked label happens to be right, and leave
    the verification unrun on the one slot that can be checked."""
    body = _apply_body()
    call = re.search(
        r"^(\s*)\w+ = _relabel_slot_filesystem\(target_dev, inactive\[.partlabel.\]\)",
        body,
        re.M,
    )
    assert call, body[body.index("_relabel_slot_filesystem") - 400 :][:600]
    assert len(call.group(1)) == 4, "the target relabel must not sit inside an if"


def test_the_active_slot_is_repaired_only_when_it_disagrees() -> None:
    """The repair for disks written before this fix. Conditional on
    purpose — relabelling a live root that is already correct is a
    superblock write for nothing."""
    body = _apply_body()
    assert re.search(
        r'if active\["fslabel"\] != active\["partlabel"\]:', body
    ), "the active-slot repair must be gated on an actual disagreement"


def test_an_unlabelled_active_slot_is_still_repaired() -> None:
    """``active.get("fslabel") and …`` was the first draft, and it skipped
    the repair on a slot carrying NO label — which is a missing label, i.e.
    the thing being repaired, not a value to be careful about.
    ``find_slot_partitions`` always sets the key, so there is no third
    "unknown" state the truthiness check could have been protecting.
    """
    body = _apply_body()
    assert 'active.get("fslabel") and' not in body
    # And the message has to survive an empty value rather than printing
    # "( → root_a)".
    assert "active['fslabel'] or '(none)'" in body


def test_the_stale_sgdisk_indices_in_the_comment_are_fixed() -> None:
    """The comment named ``-c3:root_A -c4:root_B``; the installer writes
    ``-c4:`` and ``-c5:``. Wrong prose about which partition is which is
    how somebody reaches for the wrong one at 03:00."""
    assert "-c3:root_A" not in SLOT_SRC
    assert "sgdisk -c4:root_A -c5:root_B" in SLOT_SRC
    assert "-c4:root_A" in INSTALL_SRC and "-c5:root_B" in INSTALL_SRC


# ══════════════════════════════════════════════════════════════════════
# spatium-install — the half that repairs an already-duplicated disk
# ══════════════════════════════════════════════════════════════════════

#: A disk in the post-upgrade state #1042 reported: the GPT names are
#: intact, and BOTH slots' filesystems say ``root_a``.
DUPLICATED = {
    "vda": [
        ("vda1", "", ""),
        ("vda2", "ESP", "ESP"),
        ("vda3", "STATE", "state"),
        ("vda4", "root_A", "root_a"),
        ("vda5", "root_B", "root_a"),   # ← the bug
        ("vda6", "VAR", "var"),
    ],
}
#: The same disk as a fresh install leaves it.
PRISTINE = {
    "vda": [
        ("vda1", "", ""),
        ("vda2", "ESP", "ESP"),
        ("vda3", "STATE", "state"),
        ("vda4", "root_A", "root_a"),
        ("vda5", "root_B", "root_b"),
        ("vda6", "VAR", "var"),
    ],
}
#: A #999 mirror: the member partitions carry GPT names and raid
#: superblocks, and the ext4 labels live on the md devices, which are not
#: partitions and so have no GPT name at all.
MIRRORED = {
    "vda": [
        ("vda1", "", ""),
        ("vda2", "ESP", "ESP"),
        ("vda3", "STATE", ""),
        ("vda4", "root_A", ""),
        ("vda5", "root_B", ""),
        ("vda6", "VAR", ""),
        ("md125", "", "state"),
        ("md126", "", "root_a"),
        ("md127", "", "root_b"),
        ("md124", "", "var"),
    ],
}


def _lsblk_stub(d: Path, topology: dict) -> None:
    """``lsblk -nro <COL> <dev>``: a disk lists its children, a single
    partition answers for itself. Mirrors the real tool closely enough
    that the functions under test are exercised rather than a fiction —
    `-nro NAME <disk>` includes the disk itself as the first row, which
    is why every caller pipes through ``tail -n +2``.
    """
    cases = []
    for disk, parts in topology.items():
        names = [disk] + [p[0] for p in parts]
        cases.append(f'    /dev/{disk}) col_NAME="{" ".join(names)}" ;;')
        for name, partlabel, label in parts:
            cases.append(
                f'    /dev/{name}) col_NAME="{name}"; '
                f'col_PARTLABEL="{partlabel}"; col_LABEL="{label}" ;;'
            )
    body = "\n".join(cases)
    (d / "lsblk").write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            # argv: -nro COL DEV
            col="$2"; dev="$3"
            col_NAME=""; col_PARTLABEL=""; col_LABEL=""
            case "$dev" in
            {body}
                *) exit 1 ;;
            esac
            eval "printf '%s\\n' \\$col_$col" | tr ' ' '\\n' | sed '/^$/d'
            """
        )
    )
    (d / "lsblk").chmod(0o755)


def _run_fn(tmp_path: Path, topology: dict, fns: list[str], call: str, extra: str = ""):
    d = tmp_path / "stub"
    d.mkdir(exist_ok=True)
    _lsblk_stub(d, topology)
    script = tmp_path / "run.sh"
    script.write_text(
        "set -uo pipefail\n"
        'log() { echo "LOG: $*" >&2; }\n'
        + extra
        + "\n"
        + "\n".join(_extract(f) for f in fns)
        + f"\n{call}\n"
    )
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env={"PATH": f"{d}:/usr/bin:/bin:/usr/sbin:/sbin"},
    )


# ── _slot_candidates_on / _slot_device_on ────────────────────────────


def test_the_two_slots_resolve_to_different_partitions_when_labels_collide(tmp_path):
    """The property the whole fix rests on. Both filesystems say
    ``root_a``; the GPT names still say which is which."""
    fns = ["_labelled_device_on", "_slot_candidates_on", "_slot_device_on"]
    a = _run_fn(tmp_path, DUPLICATED, fns, '_slot_device_on "/dev/vda" root_a')
    b = _run_fn(tmp_path, DUPLICATED, fns, '_slot_device_on "/dev/vda" root_b')
    assert a.stdout.strip() == "/dev/vda4", a.stderr
    assert b.stdout.strip() == "/dev/vda5", b.stderr


def test_a_pristine_disk_resolves_the_same_way(tmp_path):
    """Control: the fix must not move the answer on a disk that was never
    upgraded, or every fresh install is the regression."""
    fns = ["_labelled_device_on", "_slot_candidates_on", "_slot_device_on"]
    a = _run_fn(tmp_path, PRISTINE, fns, '_slot_device_on "/dev/vda" root_a')
    b = _run_fn(tmp_path, PRISTINE, fns, '_slot_device_on "/dev/vda" root_b')
    assert a.stdout.strip() == "/dev/vda4"
    assert b.stdout.strip() == "/dev/vda5"


def test_a_mirror_resolves_to_the_md_device_via_the_filesystem_label(tmp_path):
    """An md device is not a partition, so it has no GPT name. Dropping
    the label fallback would make the #999 mirror unreadable — and the
    picker would report ``unknown version`` for a perfectly good install.
    """
    fns = ["_labelled_device_on", "_slot_candidates_on", "_slot_device_on"]
    out = _run_fn(
        tmp_path, MIRRORED, fns, '_slot_candidates_on "/dev/vda" root_b'
    ).stdout.split()
    assert "/dev/md127" in out
    # The raid MEMBER carries the GPT name and cannot be mounted as ext4,
    # so it is listed — first, even — and the caller has to keep looking.
    assert out.index("/dev/vda5") < out.index("/dev/md127")


def test_a_candidate_is_never_listed_twice(tmp_path):
    """A caller that stops at the first hit would otherwise look like it
    tried two devices when it tried one."""
    fns = ["_labelled_device_on", "_slot_candidates_on"]
    out = _run_fn(
        tmp_path, PRISTINE, fns, '_slot_candidates_on "/dev/vda" root_a'
    ).stdout.split()
    assert out == ["/dev/vda4"], out


def test_a_foreign_disk_yields_no_slots(tmp_path):
    topology = {"vdb": [("vdb1", "", "backups")]}
    fns = ["_labelled_device_on", "_slot_candidates_on", "_slot_device_on"]
    r = _run_fn(tmp_path, topology, fns, '_slot_device_on "/dev/vdb" root_a')
    assert r.returncode != 0 and r.stdout.strip() == ""


# ── _labelled_device_on is scoped to one disk ────────────────────────


def test_a_label_is_resolved_on_the_named_disk_only(tmp_path):
    """``blkid -L var`` searched every disk on the machine. With a second
    SpatiumDDI disk attached that answers with the wrong one — and on the
    KEEP_VAR path the installer then mkfs'd a /var the operator never
    picked.
    """
    topology = {
        "vda": PRISTINE["vda"],
        "vdb": [("vdb1", "VAR", "var")],
    }
    fns = ["_labelled_device_on"]
    assert (
        _run_fn(tmp_path, topology, fns, '_labelled_device_on "/dev/vda" var').stdout
        == "/dev/vda6"
    )
    assert (
        _run_fn(tmp_path, topology, fns, '_labelled_device_on "/dev/vdb" var').stdout
        == "/dev/vdb1"
    )


def test_the_keep_var_resolution_no_longer_uses_blkid_L() -> None:
    """Structural, because the block lives inside ``do_install`` and cannot
    be extracted: a single surviving ``blkid -L`` there would reintroduce
    the cross-disk hazard for whichever label kept it.

    Scoped to that block rather than to the whole script, because the
    preseed scan's ``blkid -L CIDATA`` is machine-wide ON PURPOSE — a
    NoCloud volume is handed to the installer on whatever device the
    operator attached, and there is no target disk to scope it to yet.
    """
    # Anchored on its own `local` line: there is a second, unrelated
    # `if [ "$KEEP_VAR" = "yes" ]` in pick_disk that suppresses the mirror
    # offer, and it appears first.
    block = re.search(
        r'if \[ "\$KEEP_VAR" = "yes" \]; then\n\s+local _l _dev _name.*?\n    fi\n',
        CODE,
        re.S,
    )
    assert block, "the KEEP_VAR resolution block moved — re-anchor this test"
    assert "blkid" not in block.group(0)
    assert "_labelled_device_on" in block.group(0)
    assert "_slot_device_on" in block.group(0)


# ── _layout_is_reusable ──────────────────────────────────────────────

_REUSABLE = ["_labelled_device_on", "_slot_candidates_on", "_slot_device_on",
             "_layout_is_on_md", "_layout_is_reusable"]
#: _layout_is_on_md walks /sys; stub it away so these cases are about labels.
_NOT_MD = "_layout_is_on_md() { return 1; }\n"


def _reusable(tmp_path: Path, topology: dict, disk: str = "/dev/vda"):
    fns = [f for f in _REUSABLE if f != "_layout_is_on_md"]
    return _run_fn(tmp_path, topology, fns, f'_layout_is_reusable "{disk}"',
                   extra=_NOT_MD)


def test_an_upgraded_disk_is_still_reusable(tmp_path):
    """THE regression. This disk has no ``root_b`` filesystem label, and
    the old five-label loop therefore refused it — withdrawing the "Keep
    /var" offer and silently erasing the database of anyone who
    reinstalled a box that had ever taken an upgrade."""
    assert _reusable(tmp_path, DUPLICATED).returncode == 0


def test_a_pristine_disk_is_reusable(tmp_path):
    assert _reusable(tmp_path, PRISTINE).returncode == 0


def test_a_disk_missing_a_slot_entirely_is_not_reusable(tmp_path):
    """The refusal still has to work, or this stops being a gate. Slot B
    is gone from the TABLE here, not merely mislabelled."""
    topology = {"vda": [p for p in PRISTINE["vda"] if p[0] != "vda5"]}
    r = _reusable(tmp_path, topology)
    assert r.returncode == 1
    assert "no OS slot 'root_b'" in r.stderr


def test_a_disk_missing_var_is_not_reusable(tmp_path):
    topology = {"vda": [p for p in PRISTINE["vda"] if p[0] != "vda6"]}
    r = _reusable(tmp_path, topology)
    assert r.returncode == 1
    assert "no partition labelled 'var'" in r.stderr


def test_an_asymmetric_disk_is_refused_at_the_offer_not_at_the_wipe(tmp_path):
    """One GPT name present and the other slot identified only by a
    filesystem label resolves BOTH slots to the same device. do_install
    refuses that — but it refuses minutes later, after the operator has
    answered hostname, admin account, network and timezone. The refusal has
    to be where the offer is made.
    """
    topology = {
        "vda": [
            ("vda1", "", ""),
            ("vda2", "ESP", "ESP"),
            ("vda3", "STATE", "state"),
            # Slot A lost both its GPT name and its label; slot B kept its
            # GPT name and carries the baked-in `root_a` from an upgrade. So
            # vda5 is the only candidate for EITHER slot.
            ("vda4", "", ""),
            ("vda5", "root_B", "root_a"),
            ("vda6", "VAR", "var"),
        ],
    }
    r = _reusable(tmp_path, topology)
    assert r.returncode == 1
    assert "both OS slots resolve to" in r.stderr, r.stderr


def test_do_install_still_carries_the_same_refusal() -> None:
    """Belt and braces, and they are not redundant: preseeded installs set
    KEEP_VAR without going through pick_disk at all."""
    block = re.search(
        r'if \[ "\$KEEP_VAR" = "yes" \]; then\n\s+local _l _dev _name.*?\n    fi\n',
        CODE,
        re.S,
    )
    assert block and '[ "$ROOT_A" = "$ROOT_B" ]' in block.group(0)


def test_a_duplicated_disk_is_never_mounted_twice(tmp_path):
    """Slot B answers to both names on a #1045 disk, so the candidate lists
    overlap. Each `timeout 10 mount` is a 10 s stall in the enumeration that
    runs before the operator has picked anything — paying it twice for one
    device is the bound quietly tripling.
    """
    mounts = _existing_mount_log(
        tmp_path, DUPLICATED, {"/dev/vda4": "", "/dev/vda5": ""}
    )
    assert sorted(mounts) == ["/dev/vda4", "/dev/vda5"], mounts


def test_every_refusal_says_what_was_missing(tmp_path):
    """Each ``return 1`` used to be bare, so "a label is missing" and
    "this disk is not ours" produced identical output — which is how
    #1045 went unnoticed through a release."""
    for drop in ("vda2", "vda3", "vda5", "vda6"):
        topology = {"vda": [p for p in PRISTINE["vda"] if p[0] != drop]}
        r = _reusable(tmp_path, topology)
        assert r.returncode == 1, drop
        assert "not reusable" in r.stderr, (drop, r.stderr)


# ── _existing_install_version ────────────────────────────────────────

_EXISTING = ["_labelled_device_on", "_slot_candidates_on", "_existing_install_version"]


def _existing(tmp_path: Path, topology: dict, releases: dict[str, str | None]):
    """``releases`` maps device → appliance-release body, or None for a
    partition that will not mount."""
    d = tmp_path / "stub"
    d.mkdir(exist_ok=True)
    roots = tmp_path / "roots"
    for dev, body in releases.items():
        if body is None:
            continue
        rel = roots / dev.replace("/", "_") / "etc" / "spatiumddi"
        rel.mkdir(parents=True, exist_ok=True)
        (rel / "appliance-release").write_text(body)
    mountable = " ".join(k for k, v in releases.items() if v is not None)
    # `mount` copies the staged tree in; `umount` empties it again. Both
    # are what the function actually calls, so the control flow under test
    # is the real one rather than a stubbed-out success.
    (d / "mount").write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            for a in "$@"; do last=$a; prev=$before; before=$a; done
            src=$prev; dst=$last
            echo "$src" >> {tmp_path}/mount-attempts
            for m in {mountable}; do
              if [ "$m" = "$src" ]; then
                cp -R "{roots}/$(echo "$m" | tr / _)/." "$dst/" 2>/dev/null || true
                exit 0
              fi
            done
            exit 32
            """
        )
    )
    (d / "umount").write_text('#!/bin/sh\nrm -rf "$1"/* 2>/dev/null; exit 0\n')
    (d / "timeout").write_text('#!/bin/sh\nshift; exec "$@"\n')
    for f in ("mount", "umount", "timeout"):
        (d / f).chmod(0o755)
    return _run_fn(
        tmp_path,
        topology,
        _EXISTING,
        '_existing_install_version "/dev/vda"',
        extra=_extract("_release_field") + "\n" + _extract("_appliance_version_from") + "\n",
    )


def _existing_mount_log(tmp_path: Path, topology: dict, releases: dict):
    """Every device ``_existing_install_version`` tried to mount, in order."""
    _existing(tmp_path, topology, releases)
    log = tmp_path / "mount-attempts"
    return log.read_text().split() if log.exists() else []


def test_the_version_comes_from_slot_a_when_it_has_one(tmp_path):
    out = _existing(
        tmp_path,
        PRISTINE,
        {"/dev/vda4": 'APPLIANCE_VERSION="2026.09.04-1"\n', "/dev/vda5": None},
    )
    assert out.stdout == "2026.09.04-1", out.stderr


def test_slot_b_is_consulted_when_slot_a_carries_no_release(tmp_path):
    """Slot A mounts and has no release file — which used to short-circuit
    the whole function to "unknown version" without ever looking at B."""
    out = _existing(
        tmp_path,
        PRISTINE,
        {"/dev/vda4": "", "/dev/vda5": 'APPLIANCE_VERSION="2026.09.04-1"\n'},
    )
    assert out.stdout == "2026.09.04-1", out.stderr


def test_a_mirror_reports_its_version_from_the_md_device(tmp_path):
    """The raid member is tried first and will not mount; the array does.
    Giving up after one candidate would report ``unknown version`` for
    every mirrored install."""
    out = _existing(
        tmp_path,
        MIRRORED,
        {"/dev/md126": 'APPLIANCE_VERSION="2026.09.04-1"\n'},
    )
    assert out.stdout == "2026.09.04-1", out.stderr


def test_a_slot_that_says_nothing_is_still_an_install(tmp_path):
    out = _existing(tmp_path, PRISTINE, {"/dev/vda4": "", "/dev/vda5": ""})
    assert out.stdout == "unknown version", out.stderr


def test_a_disk_with_no_slots_reports_nothing(tmp_path):
    out = _existing(tmp_path, {"vdb": [("vdb1", "", "backups")]}, {})
    assert out.stdout == "", out.stderr
