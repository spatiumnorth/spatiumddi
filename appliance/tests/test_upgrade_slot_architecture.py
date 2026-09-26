"""``spatium-upgrade-slot`` must refuse a cross-architecture image (#1026).

The control plane refuses a mismatch it can SEE, before it stamps
desired state. It cannot always see one: an image uploaded without a
declared architecture, or fetched from an operator-pasted external URL,
arrives unlabelled. This is the gate that inspects the real bytes, and
it is the last one — the control plane must never be the only gate on an
operation that bricks a node.

**Where the check sits is the design**, and is what these tests pin:

* AFTER the ``dd``. Earlier is not possible. The architecture lives in a
  file inside an ext4 filesystem inside a non-seekable xz stream — a
  slot image is a bare rootfs, not a disk image, so there is no GPT
  partition-type GUID to read either. Learning what the image is means
  decompressing it, which is exactly what the write just did.
* BEFORE the bootloader is touched. The inactive slot is a SPARE:
  leaving a wrong-arch rootfs in it costs nothing, because the node
  keeps running on the active slot and the next apply overwrites it.
  What cannot be undone is pointing the bootloader at it — that is a
  node that does not come back, on hardware that may be in another
  building.

The ordering assertion is structural because the alternative is a real
block device, a real 8 GiB image and a reboot; the helpers underneath it
are executed.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_upgrade_slot_architecture.py -v

No root, no partitions, no appliance.
"""

from __future__ import annotations

import importlib.util
import re
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
SRC = SCRIPT.read_text(encoding="utf-8")

RUNNER = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatiumddi-slot-upgrade"
)


@pytest.fixture(scope="module")
def slot_cli():
    """Import the extensionless CLI as a module (it has a __main__ guard)."""
    loader = SourceFileLoader("spatium_upgrade_slot_arch", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# ── host_architecture ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("x86_64", "amd64"),
        ("X86_64", "amd64"),
        ("amd64", "amd64"),
        ("aarch64", "arm64"),
        ("arm64", "arm64"),
    ],
)
def test_host_architecture_normalises_uname(
    slot_cli, monkeypatch, machine: str, expected: str
) -> None:
    """The comparison is against the name the BUILD stamps, so both
    sides have to speak the same vocabulary — ``uname -m`` answers
    ``x86_64`` where the artifacts say ``amd64``."""
    monkeypatch.setattr(slot_cli.platform, "machine", lambda: machine)
    assert slot_cli.host_architecture() == expected


@pytest.mark.parametrize("machine", ["", "riscv64", "ppc64le", "mips"])
def test_host_architecture_is_none_when_unrecognised(
    slot_cli, monkeypatch, machine: str
) -> None:
    """None never counts as a mismatch. Refusing on a string we failed to
    parse would block upgrades on a port nobody has built yet — the
    opposite of the protection wanted here."""
    monkeypatch.setattr(slot_cli.platform, "machine", lambda: machine)
    assert slot_cli.host_architecture() is None


# ── slot_release_fields ────────────────────────────────────────────


def _mount_stub(slot_cli, monkeypatch, tmp_path: Path, body: str | None):
    """Make the RO mount a no-op over ``tmp_path`` with ``body`` staged."""
    if body is not None:
        rel = tmp_path / "etc" / "spatiumddi"
        rel.mkdir(parents=True, exist_ok=True)
        (rel / "appliance-release").write_text(body)

    def _fake_run(argv, **kw):
        if argv[0] == "mount" and body is None:
            import subprocess

            raise subprocess.CalledProcessError(32, argv)
        return None

    monkeypatch.setattr(slot_cli, "run", _fake_run)
    monkeypatch.setattr(slot_cli, "Path", lambda *a, **k: tmp_path)


def test_release_fields_parses_the_stamped_file(slot_cli, monkeypatch, tmp_path) -> None:
    _mount_stub(
        slot_cli,
        monkeypatch,
        tmp_path,
        '# a comment\nAPPLIANCE_VERSION="2026.09.04-1"\nAPPLIANCE_ARCH="arm64"\n\n',
    )
    fields = slot_cli.slot_release_fields({"partlabel": "root_b", "device": "/dev/x"})
    assert fields == {
        "APPLIANCE_VERSION": "2026.09.04-1",
        "APPLIANCE_ARCH": "arm64",
    }


def test_release_fields_tolerates_an_unstamped_image(
    slot_cli, monkeypatch, tmp_path
) -> None:
    """An image built before #1026 has no ``APPLIANCE_ARCH`` line. That
    is UNKNOWN, and must parse cleanly rather than raise — every image
    in every operator's catalogue today is one of these."""
    _mount_stub(slot_cli, monkeypatch, tmp_path, 'APPLIANCE_VERSION="2026.08.12-1"\n')
    fields = slot_cli.slot_release_fields({"partlabel": "root_b", "device": "/dev/x"})
    assert fields == {"APPLIANCE_VERSION": "2026.08.12-1"}
    assert fields.get("APPLIANCE_ARCH") is None


def test_release_fields_returns_none_when_the_slot_will_not_mount(
    slot_cli, monkeypatch, tmp_path
) -> None:
    """Distinct from ``{}``: a slot that cannot be mounted is not a slot
    with no release file, and ``slot_version_label`` renders the two as
    ``unreadable`` vs ``unstamped``."""
    _mount_stub(slot_cli, monkeypatch, tmp_path, None)
    assert slot_cli.slot_release_fields({"partlabel": "root_b", "device": "/dev/x"}) is None


# ── the sentinels the sidecar + GRUB titles depend on ──────────────


def test_version_label_sentinels_survive_the_refactor(
    slot_cli, monkeypatch, tmp_path
) -> None:
    """``unknown`` / ``unreadable`` / ``unstamped`` reach
    ``slot-versions.json``, the Fleet card, the console and the GRUB menu
    titles, and the UI renders them as "—". Sharing one mount with the
    architecture probe must not change any of them."""
    assert slot_cli.slot_version_label({"partlabel": "root_b", "fslabel": ""}) == "unknown"

    _mount_stub(slot_cli, monkeypatch, tmp_path, None)
    slot = {"partlabel": "root_b", "device": "/dev/x", "fslabel": "root_b"}
    assert slot_cli.slot_version_label(slot) == "unreadable"

    _mount_stub(slot_cli, monkeypatch, tmp_path, "# nothing useful\n")
    assert slot_cli.slot_version_label(slot) == "unstamped"

    _mount_stub(slot_cli, monkeypatch, tmp_path, 'APPLIANCE_VERSION="2026.09.04-1"\n')
    assert slot_cli.slot_version_label(slot) == "2026.09.04-1"


# ── ordering: after the write, before the bootloader ───────────────


def _apply_body() -> str:
    m = re.search(r"^def cmd_apply\(.*?(?=^def )", SRC, re.M | re.S)
    assert m, "cmd_apply not found"
    return m.group(0)


def test_the_refusal_is_between_the_write_and_the_bootloader() -> None:
    """The one property that matters, and the one no unit test can
    reach: a check placed after the GRUB switch protects nothing, and a
    check placed before the dd cannot know what the image is."""
    body = _apply_body()
    write = body.index('"dd"')
    refusal = body.index("APPLIANCE_ARCH")
    # NOT ``_write_progress("bootloader")`` — that is a progress LABEL
    # emitted immediately after the dd, several steps before anything
    # bootable is written, and anchoring on it fails a correctly-placed
    # check. The real mutation is the grub render.
    render = body.index('"spatium-grub-render"')
    sidecar = body.index("sync_slot_versions()")
    assert write < refusal, "the architecture cannot be known before the image is written"
    assert refusal < render, (
        "the refusal must come BEFORE grub.cfg is re-rendered — after it, "
        "the node is already going to boot an image it cannot run"
    )
    assert refusal < sidecar, (
        "and before the slot-versions sidecar records the wrong-arch slot as "
        "carrying that version — the Fleet card and the GRUB menu titles read it"
    )


def test_the_refusal_returns_before_arming_next_boot() -> None:
    """``set-next-boot`` is driven by the wrapper only on rc=0, so the
    refusal has to be a non-zero return rather than a warning."""
    body = _apply_body()
    tail = body[body.index("APPLIANCE_ARCH") :]
    assert re.search(r"\n\s+return 5\b", tail), "the refusal must return non-zero"


def test_an_unknown_side_does_not_refuse() -> None:
    """Both unknowns fall through. Every image in every catalogue today
    is unstamped, and refusing them here would make this release unable
    to apply any of them."""
    body = _apply_body()
    guard = re.search(r"if host_arch and image_arch and host_arch != image_arch:", body)
    assert guard, "the guard must require BOTH sides to be known before refusing"


def test_the_wrapper_names_the_refusal_distinctly() -> None:
    """rc=5 reads as "apply failed" otherwise, which sends the operator
    to retry a download that was never the problem."""
    runner = RUNNER.read_text(encoding="utf-8")
    assert 'apply_rc" -eq 5' in runner
    assert "different CPU architecture" in runner


# ── #1202: the image tag each slot runs ────────────────────────────


def test_probe_reads_the_slots_baked_image_tag_in_the_same_mount(
    slot_cli, monkeypatch, tmp_path
) -> None:
    """A nightly's appliance version is not its image tag, so the slot's
    baked spatiumddi-version has to be read too. One mount, both answers."""
    _mount_stub(
        slot_cli, monkeypatch, tmp_path,
        'APPLIANCE_VERSION="0.0.0-nightly-20260924+7490f61"\n',
    )
    baked = tmp_path / "usr" / "lib" / "spatiumddi"
    baked.mkdir(parents=True)
    (baked / "spatiumddi-version").write_text("nightly-20260924\n")
    mounts: list[list[str]] = []
    real_run = slot_cli.run
    monkeypatch.setattr(slot_cli, "run",
                        lambda argv, **kw: mounts.append(argv) or real_run(argv, **kw))
    fields, tag = slot_cli.slot_probe({"partlabel": "root_a", "device": "/dev/x"})
    assert fields == {"APPLIANCE_VERSION": "0.0.0-nightly-20260924+7490f61"}
    assert tag == "nightly-20260924"
    assert [a[0] for a in mounts].count("mount") == 1
    # ...and the fields-only view is unchanged for every existing caller.
    assert slot_cli.slot_release_fields({"partlabel": "root_a", "device": "/dev/x"}) == fields


def test_probe_of_an_unmountable_slot_has_no_tag(slot_cli, monkeypatch, tmp_path) -> None:
    _mount_stub(slot_cli, monkeypatch, tmp_path, None)
    assert slot_cli.slot_probe({"partlabel": "root_a", "device": "/dev/x"}) == (None, "")


def test_sync_writes_each_slots_image_tag_beside_the_versions(
    slot_cli, monkeypatch, tmp_path
) -> None:
    """#1202: slot-versions.json keeps its shape (every reader parses slot_a /
    slot_b); the tags go into the sibling slot-image-tags.json the prune reads.
    The strings are the ones the 2026.09.04-1 -> nightly upgrade had."""
    active = {"partlabel": "root_b", "device": "/dev/b", "fslabel": "root_b"}
    inactive = {"partlabel": "root_a", "device": "/dev/a", "fslabel": "root_a"}
    monkeypatch.setattr(slot_cli, "detect_active_inactive", lambda: (active, inactive))
    monkeypatch.setattr(slot_cli, "_read_active_appliance_version",
                        lambda: "0.0.0-nightly-20260924+7490f61")
    root = tmp_path / "root"
    (root / "usr" / "lib" / "spatiumddi").mkdir(parents=True)
    (root / "usr" / "lib" / "spatiumddi" / "spatiumddi-version").write_text("nightly-20260924\n")
    monkeypatch.setattr(slot_cli, "_ACTIVE_ROOT", root)
    probes: list[str] = []
    monkeypatch.setattr(slot_cli, "slot_probe", lambda slot: probes.append(slot["partlabel"])
                        or ({"APPLIANCE_VERSION": "2026.09.04-1"}, "2026.09.04-1"))
    versions_file = tmp_path / "state" / "slot-versions.json"
    tags_file = tmp_path / "state" / "slot-image-tags.json"
    monkeypatch.setattr(slot_cli, "_SLOT_VERSIONS_FILE", versions_file)
    monkeypatch.setattr(slot_cli, "_SLOT_IMAGE_TAGS_FILE", tags_file)

    got = slot_cli.sync_slot_versions()

    import json
    assert got == {"slot_a": "2026.09.04-1", "slot_b": "0.0.0-nightly-20260924+7490f61"}
    assert json.loads(versions_file.read_text()) == got
    assert json.loads(tags_file.read_text()) == {"slot_a": "2026.09.04-1",
                                                 "slot_b": "nightly-20260924"}
    assert probes == ["root_a"], "only the inactive slot is mounted, and only once"


def test_sync_never_mounts_a_slot_without_a_filesystem_label(
    slot_cli, monkeypatch, tmp_path
) -> None:
    """The 'unknown' sentinel is decided before any mount, exactly as before."""
    active = {"partlabel": "root_a", "device": "/dev/a", "fslabel": "root_a"}
    inactive = {"partlabel": "root_b", "device": "/dev/b", "fslabel": ""}
    monkeypatch.setattr(slot_cli, "detect_active_inactive", lambda: (active, inactive))
    monkeypatch.setattr(slot_cli, "_read_active_appliance_version", lambda: "2026.09.04-1")
    monkeypatch.setattr(slot_cli, "_ACTIVE_ROOT", tmp_path / "no-such-root")
    monkeypatch.setattr(slot_cli, "slot_probe",
                        lambda slot: pytest.fail("a label-less slot must not be mounted"))
    monkeypatch.setattr(slot_cli, "_SLOT_VERSIONS_FILE", tmp_path / "v.json")
    monkeypatch.setattr(slot_cli, "_SLOT_IMAGE_TAGS_FILE", tmp_path / "t.json")
    assert slot_cli.sync_slot_versions() == {"slot_a": "2026.09.04-1", "slot_b": "unknown"}
    import json
    assert json.loads((tmp_path / "t.json").read_text()) == {}
