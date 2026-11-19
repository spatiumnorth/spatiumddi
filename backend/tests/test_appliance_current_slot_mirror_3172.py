"""#3172 — the booted slot is reported on a mirrored (#999 RAID1) appliance.

``_current_slot_from_cmdline`` (the api-side mirror of the supervisor's
helper) looked for ONE udev record carrying both the
slot's ``by-partlabel`` link and the root filesystem's ``by-uuid`` link. On a
mirror those never meet: the by-uuid link is on the md array (md125), the
by-partlabel links on its member partitions (vda4 / vdb4), so Fleet showed
the active slot as unknown. The array is named after its slot, and udev
records that as ``MD_DEVNAME`` and the ``md/root_a`` link.

The udev records are the real ones from a mirrored VM installed from
nightly-20261027 (the evidence on #3172), with the property lines mdadm's
udev rules add — measured on a real md array.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from app.services.appliance import slot as slot_service

ROOT_A_FS = "bad1f6f7-7eeb-40e0-a713-d9cb8d5cb6b3"
ROOT_B_FS = "8fb55b19-fe3d-41b1-ae57-11806a676e4d"

MIRROR = {
    # md125 — /dev/md/root_a, the filesystem root=UUID= names
    "b9:125": (
        "S:disk/by-id/md-name-any:root_a\n"
        f"S:disk/by-uuid/{ROOT_A_FS}\n"
        "S:disk/by-id/md-uuid-87470471:c473569e:21159cad:0f7b34b0\n"
        "S:md/root_a\n"
        "S:disk/by-label/root_a\n"
        "E:MD_DEVNAME=root_a\n"
        "E:ID_FS_LABEL=root_a\n"
        f"E:ID_FS_UUID={ROOT_A_FS}\n"
    ),
    # md127 — /dev/md/root_b
    "b9:127": (f"S:disk/by-uuid/{ROOT_B_FS}\n" "S:md/root_b\n" "E:MD_DEVNAME=root_b\n"),
    # vda4 / vdb4 — the members: partlabel, and the ARRAY's uuid
    "b254:4": (
        "S:disk/by-partlabel/root_A\n"
        "S:disk/by-uuid/87470471-c473-569e-2115-9cad0f7b34b0\n"
        "E:ID_PART_ENTRY_NAME=root_A\n"
    ),
    "b254:20": (
        "S:disk/by-partlabel/root_A\n" "S:disk/by-uuid/87470471-c473-569e-2115-9cad0f7b34b0\n"
    ),
    "b254:5": "S:disk/by-partlabel/root_B\n",
}


def _host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: dict, root: str) -> None:
    udev = tmp_path / "udev"
    udev.mkdir()
    for name, text in records.items():
        (udev / name).write_text(text)
    cmdline = tmp_path / "cmdline"
    cmdline.write_text(f"BOOT_IMAGE=/boot/vmlinuz root=UUID={root} rw loglevel=3\n")
    monkeypatch.setattr(slot_service, "_UDEV_DATA", udev)
    monkeypatch.setattr(slot_service, "_PROC_CMDLINE", cmdline)


def test_a_mirror_booted_from_a_reports_slot_a(tmp_path, monkeypatch) -> None:
    _host(tmp_path, monkeypatch, MIRROR, ROOT_A_FS)
    assert slot_service._current_slot_from_cmdline() == "slot_a"


def test_a_mirror_booted_from_b_reports_slot_b(tmp_path, monkeypatch) -> None:
    _host(tmp_path, monkeypatch, MIRROR, ROOT_B_FS)
    assert slot_service._current_slot_from_cmdline() == "slot_b"


def test_the_md_link_alone_is_enough(tmp_path, monkeypatch) -> None:
    """An array whose record lacks MD_DEVNAME still has its named link."""
    records = {"b9:125": f"S:disk/by-uuid/{ROOT_A_FS}\nS:md/root_a\n"}
    _host(tmp_path, monkeypatch, records, ROOT_A_FS)
    assert slot_service._current_slot_from_cmdline() == "slot_a"


def test_a_non_slot_array_holding_root_is_not_a_slot(tmp_path, monkeypatch) -> None:
    records = {"b9:126": f"S:disk/by-uuid/{ROOT_A_FS}\nS:md/var\nE:MD_DEVNAME=var\n"}
    _host(tmp_path, monkeypatch, records, ROOT_A_FS)
    assert slot_service._current_slot_from_cmdline() is None


def test_a_single_disk_is_unchanged(tmp_path, monkeypatch) -> None:
    records = {
        "b8:4": "S:disk/by-partlabel/root_A\nS:disk/by-uuid/11111111-2222-4333-8444-555555555555\n",
        "b8:5": "S:disk/by-partlabel/root_B\nS:disk/by-uuid/66666666-7777-4888-9999-aaaaaaaaaaaa\n",
    }
    _host(tmp_path, monkeypatch, records, "66666666-7777-4888-9999-aaaaaaaaaaaa")
    assert slot_service._current_slot_from_cmdline() == "slot_b"


# The supervisor carries its own copy of ``_current_slot_from_cmdline`` (a
# separate package). Fleet reads the supervisor's answer, the api its own, so
# the two must agree on every record set — including the precedence cases
# where a record carries more than one name.
PARITY_CASES: list[tuple[str, dict[str, str], str]] = [
    ("mirror-a", MIRROR, ROOT_A_FS),
    ("mirror-b", MIRROR, ROOT_B_FS),
    ("md-link-only", {"b9:125": f"S:disk/by-uuid/{ROOT_A_FS}\nS:md/root_a\n"}, ROOT_A_FS),
    (
        "devname-only",
        {"b9:125": f"S:disk/by-uuid/{ROOT_A_FS}\nE:MD_DEVNAME=root_a\n"},
        ROOT_A_FS,
    ),
    (
        "devname-beats-link-link-first",
        {"b9:125": f"S:md/root_b\nS:disk/by-uuid/{ROOT_A_FS}\nE:MD_DEVNAME=root_a\n"},
        ROOT_A_FS,
    ),
    (
        "devname-beats-link-devname-first",
        {"b9:125": f"E:MD_DEVNAME=root_a\nS:disk/by-uuid/{ROOT_A_FS}\nS:md/root_b\n"},
        ROOT_A_FS,
    ),
    (
        "partlabel-beats-devname",
        {
            "b9:125": f"E:MD_DEVNAME=root_b\nS:disk/by-uuid/{ROOT_A_FS}\nS:disk/by-partlabel/root_A\n"
        },
        ROOT_A_FS,
    ),
    (
        "empty-devname-falls-back-to-link",
        {"b9:125": f"E:MD_DEVNAME=\nS:disk/by-uuid/{ROOT_A_FS}\nS:md/ROOT_B\n"},
        ROOT_A_FS,
    ),
    ("non-slot-array", {"b9:126": f"S:disk/by-uuid/{ROOT_A_FS}\nE:MD_DEVNAME=var\n"}, ROOT_A_FS),
    ("member-only-no-fs-uuid", {"b254:4": "S:disk/by-partlabel/root_A\n"}, ROOT_A_FS),
    (
        "single-disk",
        {"b8:4": f"S:disk/by-partlabel/root_A\nS:disk/by-uuid/{ROOT_A_FS}\n"},
        ROOT_A_FS,
    ),
]


def _supervisor_state():  # type: ignore[no-untyped-def]
    path = (
        Path(__file__).resolve().parents[2]
        / "agent/supervisor/spatium_supervisor/appliance_state.py"
    )
    if not path.exists():
        pytest.skip("agent/supervisor is not in this checkout")
    spec = importlib.util.spec_from_file_location("_sup_appliance_state_3172", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    ("records", "root"), [c[1:] for c in PARITY_CASES], ids=[c[0] for c in PARITY_CASES]
)
def test_supervisor_copy_agrees(tmp_path, monkeypatch, records, root) -> None:
    sup = _supervisor_state()
    _host(tmp_path, monkeypatch, records, root)
    monkeypatch.setattr(sup, "_UDEV_DATA", slot_service._UDEV_DATA)
    monkeypatch.setattr(sup, "_PROC_CMDLINE", slot_service._PROC_CMDLINE)
    assert sup._current_slot_from_cmdline() == slot_service._current_slot_from_cmdline()
