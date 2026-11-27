"""The upgrade's fallback grub.cfg patch re-points the active-slot UUID (#4961).

``spatium-upgrade-slot`` re-renders grub.cfg with ``spatium-grub-render`` after
writing the inactive slot; when that fails it falls back to
``_patch_grub_cfg_slot_uuid``, which rewrites the UUIDs inside the slot's own
menuentry. Since #4961 the verbose and recovery entries boot
``${sp_act_uuid}``, set outside every menuentry from each slot's UUID, so the
fallback must re-point that line too: otherwise, after an upgrade into slot B
whose render failed, both entries would search for slot B's old filesystem.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

BIN = Path(__file__).parent.parent / "mkosi.extra" / "usr" / "local" / "bin"
UUID_A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
UUID_B = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
NEW_B = "cccccccc-3333-4333-8333-cccccccccccc"


@pytest.fixture(scope="module")
def slot_cli():
    loader = SourceFileLoader("spatium_upgrade_slot_4961", str(BIN / "spatium-upgrade-slot"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _rendered() -> str:
    return subprocess.run(
        [sys.executable, str(BIN / "spatium-grub-render"), "--print",
         "--root-a-uuid", UUID_A, "--root-b-uuid", UUID_B],
        check=True, capture_output=True, text=True,
    ).stdout


def _set_lines(cfg: str) -> list[str]:
    return re.findall(r"set sp_act_uuid=(\S+)", cfg)


def test_fallback_patch_repoints_active_slot_uuid(slot_cli, tmp_path) -> None:
    cfg = tmp_path / "grub.cfg"
    cfg.write_text(_rendered())
    assert sorted(_set_lines(cfg.read_text())) == sorted([UUID_A, UUID_B])

    slot_cli._patch_grub_cfg_slot_uuid("root_b", NEW_B, cfg_path=str(cfg))

    out = cfg.read_text()
    assert UUID_B not in out, "slot B's old UUID survived the fallback patch"
    assert sorted(_set_lines(out)) == sorted([UUID_A, NEW_B])


def test_fallback_patch_leaves_other_slot_alone(slot_cli, tmp_path) -> None:
    cfg = tmp_path / "grub.cfg"
    cfg.write_text(_rendered())

    slot_cli._patch_grub_cfg_slot_uuid("root_b", NEW_B, cfg_path=str(cfg))

    out = cfg.read_text()
    # Slot A's menuentry (2 refs) and its sp_act_uuid line (1) are untouched.
    assert out.count(UUID_A) == 3
