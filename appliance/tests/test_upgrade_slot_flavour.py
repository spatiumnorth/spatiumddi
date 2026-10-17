"""``spatium-upgrade-slot`` must refuse a cross-FLAVOUR image (Pi 5 profile).

The #1026 arch gate is not enough on its own: a generic arm64 image and a
Raspberry Pi (``rpi5``) image both report ``arch=arm64``, so the arch gate
would wave a generic image onto a Pi. That swaps the Raspberry Pi downstream
kernel for Debian's generic one — which has no RP1 Ethernet driver — and the
node reboots with no onboard NIC, on hardware that may be in another building.

These tests pin the twin gate: it reads the build profile the same way the
arch gate reads the architecture, sits in the same window (AFTER the ``dd``,
BEFORE the bootloader), and refuses with the same non-zero return. An
absent/empty ``APPLIANCE_PROFILE`` is the generic build (and what pre-profile
images report), normalised on both sides so a generic image onto a Pi is
refused rather than silently accepted.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_upgrade_slot_flavour.py -v

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


@pytest.fixture(scope="module")
def slot_cli():
    """Import the extensionless CLI as a module (it has a __main__ guard)."""
    loader = SourceFileLoader("spatium_upgrade_slot_flavour", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# ── _read_active_appliance_profile ─────────────────────────────────


def test_reads_profile_from_release(slot_cli, monkeypatch, tmp_path) -> None:
    f = tmp_path / "appliance-release"
    f.write_text('APPLIANCE_VERSION="x"\nAPPLIANCE_PROFILE="rpi5"\n')
    monkeypatch.setattr(slot_cli, "_ACTIVE_RELEASE_FILE", f)
    assert slot_cli._read_active_appliance_profile() == "rpi5"


def test_profile_is_empty_when_unstamped(slot_cli, monkeypatch, tmp_path) -> None:
    """A generic build, and any image built before the profile stamp existed,
    has no ``APPLIANCE_PROFILE`` line — that is the generic flavour, "" ."""
    f = tmp_path / "appliance-release"
    f.write_text('APPLIANCE_VERSION="x"\nAPPLIANCE_ARCH="arm64"\n')
    monkeypatch.setattr(slot_cli, "_ACTIVE_RELEASE_FILE", f)
    assert slot_cli._read_active_appliance_profile() == ""


def test_profile_is_empty_when_file_missing(slot_cli, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(slot_cli, "_ACTIVE_RELEASE_FILE", tmp_path / "nope")
    assert slot_cli._read_active_appliance_profile() == ""


# ── the gate sits in the same window as the #1026 arch gate ────────


def _apply_body() -> str:
    m = re.search(r"^def cmd_apply\(.*?(?=^def )", SRC, re.M | re.S)
    assert m, "cmd_apply not found"
    return m.group(0)


def test_flavour_gate_is_between_the_write_and_the_bootloader() -> None:
    body = _apply_body()
    write = body.index('"dd"')
    refusal = body.index("APPLIANCE_PROFILE")
    render = body.index('"spatium-grub-render"')
    sidecar = body.index("sync_slot_versions()")
    assert write < refusal, "the flavour cannot be known before the image is written"
    assert refusal < render, "the refusal must come BEFORE grub.cfg is re-rendered"
    assert refusal < sidecar, "and before the sidecar records the wrong-flavour slot"


def test_flavour_gate_returns_nonzero() -> None:
    """``set-next-boot`` runs only on rc=0, so the refusal must return non-zero,
    like the arch gate (rc 5), not warn."""
    body = _apply_body()
    tail = body[body.index("APPLIANCE_PROFILE") :]
    assert re.search(r"\n\s+return 5\b", tail), "the flavour refusal must return non-zero"


def test_flavour_gate_normalises_both_sides() -> None:
    """generic<->generic and rpi5<->rpi5 pass; any cross is refused. Because
    empty is normalised to generic on BOTH sides, a pre-profile (unstamped)
    image onto a Pi is refused, not silently accepted."""
    body = _apply_body()
    assert "host_profile = _read_active_appliance_profile()" in body
    assert '(written or {}).get("APPLIANCE_PROFILE")' in body
    assert "if host_profile != image_profile:" in body
