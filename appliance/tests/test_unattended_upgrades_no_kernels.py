"""Unattended upgrades must never install a kernel package (#1249).

Each A/B slot boots ``/boot/vmlinuz`` and ``/boot/initrd.img``, symlinks the
slot-image build (``build-slot-image.sh``) and the installer point at the
image's own kernel. A new-ABI security kernel installed in place by
unattended-upgrades does not move them, since Debian maintains its kernel
symlinks in ``/``, so it never boots and only fills a fixed-size slot; a
revision of the slot's own ABI overwrites the ``vmlinuz-<ver>`` they name, so
the slot boots a kernel its image never shipped.
Kernels ship with slot images. ``mkosi.conf`` said "No kernel upgrades" while
the drop-in allowed them; this pins the drop-in to what the comment says.

    python3 -m pytest appliance/tests/test_unattended_upgrades_no_kernels.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DROPIN = REPO / "appliance" / "mkosi.extra" / "etc" / "apt" / "apt.conf.d" / "52unattended-upgrades-spatium"

pytestmark = pytest.mark.skipif(not DROPIN.is_file(), reason="appliance tree not present")


def _blacklist() -> list[str]:
    # apt.conf has both C++ (//) and C (/* */) comments; an entry inside
    # either is not in effect, so it must not satisfy the assertions below.
    text = re.sub(r"/\*.*?\*/", "", DROPIN.read_text(encoding="utf-8"), flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    block = re.search(r"Unattended-Upgrade::Package-Blacklist\s*\{(.*?)\};", text, re.S)
    assert block, "52unattended-upgrades-spatium has no Package-Blacklist"
    return re.findall(r'"([^"]*)"', block.group(1))


@pytest.mark.parametrize(
    "package",
    [
        "linux-image-amd64",
        "linux-image-arm64",
        "linux-image-rpi-2712",
        "linux-image-6.12.48+deb13-amd64",
    ],
)
def test_every_kernel_package_is_blacklisted(package: str) -> None:
    # unattended-upgrades matches each entry as a regex from the start of
    # the package name (re.match).
    assert any(re.match(entry, package) for entry in _blacklist()), package


@pytest.mark.parametrize("package", ["linux-base", "openssl", "libc6", "firmware-linux-free"])
def test_nothing_else_is_caught(package: str) -> None:
    assert not any(re.match(entry, package) for entry in _blacklist()), package
