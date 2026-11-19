"""The data-disk guidance in docs/deployment/APPLIANCE.md agrees with the
installer's partition layout (#2240).

Everything that grows with the data (the Postgres volumes, etcd, the container
images, the logs) lives on ``/var``, and ``/var`` is whatever the disk has left
after the fixed partitions ``spatium-install`` creates ahead of it. The doc
tells an operator how much ``/var`` a 40 GiB and a 64 GiB disk give, and
recommends 64 GiB or more per control-plane node for about 1M devices. The
``/var`` figures are arithmetic on the installer's ``sgdisk`` layout, so they
are checked against it here: a change to the root-slot, ESP or state sizes
has to change the doc as well.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "appliance" / "mkosi.extra" / "usr" / "local" / "bin" / "spatium-install"
DOC = ROOT / "docs" / "deployment" / "APPLIANCE.md"

_UNIT_GIB = {"M": 1 / 1024, "G": 1.0}


def _fixed_gib() -> float:
    """GiB the installer gives the partitions before ``/var`` (p6, the rest of
    the disk): the x86-64 BIOS boot partition plus p2 to p5 of the first
    ``sgdisk -n`` layout (the second disk of a mirror repeats it)."""
    text = INSTALL.read_text()
    bios = re.search(r"_BIOS_BOOT_ARGS=\(-n1:0:\+(\d+)([MG])", text)
    assert bios, "the x86-64 BIOS boot partition's size is no longer where this test reads it"
    total = int(bios.group(1)) * _UNIT_GIB[bios.group(2)]
    seen: dict[str, float] = {}
    for num, size, unit in re.findall(r"-n([2-5]):0:\+(\d+)([MG])", text):
        seen.setdefault(num, int(size) * _UNIT_GIB[unit])
    assert sorted(seen) == ["2", "3", "4", "5"], f"partitions read: {seen}"
    var = re.search(r"-n6:0:0\s+-t6:8310\s+-c6:var", text)
    assert var, "/var is no longer partition 6, the rest of the disk"
    return total + sum(seen.values())


def _guidance() -> str:
    """The data-disk paragraph: from its bold lead-in to the next blank line."""
    doc = DOC.read_text()
    start = doc.find("**Data disk for large installs (#2240).**")
    assert start >= 0, "APPLIANCE.md has no data-disk guidance for large installs"
    end = doc.find("\n\n", start)
    return doc[start:end if end > 0 else None]


def test_the_doc_states_the_var_each_disk_size_gives():
    fixed = _fixed_gib()
    para = _guidance()
    pairs = re.findall(r"a (\d+) GiB disk(?: gives)? (\d+) GiB(?: of `/var`)?", para)
    assert len(pairs) >= 2, f"no '<disk> GiB disk gives <var> GiB of /var' figures in: {para}"
    for disk, var in pairs:
        want = math.floor(int(disk) - fixed)
        assert int(var) == want, (
            f"a {disk} GiB disk leaves {int(disk) - fixed:.2f} GiB for /var after the "
            f"installer's {fixed:.2f} GiB of fixed partitions, so the doc should say {want}, "
            f"not {var}")
    assert f"about {round(fixed)} GiB" in para, (
        f"the doc should give the fixed partitions as about {round(fixed)} GiB")


def test_the_doc_recommends_64_gib_or_more_for_about_1m_devices():
    para = _guidance()
    assert "1M devices" in para and "64 GiB or more" in para, para
    # The measured point the recommendation rests on, and the alert that watches it.
    assert "88 to 91%" in para and "`appliance_disk_usage`" in para, para
