"""Kea's DHCP socket gets a 1 MiB receive buffer on the appliance (#4544).

Kea never calls setsockopt(SO_RCVBUF), so the socket takes
net.core.rmem_default. The appliance image sets it (and rmem_max) to 1 MiB in a
sysctl drop-in, and nothing else in the image may set either lower.

    python3 -m pytest appliance/tests/test_kea_rcvbuf_sysctl.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DROPIN = REPO / "appliance/mkosi.extra/etc/sysctl.d/60-spatium-net.conf"
WANT = 1048576
KEY = re.compile(r"^\s*(?:net\.core\.|net/core/)(rmem_default|rmem_max)\s*=\s*(\d+)", re.M)


def _values(text: str) -> dict[str, int]:
    return {k: int(v) for k, v in KEY.findall(text)}


def test_dropin_sets_both_to_one_mib() -> None:
    assert DROPIN.is_file()
    assert _values(DROPIN.read_text()) == {"rmem_default": WANT, "rmem_max": WANT}


def test_nothing_else_in_the_image_sets_them_lower() -> None:
    for root in ("appliance", "charts"):
        for p in (REPO / root).rglob("*"):
            if not p.is_file() or p == DROPIN or "tests" in p.parts:
                continue
            try:
                text = p.read_text()
            except UnicodeDecodeError:
                continue
            for k, v in _values(text).items():
                assert v >= WANT, f"{p} sets {k} = {v}"


def test_docs_mention_the_buffer() -> None:
    dhcp = (REPO / "docs/features/DHCP.md").read_text()
    assert "rmem_default" in dhcp and "60-spatium-net.conf" in dhcp
    obs = (REPO / "docs/OBSERVABILITY.md").read_text()
    assert "rmem_default" in obs and "ss -uanm" in obs
