"""The BIND9 agent renders only zone names that are safe as config and file names."""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver


def _zone(name: str) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "forwarders": [],
        "forward_only": True,
        "view_name": None,
        "records": [],
    }


@pytest.mark.parametrize(
    "bad",
    [
        'x"; };\nzone "evil',
        "a b.example.",
        "../../etc/evil.",
        "a{b}.example.",
        "a;b.example.",
        "a\\b.example.",
        "/abs.example.",
    ],
)
def test_unsafe_zone_name_is_not_rendered(tmp_path: Path, bad: str) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render({"options": {}, "zones": [_zone("ok.example."), _zone(bad)]})
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert 'zone "ok.example."' in conf
    assert bad not in conf
    assert "evil" not in conf
    assert not list(tmp_path.rglob("*evil*"))


def test_classless_reverse_zone_still_renders(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render({"options": {}, "zones": [_zone("0/26.2.0.192.in-addr.arpa.")]})
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert 'zone "0/26.2.0.192.in-addr.arpa."' in conf
