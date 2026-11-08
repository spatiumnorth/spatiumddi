"""#3764 — a hostname ``producer_addr`` is never rendered into named.conf."""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver

from .test_views_render import _split_horizon_bundle

_KEY = {"name": "spatium-group", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"}


def _conf(tmp_path: Path, addr: str, keys: list | None = None) -> str:
    b = _split_horizon_bundle()
    b["views"] = []
    b["tsig_keys"] = keys or []
    b["catalog"] = {"mode": "consumer", "zone_name": "cat.test.", "producer_addr": addr}
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(b)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_hostname_not_rendered(tmp_path: Path) -> None:
    conf = _conf(tmp_path, "ns1.example.com")
    assert "ns1.example.com" not in conf
    assert "catalog-zones" not in conf


def test_ip_rendered(tmp_path: Path) -> None:
    conf = _conf(tmp_path, "192.0.2.7")
    assert "default-masters { 192.0.2.7" in conf


def test_consumer_declares_the_catalog_zone(tmp_path: Path) -> None:
    """BIND refuses a ``catalog-zones`` entry for an undeclared zone."""
    conf = _conf(tmp_path, "2001:db8::7")
    assert 'zone "cat.test." { type secondary; primaries { 2001:db8::7; }; };' in conf


def test_member_transfers_are_signed_with_the_group_key(tmp_path: Path) -> None:
    """The producer grants ``allow-transfer`` to the group's keys only."""
    conf = _conf(tmp_path, "192.0.2.7", [_KEY])
    assert 'default-masters { 192.0.2.7 key "spatium-group"; }' in conf
