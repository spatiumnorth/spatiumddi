"""#3764 — catalog zones are producer-only for an agent group.

Every agent in a group already gets every zone in its own bundle, so a
member that also consumed the catalog loaded each member zone twice and
named refused the next ``rndc reconfig``. The producer still publishes the
catalog for secondaries outside the group; a consumer block, which only a
control plane older than #3764 sends, renders nothing.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver

from .test_views_render import _split_horizon_bundle

_KEY = {"name": "spatium-group", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"}


def _render(tmp_path: Path, catalog: dict | None) -> str:
    b = _split_horizon_bundle()
    b["views"] = []
    b["tsig_keys"] = [_KEY]
    b["catalog"] = catalog
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(b)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_consumer_block_renders_no_catalog(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        {"mode": "consumer", "zone_name": "cat.test.", "producer_addr": "192.0.2.7"},
    )
    assert "catalog-zones" not in conf
    assert "cat.test." not in conf
    assert "192.0.2.7" not in conf


def test_consumer_block_with_a_hostname_renders_no_catalog(tmp_path: Path) -> None:
    """The #3764 report's shape: a hostname in ``producer_addr``."""
    conf = _render(
        tmp_path,
        {"mode": "consumer", "zone_name": "cat.test.", "producer_addr": "ns1.example.com"},
    )
    assert "catalog-zones" not in conf
    assert "ns1.example.com" not in conf


def test_consumer_conf_matches_no_catalog_at_all(tmp_path: Path) -> None:
    consumer = _render(
        tmp_path / "a",
        {"mode": "consumer", "zone_name": "cat.test.", "producer_addr": "192.0.2.7"},
    )
    off = _render(tmp_path / "b", None)
    assert consumer.replace(str(tmp_path / "a"), "") == off.replace(str(tmp_path / "b"), "")


def test_producer_still_publishes_the_catalog(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        {"mode": "producer", "zone_name": "cat.test.", "members": [{"zone_name": "example.com."}]},
    )
    assert 'zone "cat.test." { type master;' in conf
    # #3578 — not world-transferable: the group key (plus the operator's
    # allow_transfer, none here), and the same list gates queries.
    assert "allow-transfer { any; }" not in conf
    line = next(ln for ln in conf.splitlines() if ln.startswith('zone "cat.test."'))
    assert 'allow-transfer { key "spatium-group"; };' in line
    assert 'allow-query { key "spatium-group"; };' in line
    assert "notify yes;" in line
    assert "catalog-zones" not in conf
    zfile = (tmp_path / "rendered.new" / "zones" / "cat.test.db").read_text()
    assert 'version IN TXT "2"' in zfile
    assert "IN PTR example.com." in zfile


def test_catalog_follows_the_operator_transfer_acl(tmp_path: Path) -> None:
    b = _split_horizon_bundle()
    b["views"] = []
    b["tsig_keys"] = [_KEY]
    b["options"] = {**(b.get("options") or {}), "allow_transfer": ["198.51.100.7"]}
    b["catalog"] = {"mode": "producer", "zone_name": "cat.test.", "members": []}
    Bind9Driver(state_dir=tmp_path).render(b)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    line = next(ln for ln in conf.splitlines() if ln.startswith('zone "cat.test."'))
    assert 'allow-transfer { key "spatium-group"; 198.51.100.7; };' in line
    assert 'allow-query { key "spatium-group"; 198.51.100.7; };' in line
