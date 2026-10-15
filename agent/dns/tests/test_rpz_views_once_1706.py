"""A group blocklist reaches each view once (#1706).

A view's own RPZ zone already folds in the group's lists, so the group zone
(``view_name`` None) rendered beside it loaded the same entries a second
time in every view. These assert on the rendered named.conf and the zone
files named loads.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver

_ENTRY = {"domain": "ads.example.test", "action": "block", "block_mode": "nxdomain"}


def _bl(zone: str, view: str | None) -> dict:
    return {
        "rpz_zone_name": zone,
        "entries": [dict(_ENTRY)],
        "exceptions": [],
        "view_name": view,
    }


def _bundle(blocklists: list[dict]) -> dict:
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": [
            {
                "id": "v1",
                "name": "internal",
                "match_clients": ["10.0.0.0/8"],
                "match_destinations": [],
                "recursion": True,
                "order": 0,
            },
            {
                "id": "v2",
                "name": "external",
                "match_clients": ["any"],
                "match_destinations": [],
                "recursion": True,
                "order": 1,
            },
        ],
        "zones": [],
        "tsig_keys": [],
        "blocklists": blocklists,
    }


def _view_block(conf: str, name: str) -> str:
    start = conf.index(f'view "{name}" {{')
    nxt = conf.find("\nview ", start + 1)
    return conf[start : nxt if nxt != -1 else len(conf)]


def _render(tmp_path: Path, blocklists: list[dict]) -> tuple[str, Path]:
    Bind9Driver(state_dir=tmp_path).render(_bundle(blocklists))
    root = tmp_path / "rendered.new"
    return (root / "named.conf").read_text(), root


def test_group_zone_is_not_loaded_beside_a_views_own_zone(tmp_path: Path) -> None:
    conf, root = _render(
        tmp_path,
        [
            _bl("spatium-blocklist-internal.rpz.", "internal"),
            _bl("spatium-blocklist-external.rpz.", "external"),
            _bl("spatium-blocklist.rpz.", None),
        ],
    )
    for view in ("internal", "external"):
        block = _view_block(conf, view)
        assert f'zone "spatium-blocklist-{view}.rpz"' in block
        assert 'zone "spatium-blocklist.rpz"' not in block
        assert f'response-policy {{ zone "spatium-blocklist-{view}.rpz"; }}' in block
        assert (root / "zones" / view / f"spatium-blocklist-{view}.rpz.db").exists()
        assert not (root / "zones" / view / "spatium-blocklist.rpz.db").exists()


def test_view_without_its_own_zone_still_gets_the_group_zone(tmp_path: Path) -> None:
    conf, root = _render(
        tmp_path,
        [
            _bl("spatium-blocklist-internal.rpz.", "internal"),
            _bl("spatium-blocklist.rpz.", None),
        ],
    )
    internal = _view_block(conf, "internal")
    external = _view_block(conf, "external")
    assert 'zone "spatium-blocklist.rpz"' not in internal
    assert 'zone "spatium-blocklist.rpz"' in external
    assert "response-policy" in external
    assert (root / "zones" / "external" / "spatium-blocklist.rpz.db").exists()
