"""An RFC 2317 zone's file must not nest (#4165).

``64/26.2.0.192.in-addr.arpa`` used to be written as ``zones/<view>/64/26...db``;
``_zone_views_under`` globs one level, so the zone was never listed, never
frozen/reloaded, and record edits under a view were never served.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver

CLASSLESS = "64/26.2.0.192.in-addr.arpa."


def _zone(name: str, view: str | None) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "forwarders": [],
        "forward_only": True,
        "view_name": view,
        "records": [],
    }


def _promote(tmp_path: Path) -> None:
    (tmp_path / "rendered").mkdir(exist_ok=True)
    live = tmp_path / "rendered"
    new = tmp_path / "rendered.new"
    import shutil

    shutil.rmtree(live)
    new.rename(live)


def test_classless_zone_under_a_view_is_listed_for_reload(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    bundle = {
        "options": {},
        "views": [{"name": "internal", "match_clients": ["any"], "order": 0}],
        "zones": [_zone(CLASSLESS, "internal"), _zone("example.com.", "internal")],
    }
    drv.render(bundle)
    _promote(tmp_path)
    got = sorted(drv.rendered_zone_views())
    assert ("64/26.2.0.192.in-addr.arpa", "internal") in got
    assert ("example.com", "internal") in got
    assert not (tmp_path / "rendered" / "zones" / "internal" / "64").exists()


def test_classless_zone_without_views_is_not_read_as_a_view(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render({"options": {}, "zones": [_zone(CLASSLESS, None)]})
    _promote(tmp_path)
    assert drv.rendered_zone_views() == [("64/26.2.0.192.in-addr.arpa", None)]


def test_nested_file_from_an_older_render_is_migrated(tmp_path: Path) -> None:
    live = tmp_path / "rendered" / "zones"
    for base in (live, live / "internal"):
        nested = base / "64"
        nested.mkdir(parents=True)
        (nested / "26.2.0.192.in-addr.arpa.db").write_text("; dynamic data\n")
        (nested / "26.2.0.192.in-addr.arpa.db.jnl").write_text("jnl")
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(
        {
            "options": {},
            "views": [{"name": "internal", "match_clients": ["any"], "order": 0}],
            "zones": [_zone(CLASSLESS, "internal")],
        }
    )
    flat = "64%2F26.2.0.192.in-addr.arpa.db"
    assert (live / "internal" / flat).read_text() == "; dynamic data\n"
    assert (live / "internal" / (flat + ".jnl")).exists()
    assert (live / flat).exists()
    assert not (live / "internal" / "64").exists()
    assert not (live / "64").exists()
