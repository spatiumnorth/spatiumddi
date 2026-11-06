"""Identical zones load once under split-horizon (#3551).

Every zone used to load once per view, so a group's memory scaled with
views × data: adding a second view doubled named's footprint and OOM-looped
agents under a 1 Gi limit. A copy that renders identically in a later view
is now defined in the first view that holds it and referenced with BIND's
``in-view``. These assert on the rendered named.conf and zone files, and
(when a bind9 toolchain is present) that named-checkconf accepts them.
``live_views_share_check.py`` loads the result in a real named.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _zone_views_under

_A = {"name": "www", "type": "A", "ttl": 300, "value": "192.0.2.10"}


def _rec(name: str, value: str) -> dict:
    return {"name": name, "type": "A", "ttl": 300, "value": value}


def _view(name: str, clients: list[str], **extra: object) -> dict:
    return {
        "id": name,
        "name": name,
        "match_clients": clients,
        "match_destinations": [],
        "recursion": True,
        **extra,
    }


def _zone(name: str, view: str, records: list[dict], **extra: object) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 1,
        "view_name": view,
        "records": records,
        **extra,
    }


def _bl(zone: str, view: str | None, domain: str = "ads.example.net") -> dict:
    return {
        "rpz_zone_name": zone,
        "entries": [{"domain": domain, "action": "block", "block_mode": "nxdomain"}],
        "exceptions": [],
        "view_name": view,
    }


def _bundle(
    zones: list[dict],
    views: list[dict] | None = None,
    blocklists: list[dict] | None = None,
) -> dict:
    return {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": (
            views
            if views is not None
            else [
                _view("restricted", ["192.0.2.0/24"]),
                _view("default", ["any"]),
            ]
        ),
        "zones": zones,
        "tsig_keys": [],
        "blocklists": blocklists or [],
    }


def _both(name: str, records: list[dict], **extra: object) -> list[dict]:
    """The zone as the control plane ships a global zone: one copy per view."""
    return [
        _zone(name, "restricted", list(records), **extra),
        _zone(name, "default", list(records), **extra),
    ]


def _render(tmp_path: Path, bundle: dict) -> tuple[str, Path]:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    root = tmp_path / "rendered.new"
    return (root / "named.conf").read_text(), root


def _view_block(conf: str, name: str) -> str:
    start = conf.index(f'view "{name}" {{')
    nxt = conf.find("\nview ", start + 1)
    return conf[start : nxt if nxt != -1 else len(conf)]


def _checkconf(conf_path: Path) -> None:
    if shutil.which("named-checkconf") is None:
        return
    r = subprocess.run(
        ["named-checkconf", str(conf_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_an_identical_zone_is_defined_once_and_referenced_in_view(
    tmp_path: Path,
) -> None:
    conf, root = _render(tmp_path, _bundle(_both("example.com.", [_A])))

    restricted = _view_block(conf, "restricted")
    default = _view_block(conf, "default")
    # One definition, in the FIRST view: BIND resolves ``in-view`` only
    # against a view defined above the reference.
    assert conf.count('zone "example.com." { type master;') == 1
    assert 'zone "example.com." { type master;' in restricted
    assert 'zone "example.com." { in-view "restricted"; };' in default
    assert conf.index('view "restricted"') < conf.index('view "default"')
    # And one file, which is what named loads.
    assert (root / "zones" / "restricted" / "example.com.db").exists()
    assert not (root / "zones" / "default" / "example.com.db").exists()
    # Everything that walks the rendered tree sees the one zone named holds.
    assert [zv for zv in _zone_views_under(root) if zv[0] == "example.com"] == [
        ("example.com", "restricted")
    ]
    _checkconf(root / "named.conf")


def test_view_order_is_never_changed_to_make_a_zone_shareable(
    tmp_path: Path,
) -> None:
    """The defining view is the first to hold the copy; the views keep the
    order the control plane gave them, which is what picks a client's view."""
    views = [_view("default", ["any"]), _view("restricted", ["192.0.2.0/24"])]
    zones = [
        _zone("example.com.", "default", [_A]),
        _zone("example.com.", "restricted", [_A]),
    ]
    conf, _root = _render(tmp_path, _bundle(zones, views))
    assert conf.index('view "default"') < conf.index('view "restricted"')
    assert 'zone "example.com." { in-view "default"; };' in _view_block(
        conf, "restricted"
    )


def test_a_view_specific_record_keeps_separate_copies(tmp_path: Path) -> None:
    zones = [
        _zone("example.com.", "restricted", [_A, _rec("app", "192.0.2.20")]),
        _zone("example.com.", "default", [_A, _rec("app", "198.51.100.20")]),
    ]
    conf, root = _render(tmp_path, _bundle(zones))
    assert "in-view" not in conf
    assert (
        "192.0.2.20" in (root / "zones" / "restricted" / "example.com.db").read_text()
    )
    assert (
        "198.51.100.20" in (root / "zones" / "default" / "example.com.db").read_text()
    )
    _checkconf(root / "named.conf")


@pytest.mark.parametrize(
    "option",
    [
        {"allow_transfer": ["192.0.2.53"]},
        {"dnssec_enabled": True},
        {"also_notify": ["192.0.2.54"]},
        {
            "dynamic_update_enabled": True,
            "update_acl": [
                {"action": "grant", "match_kind": "ip", "ip_cidr": "192.0.2.7"}
            ],
        },
    ],
    ids=lambda o: next(iter(o)),
)
def test_differing_zone_options_keep_separate_copies(
    tmp_path: Path, option: dict
) -> None:
    """Zone options live only on the defining view, so a copy whose options
    differ cannot borrow another view's stanza."""
    zones = [
        _zone("example.com.", "restricted", [_A], **option),
        _zone("example.com.", "default", [_A]),
    ]
    conf, root = _render(tmp_path, _bundle(zones))
    assert "in-view" not in conf
    assert (root / "zones" / "restricted" / "example.com.db").exists()
    assert (root / "zones" / "default" / "example.com.db").exists()


def test_a_differing_view_allow_query_keeps_separate_copies(tmp_path: Path) -> None:
    """A shared zone takes its query ACL from the DEFINING view. Referencing
    one from a view with a wider allow-query refuses that view's clients
    (verified against BIND 9.20), so the view ACL is part of the match."""
    views = [
        _view("restricted", ["192.0.2.0/24"], allow_query=["192.0.2.0/24"]),
        _view("default", ["any"]),
    ]
    conf, _root = _render(tmp_path, _bundle(_both("example.com.", [_A]), views))
    assert "in-view" not in conf


def test_the_same_allow_query_still_shares(tmp_path: Path) -> None:
    views = [
        _view("restricted", ["192.0.2.0/24"], allow_query=["any"]),
        _view("default", ["any"], allow_query=["any"]),
    ]
    conf, _root = _render(tmp_path, _bundle(_both("example.com.", [_A]), views))
    assert 'zone "example.com." { in-view "restricted"; };' in conf


def test_a_later_view_references_the_first_copy_it_matches(tmp_path: Path) -> None:
    views = [
        _view("lab", ["198.51.100.0/24"]),
        _view("restricted", ["192.0.2.0/24"]),
        _view("default", ["any"]),
    ]
    zones = [
        _zone("example.com.", "lab", [_rec("www", "198.51.100.10")]),
        _zone("example.com.", "restricted", [_A]),
        _zone("example.com.", "default", [_A]),
    ]
    conf, root = _render(tmp_path, _bundle(zones, views))
    assert 'zone "example.com." { in-view "restricted"; };' in _view_block(
        conf, "default"
    )
    assert (root / "zones" / "lab" / "example.com.db").exists()
    assert (root / "zones" / "restricted" / "example.com.db").exists()
    assert not (root / "zones" / "default" / "example.com.db").exists()
    _checkconf(root / "named.conf")


def test_forward_and_secondary_zones(tmp_path: Path) -> None:
    """BIND refuses ``in-view`` of a forward zone, so those repeat (they hold
    no data). A secondary shares like a primary: one transfer, one copy."""
    fwd = {"type": "forward", "forwarders": ["192.0.2.1"], "forward_only": True}
    sec = {"type": "secondary", "masters": ["192.0.2.2"]}
    zones = [
        *_both("fwd.example.com.", [], **fwd),
        *_both("sec.example.com.", [], **sec),
    ]
    conf, root = _render(tmp_path, _bundle(zones))
    default = _view_block(conf, "default")
    assert 'zone "fwd.example.com." { type forward;' in default
    assert 'zone "sec.example.com." { in-view "restricted"; };' in default
    _checkconf(root / "named.conf")


def test_rpz_zones_are_never_shared_with_in_view(tmp_path: Path) -> None:
    """BIND refuses a response-policy zone defined by ``in-view`` ("is not a
    primary or secondary zone", BIND 9.20), so the group list a view falls
    back to is still loaded into each view that uses it, and the per-view
    sets stay separate zones."""
    conf, root = _render(
        tmp_path,
        _bundle(
            _both("example.com.", [_A]),
            blocklists=[
                _bl("spatium-blocklist-restricted.rpz.", "restricted", "a.example.net"),
                _bl("spatium-blocklist.rpz.", None, "b.example.net"),
            ],
        ),
    )
    restricted = _view_block(conf, "restricted")
    default = _view_block(conf, "default")
    assert 'response-policy { zone "spatium-blocklist-restricted.rpz"; }' in restricted
    assert 'response-policy { zone "spatium-blocklist.rpz"; }' in default
    assert 'zone "spatium-blocklist.rpz." { type master;' in default
    assert 'zone "spatium-blocklist-restricted.rpz." { type master;' in restricted
    assert (root / "zones" / "default" / "spatium-blocklist.rpz.db").exists()
    for line in conf.splitlines():
        if "in-view" in line:
            assert ".rpz" not in line
    # The authoritative zone still shares beside them.
    assert 'zone "example.com." { in-view "restricted"; };' in default
    _checkconf(root / "named.conf")


def test_the_group_list_in_two_views_renders_valid_config(tmp_path: Path) -> None:
    conf, root = _render(
        tmp_path,
        _bundle(
            _both("example.com.", [_A]),
            blocklists=[_bl("spatium-blocklist.rpz.", None)],
        ),
    )
    for view in ("restricted", "default"):
        assert 'response-policy { zone "spatium-blocklist.rpz"; }' in _view_block(
            conf, view
        )
        assert (root / "zones" / view / "spatium-blocklist.rpz.db").exists()
    _checkconf(root / "named.conf")


# ── RFC 2136 records named holds are never dropped by sharing (#2850) ──────


def _promote(tmp_path: Path) -> Path:
    """Make the last render the live tree, as a swap would."""
    live = tmp_path / "rendered"
    if live.exists():
        shutil.rmtree(live)
    (tmp_path / "rendered.new").rename(live)
    return live


def _dynamic(records: list[dict]) -> list[dict]:
    return _both(
        "example.com.",
        records,
        dynamic_update_enabled=True,
        update_acl=[{"action": "grant", "match_kind": "ip", "ip_cidr": "192.0.2.0/24"}],
    )


def test_a_copy_holding_third_party_records_is_not_shared(tmp_path: Path) -> None:
    """The upgrade from per-view copies: the later view's copy took an RFC
    2136 update (its journal). Sharing would drop it with the file."""
    from spatium_dns_agent.drivers.bind9 import _owned_sidecar

    Bind9Driver(state_dir=tmp_path).render(_bundle(_dynamic([_A])))
    live = _promote(tmp_path)
    # The tree a pre-#3551 agent left: no in-view, a journal on default.
    conf = (live / "named.conf").read_text()
    (live / "named.conf").write_text(
        conf.replace(
            'zone "example.com." { in-view "restricted"; };',
            'zone "example.com." { type master; file "x"; };',
        )
    )
    default_copy = live / "zones" / "default" / "example.com.db"
    default_copy.parent.mkdir(exist_ok=True)
    shutil.copyfile(live / "zones" / "restricted" / "example.com.db", default_copy)
    shutil.copyfile(
        _owned_sidecar(live / "zones" / "restricted" / "example.com.db"),
        _owned_sidecar(default_copy),
    )
    default_copy.with_name(default_copy.name + ".jnl").write_bytes(b"journal")

    conf, root = _render(tmp_path, _bundle(_dynamic([_A])))

    assert "in-view" not in _view_block(conf, "default")
    assert (root / "zones" / "default" / "example.com.db").is_file()


def test_a_dynamic_zone_is_never_shared_across_views(tmp_path: Path) -> None:
    """An update sent through one view would land in the one shared copy and
    be answered in every view, so a zone that accepts updates keeps a copy per
    view even when its copies render identically."""
    conf, root = _render(tmp_path, _bundle(_dynamic([_A])))

    assert "in-view" not in conf
    assert conf.count('zone "example.com." { type master;') == 2
    assert (root / "zones" / "restricted" / "example.com.db").is_file()
    assert (root / "zones" / "default" / "example.com.db").is_file()
    _checkconf(root / "named.conf")


def test_a_static_identical_zone_still_shares_beside_a_dynamic_one(
    tmp_path: Path,
) -> None:
    zones = _dynamic([_A]) + _both("static.example.com.", [_A])
    conf, _root = _render(tmp_path, _bundle(zones))

    assert 'zone "static.example.com." { in-view "restricted"; };' in _view_block(
        conf, "default"
    )
    assert 'zone "example.com." { in-view' not in conf
    assert conf.count('zone "example.com." { type master;') == 2


def test_a_new_copy_of_a_shared_zone_carries_from_the_defining_copy(
    tmp_path: Path,
) -> None:
    """A view that takes its own copy back from a shared zone served the
    defining view's zone, so that is where its RFC 2136 records are."""
    from spatium_dns_agent.drivers.bind9 import _view_carry_sources

    # The tree an earlier build left: the dynamic zone shared through in-view.
    Bind9Driver(state_dir=tmp_path).render(_bundle(_dynamic([_A])))
    live = _promote(tmp_path)
    conf = (live / "named.conf").read_text()
    default = _view_block(conf, "default")
    start = default.index('zone "example.com."')
    stanza = default[start : default.index("\n", start)]
    (live / "named.conf").write_text(
        conf.replace(stanza, 'zone "example.com." { in-view "restricted"; };')
    )
    (live / "zones" / "default" / "example.com.db").unlink()
    (live / "zones" / "restricted" / "example.com.db.jnl").write_bytes(b"journal")
    split = _dynamic([_A])
    split[1]["records"].append(_rec("only", "198.51.100.5"))
    driver = Bind9Driver(state_dir=tmp_path)
    driver.render(_bundle(split))
    new_dir = tmp_path / "rendered.new"

    assert _view_carry_sources(new_dir, live) == {
        ("example.com", "default"): ("example.com", "restricted")
    }
    assert ("example.com", "default") in driver._carry_candidates(new_dir, live)
