"""DNS Views — split-horizon BIND9 rendering on the agent (issue #24).

The agent receives a long-poll bundle whose zones are pre-expanded
per view (each zone copy tagged with ``view_name`` and carrying only
that view's records) and renders ``named.conf`` with one ``view { … }``
block per view, plus per-view zone files so an identical zone name in
two views doesn't clobber files.

These tests exercise ``Bind9Driver.render`` against hand-built bundles
shaped exactly like ``app.services.dns.agent_config.build_config_bundle``
emits.
"""

from __future__ import annotations

import re
from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver


def _zone(name: str, view_name: str | None, records: list[dict]) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "forwarders": [],
        "forward_only": True,
        "view_name": view_name,
        "records": records,
    }


def _split_horizon_bundle() -> dict:
    # Same zone "example.com." served two ways: internal clients see the
    # RFC 1918 address, external clients see the public one; the MX is
    # shared (view_name folded to NULL on the control plane → present in
    # both view copies).
    internal_recs = [
        {
            "name": "www",
            "type": "A",
            "ttl": 300,
            "value": "10.0.0.1",
            "priority": None,
            "weight": None,
            "port": None,
        },
        {
            "name": "@",
            "type": "MX",
            "ttl": 3600,
            "value": "mail.example.com.",
            "priority": 10,
            "weight": None,
            "port": None,
        },
    ]
    external_recs = [
        {
            "name": "www",
            "type": "A",
            "ttl": 300,
            "value": "203.0.113.10",
            "priority": None,
            "weight": None,
            "port": None,
        },
        {
            "name": "@",
            "type": "MX",
            "ttl": 3600,
            "value": "mail.example.com.",
            "priority": 10,
            "weight": None,
            "port": None,
        },
    ]
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
                "recursion": False,
                "order": 1,
            },
        ],
        "zones": [
            _zone("example.com.", "internal", internal_recs),
            _zone("example.com.", "external", external_recs),
        ],
        "tsig_keys": [],
        "blocklists": [],
    }


def test_render_wraps_zones_in_view_blocks(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_split_horizon_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    # One view block per view, with the right match-clients + recursion.
    assert 'view "internal" {' in conf
    assert 'view "external" {' in conf
    assert "match-clients { 10.0.0.0/8; };" in conf
    # internal recursion yes, external recursion no. Internal (order 0)
    # is emitted before external (order 1), so the internal block is the
    # text between the two view headers.
    internal_block = conf.split('view "internal" {', 1)[1].split(
        'view "external" {', 1
    )[0]
    external_block = conf.split('view "external" {', 1)[1]
    assert "recursion yes;" in internal_block
    assert "recursion no;" in external_block

    # The zone appears inside BOTH view blocks, each pointing at a
    # per-view zone file (no clobber).
    assert "zones/internal/example.com.db" in conf
    assert "zones/external/example.com.db" in conf


def test_per_view_zone_files_hold_view_scoped_records(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_split_horizon_bundle())
    zdir = tmp_path / "rendered.new" / "zones"

    internal_zone = (zdir / "internal" / "example.com.db").read_text()
    external_zone = (zdir / "external" / "example.com.db").read_text()

    # Split horizon: the same name resolves differently per view.
    assert "www 300 IN A 10.0.0.1" in internal_zone
    assert "10.0.0.1" not in external_zone
    assert "www 300 IN A 203.0.113.10" in external_zone
    assert "203.0.113.10" not in internal_zone
    # Shared record present in both.
    assert "mail.example.com." in internal_zone
    assert "mail.example.com." in external_zone


def test_per_view_allow_query_acl_is_enforced(tmp_path: Path) -> None:
    """#430 — a view's allow_query / allow_query_cache render into its block.

    Previously these round-tripped through the API but were never emitted,
    so a view-scoped query ACL silently never took effect."""
    bundle = _split_horizon_bundle()
    # internal: restrict queries to the RFC 1918 client range + cache to it.
    bundle["views"][0]["allow_query"] = ["10.0.0.0/8", "localhost"]
    bundle["views"][0]["allow_query_cache"] = ["10.0.0.0/8"]
    # external: leave both unset → inherit server-options allow-query.
    bundle["views"][1]["allow_query"] = None
    bundle["views"][1]["allow_query_cache"] = None

    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    internal_block = conf.split('view "internal" {', 1)[1].split(
        'view "external" {', 1
    )[0]
    external_block = conf.split('view "external" {', 1)[1]

    assert "allow-query { 10.0.0.0/8; localhost; };" in internal_block
    assert "allow-query-cache { 10.0.0.0/8; };" in internal_block
    # The unset view emits neither line (inherits server options).
    assert "allow-query {" not in external_block
    assert "allow-query-cache {" not in external_block


def test_no_views_keeps_flat_render(tmp_path: Path) -> None:
    # Backward-compat: a bundle with no views renders flat (no view {}
    # blocks, zone file at zones/<name>.db).
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(
        {
            "options": {"recursion_enabled": True, "allow_query": ["any"]},
            "views": [],
            "zones": [
                _zone(
                    "flat.example.",
                    None,
                    [
                        {
                            "name": "a",
                            "type": "A",
                            "ttl": 300,
                            "value": "192.0.2.1",
                            "priority": None,
                            "weight": None,
                            "port": None,
                        }
                    ],
                )
            ],
            "tsig_keys": [],
            "blocklists": [],
        }
    )
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert 'view "' not in conf
    assert 'zone "flat.example." {' in conf
    assert (tmp_path / "rendered.new" / "zones" / "flat.example.db").exists()


def test_global_zone_renders_into_every_view(tmp_path: Path) -> None:
    # A zone with view_name set per the control-plane "global zone →
    # every view" expansion: here we simulate it by emitting the same
    # zone for both views with identical records.
    recs = [
        {
            "name": "shared",
            "type": "A",
            "ttl": 300,
            "value": "198.51.100.5",
            "priority": None,
            "weight": None,
            "port": None,
        }
    ]
    bundle = {
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
        "zones": [
            _zone("global.example.", "internal", recs),
            _zone("global.example.", "external", recs),
        ],
        "tsig_keys": [],
        "blocklists": [],
    }
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(bundle)
    zdir = tmp_path / "rendered.new" / "zones"
    assert (zdir / "internal" / "global.example.db").exists()
    assert (zdir / "external" / "global.example.db").exists()
    for v in ("internal", "external"):
        assert (
            "shared 300 IN A 198.51.100.5"
            in (zdir / v / "global.example.db").read_text()
        )


# ── #920: the control plane's own transfers select a view by key ────────────
#
# BIND picks a view by match-clients BEFORE it consults allow-transfer. The
# operator's client lists never name the control plane, so its signed drift /
# sync transfers either matched no view (answered BADKEY, "the key is
# unknown", for a key that is loaded and granted) or were captured by a broad
# earlier view and read that view's copy. Each view now carries a transfer key
# of its own, which the render admits into that view and refuses everywhere
# else.

_GROUP_KEY = {"name": "spatium-grp", "secret": "Z3JvdXBrZXk=", "algorithm": "hmac-sha256"}


def _keyed_bundle() -> dict:
    """The split-horizon bundle as a #920-aware control plane ships it."""
    bundle = _split_horizon_bundle()
    bundle["tsig_keys"] = [dict(_GROUP_KEY)]
    for view, secret in zip(bundle["views"], ("aW50ZXJuYWw=", "ZXh0ZXJuYWw="), strict=True):
        view["transfer_key"] = {
            "name": f"spatium_xfr_{view['name']}",
            "secret": secret,
            "algorithm": "hmac-sha256",
        }
    return bundle


def _view_block(conf: str, name: str) -> str:
    """The text of one ``view "<name>" { … };`` block."""
    return conf.split(f'view "{name}" {{', 1)[1].split("\n};\n", 1)[0]


def test_each_view_admits_its_own_transfer_key_before_the_operators_clients(
    tmp_path: Path,
) -> None:
    """Own key first, every other view's key refused, then the operator's
    list unchanged. The refusal is what stops ``external`` (``any``) from
    capturing a transfer meant for a later view, or ``internal`` from
    capturing one meant for ``external`` should the api sit in 10/8."""
    Bind9Driver(state_dir=tmp_path).render(_keyed_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    assert (
        'match-clients { key "spatium_xfr_internal"; !key "spatium_xfr_external"; '
        "10.0.0.0/8; };" in _view_block(conf, "internal")
    )
    assert (
        'match-clients { key "spatium_xfr_external"; !key "spatium_xfr_internal"; '
        "any; };" in _view_block(conf, "external")
    )


def test_view_transfer_keys_are_defined_and_granted_but_never_for_updates(
    tmp_path: Path,
) -> None:
    Bind9Driver(state_dir=tmp_path).render(_keyed_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    view_key_file = tmp_path / "tsig" / "view-transfer.key"

    # Defined at global scope, above the first view that names them.
    include = f'include "{view_key_file}";'
    assert include in conf
    assert conf.index(include) < conf.index('view "internal"')
    # Granted transfer — selecting the view is only half of a transfer.
    assert (
        'allow-transfer { key "spatium-grp"; key "spatium_xfr_internal"; '
        'key "spatium_xfr_external"; };' in conf
    )
    # ...and nothing else: no zone lets a view key write.
    for clause in re.findall(r"allow-update \{[^}]*\}", conf):
        assert "spatium_xfr_" not in clause


def test_view_transfer_keys_live_in_their_own_0600_file(tmp_path: Path) -> None:
    """ddns.key's first key is the loopback identity the record-op path and
    the ingest worker sign with, so the view keys never go into it."""
    Bind9Driver(state_dir=tmp_path).render(_keyed_bundle())
    view_key_file = tmp_path / "tsig" / "view-transfer.key"
    ddns_key_file = tmp_path / "tsig" / "ddns.key"

    assert view_key_file.stat().st_mode & 0o777 == 0o600
    text = view_key_file.read_text()
    assert 'key "spatium_xfr_internal" { algorithm hmac-sha256; secret "aW50ZXJuYWw="; };' in text
    assert 'key "spatium_xfr_external" { algorithm hmac-sha256; secret "ZXh0ZXJuYWw="; };' in text
    ddns = ddns_key_file.read_text()
    assert ddns.count("key ") == 1
    assert ddns.startswith('key "spatium-grp"')


def test_a_view_pinned_to_a_destination_admits_its_key_there_too(tmp_path: Path) -> None:
    """A view must match on both lists, and BIND checks match-destinations
    with the request's key as well — so the key goes on both."""
    bundle = _keyed_bundle()
    bundle["views"][0]["match_destinations"] = ["192.0.2.53"]
    Bind9Driver(state_dir=tmp_path).render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    assert 'match-destinations { key "spatium_xfr_internal"; 192.0.2.53; };' in _view_block(
        conf, "internal"
    )
    assert "match-destinations" not in _view_block(conf, "external")


def test_a_bundle_without_view_transfer_keys_renders_exactly_as_before(
    tmp_path: Path,
) -> None:
    """A control plane that predates #920 ships no transfer_key; the render
    must be the pre-#920 render, not a half-keyed one."""
    bundle = _split_horizon_bundle()
    bundle["tsig_keys"] = [dict(_GROUP_KEY)]
    Bind9Driver(state_dir=tmp_path).render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    assert "match-clients { 10.0.0.0/8; };" in conf
    assert "match-clients { any; };" in conf
    assert "view-transfer.key" not in conf
    assert 'allow-transfer { key "spatium-grp"; };' in conf
    assert not (tmp_path / "tsig" / "view-transfer.key").exists()


def test_the_view_key_file_goes_when_the_views_do(tmp_path: Path) -> None:
    """No secret outlives the config that needed it."""
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_keyed_bundle())
    assert (tmp_path / "tsig" / "view-transfer.key").exists()

    flat = _split_horizon_bundle()
    flat["tsig_keys"] = [dict(_GROUP_KEY)]
    flat["views"] = []
    flat["zones"] = [_zone("example.com.", None, [])]
    drv.render(flat)
    assert not (tmp_path / "tsig" / "view-transfer.key").exists()
    assert "view-transfer.key" not in (tmp_path / "rendered.new" / "named.conf").read_text()
