"""Record ops applied into the view they name (#2242, slice 4).

Under split-horizon an RFC 2136 update to loopback lands in whichever view
matches ``127.0.0.1``. The control plane now ships a view's ops to an agent that
says ``per-view-ops``, each naming its view, and the bundle's views carry an
``update_key``. The agent admits that key into exactly its own view
(``match-clients``), grants it ``allow-update`` on that view's copy of each
zone and nowhere else, and signs the op's update (and its SOA reads) with it, so
named routes the update into the right copy.
"""

from __future__ import annotations

import base64
import re
import shutil
from pathlib import Path
from typing import Any

import dns.query
import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _view_share_key
from tests.test_rrset_ops import _FakeDnsResponse, _wire_sections
from tests.test_views_render import _keyed_bundle, _view_block

_UPDATE_SECRETS = {"internal": "aW50ZXJuYWx1cGQ=", "external": "ZXh0ZXJuYWx1cGQ="}


def _bundle(**zone_overrides: Any) -> dict[str, Any]:
    bundle = _keyed_bundle()
    for view in bundle["views"]:
        view["update_key"] = {
            "name": f"spatium_upd_{view['name']}",
            "secret": _UPDATE_SECRETS[view["name"]],
            "algorithm": "hmac-sha256",
        }
    for zone in bundle["zones"]:
        zone.update(zone_overrides)
    return bundle


def _op(view: str | None, value: str = "10.9.9.9") -> dict[str, Any]:
    op: dict[str, Any] = {
        "op_id": "o1",
        "zone_name": "example.com.",
        "op": "create",
        "record": {
            "name": "app",
            "type": "A",
            "value": value,
            "ttl": 300,
            "rrset": {"ttl": 300, "members": [{"value": value}]},
        },
    }
    if view is not None:
        op["view_name"] = view
    return op


def _apply(
    monkeypatch: pytest.MonkeyPatch, drv: Bind9Driver, op: dict[str, Any]
) -> list[Any]:
    sent: list[Any] = []

    def fake_tcp(q: Any, where: str, timeout: float | None = None, **kw: Any) -> Any:
        sent.append(q)
        return _FakeDnsResponse()

    monkeypatch.setattr(dns.query, "tcp", fake_tcp)
    drv.apply_record_op(op)
    return sent


# ── the render ──────────────────────────────────────────────────────────────


def test_each_view_admits_its_own_update_key_and_refuses_the_others(
    tmp_path: Path,
) -> None:
    Bind9Driver(state_dir=tmp_path).render(_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    assert (
        'match-clients { key "spatium_xfr_internal"; key "spatium_upd_internal"; '
        '!key "spatium_xfr_external"; !key "spatium_upd_external"; 10.0.0.0/8; };'
        in _view_block(conf, "internal")
    )
    assert (
        'match-clients { key "spatium_xfr_external"; key "spatium_upd_external"; '
        '!key "spatium_xfr_internal"; !key "spatium_upd_internal"; any; };'
        in _view_block(conf, "external")
    )


def test_the_update_keys_are_defined_in_their_own_0600_file(tmp_path: Path) -> None:
    Bind9Driver(state_dir=tmp_path).render(_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    key_file = tmp_path / "rendered.new" / "tsig" / "view-update.key"

    include = f'include "{tmp_path / "rendered" / "tsig" / "view-update.key"}";'
    assert include in conf and conf.index(include) < conf.index('view "internal"')
    assert key_file.stat().st_mode & 0o777 == 0o600
    text = key_file.read_text()
    assert (
        'key "spatium_upd_internal" { algorithm hmac-sha256; secret "aW50ZXJuYWx1cGQ="; };'
        in text
    )
    # ddns.key keeps the loopback key alone, as before.
    assert (tmp_path / "rendered.new" / "tsig" / "ddns.key").read_text().count(
        "key "
    ) == 1


def test_a_view_update_key_writes_its_own_views_copy_only(tmp_path: Path) -> None:
    Bind9Driver(state_dir=tmp_path).render(_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    inner = _view_block(conf, "internal")
    outer = _view_block(conf, "external")
    assert 'allow-update { key "spatium-grp"; key "spatium_upd_internal"; }' in inner
    assert 'allow-update { key "spatium-grp"; key "spatium_upd_external"; }' in outer
    assert "spatium_upd_external" not in re.sub(r"match-clients \{[^}]*\}", "", inner)
    # Reading and writing stay apart: nothing grants a transfer by an update
    # key, and no zone lets a transfer key write.
    assert "allow-transfer" not in "".join(
        re.findall(r"[^\n]*spatium_upd_[^\n]*", conf)
    ).replace("match-clients", "") or all(
        "spatium_upd_" not in c for c in re.findall(r"allow-transfer \{[^}]*\}", conf)
    )
    for clause in re.findall(r"allow-update \{[^}]*\}", conf):
        assert "spatium_xfr_" not in clause


def test_a_fine_grained_zone_grants_the_update_key_the_soa_too(tmp_path: Path) -> None:
    bundle = _bundle(
        dynamic_update_enabled=True,
        update_acl=[
            {
                "action": "grant",
                "match_kind": "tsig_key",
                "tsig_key_name": "ddns-client",
                "name_scope": "name",
                "name_pattern": "dyn.example.com.",
                "record_types": ["A"],
            }
        ],
    )
    bundle["tsig_keys"].append(
        {"name": "ddns-client", "secret": "Y2xpZW50", "algorithm": "hmac-sha256"}
    )
    Bind9Driver(state_dir=tmp_path).render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()

    assert "grant spatium_upd_internal zonesub ANY;" in _view_block(conf, "internal")
    assert "grant spatium_upd_external" not in _view_block(conf, "internal")


def test_identical_primary_copies_are_not_shared_across_views(tmp_path: Path) -> None:
    """A shared copy would take a view's update for every view (or refuse it:
    the update grant is the defining view's), so with per-view ops each view
    loads its own copy of a primary zone."""
    bundle = _bundle()
    for zone in bundle["zones"]:
        zone["records"] = [dict(r) for r in bundle["zones"][0]["records"]]
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "in-view" not in conf
    assert (
        tmp_path / "rendered.new" / "zones" / "external" / "example.com.db"
    ).exists()

    zone = bundle["zones"][0]
    view = bundle["views"][0]
    assert _view_share_key(zone, view) is not None  # shareable without per-view ops
    assert _view_share_key(zone, view, per_view_updates=True) is None


def test_a_bundle_without_update_keys_renders_as_before(tmp_path: Path) -> None:
    Bind9Driver(state_dir=tmp_path).render(_keyed_bundle())
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "spatium_upd_" not in conf and "view-update.key" not in conf
    assert not (tmp_path / "rendered.new" / "tsig" / "view-update.key").exists()


# ── the op ──────────────────────────────────────────────────────────────────


def test_an_op_is_signed_with_the_key_of_the_view_it_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_bundle())

    for view in ("internal", "external"):
        (msg,) = _apply(monkeypatch, drv, _op(view, f"10.9.9.{len(view)}"))
        assert str(msg.keyname).rstrip(".") == f"spatium_upd_{view}"
        assert _wire_sections(msg)[-1][2] == "A"
        assert msg.keyring.secret == base64.b64decode(_UPDATE_SECRETS[view])


def test_an_op_naming_no_view_or_an_unknown_one_is_refused_not_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_bundle())
    with pytest.raises(RuntimeError, match="names no view"):
        _apply(monkeypatch, drv, _op(None))
    with pytest.raises(RuntimeError, match="no update key for view 'nope'"):
        _apply(monkeypatch, drv, _op("nope"))


def test_a_group_without_views_applies_over_the_loopback_key_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(
        {
            "options": {"recursion_enabled": True},
            "views": [],
            "zones": [
                {
                    "name": "example.com.",
                    "type": "primary",
                    "ttl": 3600,
                    "view_name": None,
                    "records": [],
                }
            ],
            "tsig_keys": [
                {
                    "name": "spatium-grp",
                    "secret": "Z3JvdXBrZXk=",
                    "algorithm": "hmac-sha256",
                    "loopback": True,
                }
            ],
            "blocklists": [],
        }
    )
    # The render is staged; the live tree (where the op path reads the key)
    # appears with the swap.
    shutil.copytree(tmp_path / "rendered.new" / "tsig", tmp_path / "rendered" / "tsig")
    (msg,) = _apply(monkeypatch, drv, _op(None))
    assert str(msg.keyname).rstrip(".") == "spatium-grp"


def test_the_serial_and_apex_reads_follow_the_ops_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SOA read before an op and after it, and the apex NS it reconciles,
    are of THIS view's copy: the same zone differs per view."""
    bundle = _bundle()
    bundle["zones"][0]["records"].append(
        {
            "name": "@",
            "type": "NS",
            "ttl": 3600,
            "value": "ns-in.example.com.",
            "priority": None,
            "weight": None,
            "port": None,
        }
    )
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(bundle)
    inner = drv._apex_state("example.com", "internal")
    outer = drv._apex_state("example.com", "external")
    assert inner is not None and outer is not None
    assert inner["ns"] == ["ns-in.example.com."] and outer["ns"] == []

    reads: list[tuple[str, str | None]] = []

    def soa(zone: str, view: str | None = None) -> tuple[Any, int, int, bool]:
        reads.append(("soa", view))
        return None, 3600, 7, False

    def ns(zone: str, view: str | None = None) -> list[str]:
        reads.append(("ns", view))
        return ["ns-in.example.com."]

    monkeypatch.setattr(drv, "_served_soa", soa)
    monkeypatch.setattr(drv, "_served_apex_ns", ns)
    op = _op("internal", "ns-new.example.com.")
    op["record"].update({"name": "@", "type": "NS"})
    op["target_serial"] = 8
    _apply(monkeypatch, drv, op)

    assert ("ns", "internal") in reads and ("soa", "internal") in reads
    assert all(v == "internal" for _, v in reads)
    # The overlay (what the next render must match) is the internal copy's.
    assert drv._apex_state("example.com", "internal")["ns"] == ["ns-new.example.com."]
    assert drv._apex_state("example.com", "external")["ns"] == []
