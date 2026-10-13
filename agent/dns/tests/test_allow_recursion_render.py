"""The BIND9 agent renders ``allow-recursion`` (#1786).

The group's ``allow_recursion`` was stored and shipped but never written to
``named.conf``, so BIND always ran its built-in ``localnets; localhost;``.
Assertions are on the rendered ``named.conf`` text, not the stored option.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.bind9 import Bind9Driver


def _conf(
    tmp_path: Path, options: dict[str, Any], acls: list[dict] | None = None
) -> str:
    Bind9Driver(state_dir=tmp_path).render(
        {
            "server": {"name": "s1", "driver": "bind9"},
            "options": options,
            "acls": acls or [],
            "views": [],
            "zones": [],
            "blocklists": [],
            "tsig_keys": [],
            "pending_ops": [],
        }
    )
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_explicit_list_is_rendered_inside_options(tmp_path: Path) -> None:
    conf = _conf(
        tmp_path, {"allow_recursion": ["10.0.0.0/8", "!10.9.0.0/16", "localhost"]}
    )
    assert "allow-recursion { 10.0.0.0/8; !10.9.0.0/16; localhost; };" in conf
    assert conf.index("options {") < conf.index("allow-recursion")


def test_stored_default_any_is_treated_as_unset(tmp_path: Path) -> None:
    """Omitted, BIND derives allow-recursion from the rendered allow-query.

    That is what every group got before #1786. A literal ``any`` would widen
    recursion past a restricted ``allow-query``.
    """
    for stored in (["any"], ["ANY"], [], None):
        assert "allow-recursion" not in _conf(tmp_path, {"allow_recursion": stored})


def test_not_rendered_when_recursion_is_off(tmp_path: Path) -> None:
    conf = _conf(
        tmp_path, {"recursion_enabled": False, "allow_recursion": ["10.0.0.0/8"]}
    )
    assert "recursion no;" in conf
    assert "allow-recursion" not in conf


def test_widening_needs_an_explicit_value(tmp_path: Path) -> None:
    conf = _conf(tmp_path, {"allow_recursion": ["0.0.0.0/0", "::/0"]})
    assert "allow-recursion { 0.0.0.0/0; ::/0; };" in conf


def test_none_literal_renders(tmp_path: Path) -> None:
    assert "allow-recursion { none; };" in _conf(
        tmp_path, {"allow_recursion": ["none"]}
    )


def test_named_acl_is_defined_above_options(tmp_path: Path) -> None:
    acl = {
        "id": "o",
        "name": "office",
        "entries": [{"value": "10.0.0.0/8", "negate": False}],
    }
    conf = _conf(tmp_path, {"allow_recursion": ["office"]}, [acl])
    assert "allow-recursion { office; };" in conf
    assert conf.index('acl "office"') < conf.index("options {")


def test_malformed_entry_never_reaches_named_conf(tmp_path: Path) -> None:
    conf = _conf(
        tmp_path, {"allow_recursion": ["10.0.0.0/8", "any; }; include /etc/x"]}
    )
    assert "allow-recursion { 10.0.0.0/8; };" in conf
    assert "include /etc/x" not in conf


def test_nothing_usable_fails_closed(tmp_path: Path) -> None:
    """Omitting the line would inherit ``allow-query { any; }``: open."""
    for stored in (["a b; c"], ["10.0.0.0/33"], ["deleted_acl"]):
        conf = _conf(tmp_path, {"allow_recursion": stored})
        assert "allow-recursion { none; };" in conf, stored


def test_undefined_acl_name_is_dropped(tmp_path: Path) -> None:
    """An ACL deleted since it was stored would be an undefined symbol."""
    acl = {"id": "o", "name": "office", "entries": [{"value": "10.0.0.0/8"}]}
    conf = _conf(tmp_path, {"allow_recursion": ["office", "gone"]}, [acl])
    assert "allow-recursion { office; };" in conf


def test_key_and_ipv6_and_negation_pass(tmp_path: Path) -> None:
    conf = _conf(
        tmp_path,
        {"allow_recursion": ["!2001:db8:1::/48", "2001:db8::/32", "key k1", "::1"]},
    )
    assert "allow-recursion { !2001:db8:1::/48; 2001:db8::/32; key k1; ::1; };" in conf
