"""The BIND9 agent renders the group-level ``allow-query-cache`` (#2264).

Only the per-view override was rendered, so narrowing cache access on the
group (cache snooping) never reached named. Assertions are on the rendered
``named.conf``.
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


def test_set_value_renders_inside_options(tmp_path: Path) -> None:
    conf = _conf(tmp_path, {"allow_query_cache": ["10.0.0.0/8", "localhost"]})
    assert "allow-query-cache { 10.0.0.0/8; localhost; };" in conf
    assert (
        conf.index("options {") < conf.index("allow-query-cache") < conf.index("\n};\n")
    )


def test_unset_renders_nothing_and_is_byte_identical(tmp_path: Path) -> None:
    base = _conf(tmp_path, {"recursion_enabled": True})
    assert "allow-query-cache" not in base
    # The skeleton gained a placeholder; absent must not add a blank line.
    assert "allow-query {" in base
    assert "\n\n    allow-transfer" not in base


def test_undefined_acl_is_dropped_and_empty_fails_closed(tmp_path: Path) -> None:
    conf = _conf(tmp_path, {"allow_query_cache": ["ghost-acl"]})
    assert "allow-query-cache { none; };" in conf
    conf = _conf(
        tmp_path, {"allow_query_cache": ["lan", "ghost-acl"]}, acls=[{"name": "lan"}]
    )
    assert "allow-query-cache { lan; };" in conf
