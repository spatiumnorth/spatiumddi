"""The DNS daemons say nothing about themselves over CHAOS queries (#2935).

``version.bind CH TXT`` is the first question a DNS fingerprinting scan
asks, and by default BIND9 and PowerDNS answer it with the exact build;
``hostname.bind`` / ``id.server`` name the container. Version and stack
details are for signed-in users only, so both renderers pin the answers to
"none". The strings are answered rather than refused, so the liveness
checks that dig them (the PowerDNS readiness probe and image HEALTHCHECK on
``id.server``, the kind smoke test on ``version.bind``) still get a reply.

Assertions are on the rendered config text, not on a stored option.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


def _named_conf(tmp_path: Path, views: list[dict] | None = None) -> str:
    Bind9Driver(state_dir=tmp_path).render(
        {
            "server": {"name": "s1", "driver": "bind9"},
            "options": {},
            "acls": [],
            "views": views or [],
            "zones": [],
            "blocklists": [],
            "tsig_keys": [],
            "pending_ops": [],
        }
    )
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def _options_block(conf: str) -> str:
    start = conf.index("options {")
    return conf[start : conf.index("\n};", start)]


def test_bind9_options_hide_version_and_hostname(tmp_path: Path) -> None:
    options = _options_block(_named_conf(tmp_path))
    assert '    version "none";' in options
    assert "    hostname none;" in options


def test_bind9_hides_them_with_views_too(tmp_path: Path) -> None:
    """Split-horizon renders zones per view; the identity answers live in
    ``options`` and so cover every view."""
    conf = _named_conf(
        tmp_path,
        views=[{"id": "v1", "name": "internal", "match_clients": ["10.0.0.0/8"]}],
    )
    assert '    version "none";' in _options_block(conf)


def test_pdns_conf_hides_version_and_server_id(tmp_path: Path) -> None:
    for alias_resolver in ("", "192.0.2.53"):
        lines = (
            PowerDNSDriver(state_dir=tmp_path)
            ._render_conf(api_key="k", log_level=4, alias_resolver=alias_resolver)
            .splitlines()
        )
        assert "version-string=none" in lines
        assert "server-id=none" in lines
