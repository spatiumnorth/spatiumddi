"""The control-plane pdns.conf preview matches the agent's fixed values (#4604 B7)."""

from __future__ import annotations

from app.drivers.dns.base import ServerOptions
from app.drivers.dns.powerdns import PowerDNSDriver, render_pdns_conf


def _lines(**kw: object) -> list[str]:
    return render_pdns_conf(api_key="k", **kw).splitlines()  # type: ignore[arg-type]


def test_preview_fixed_values_match_the_agent() -> None:
    lines = _lines()
    assert "enable-lua-records=yes" in lines
    assert "local-address=0.0.0.0, ::" in lines


def test_preview_expand_alias_follows_the_resolver() -> None:
    assert "expand-alias=no" in _lines()
    lines = _lines(alias_resolver="10.0.0.53")
    assert "expand-alias=yes" in lines
    assert "resolver=10.0.0.53" in lines


def test_preview_query_logging_follows_the_option() -> None:
    off = PowerDNSDriver().render_server_config(None, ServerOptions()).splitlines()
    assert "log-dns-queries=no" in off
    on = (
        PowerDNSDriver()
        .render_server_config(None, ServerOptions(query_log_enabled=True))
        .splitlines()
    )
    assert "log-dns-queries=yes" in on
    assert "log-dns-details=yes" in on
    assert "loglevel=6" in on


def test_preview_resolver_comes_from_the_groups_forwarders() -> None:
    lines = (
        PowerDNSDriver()
        .render_server_config(None, ServerOptions(forwarders=("192.0.2.53",)))
        .splitlines()
    )
    assert "resolver=192.0.2.53" in lines
