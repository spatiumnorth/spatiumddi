"""PowerDNS's ALIAS resolver has no built-in public default (#1353).

The agent used to render ``resolver=1.1.1.1,8.8.8.8`` whenever the control
plane sent no ``alias_resolver``, which it never did, so every PowerDNS server
sent ALIAS targets to Cloudflare and Google. The control plane now sends the
group's plain-DNS forwarders, and with none ALIAS expansion is off.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _safe_alias_resolver


def _lines(conf: str) -> list[str]:
    return conf.splitlines()


def test_no_resolver_by_default(tmp_path: Path) -> None:
    conf = _lines(PowerDNSDriver(state_dir=tmp_path)._render_conf(api_key="k", log_level=4))
    assert "expand-alias=no" in conf
    assert not [line for line in conf if line.startswith("resolver=")]


def test_the_forwarders_become_the_resolver(tmp_path: Path) -> None:
    conf = _lines(
        PowerDNSDriver(state_dir=tmp_path)._render_conf(
            api_key="k", log_level=4, alias_resolver="10.0.0.53,[2001:db8::53]:5353"
        )
    )
    assert "expand-alias=yes" in conf
    assert "resolver=10.0.0.53,[2001:db8::53]:5353" in conf


@pytest.mark.parametrize("value", [None, "", "   ", 42])
def test_absent_or_empty_is_off(value: object) -> None:
    assert _safe_alias_resolver(value) == ""


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.53\nlaunch=bind",  # a newline would start a new pdns.conf directive
        "ns.example.com",
        "10.0.0.53;rm",
    ],
)
def test_anything_but_an_address_list_is_refused(value: str) -> None:
    assert _safe_alias_resolver(value) == ""


def test_an_address_list_passes() -> None:
    assert _safe_alias_resolver(" 10.0.0.53:53,::1 ") == "10.0.0.53:53,::1"
