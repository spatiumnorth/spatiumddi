"""pdns.conf ``local-address`` must cover IPv6 where the host has it (#2307).

Setting ``local-address`` replaces pdns's default (which includes ``::``), so
a bare ``0.0.0.0`` left IPv6 clients with no answer while BIND9 groups
(``listen-on-v6 { any; }``) answered. Where AF_INET6 does not exist at all
(kernel ``ipv6.disable=1``) pdns aborts on a ``::`` entry, so the line must
fall back to IPv4 only — BIND skips the v6 listener there and carries on.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


def _local_address(tmp_path: Path) -> list[str]:
    PowerDNSDriver(state_dir=tmp_path).render({"options": {}, "zones": []})
    conf = (tmp_path / "rendered.new" / "pdns.conf").read_text()
    lines = [ln for ln in conf.splitlines() if ln.startswith("local-address=")]
    assert len(lines) == 1
    return [a.strip() for a in lines[0].split("=", 1)[1].split(",")]


def _fake_socket(v6: bool):
    real = socket.socket

    def factory(family=socket.AF_INET, *args, **kwargs):
        if family == socket.AF_INET6 and not v6:
            raise OSError(97, "Address family not supported by protocol")
        return real(family, *args, **kwargs)

    return factory


def test_listens_on_both_families_when_ipv6_is_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(socket, "socket", _fake_socket(True))
    assert _local_address(tmp_path) == ["0.0.0.0", "::"]


def test_falls_back_to_ipv4_only_without_an_ipv6_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(socket, "socket", _fake_socket(False))
    assert _local_address(tmp_path) == ["0.0.0.0"]
