"""PROXY protocol between the dnsdist front and pdns (#4576).

Behind the front every query came from the front's address, so ``allow-axfr``
and ``ALLOW-DNSUPDATE-FROM`` never matched a real client and the query log
named the front. pdns must trust a PROXY header from the front only, and the
front must send it only when pdns is told to expect it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver

ENTRYPOINT = Path(__file__).resolve().parents[1] / "images" / "dnsdist" / "entrypoint.sh"


def _conf(tmp_path: Path) -> str:
    return PowerDNSDriver(state_dir=tmp_path)._render_conf(api_key="k", log_level=4)


def test_proxy_protocol_off_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PDNS_PROXY_PROTOCOL_FROM", raising=False)
    assert "proxy-protocol-from" not in _conf(tmp_path)


def test_proxy_protocol_from_front_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDNS_PROXY_PROTOCOL_FROM", "172.18.0.0/16, 10.1.2.3")
    assert "proxy-protocol-from=172.18.0.0/16,10.1.2.3\n" in _conf(tmp_path) + "\n"


def test_proxy_protocol_unresolvable_host_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(*_a: object, **_k: object) -> None:
        raise OSError("no such host")

    monkeypatch.setattr("spatium_dns_agent.drivers.powerdns.socket.getaddrinfo", _fail)
    monkeypatch.setenv("PDNS_PROXY_PROTOCOL_FROM", "no-such-front.invalid")
    assert "proxy-protocol-from" not in _conf(tmp_path)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
@pytest.mark.parametrize("flag,expected", [("1", True), ("0", False), ("", False)])
def test_dnsdist_front_sends_proxy_protocol_only_when_enabled(
    tmp_path: Path, flag: str, expected: bool
) -> None:
    # Source the entrypoint's functions without running its supervise loop.
    src = ENTRYPOINT.read_text().split("trap 'stop_dnsdist")[0]
    out = tmp_path / "dnsdist.conf"
    script = tmp_path / "t.sh"
    script.write_text(src + '\nbuild_conf "10.0.0.5:53"\n')
    env = {
        **os.environ,
        "DNSDIST_PROXY_PROTOCOL": flag,
        "DNSDIST_CONF": str(out),
        "DNSDIST_RULES_FILE": str(tmp_path / "none"),
    }
    subprocess.run(["bash", str(script)], check=True, env=env)
    conf = out.read_text()
    assert ("useProxyProtocol=true" in conf) is expected
    # Quieter health check, never the 1 s default (#4576).
    assert "checkInterval=5" in conf
    assert 'checkName="spatium-healthcheck.invalid."' in conf
