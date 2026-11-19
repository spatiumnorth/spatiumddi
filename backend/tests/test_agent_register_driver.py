"""Agent registration rejects drivers no agent can serve (#1567).

``POST /dns/agents/register`` and ``POST /dhcp/agents/register`` used to
accept ``driver`` as a free-form string and write it on create and on
every re-registration. A mistyped ``AGENT_DRIVER`` registered an
``active`` server row before the agent crash-looped on ``Unknown
driver``, and a PSK holder could register a row as an *agentless*
driver (``windows_dns``, a cloud provider, ``fortigate`` …) that
bundle construction, health checks and record-op routing branch on.
The register schemas now validate against the agent-capable set only:
bind9 / powerdns / technitium for DNS, kea for DHCP.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from pydantic import ValidationError

from app.api.v1.dhcp.agents import AgentRegisterRequest as DHCPRegisterRequest
from app.api.v1.dns.agents import AgentRegisterRequestV2 as DNSRegisterRequest


@pytest.mark.parametrize("driver", ["bind9", "powerdns", "technitium"])
def test_dns_register_accepts_agent_capable_drivers(driver: str) -> None:
    body = DNSRegisterRequest(hostname="ns1", driver=driver, fingerprint="f1")
    assert body.driver == driver


def test_dns_register_defaults_to_bind9() -> None:
    body = DNSRegisterRequest(hostname="ns1", fingerprint="f1")
    assert body.driver == "bind9"


@pytest.mark.parametrize(
    "driver",
    [
        "windows_dns",  # agentless (WinRM / RFC 2136 from the control plane)
        "technitium_api",  # agentless Technitium — distinct from `technitium`
        "cloudflare",  # agentless cloud provider
        "route53",
        "bind",  # typo of bind9
        "knot",
        "",
    ],
)
def test_dns_register_rejects_non_agent_drivers(driver: str) -> None:
    with pytest.raises(ValidationError):
        DNSRegisterRequest(hostname="ns1", driver=driver, fingerprint="f1")


def test_dhcp_register_accepts_kea() -> None:
    body = DHCPRegisterRequest(hostname="dhcp1", driver="kea", fingerprint="f1")
    assert body.driver == "kea"


def test_dhcp_register_defaults_to_kea() -> None:
    body = DHCPRegisterRequest(hostname="dhcp1", fingerprint="f1")
    assert body.driver == "kea"


@pytest.mark.parametrize(
    "driver",
    [
        "windows_dhcp",  # agentless
        "fortigate",  # agentless cloud/REST
        "isc-dhcp",  # typo / unsupported
        "bind9",  # a DNS driver is not a DHCP agent driver
        "",
    ],
)
def test_dhcp_register_rejects_non_agent_drivers(driver: str) -> None:
    with pytest.raises(ValidationError):
        DHCPRegisterRequest(hostname="dhcp1", driver=driver, fingerprint="f1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "header", "env_var", "driver"),
    [
        ("/api/v1/dns/agents/register", "X-DNS-Agent-Key", "DNS_AGENT_KEY", "windows_dns"),
        ("/api/v1/dhcp/agents/register", "X-DHCP-Agent-Key", "DHCP_AGENT_KEY", "fortigate"),
    ],
)
async def test_register_endpoint_422s_on_agentless_driver(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    header: str,
    env_var: str,
    driver: str,
) -> None:
    # A valid PSK gets past the bootstrap gate; the bogus driver must
    # then fail schema validation (422) instead of writing a server row.
    monkeypatch.setenv(env_var, "expected-key")
    resp = await client.post(
        path,
        headers={header: "expected-key"},
        json={"hostname": "h1", "fingerprint": "f1", "driver": driver},
    )
    assert resp.status_code == 422, resp.text
