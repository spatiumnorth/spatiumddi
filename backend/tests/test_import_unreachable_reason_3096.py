"""A source that cannot be reached must say why (#3096).

``str()`` of an httpx timeout is empty, so ``f"Could not reach ...: {exc}"``
ended at the colon and told the operator nothing. The integration
test-connection routes were worse: they caught only ``ConnectError``, so a
``ConnectTimeout`` (the firewall case) fell through to ``str(exc)`` and the
whole message was the empty string.

Every case patches ``httpx.AsyncClient.send`` — the one method ``get``,
``post`` and ``request`` all go through — to raise a timeout with no text.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from app.api.v1.docker.router import _probe as docker_probe
from app.api.v1.kubernetes.router import _detect_cidrs, _probe_cluster
from app.api.v1.opnsense.router import _probe as opnsense_probe
from app.api.v1.proxmox.router import _probe as proxmox_probe
from app.api.v1.tailscale.router import _probe as tailscale_probe
from app.api.v1.unifi.router import _probe as unifi_probe
from app.services.dns_import import powerdns as pdns
from app.services.dns_import import technitium as tdns
from app.services.dns_import.powerdns import PowerDNSImportError
from app.services.dns_import.technitium import TechnitiumImportError
from app.services.docker.client import DockerClient, DockerClientError
from app.services.netbird.client import NetbirdClient, NetbirdClientError
from app.services.tailscale.client import TailscaleClient, TailscaleClientError

SECRET = "s3cr3t-token-value"


@pytest.fixture(autouse=True)
def _timeout_with_empty_message(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _send(self: httpx.AsyncClient, request: httpx.Request, **kw: object) -> Any:
        raise httpx.ConnectTimeout("", request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", _send)


def _assert_reason(msg: str) -> None:
    assert msg.strip(), "empty message"
    assert not msg.rstrip().endswith(":"), msg
    assert "ConnectTimeout" in msg, msg
    # the reason is the exception's type, never the request it carried
    assert SECRET not in msg, msg


# ── DNS importers ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_powerdns_pull_gives_a_reason() -> None:
    with pytest.raises(PowerDNSImportError) as ei:
        await pdns.parse_powerdns_server(api_url="http://pdns:8081", api_key=SECRET)
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_powerdns_test_gives_a_reason() -> None:
    with pytest.raises(PowerDNSImportError) as ei:
        await pdns.test_powerdns_connection(api_url="http://pdns:8081", api_key=SECRET)
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_technitium_pull_gives_a_reason() -> None:
    with pytest.raises(TechnitiumImportError) as ei:
        await tdns.parse_technitium_server(api_url="http://t:5380", api_token=SECRET)
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_technitium_test_gives_a_reason() -> None:
    with pytest.raises(TechnitiumImportError) as ei:
        await tdns.test_technitium_connection(api_url="http://t:5380", api_token=SECRET)
    _assert_reason(str(ei.value))


# ── Integration test-connection routes ─────────────────────────────────────

_PROBES: dict[str, Callable[[], Awaitable[Any]]] = {
    "docker": lambda: docker_probe(
        connection_type="tcp",
        endpoint="docker.example:2375",
        ca_bundle_pem="",
        client_cert_pem="",
        client_key_pem="",
    ),
    "kubernetes": lambda: _probe_cluster(
        api_server_url="https://k8s.example:6443", token=SECRET, ca_bundle_pem=""
    ),
    "opnsense": lambda: opnsense_probe(
        host="opn.example",
        port=443,
        verify_tls=False,
        ca_bundle_pem="",
        api_key="k",
        api_secret=SECRET,
    ),
    "proxmox": lambda: proxmox_probe(
        host="pve.example",
        port=8006,
        verify_tls=False,
        ca_bundle_pem="",
        token_id="root@pam!t",
        token_secret=SECRET,
    ),
    "tailscale": lambda: tailscale_probe(tailnet="-", api_key=SECRET),
    "unifi": lambda: unifi_probe(
        mode="local",
        host="unifi.example",
        port=443,
        cloud_host_id=None,
        verify_tls=False,
        ca_bundle_pem="",
        auth_kind="api_key",
        api_key=SECRET,
        username="",
        password="",
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", sorted(_PROBES))
async def test_integration_probe_names_the_timeout(kind: str) -> None:
    result = await _PROBES[kind]()
    assert result.ok is False
    assert result.message.startswith("Could not reach"), result.message
    _assert_reason(result.message)


@pytest.mark.asyncio
async def test_kubernetes_cidr_detection_names_the_timeout() -> None:
    result = await _detect_cidrs(
        api_server_url="https://k8s.example:6443", token=SECRET, ca_bundle_pem=""
    )
    # each per-endpoint probe catches its own error and reports it
    failures = [m for m in result.messages if "failed" in m]
    assert len(failures) == 4, result.messages
    for m in failures:
        _assert_reason(m)


# ── Integration sync clients ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tailscale_client_names_the_timeout() -> None:
    with pytest.raises(TailscaleClientError) as ei:
        async with TailscaleClient(api_key=SECRET) as c:
            await c.list_devices()
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_netbird_client_names_the_timeout() -> None:
    with pytest.raises(NetbirdClientError) as ei:
        async with NetbirdClient(api_key=SECRET, api_url="https://nb.example") as c:
            await c.list_peers()
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_docker_client_names_the_timeout() -> None:
    with pytest.raises(DockerClientError) as ei:
        async with DockerClient(connection_type="tcp", endpoint="docker.example:2375") as c:
            await c.info()
    _assert_reason(str(ei.value))
