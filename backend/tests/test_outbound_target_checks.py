"""Outbound target checks: ACME client + network tools + nmap targets."""

from __future__ import annotations

import httpx
import pytest

from app.services.acme_client.engine import ACMEClient, ACMEProtocolError, generate_account_key_pem
from app.services.nettools import socket_tools
from app.services.nettools.schemas import is_blocked_target
from app.services.nmap.runner import NmapArgError, _validate_target


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "127.1",
        "2130706433",
        "0x7f000001",
        "127.0.0.1",
        "169.254.169.254",
        "a.localhost",
    ],
)
def test_blocked_spellings(value: str) -> None:
    assert is_blocked_target(value)


@pytest.mark.parametrize("value", ["10.1.2.3", "192.168.0.1", "example.com", "8.8.8.8"])
def test_private_and_public_not_blocked(value: str) -> None:
    assert not is_blocked_target(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "127.1", "2130706433", "0x7f000001"])
async def test_socket_tools_refuse_loopback_names(host: str) -> None:
    res = await socket_tools.test_port(host, 80, "tcp")
    assert res.state == "error" and "blocked" in (res.error or "")
    cert = await socket_tools.inspect_tls_cert(host, 443, host)
    assert not cert.ok and "blocked" in (cert.error or "")


@pytest.mark.parametrize(
    "target", ["127.0.0.1", "169.254.169.254", "localhost", "127.1", "127.0.0.0/24", "0x7f000001"]
)
def test_nmap_refuses_blocked_targets(target: str) -> None:
    with pytest.raises(NmapArgError):
        _validate_target(target)


def test_nmap_allows_private_targets() -> None:
    assert _validate_target("10.0.0.0/24") == "10.0.0.0/24"
    assert _validate_target("192.168.1.5") == "192.168.1.5"


def _client(directory: str = "https://ca.example/dir") -> ACMEClient:
    return ACMEClient(directory, generate_account_key_pem())


@pytest.mark.asyncio
async def test_acme_directory_urls_must_be_https() -> None:
    c = _client()
    c._directory = {"newNonce": "http://ca.example/nonce"}
    with pytest.raises(ACMEProtocolError):
        await c._ensure_nonce()
    await c.aclose()


@pytest.mark.asyncio
async def test_acme_error_body_from_non_acme_host_is_not_quoted() -> None:
    c = _client()
    c._nonce = "n"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="SECRET-INTERNAL-BODY")

    c._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ACMEProtocolError) as ei:
        await c._post("https://ca.example/acct", {})
    assert "SECRET-INTERNAL-BODY" not in str(ei.value)
    await c.aclose()


@pytest.mark.asyncio
async def test_acme_client_refuses_loopback_directory() -> None:
    c = _client("https://127.0.0.1/dir")
    with pytest.raises(Exception) as ei:
        await c._get_directory()
    assert ei.type.__name__ in ("SSRFBlockedError", "ConnectError")
    await c.aclose()
