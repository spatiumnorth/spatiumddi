"""Outbound target checks, part two: names and numeric spellings.

The ACME account save, dig's ``@server`` and ping / traceroute / mtr resolve the
host in the backend, refuse a loopback / link-local / metadata answer and hand
the binary the address that was checked. Private ranges stay allowed.
"""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.nettools import runner
from app.services.nettools.runner import NetToolArgError
from tests.test_acme_client import _hdr, _superadmin

_BLOCKED_TEXT = "directory_url must not point at a loopback, link-local or metadata address"


def _patch_resolver(*addrs: str):
    async def fake(host: str) -> list:
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0))
            for a in addrs
        ]

    return patch("app.services.nettools.schemas._getaddrinfo", fake)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host",
    ["localhost", "127.1", "2130706433", "0x7f000001", "ip6-localhost", "[::1]", "127.0.0.1"],
)
async def test_acme_save_refuses_loopback_spellings(
    client: AsyncClient, db_session: AsyncSession, host: str
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    with _patch_resolver("::1"):
        r = await client.put(
            "/api/v1/appliance/acme/account",
            json={"directory_url": f"https://{host}/directory"},
            headers=_hdr(token),
        )
    assert r.status_code == 422, r.text
    assert _BLOCKED_TEXT in r.text


@pytest.mark.asyncio
async def test_acme_save_refuses_name_resolving_to_loopback(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    with _patch_resolver("::1"):
        r = await client.put(
            "/api/v1/appliance/acme/account",
            json={"directory_url": "https://ca.corp.example/directory"},
            headers=_hdr(token),
        )
    assert r.status_code == 422 and _BLOCKED_TEXT in r.text


@pytest.mark.asyncio
async def test_acme_save_accepts_private_https_and_unresolvable_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _superadmin(db_session)
    await db_session.commit()
    r = await client.put(
        "/api/v1/appliance/acme/account",
        json={"directory_url": "https://192.168.122.1:8443/directory"},
        headers=_hdr(token),
    )
    assert r.status_code == 200, r.text

    async def fail(host: str) -> list:
        raise socket.gaierror("no such name")

    with patch("app.services.nettools.schemas._getaddrinfo", fail):
        r = await client.put(
            "/api/v1/appliance/acme/account",
            json={"directory_url": "https://ca.not-resolvable.example/directory"},
            headers=_hdr(token),
        )
    assert r.status_code == 200, r.text


# ── dig @server ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dig_refuses_server_name_resolving_to_loopback() -> None:
    spawn = AsyncMock()
    with (
        _patch_resolver("::1"),
        patch.object(runner.asyncio, "create_subprocess_exec", spawn),
        pytest.raises(NetToolArgError),
    ):
        await runner.run_dig("example.com", "A", "ns.internal.example")
    spawn.assert_not_called()


@pytest.mark.asyncio
async def test_dig_queries_the_checked_address_not_the_name() -> None:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    proc.returncode = 0
    spawn = AsyncMock(return_value=proc)
    with (
        _patch_resolver("10.0.0.53"),
        patch.object(runner.asyncio, "create_subprocess_exec", spawn),
    ):
        res = await runner.run_dig("example.com", "A", "ns.internal.example")
    assert "@10.0.0.53" in res.argv
    assert "@ns.internal.example" not in res.argv
    assert res.argv[-2:] == ["example.com", "A"]


# ── ping / traceroute / mtr ─────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("fn", ["run_ping", "run_traceroute", "run_mtr"])
@pytest.mark.parametrize(
    "host", ["127.0.0.1", "localhost", "127.1", "2130706433", "0x7f000001", "169.254.169.254"]
)
async def test_probe_tools_refuse_loopback_spellings(fn: str, host: str) -> None:
    spawn = AsyncMock()
    with patch.object(runner.asyncio, "create_subprocess_exec", spawn):
        with pytest.raises(NetToolArgError):
            await getattr(runner, fn)(host)
    spawn.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("fn", ["run_ping", "run_traceroute", "run_mtr"])
async def test_probe_tools_refuse_name_resolving_to_loopback(fn: str) -> None:
    spawn = AsyncMock()
    with (
        _patch_resolver("127.0.0.1"),
        patch.object(runner.asyncio, "create_subprocess_exec", spawn),
        pytest.raises(NetToolArgError),
    ):
        await getattr(runner, fn)("router.internal.example")
    spawn.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("fn", ["run_ping", "run_traceroute", "run_mtr"])
async def test_probe_tools_run_against_the_checked_address(fn: str) -> None:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(b"", b""))
    proc.returncode = 0
    spawn = AsyncMock(return_value=proc)
    with (
        _patch_resolver("10.1.2.3"),
        patch.object(runner.asyncio, "create_subprocess_exec", spawn),
    ):
        res = await getattr(runner, fn)("router.internal.example")
    assert res.argv[-1] == "10.1.2.3"
