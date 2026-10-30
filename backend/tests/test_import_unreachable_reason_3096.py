"""An importer that cannot reach its source must say why (#3096).

``str()`` of an httpx timeout is empty, so ``f"Could not reach ...: {exc}"``
ended at the colon and told the operator nothing.
"""

from __future__ import annotations

import httpx
import pytest

from app.services.dns_import import powerdns as pdns
from app.services.dns_import import technitium as tdns
from app.services.dns_import.powerdns import PowerDNSImportError
from app.services.dns_import.technitium import TechnitiumImportError


@pytest.fixture(autouse=True)
def _timeout_with_empty_message(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get(self: httpx.AsyncClient, *a: object, **kw: object) -> httpx.Response:
        raise httpx.ReadTimeout("")

    monkeypatch.setattr(httpx.AsyncClient, "get", _get)


def _assert_reason(msg: str) -> None:
    assert "Could not reach" in msg
    assert not msg.rstrip().endswith(":"), msg
    assert "ReadTimeout" in msg


@pytest.mark.asyncio
async def test_powerdns_pull_gives_a_reason() -> None:
    with pytest.raises(PowerDNSImportError) as ei:
        await pdns.parse_powerdns_server(api_url="http://pdns:8081", api_key="k")
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_powerdns_test_gives_a_reason() -> None:
    with pytest.raises(PowerDNSImportError) as ei:
        await pdns.test_powerdns_connection(api_url="http://pdns:8081", api_key="k")
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_technitium_pull_gives_a_reason() -> None:
    with pytest.raises(TechnitiumImportError) as ei:
        await tdns.parse_technitium_server(api_url="http://t:5380", api_token="k")
    _assert_reason(str(ei.value))


@pytest.mark.asyncio
async def test_technitium_test_gives_a_reason() -> None:
    with pytest.raises(TechnitiumImportError) as ei:
        await tdns.test_technitium_connection(api_url="http://t:5380", api_token="k")
    _assert_reason(str(ei.value))
