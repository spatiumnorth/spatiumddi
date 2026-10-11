"""#1782 — Technitium catalog zones are broken in both roles, so they are
not claimed: capability false, enabling refused (422), existing groups warned.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.technitium import TechnitiumDriver
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from tests.test_dns_server_group_move import _auth, _group, _server, _superadmin


def _caps(cls: type) -> dict:
    return cls().capabilities()


def test_capability_flag_is_false() -> None:
    assert _caps(TechnitiumDriver)["catalog_zones"] is False
    assert _caps(TechnitiumAPIDriver)["catalog_zones"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["technitium", "technitium_api"])
async def test_enabling_catalog_on_technitium_group_is_422(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    token = await _superadmin(db_session, f"root1782{driver}")
    g = await _group(db_session, f"t-{driver}")
    await _server(db_session, g, "ns1", driver=driver)
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}",
        json={"catalog_zones_enabled": True},
        headers=_auth(token),
    )
    assert r.status_code == 422
    assert "#1766" in r.json()["detail"]


@pytest.mark.asyncio
async def test_enabling_catalog_on_bind9_group_still_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1782b")
    g = await _group(db_session, "b")
    await _server(db_session, g, "ns1", driver="bind9")
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}",
        json={"catalog_zones_enabled": True},
        headers=_auth(token),
    )
    assert r.status_code == 200
    assert r.json()["catalog_zones_enabled"] is True
    assert r.json()["catalog_unsupported_warning"] is None


@pytest.mark.asyncio
async def test_existing_enabled_group_warns_and_can_still_be_saved(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1782c")
    g = await _group(db_session, "legacy", catalog_zones_enabled=True)
    await _server(db_session, g, "ns1", driver="technitium")
    got = await client.get(f"/api/v1/dns/groups/{g.id}", headers=_auth(token))
    assert "#1766" in got.json()["catalog_unsupported_warning"]
    # Re-saving the already-enabled flag (the UI always sends it) is not a refusal.
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}",
        json={"catalog_zones_enabled": True, "description": "x"},
        headers=_auth(token),
    )
    assert r.status_code == 200
    assert r.json()["catalog_unsupported_warning"]


@pytest.mark.asyncio
async def test_adding_technitium_server_to_catalog_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1782d")
    g = await _group(db_session, "cat", catalog_zones_enabled=True)
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "t1", "driver": "technitium", "host": "t1", "port": 53},
        headers=_auth(token),
    )
    assert r.status_code == 422
    assert "#1766" in r.json()["detail"]
