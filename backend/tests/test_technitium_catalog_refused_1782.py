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
    detail = r.json()["detail"]
    if driver == "technitium_api":
        # #1784's experimental-scope refusal runs first for the agentless
        # driver; either refusal keeps catalog zones off, which is the point.
        assert "#1766" in detail or "experimental in 1.0" in detail
    else:
        assert "#1766" in detail


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


@pytest.mark.asyncio
async def test_moving_technitium_server_into_catalog_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1782e")
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst", catalog_zones_enabled=True)
    srv = await _server(db_session, src, "t1", driver="technitium")
    r = await client.put(
        f"/api/v1/dns/groups/{src.id}/servers/{srv.id}",
        json={"group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert r.status_code == 422
    assert "#1766" in r.json()["detail"]


@pytest.mark.asyncio
async def test_fleet_assigning_technitium_appliance_to_catalog_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An appliance whose agent has not registered yet has no server row for
    the #934 move to refuse, so the role assignment itself must."""
    from tests.test_dns_server_group_move import _fleet_appliance, _roles_url

    token = await _superadmin(db_session, "root1782f")
    plain = await _group(db_session, "plain")
    cat = await _group(db_session, "catgrp", catalog_zones_enabled=True)
    appliance = await _fleet_appliance(db_session, plain)
    appliance.assigned_roles = ["dns-technitium"]
    await db_session.flush()
    r = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(cat.id)}, headers=_auth(token)
    )
    assert r.status_code == 422, r.text
    assert "#1766" in r.json()["detail"]

    # A pre-existing assignment (legacy) is not refused on a re-save.
    legacy = await _fleet_appliance(db_session, cat)
    legacy.assigned_roles = ["dns-technitium"]
    await db_session.flush()
    r = await client.put(
        _roles_url(legacy.id), json={"dns_group_id": str(cat.id)}, headers=_auth(token)
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_copilot_assigning_technitium_appliance_to_catalog_group_is_refused(
    db_session: AsyncSession,
) -> None:
    from sqlalchemy import select

    from app.models.auth import User
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
        _preview_assign_appliance_role,
    )
    from tests.test_dns_server_group_move import _fleet_appliance

    await _superadmin(db_session, "root1782g")
    user = (await db_session.execute(select(User).where(User.username == "root1782g"))).scalar_one()
    plain = await _group(db_session, "plain-g")
    cat = await _group(db_session, "cat-g", catalog_zones_enabled=True)
    appliance = await _fleet_appliance(db_session, plain)
    args = AssignApplianceRoleArgs(
        appliance_id=str(appliance.id), roles=["dns-technitium"], dns_group_id=str(cat.id)
    )
    preview = await _preview_assign_appliance_role(db_session, user, args)
    assert not preview.ok
    assert "#1766" in preview.detail
    with pytest.raises(ValueError, match="#1766"):
        await _apply_assign_appliance_role(db_session, user, args)
    assert appliance.assigned_dns_group_id == plain.id
