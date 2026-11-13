"""#1766 — catalog zones work on the agent-managed Technitium driver (producer
role), so it claims them and nothing refuses a catalog group. The agentless
``technitium_api`` driver writes no catalog state and stays refused (#1782).
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


def test_capability_flag() -> None:
    assert _caps(TechnitiumDriver)["catalog_zones"] is True
    assert _caps(TechnitiumAPIDriver)["catalog_zones"] is False


@pytest.mark.asyncio
async def test_enabling_catalog_on_technitium_agent_group_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1766a")
    g = await _group(db_session, "t-agent")
    await _server(db_session, g, "ns1", driver="technitium")
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}",
        json={"catalog_zones_enabled": True},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["catalog_zones_enabled"] is True
    assert r.json()["catalog_unsupported_warning"] is None


@pytest.mark.asyncio
async def test_enabling_catalog_on_technitium_api_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1766b")
    g = await _group(db_session, "t-api")
    await _server(db_session, g, "ns1", driver="technitium_api")
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}",
        json={"catalog_zones_enabled": True},
        headers=_auth(token),
    )
    assert r.status_code == 422


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
    await _server(db_session, g, "ns1", driver="technitium_api")
    got = await client.get(f"/api/v1/dns/groups/{g.id}", headers=_auth(token))
    assert "agentless" in got.json()["catalog_unsupported_warning"]
    # Re-saving the already-enabled flag (the UI always sends it) is not a refusal.
    r = await client.put(
        f"/api/v1/dns/groups/{g.id}",
        json={"catalog_zones_enabled": True, "description": "x"},
        headers=_auth(token),
    )
    assert r.status_code == 200
    assert r.json()["catalog_unsupported_warning"]


@pytest.mark.asyncio
async def test_adding_technitium_api_server_to_catalog_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1782d")
    g = await _group(db_session, "cat", catalog_zones_enabled=True)
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "t1", "driver": "technitium_api", "host": "t1", "port": 53},
        headers=_auth(token),
    )
    assert r.status_code == 422
    assert "agentless" in r.json()["detail"] or "experimental" in r.json()["detail"]


@pytest.mark.asyncio
async def test_adding_technitium_agent_server_to_catalog_group_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1766c")
    g = await _group(db_session, "cat-agent", catalog_zones_enabled=True)
    r = await client.post(
        f"/api/v1/dns/groups/{g.id}/servers",
        json={"name": "t1", "driver": "technitium", "host": "t1", "port": 53},
        headers=_auth(token),
    )
    assert r.status_code in (200, 201), r.text


@pytest.mark.asyncio
async def test_moving_technitium_server_into_catalog_group_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1766d")
    src = await _group(db_session, "src")
    dst = await _group(db_session, "dst", catalog_zones_enabled=True)
    srv = await _server(db_session, src, "t1", driver="technitium")
    r = await client.put(
        f"/api/v1/dns/groups/{src.id}/servers/{srv.id}",
        json={"group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_moving_technitium_api_server_into_catalog_group_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1766e")
    src = await _group(db_session, "src2")
    dst = await _group(db_session, "dst2", catalog_zones_enabled=True)
    srv = await _server(db_session, src, "t1", driver="technitium_api")
    r = await client.put(
        f"/api/v1/dns/groups/{src.id}/servers/{srv.id}",
        json={"group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert r.status_code == 422
    assert "agentless" in r.json()["detail"]


@pytest.mark.asyncio
async def test_fleet_assigning_technitium_appliance_to_catalog_group_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from tests.test_dns_server_group_move import _fleet_appliance, _roles_url

    token = await _superadmin(db_session, "root1766f")
    plain = await _group(db_session, "plain")
    cat = await _group(db_session, "catgrp", catalog_zones_enabled=True)
    appliance = await _fleet_appliance(db_session, plain)
    appliance.assigned_roles = ["dns-technitium"]
    await db_session.flush()
    r = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(cat.id)}, headers=_auth(token)
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_copilot_assigning_technitium_appliance_to_catalog_group_is_not_refused(
    db_session: AsyncSession,
) -> None:
    from sqlalchemy import select

    from app.models.auth import User
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _preview_assign_appliance_role,
    )
    from tests.test_dns_server_group_move import _fleet_appliance

    await _superadmin(db_session, "root1766g")
    user = (await db_session.execute(select(User).where(User.username == "root1766g"))).scalar_one()
    plain = await _group(db_session, "plain-g")
    cat = await _group(db_session, "cat-g", catalog_zones_enabled=True)
    appliance = await _fleet_appliance(
        db_session, plain, capabilities={"can_run_dns_technitium": True}
    )
    args = AssignApplianceRoleArgs(
        appliance_id=str(appliance.id), roles=["dns-technitium"], dns_group_id=str(cat.id)
    )
    preview = await _preview_assign_appliance_role(db_session, user, args)
    assert preview.ok, preview.detail
