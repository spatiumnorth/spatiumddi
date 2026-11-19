"""#2500 — pool start/end must be valid IPs, ordered, and inside the scope's subnet."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPool, DHCPScope
from tests.test_dhcp_static_in_pool import _admin, _scope_with_dynamic_pool  # subnet 10.70.0.0/24


def _post(client: AsyncClient, h: dict, scope: DHCPScope, **body):
    return client.post(f"/api/v1/dhcp/scopes/{scope.id}/pools", headers=h, json=body)


@pytest.mark.asyncio
@pytest.mark.parametrize("pool_type", ["dynamic", "reserved", "excluded"])
async def test_range_outside_subnet_is_422(
    client: AsyncClient, db_session: AsyncSession, pool_type: str
) -> None:
    h = await _admin(db_session)
    _, scope = await _scope_with_dynamic_pool(db_session)
    r = await _post(
        client,
        h,
        scope,
        name="stray",
        start_ip="10.9.9.10",
        end_ip="10.9.9.20",
        pool_type=pool_type,
    )
    assert r.status_code == 422, r.text
    assert "10.70.0.0/24" in r.text
    # Straddling the boundary is also refused.
    r = await _post(client, h, scope, name="x", start_ip="10.70.0.200", end_ip="10.70.1.5")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_malformed_ip_is_422_not_500(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    _, scope = await _scope_with_dynamic_pool(db_session)
    r = await _post(client, h, scope, name="bad", start_ip="nope", end_ip="also-nope")
    assert r.status_code == 422
    r = await _post(client, h, scope, name="bad", start_ip="10.70.0.5", end_ip="10.70.0.300")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_wrong_family_and_reversed_range_are_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    _, scope = await _scope_with_dynamic_pool(db_session)
    r = await _post(client, h, scope, name="v6", start_ip="2001:db8::10", end_ip="2001:db8::20")
    assert r.status_code == 422
    r = await _post(client, h, scope, name="rev", start_ip="10.70.0.60", end_ip="10.70.0.50")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_valid_pool_still_created(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    _, scope = await _scope_with_dynamic_pool(db_session)
    r = await _post(client, h, scope, name="ok", start_ip="10.70.0.10", end_ip="10.70.0.20")
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_update_checks_merged_range(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    _, scope = await _scope_with_dynamic_pool(db_session)
    # Existing pool is 10.70.0.100-150: moving only the end below the start,
    # or out of the subnet, is judged against the stored other half.
    from sqlalchemy import select

    pool = (
        await db_session.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id))
    ).scalar_one()
    url = f"/api/v1/dhcp/pools/{pool.id}"
    assert (await client.put(url, headers=h, json={"end_ip": "10.70.0.50"})).status_code == 422
    assert (await client.put(url, headers=h, json={"end_ip": "10.71.0.1"})).status_code == 422
    assert (await client.put(url, headers=h, json={"start_ip": "zzz"})).status_code == 422
    r = await client.put(url, headers=h, json={"end_ip": "10.70.0.160"})
    assert r.status_code == 200, r.text
    assert r.json()["end_ip"] == "10.70.0.160"


@pytest.mark.asyncio
async def test_rename_of_legacy_out_of_subnet_pool_not_blocked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A row an importer / Windows pull stored is not locked out of unrelated edits."""
    h = await _admin(db_session)
    _, scope = await _scope_with_dynamic_pool(db_session)
    legacy = DHCPPool(
        scope_id=scope.id,
        name="old",
        start_ip="10.99.0.1",
        end_ip="10.99.0.9",
        pool_type="excluded",
    )
    db_session.add(legacy)
    await db_session.commit()
    r = await client.put(f"/api/v1/dhcp/pools/{legacy.id}", headers=h, json={"name": "renamed"})
    assert r.status_code == 200, r.text
