"""#2445 — only a dynamic pool is warned about addresses already in use in
its range; excluded / reserved pools hand out no dynamic leases."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress
from tests.test_dhcp_pool_lease_override_1689 import _setup


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pool_type,expect_warning",
    [("dynamic", True), ("excluded", False), ("reserved", False)],
)
async def test_existing_ips_listed_only_for_dynamic_pool(
    client: AsyncClient, db_session: AsyncSession, pool_type: str, expect_warning: bool
) -> None:
    headers, scope = await _setup(db_session)
    db_session.add(IPAddress(subnet_id=scope.subnet_id, address="10.71.0.12", status="static_dhcp"))
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/pools",
        json={"start_ip": "10.71.0.10", "end_ip": "10.71.0.20", "pool_type": pool_type},
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text
    existing = r.json().get("existing_ips_in_range")
    if expect_warning:
        assert [i["address"] for i in existing] == ["10.71.0.12"]
    else:
        assert not existing


@pytest.mark.asyncio
async def test_update_widening_dynamic_pool_lists_existing_ips_4027(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#4027 — Edit Pool gets the same notice as New Pool."""
    headers, scope = await _setup(db_session)
    db_session.add(IPAddress(subnet_id=scope.subnet_id, address="10.71.0.60", status="reserved"))
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/pools",
        json={"start_ip": "10.71.0.10", "end_ip": "10.71.0.50", "pool_type": "dynamic"},
        headers=headers,
    )
    assert r.status_code in (200, 201), r.text
    pid = r.json()["id"]
    assert not r.json().get("existing_ips_in_range")
    # A rename leaves the range alone: no notice.
    r = await client.put(f"/api/v1/dhcp/pools/{pid}", json={"name": "x"}, headers=headers)
    assert r.status_code == 200, r.text
    assert not r.json().get("existing_ips_in_range")
    # Widening over the reserved address names it.
    r = await client.put(
        f"/api/v1/dhcp/pools/{pid}", json={"end_ip": "10.71.0.70"}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert [i["address"] for i in r.json()["existing_ips_in_range"]] == ["10.71.0.60"]
    # Excluded -> dynamic over it names it too; dynamic -> excluded does not.
    r = await client.put(
        f"/api/v1/dhcp/pools/{pid}", json={"pool_type": "excluded"}, headers=headers
    )
    assert not r.json().get("existing_ips_in_range")
    r = await client.put(
        f"/api/v1/dhcp/pools/{pid}", json={"pool_type": "dynamic"}, headers=headers
    )
    assert [i["address"] for i in r.json()["existing_ips_in_range"]] == ["10.71.0.60"]
