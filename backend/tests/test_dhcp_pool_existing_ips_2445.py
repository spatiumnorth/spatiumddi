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
