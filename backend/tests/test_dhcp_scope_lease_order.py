"""#2499 — scope lease_time / min / max must be ordered, on create and update."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_dhcp_scope_sync_mode import _create, _make_token, _subnet_and_group


@pytest.mark.asyncio
async def test_create_out_of_order_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    h = {"Authorization": f"Bearer {await _make_token(db_session)}"}
    subnet, grp = await _subnet_and_group(db_session)
    url = f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes"
    for extra, field in [
        ({"lease_time": 100, "min_lease_time": 200, "max_lease_time": 300}, "min_lease_time"),
        ({"lease_time": 400, "max_lease_time": 300}, "max_lease_time"),
        ({"lease_time": 0}, "lease_time"),
    ]:
        r = await client.post(url, headers=h, json={"group_id": str(grp.id), "name": "s", **extra})
        assert r.status_code == 422, extra
        assert field in r.text


@pytest.mark.asyncio
async def test_create_in_order_ok(client: AsyncClient, db_session: AsyncSession) -> None:
    h = {"Authorization": f"Bearer {await _make_token(db_session)}"}
    subnet, grp = await _subnet_and_group(db_session)
    body = await _create(
        client, h, subnet, grp, lease_time=200, min_lease_time=100, max_lease_time=300
    )
    assert body["lease_time"] == 200


@pytest.mark.asyncio
async def test_update_checks_merged_values(client: AsyncClient, db_session: AsyncSession) -> None:
    h = {"Authorization": f"Bearer {await _make_token(db_session)}"}
    subnet, grp = await _subnet_and_group(db_session)
    body = await _create(client, h, subnet, grp, lease_time=100)
    url = f"/api/v1/dhcp/scopes/{body['id']}"
    r = await client.put(url, headers=h, json={"max_lease_time": 50})
    assert r.status_code == 422
    assert "max_lease_time" in r.text
    # Stored row unchanged, and an unrelated edit still works.
    r = await client.put(url, headers=h, json={"name": "renamed"})
    assert r.status_code == 200
    assert r.json()["max_lease_time"] is None
    # Valid patch merges fine; then lowering lease below the stored min fails.
    r = await client.put(url, headers=h, json={"min_lease_time": 60, "max_lease_time": 500})
    assert r.status_code == 200
    r = await client.put(url, headers=h, json={"lease_time": 30})
    assert r.status_code == 422
    # Clearing min/max with explicit nulls is allowed.
    r = await client.put(url, headers=h, json={"min_lease_time": None, "max_lease_time": None})
    assert r.status_code == 200
