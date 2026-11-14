"""A caller whose only grant is read on NAT mappings sees no subnet detail.

Every route that returns mappings (list, get, by-ip, by-subnet) leaves the
internal subnet's name and network out, and says the subnet was withheld.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, NATMapping
from tests.test_nat_mapping import _make_subnet, _user_with


@pytest.mark.asyncio
async def test_nat_only_reader_gets_no_subnet_detail_on_any_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    sub = await _make_subnet(db_session)
    ip = IPAddress(subnet_id=sub.id, address="10.10.0.5", status="allocated")
    db_session.add(ip)
    await db_session.flush()
    m = NATMapping(
        name="hide-scoped",
        kind="hide",
        internal_subnet_id=sub.id,
        internal_ip="10.10.0.5",
        internal_ip_address_id=ip.id,
        external_ip="203.0.113.9",
        protocol="any",
    )
    db_session.add(m)
    nat_only = await _user_with(db_session, [{"action": "read", "resource_type": "nat_mapping"}])
    await db_session.commit()
    h = {"Authorization": f"Bearer {nat_only}"}

    for path in (
        "/api/v1/ipam/nat-mappings",
        f"/api/v1/ipam/nat-mappings/{m.id}",
        f"/api/v1/ipam/nat-mappings/by-ip/{ip.id}",
    ):
        r = await client.get(path, headers=h)
        assert r.status_code == 200, (path, r.text)
        body = r.json()
        rows = body["items"] if isinstance(body, dict) and "items" in body else body
        rows = rows if isinstance(rows, list) else [rows]
        assert len(rows) == 1, path
        assert rows[0]["internal_subnet_name"] is None, path
        assert rows[0]["internal_subnet_cidr"] is None, path
        assert rows[0]["internal_subnet_redacted"] is True, path
        assert "10.10.0.0/24" not in r.text, path

    r = await client.get(f"/api/v1/ipam/nat-mappings/by-subnet/{sub.id}", headers=h)
    assert r.status_code == 403
    assert "10.10.0.0/24" not in r.text
