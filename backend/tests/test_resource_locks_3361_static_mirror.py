"""An edit-locked IP address that mirrors a DHCP reservation also protects it
from the reservation's own edit and delete (#3361)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress
from tests.test_resource_locks_3361 import _ipam, _lock, _user


@pytest.mark.asyncio
async def test_locked_address_blocks_the_reservations_own_edit_and_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    admin = await _user(db_session)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address="10.30.0.50", mac_address="aa:bb:cc:dd:ee:01", hostname="p1"
    )
    db_session.add(st)
    await db_session.flush()
    ip = IPAddress(
        subnet_id=subnet.id,
        address="10.30.0.50",
        status="static_dhcp",
        hostname="p1",
        mac_address="aa:bb:cc:dd:ee:01",
        static_assignment_id=str(st.id),
    )
    db_session.add(ip)
    await db_session.flush()
    st.ip_address_id = ip.id
    st_id, ip_id = st.id, ip.id
    await db_session.commit()

    # A delete lock on the address does not stop a reservation edit.
    assert (await _lock(client, admin, "ip_address", ip_id, "delete")).status_code == 200
    ok = await client.put(f"/api/v1/dhcp/statics/{st_id}", headers=admin, json={"hostname": "p2"})
    assert ok.status_code == 200, ok.text

    # An edit lock does: hostname / MAC / address reach the address row.
    assert (await _lock(client, admin, "ip_address", ip_id, "edit")).status_code == 200
    for body in ({"hostname": "p3"}, {"mac_address": "aa:bb:cc:dd:ee:09"}):
        r = await client.put(f"/api/v1/dhcp/statics/{st_id}", headers=admin, json=body)
        assert r.status_code == 423, body
        detail = r.json()["detail"]
        assert detail["code"] == "resource_locked"
        assert detail["locked_descendants"][0]["resource_id"] == str(ip_id)
    # Annotations the mirror does not carry stay editable.
    ok = await client.put(
        f"/api/v1/dhcp/statics/{st_id}", headers=admin, json={"description": "printer"}
    )
    assert ok.status_code == 200, ok.text
    gone = await client.delete(f"/api/v1/dhcp/statics/{st_id}", headers=admin)
    assert gone.status_code == 423
    assert (
        await db_session.scalar(
            select(DHCPStaticAssignment.id).where(DHCPStaticAssignment.id == st_id)
        )
        is not None
    )
