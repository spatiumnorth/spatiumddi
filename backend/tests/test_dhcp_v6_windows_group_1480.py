"""A DHCPv6 scope and a Windows DHCP server don't share a group (#1480).

The Windows write path speaks DHCPv4 only: ``Add-/Set-DhcpServerv4Scope`` and
``Set-DhcpServerv4OptionValue``, given the scope's network and mask. A v6
scope on a group with a Windows member was accepted and then handed to v4
cmdlets: a 502, or a scope that existed in SpatiumDDI and on no server.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _v6_subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    net = f"2001:db8:{uuid.uuid4().int % 9000 + 1000:x}::/64"
    block = IPBlock(space_id=space.id, network=net, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=net, name="s")
    db.add(subnet)
    await db.flush()
    return subnet


def _server(group: DHCPServerGroup, driver: str) -> DHCPServer:
    return DHCPServer(
        name=f"{driver}-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host="192.0.2.70",
        port=67,
        server_group_id=group.id,
    )


@pytest.mark.asyncio
async def test_a_v6_scope_is_refused_on_a_group_with_a_windows_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet = await _v6_subnet(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    db_session.add(_server(grp, "windows_dhcp"))
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes", headers=h, json={"group_id": str(grp.id)}
    )

    assert r.status_code == 422, r.text
    assert "DHCPv4 only" in r.json()["detail"]


@pytest.mark.asyncio
async def test_a_v6_scope_on_a_kea_group_is_still_fine(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet = await _v6_subnet(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    db_session.add(_server(grp, "kea"))
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes", headers=h, json={"group_id": str(grp.id)}
    )

    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_a_windows_server_cannot_join_a_group_with_v6_scopes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    subnet = await _v6_subnet(db_session)
    target = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    home = DHCPServerGroup(name=f"h-{uuid.uuid4().hex[:6]}")
    db_session.add_all([target, home])
    await db_session.flush()
    db_session.add(
        DHCPScope(group_id=target.id, subnet_id=subnet.id, name="v6", address_family="ipv6")
    )
    server = _server(home, "windows_dhcp")
    db_session.add(server)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/servers/{server.id}", headers=h, json={"server_group_id": str(target.id)}
    )

    assert r.status_code == 422, r.text
    assert "DHCPv6 scopes" in r.json()["detail"]
