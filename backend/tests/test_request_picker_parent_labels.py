"""The request portal pickers show a parent's name only to a user who can
read that parent.

A zone option is labelled with its view's name and a scope option with its
subnet's network. A caller holding read on just the zone (or scope) is shown
the option, but the view / subnet text comes from an object their grants do
not cover, so it is omitted for them.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.dns import DNSServerGroup, DNSView, DNSZone
from tests.test_request_resource_picker import (
    REQUESTER_PERMS,
    _auth,
    _enable_module,
    _subnets,
    _user,
)

URL = "/api/v1/requests/resource-options"


async def _zone(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone]:
    g = DNSServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    v = DNSView(group_id=g.id, name="inside-view")
    db.add(v)
    await db.flush()
    z = DNSZone(group_id=g.id, view_id=v.id, name="corp.example.test.", zone_type="primary")
    db.add(z)
    await db.flush()
    return g, z


async def _scope(db: AsyncSession, name: str = "office") -> tuple[object, DHCPScope]:
    (sub,) = await _subnets(db, ["10.77.0.0/24"])
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    sc = DHCPScope(subnet_id=sub.id, group_id=grp.id, name=name, is_active=True)
    db.add(sc)
    await db.flush()
    return sub, sc


async def _options(client: AsyncClient, token: str, resource: str, **params: str) -> list[dict]:
    resp = await client.get(URL, headers=_auth(token), params={"resource": resource, **params})
    assert resp.status_code == 200
    return resp.json()["options"]


@pytest.mark.asyncio
async def test_zone_option_omits_view_name_without_group_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    _, z = await _zone(db_session)
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [{"action": "read", "resource_type": "dns_zone", "resource_id": str(z.id)}],
    )
    await db_session.commit()
    opts = await _options(client, token, "dns_zone")
    assert [o["id"] for o in opts] == [str(z.id)]
    assert opts[0]["label"] == "corp.example.test."
    assert not opts[0]["sublabel"]


@pytest.mark.asyncio
async def test_zone_option_shows_view_name_with_group_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    _, z = await _zone(db_session)
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [
            {"action": "read", "resource_type": "dns_zone", "resource_id": str(z.id)},
            {"action": "read", "resource_type": "dns_group"},
        ],
    )
    await db_session.commit()
    opts = await _options(client, token, "dns_zone")
    assert opts[0]["sublabel"] == "inside-view"


@pytest.mark.asyncio
async def test_scope_option_omits_network_without_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    _, sc = await _scope(db_session)
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [{"action": "read", "resource_type": "dhcp_scope", "resource_id": str(sc.id)}],
    )
    await db_session.commit()
    opts = await _options(client, token, "dhcp_scope")
    assert [o["id"] for o in opts] == [str(sc.id)]
    assert opts[0]["label"] == "office"
    assert not opts[0]["sublabel"]
    # Searching by the network text must not match through the hidden subnet.
    assert await _options(client, token, "dhcp_scope", q="10.77") == []


@pytest.mark.asyncio
async def test_unnamed_scope_label_does_not_carry_the_network(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    _, sc = await _scope(db_session, name="")
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "dhcp_scope"}],
    )
    await db_session.commit()
    opts = await _options(client, token, "dhcp_scope")
    assert "10.77" not in opts[0]["label"]
    assert not opts[0]["sublabel"]


@pytest.mark.asyncio
async def test_scope_option_shows_network_with_scoped_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    sub, sc = await _scope(db_session)
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [
            {"action": "read", "resource_type": "dhcp_scope", "resource_id": str(sc.id)},
            {"action": "read", "resource_type": "subnet", "resource_id": str(sub.id)},
        ],
    )
    await db_session.commit()
    opts = await _options(client, token, "dhcp_scope")
    assert opts[0]["sublabel"] == "10.77.0.0/24"
    assert [o["id"] for o in await _options(client, token, "dhcp_scope", q="10.77")] == [str(sc.id)]


@pytest.mark.asyncio
async def test_superadmin_sees_parent_names(client: AsyncClient, db_session: AsyncSession) -> None:
    await _enable_module(db_session)
    await _zone(db_session)
    await _scope(db_session)
    _, token = await _user(db_session, superadmin=True)
    await db_session.commit()
    assert (await _options(client, token, "dns_zone"))[0]["sublabel"] == "inside-view"
    assert (await _options(client, token, "dhcp_scope"))[0]["sublabel"] == "10.77.0.0/24"
