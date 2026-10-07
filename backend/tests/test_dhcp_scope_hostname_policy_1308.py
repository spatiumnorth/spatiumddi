"""#1308 — a DHCP scope's DDNS hostname policy has one vocabulary, on create and on update.

The scope API's vocabulary is ``client`` / ``server_name`` / ``derived`` /
``none`` (``VALID_HOSTNAME_POLICIES``). Create refused anything else with a 422,
but the update path had no check at all: the scope dialog offered ``ipam`` and
``generate``, so the same choice that 422'd on create answered 200 on edit and
was stored. Update now refuses a value outside the vocabulary too. A value
stored before this check existed is grandfathered the way scope options are
(#597, #1228): the dialog sends the stored policy back on every save, so an
unchanged one must not block an unrelated edit.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.scopes import VALID_HOSTNAME_POLICIES
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet

CIDR = "192.0.2.0/24"


async def _make_token(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _subnet_and_group(db: AsyncSession) -> tuple[Subnet, DHCPServerGroup]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    return subnet, grp


async def _create(
    client: AsyncClient, h: dict, subnet: Subnet, grp: DHCPServerGroup, **extra
) -> dict:
    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s", **extra},
    )
    assert r.status_code in (200, 201), r.text
    return r.json()


async def _stored_policy(db: AsyncSession, scope_id: str) -> str:
    scope = await db.get(DHCPScope, uuid.UUID(scope_id))
    assert scope is not None
    await db.refresh(scope)
    return scope.ddns_hostname_policy


@pytest.mark.asyncio
@pytest.mark.parametrize("offered", ["ipam", "generate"])
async def test_update_refuses_the_policy_create_refuses(
    client: AsyncClient, db_session: AsyncSession, offered: str
) -> None:
    """The issue's case: the dialog's From IPAM / Generate. Create says 422;
    so must update, and the stored policy must not move."""
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={
            "group_id": str(grp.id),
            "name": "s",
            "ddns_enabled": True,
            "ddns_hostname_policy": offered,
        },
    )
    assert r.status_code == 422, r.text

    body = await _create(client, h, subnet, grp, ddns_enabled=True)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"ddns_enabled": True, "ddns_hostname_policy": offered},
    )
    assert r.status_code == 422, r.text
    assert "ddns_hostname_policy" in r.text
    assert await _stored_policy(db_session, body["id"]) == "client"


@pytest.mark.asyncio
async def test_every_policy_of_the_vocabulary_saves_on_create_and_on_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _make_token(db_session)
    h = {"Authorization": f"Bearer {token}"}
    policies = sorted(VALID_HOSTNAME_POLICIES)
    assert policies == ["client", "derived", "none", "server_name"]
    for i, policy in enumerate(policies):
        subnet, grp = await _subnet_and_group(db_session)
        await db_session.commit()
        body = await _create(client, h, subnet, grp, ddns_enabled=True, ddns_hostname_policy=policy)
        assert body["ddns_hostname_policy"] == policy

        moved = policies[(i + 1) % len(policies)]
        r = await client.put(
            f"/api/v1/dhcp/scopes/{body['id']}",
            headers=h,
            json={"ddns_hostname_policy": moved},
        )
        assert r.status_code == 200, r.text
        assert r.json()["ddns_hostname_policy"] == moved


@pytest.mark.asyncio
async def test_a_stored_policy_outside_the_vocabulary_does_not_block_an_unrelated_edit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A scope edited to ``ipam`` before update checked the field keeps
    saving: the dialog sends the stored policy back with every edit."""
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}
    body = await _create(client, h, subnet, grp, ddns_enabled=True)
    scope = await db_session.get(DHCPScope, uuid.UUID(body["id"]))
    assert scope is not None
    scope.ddns_hostname_policy = "ipam"
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"lease_time": 7200, "ddns_enabled": True, "ddns_hostname_policy": "ipam"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["lease_time"] == 7200
    assert await _stored_policy(db_session, body["id"]) == "ipam"

    # Moving it is checked like any other change.
    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"ddns_hostname_policy": "generate"},
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/dhcp/scopes/{body['id']}",
        headers=h,
        json={"ddns_hostname_policy": "derived"},
    )
    assert r.status_code == 200, r.text
    assert await _stored_policy(db_session, body["id"]) == "derived"
