"""#2270 — a DHCP scope's DDNS toggle / hostname policy are inert (DDNS is
subnet-level), so they are refused with a 422 that names them, and they no
longer shift the DHCP ConfigBundle ETag (a Kea reload for a byte-identical
config)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.config_bundle import build_config_bundle

CIDR = "192.0.2.0/24"


async def _world(db: AsyncSession) -> tuple[dict, Subnet, DHCPServerGroup, DHCPServer]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([user, space, grp])
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="s")
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add_all([subnet, srv])
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, subnet, grp, srv


async def _create(client: AsyncClient, h: dict, subnet: Subnet, grp: DHCPServerGroup, **extra):
    return await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s", **extra},
    )


@pytest.mark.asyncio
async def test_create_refuses_scope_ddns_enabled_naming_the_field(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, subnet, grp, _ = await _world(db_session)
    r = await _create(client, h, subnet, grp, ddns_enabled=True)
    assert r.status_code == 422, r.text
    assert "ddns_enabled" in r.text and "subnet" in r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["derived", "none", "server_name", "ipam"])
async def test_create_refuses_a_non_default_policy(
    client: AsyncClient, db_session: AsyncSession, policy: str
) -> None:
    h, subnet, grp, _ = await _world(db_session)
    r = await _create(client, h, subnet, grp, ddns_hostname_policy=policy)
    assert r.status_code == 422, r.text
    assert "ddns_hostname_policy" in r.text


@pytest.mark.asyncio
async def test_update_refuses_changes_but_tolerates_stored_values(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, subnet, grp, _ = await _world(db_session)
    r = await _create(client, h, subnet, grp)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["id"]

    r = await client.put(f"/api/v1/dhcp/scopes/{sid}", headers=h, json={"ddns_enabled": True})
    assert r.status_code == 422 and "ddns_enabled" in r.text
    r = await client.put(
        f"/api/v1/dhcp/scopes/{sid}", headers=h, json={"ddns_hostname_policy": "derived"}
    )
    assert r.status_code == 422 and "ddns_hostname_policy" in r.text

    # A scope stored before the refusal (ddns on, odd policy) can still be
    # edited by a dialog that sends the stored values back, and switched off.
    scope = await db_session.get(DHCPScope, uuid.UUID(sid))
    scope.ddns_enabled = True
    scope.ddns_hostname_policy = "ipam"
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dhcp/scopes/{sid}",
        headers=h,
        json={"lease_time": 7200, "ddns_enabled": True, "ddns_hostname_policy": "ipam"},
    )
    assert r.status_code == 200, r.text
    r = await client.put(
        f"/api/v1/dhcp/scopes/{sid}",
        headers=h,
        json={"ddns_enabled": False, "ddns_hostname_policy": "client"},
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_scope_ddns_fields_do_not_move_the_bundle_etag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, subnet, grp, srv = await _world(db_session)
    r = await _create(client, h, subnet, grp)
    assert r.status_code in (200, 201), r.text
    scope = await db_session.get(DHCPScope, uuid.UUID(r.json()["id"]))

    before = await build_config_bundle(db_session, srv)
    scope.ddns_enabled = True
    scope.ddns_hostname_policy = "derived"
    await db_session.flush()
    after = await build_config_bundle(db_session, srv)
    assert after.etag == before.etag

    # Control: a field Kea does render still moves it.
    scope.lease_time = scope.lease_time + 60
    await db_session.flush()
    assert (await build_config_bundle(db_session, srv)).etag != before.etag
