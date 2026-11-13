"""A ``clear`` list on update bodies (#1211).

A generated client cannot send an explicit ``null`` for an optional property
(it omits the key, which ``exclude_unset`` handlers read as "unchanged"), and
#907 publishes the nullable fields as plain scalars. So ``IPAddressUpdate``,
``SubnetUpdate`` and ``RecordUpdate`` take ``clear: [...]``, a plain string
array that appears in the published schema.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_record_clear_list_resets_ttl_and_struct_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="z.example.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db_session.add(zone)
    await db_session.flush()
    rec = DNSRecord(
        zone_id=zone.id,
        name="h",
        fqdn="h.z.example.test.",
        record_type="A",
        value="192.0.2.1",
        ttl=300,
    )
    db_session.add(rec)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/{rec.id}"

    # A bare null for priority is still dropped, not a clear.
    r = await client.put(url, json={"ttl": 60}, headers=headers)
    assert r.status_code == 200 and r.json()["ttl"] == 60, r.text

    r = await client.put(url, json={"clear": ["ttl"]}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["ttl"] is None

    # A value and a clear for the same field contradict each other.
    r = await client.put(url, json={"ttl": 60, "clear": ["ttl"]}, headers=headers)
    assert r.status_code == 422, r.text
    # Only the listed fields are clearable.
    r = await client.put(url, json={"clear": ["value"]}, headers=headers)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_address_clear_list_clears_mac(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.9.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.9.1.0/24", name="n")
    db_session.add(subnet)
    await db_session.flush()
    ip = IPAddress(
        subnet_id=subnet.id, address="10.9.1.5", status="allocated", mac_address="aa:bb:cc:dd:ee:ff"
    )
    db_session.add(ip)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/ipam/addresses/{ip.id}", json={"clear": ["mac_address"]}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["mac_address"] is None

    r = await client.put(
        f"/api/v1/ipam/addresses/{ip.id}",
        json={"mac_address": "aa:bb:cc:dd:ee:01", "clear": ["mac_address"]},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip.id}", json={"clear": ["hostname"]}, headers=headers
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_subnet_clear_list_clears_gateway(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.8.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.8.1.0/24", name="n", gateway="10.8.1.1"
    )
    db_session.add(subnet)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/ipam/subnets/{subnet.id}", json={"clear": ["gateway"]}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["gateway"] is None


def test_clear_is_published_in_the_openapi_schema() -> None:
    from app.main import create_app

    schemas = create_app().openapi()["components"]["schemas"]
    for name, members in (
        ("IPAddressUpdate", {"mac_address"}),
        ("SubnetUpdate", {"gateway"}),
        ("RecordUpdate", {"ttl", "priority", "weight", "port"}),
    ):
        clear = schemas[name]["properties"]["clear"]
        assert clear["type"] == "array", (name, clear)
        items = clear["items"]  # a one-member Literal publishes as ``const``
        assert set(items.get("enum") or [items["const"]]) == members, (name, clear)
