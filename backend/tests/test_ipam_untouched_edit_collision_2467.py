"""An untouched Edit address Save asks for no collision confirmation (#2467).

The dialog sends hostname, MAC and zone on every Save; presence used to count as
a change, so a row stored with a confirmed MAC / hostname collision was refused
again on a Save that changed nothing.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace


async def _setup(client: AsyncClient, db: AsyncSession) -> tuple[dict[str, str], str, DNSZone]:
    user = User(
        username=f"u2122-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    grp = DNSServerGroup(name=f"g2122-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"d{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    space = IPSpace(name=f"sp2122-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.67.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.67.5.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return headers, str(resp.json()["id"]), zone


MAC = "02:98:00:00:00:01"


async def _two_sharing(client: AsyncClient, headers: dict[str, str], sid: str, **extra: object):
    first = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.67.5.70", "hostname": "nic1", "mac_address": MAC, **extra},
    )
    assert first.status_code == 201, first.text
    second = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={
            "address": "10.67.5.71",
            "hostname": "nic2",
            "mac_address": MAC,
            "force": True,
            **extra,
        },
    )
    assert second.status_code == 201, second.text
    return second.json()["id"]


async def test_untouched_save_of_an_address_sharing_its_mac_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _two_sharing(client, headers, sid)
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={
            "hostname": "nic2",
            "description": "",
            "mac_address": MAC,
            "status": "allocated",
            "custom_fields": {},
            "role": None,
            "reserved_until": None,
            "force": False,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["mac_address"].lower() == MAC
    # A different spelling of the same MAC is still no change.
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"hostname": "nic2", "mac_address": MAC.upper().replace(":", "-")},
    )
    assert r.status_code == 200, r.text


async def test_changing_to_a_mac_another_address_holds_still_asks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _two_sharing(client, headers, sid)
    third = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.67.5.72", "hostname": "nic3", "mac_address": "02:98:00:00:00:09"},
    )
    assert third.status_code == 201, third.text
    r = await client.put(
        f"/api/v1/ipam/addresses/{third.json()['id']}",
        headers=headers,
        json={"hostname": "nic3", "mac_address": MAC},
    )
    assert r.status_code == 409, r.text
    kinds = [w["kind"] for w in r.json()["detail"]["warnings"]]
    assert "mac_collision" in kinds
    assert ip_id


async def test_changing_to_a_hostname_another_address_holds_still_asks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _two_sharing(client, headers, sid)
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "nic1"}
    )
    assert r.status_code == 409, r.text


async def test_untouched_save_of_an_address_sharing_its_hostname_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    first = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.67.5.80", "hostname": "rr"},
    )
    assert first.status_code == 201, first.text
    second = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.67.5.81", "hostname": "rr", "force": True},
    )
    assert second.status_code == 201, second.text
    r = await client.put(
        f"/api/v1/ipam/addresses/{second.json()['id']}",
        headers=headers,
        json={"hostname": "rr", "description": "", "status": "allocated"},
    )
    assert r.status_code == 200, r.text
