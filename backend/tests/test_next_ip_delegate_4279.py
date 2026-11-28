"""#4279 - Next available for an address-set delegate searches inside its sets.

The whole-subnet picks (a 32-draw random on a /64, a 65,536-host walk) answered
"none free" while the caller's set held free hosts. A delegate's pick draws or
walks inside the set's own ranges, and only reports full when the set is.
"""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.address_set import AddressSet
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _delegate(db: AsyncSession, set_id: uuid.UUID) -> dict[str, str]:
    user = User(
        username=f"d-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="d",
        hashed_password=hash_password("password123"),
    )
    role = Role(
        name=f"r-{uuid.uuid4().hex[:8]}",
        permissions=[
            {"action": "read", "resource_type": "*"},
            {"action": "write", "resource_type": "address_set", "resource_id": str(set_id)},
        ],
    )
    group = Group(name=f"g-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _world(
    db: AsyncSession, block: str, net: str, start: str, end: str, **subnet_kw: object
) -> tuple[Subnet, AddressSet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    blk = IPBlock(space_id=space.id, network=block, name="b")
    db.add(blk)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=blk.id, network=net, name="s", **subnet_kw)
    db.add(subnet)
    await db.flush()
    aset = AddressSet(
        name="set",
        subnet_id=subnet.id,
        range_kind="contiguous",
        start_address=start,
        end_address=end,
    )
    db.add(aset)
    await db.flush()
    return subnet, aset


@pytest.mark.asyncio
async def test_v6_random_policy_delegate_gets_an_address_in_its_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, aset = await _world(
        db_session,
        "fd5e:1113::/48",
        "fd5e:1113:0:1::/64",
        "fd5e:1113:0:1::100",
        "fd5e:1113:0:1::1ff",
    )
    hdr = await _delegate(db_session, aset.id)
    await db_session.commit()
    lo, hi = ipaddress.ip_address("fd5e:1113:0:1::100"), ipaddress.ip_address("fd5e:1113:0:1::1ff")

    for _ in range(5):
        r = await client.get(
            f"/api/v1/ipam/subnets/{subnet.id}/next-ip-preview?strategy=sequential", headers=hdr
        )
        assert r.status_code == 200, r.text
        assert r.json()["address"] is not None, r.text
        assert lo <= ipaddress.ip_address(r.json()["address"]) <= hi

    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={"status": "allocated", "hostname": "host-1"},
    )
    assert r.status_code == 201, r.text
    assert lo <= ipaddress.ip_address(r.json()["address"]) <= hi


@pytest.mark.asyncio
async def test_v6_full_set_refuses_in_words_and_free_tail_is_found(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, aset = await _world(
        db_session, "fd5e:1114::/48", "fd5e:1114:0:1::/64", "fd5e:1114:0:1::10", "fd5e:1114:0:1::12"
    )
    hdr = await _delegate(db_session, aset.id)
    for last in ("10", "11"):
        db_session.add(
            IPAddress(subnet_id=subnet.id, address=f"fd5e:1114:0:1::{last}", status="allocated")
        )
    await db_session.commit()
    # Only ::12 is free: the pick must find it every time, not by luck.
    for _ in range(3):
        r = await client.get(
            f"/api/v1/ipam/subnets/{subnet.id}/next-ip-preview?strategy=sequential", headers=hdr
        )
        assert r.json()["address"] == "fd5e:1114:0:1::12", r.text
    db_session.add(IPAddress(subnet_id=subnet.id, address="fd5e:1114:0:1::12", status="allocated"))
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next", headers=hdr, json={"hostname": "h"}
    )
    assert r.status_code == 409, r.text
    assert "address set" in r.json()["detail"]


@pytest.mark.asyncio
async def test_v4_set_past_the_first_65536_hosts_is_found(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, aset = await _world(db_session, "10.0.0.0/8", "10.0.0.0/8", "10.5.0.10", "10.5.0.19")
    hdr = await _delegate(db_session, aset.id)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/next",
        headers=hdr,
        json={"status": "allocated", "hostname": "h"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["address"] == "10.5.0.10"
