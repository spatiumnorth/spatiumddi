"""A role scoped to one subnet and one zone can find that zone (#4854).

``GET /dns/groups/{id}/zones`` needs a type-level DNS read, so such a role was
refused it while ``POST .../addresses`` naming the zone succeeded. The subnet's
``writable-zones`` read gives the console the zones the caller may write.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_address_role_matrix_3636 import _session


async def test_scoped_writer_lists_only_the_zone_it_may_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.5.0/24",
        name="x",
        dns_inherit_settings=False,
        dns_group_ids=[str(group.id)],
    )
    z1 = DNSZone(group_id=group.id, name="z1.test.", kind="forward")
    z2 = DNSZone(group_id=group.id, name="z2.test.", kind="forward")
    db.add_all([subnet, z1, z2])
    await db.flush()
    sid = str(subnet.id)
    h = await _session(
        db,
        [
            {"action": "read", "resource_type": "subnet", "resource_id": sid},
            {"action": "write", "resource_type": "subnet", "resource_id": sid},
            {"action": "write", "resource_type": "dns_zone", "resource_id": str(z1.id)},
        ],
    )
    r = await client.get(f"/api/v1/dns/groups/{group.id}/zones", headers=h)
    assert r.status_code == 403
    r = await client.get(f"/api/v1/ipam/subnets/{sid}/writable-zones", headers=h)
    assert r.status_code == 200, r.text
    assert [z["id"] for z in r.json()] == [str(z1.id)]


async def _world(db: AsyncSession):
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    g1 = DNSServerGroup(name=f"g1-{uuid.uuid4().hex[:6]}", description="")
    g2 = DNSServerGroup(name=f"g2-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([g1, g2])
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.5.0/24",
        name="x",
        dns_inherit_settings=False,
        dns_group_ids=[str(g1.id)],
    )
    other = Subnet(space_id=space.id, block_id=block.id, network="10.0.6.0/24", name="y")
    z1 = DNSZone(group_id=g1.id, name="z1.test.", kind="forward")
    zo = DNSZone(group_id=g2.id, name="zo.test.", kind="forward")
    db.add_all([subnet, other, z1, zo])
    await db.flush()
    return subnet, other, g2, z1, zo


async def test_no_grant_on_the_subnet_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, other, _g2, z1, _zo = await _world(db_session)
    # Write on the zone and on ANOTHER subnet, nothing on this one.
    h = await _session(
        db_session,
        [
            {"action": "read", "resource_type": "subnet", "resource_id": str(other.id)},
            {"action": "write", "resource_type": "dns_zone", "resource_id": str(z1.id)},
        ],
    )
    r = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/writable-zones", headers=h)
    assert r.status_code in (403, 404), r.text


async def test_zones_of_a_group_the_subnet_is_not_in_never_appear(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, _other, g2, z1, zo = await _world(db_session)
    sid = str(subnet.id)
    h = await _session(
        db_session,
        [
            {"action": "read", "resource_type": "subnet", "resource_id": sid},
            {"action": "write", "resource_type": "dns_zone", "resource_id": str(z1.id)},
            {"action": "write", "resource_type": "dns_zone", "resource_id": str(zo.id)},
        ],
    )
    r = await client.get(f"/api/v1/ipam/subnets/{sid}/writable-zones", headers=h)
    assert [z["id"] for z in r.json()] == [str(z1.id)]
    r = await client.get(
        f"/api/v1/ipam/subnets/{sid}/writable-zones", params={"group_id": str(g2.id)}, headers=h
    )
    assert r.status_code == 200 and r.json() == []
