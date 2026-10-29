"""A block's allocated count follows its live subnets after tree writes (#2412).

#509 made every write recompute the utilisation counters inline; these tree
writes still skipped it: Move to Trash of a subnet / block, a New Block that
adopts existing subnets, the cross-space block move, plan apply, and a trash
restore. After each, ``allocated_ips`` of a block must equal the sum over the
live subnets of its subtree.

Each subnet counts in its block with its network and broadcast addresses
(a block's utilisation is the share of its CIDR in use, #2982), so every
IPv4 subnet below /31 here adds ``_NB`` more to its block than to itself.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers

# What an IPv4 subnet below /31 adds to its block beyond its own count:
# its network + broadcast addresses (#2982).
_NB = 2


async def _space_block(db: AsyncSession, net: str) -> tuple[str, str]:
    space = IPSpace(name=f"sp2412-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=net, name="root")
    db.add(block)
    await db.flush()
    await db.commit()
    return str(space.id), str(block.id)


async def _subnet(client, h, space_id, block_id, cidr, hosts=2) -> str:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": cidr,
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    sid = str(r.json()["id"])
    base = cidr.split("/")[0].rsplit(".", 1)[0]
    for i in range(hosts):
        a = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            headers=h,
            json={"address": f"{base}.{10 + i}", "hostname": f"h{i}"},
        )
        assert a.status_code == 201, a.text
    return sid


async def _alloc(client, h, kind: str, rid: str) -> int:
    r = await client.get(f"/api/v1/ipam/{kind}/{rid}", headers=h)
    assert r.status_code == 200, r.text
    return int(r.json()["allocated_ips"])


async def test_trash_subnet_and_new_block_adoption(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, root = await _space_block(db_session, "10.227.0.0/16")
    s0 = await _subnet(client, h, space, root, "10.227.0.0/24")
    s1 = await _subnet(client, h, space, root, "10.227.1.0/24")
    s40 = await _subnet(client, h, space, root, "10.227.40.0/24")
    per_subnet = await _alloc(client, h, "subnets", s0) + _NB
    assert await _alloc(client, h, "blocks", root) == 3 * per_subnet

    # Move to Trash of one /24: the parent block stops counting it.
    r = await client.delete(f"/api/v1/ipam/subnets/{s1}", headers=h)
    assert r.status_code == 204, r.text
    assert await _alloc(client, h, "blocks", root) == 2 * per_subnet

    # A New Block over the /24 adopts it and rolls it up (was 0 / 0).
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={
            "space_id": space,
            "parent_block_id": root,
            "network": "10.227.40.0/22",
            "name": "adopt",
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["allocated_ips"] == per_subnet
    assert r.json()["total_ips"] == 1024
    assert await _alloc(client, h, "subnets", s40) + _NB == per_subnet
    assert await _alloc(client, h, "blocks", root) == 2 * per_subnet

    # Restoring the trashed subnet brings it back into the rollup.
    rr = await client.post(f"/api/v1/admin/trash/subnet/{s1}/restore", headers=h)
    assert rr.status_code == 200, rr.text
    assert await _alloc(client, h, "blocks", root) == 3 * per_subnet


async def test_trash_block_updates_parent(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, root = await _space_block(db_session, "10.228.0.0/16")
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": space, "parent_block_id": root, "network": "10.228.1.0/24", "name": "c"},
    )
    assert r.status_code == 201, r.text
    child = r.json()["id"]
    await _subnet(client, h, space, child, "10.228.1.0/25")
    keep = await _subnet(client, h, space, root, "10.228.2.0/24")
    assert await _alloc(client, h, "blocks", root) > await _alloc(client, h, "subnets", keep) + _NB

    d = await client.delete(f"/api/v1/ipam/blocks/{child}", headers=h)
    assert d.status_code == 204, d.text
    assert await _alloc(client, h, "blocks", root) == await _alloc(client, h, "subnets", keep) + _NB


async def test_cross_space_block_move_rolls_up_both_sides(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    space_a, root_a = await _space_block(db_session, "10.229.0.0/16")
    space_b, root_b = await _space_block(db_session, "10.229.0.0/16")
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={
            "space_id": space_a,
            "parent_block_id": root_a,
            "network": "10.229.1.0/24",
            "name": "m",
        },
    )
    mv = r.json()["id"]
    s = await _subnet(client, h, space_a, mv, "10.229.1.0/25")
    per = await _alloc(client, h, "subnets", s) + _NB
    assert await _alloc(client, h, "blocks", root_a) == per

    # Move 10.229.1.0/24 into space B under 10.230.0.0/16 (needs a non-overlapping
    # CIDR, so move a block whose network fits: re-create under B's range).
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={
            "space_id": space_a,
            "parent_block_id": root_a,
            "network": "10.229.9.0/24",
            "name": "m2",
        },
    )
    assert r.status_code == 201
    mv2 = r.json()["id"]
    s2 = await _subnet(client, h, space_a, mv2, "10.229.9.0/25")
    per2 = await _alloc(client, h, "subnets", s2) + _NB
    assert await _alloc(client, h, "blocks", root_a) == per + per2

    cm = await client.post(
        f"/api/v1/ipam/blocks/{mv2}/move/commit",
        headers=h,
        json={
            "target_space_id": space_b,
            "target_parent_id": root_b,
            "confirmation_cidr": "10.229.9.0/24",
        },
    )
    assert cm.status_code == 200, cm.text
    assert await _alloc(client, h, "blocks", root_a) == per
    assert await _alloc(client, h, "blocks", mv2) == per2
    assert await _alloc(client, h, "blocks", root_b) == per2


async def test_plan_apply_rolls_up_created_rows(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    space, root = await _space_block(db_session, "10.231.0.0/16")
    tree = {
        "id": "r",
        "network": "10.231.0.0/16",
        "name": "root",
        "kind": "block",
        "existing_block_id": root,
        "children": [
            {
                "id": "b",
                "network": "10.231.8.0/22",
                "name": "b",
                "kind": "block",
                "children": [
                    {"id": "s1", "network": "10.231.8.0/24", "name": "s1", "kind": "subnet"},
                    {"id": "s2", "network": "10.231.9.0/24", "name": "s2", "kind": "subnet"},
                ],
            }
        ],
    }
    c = await client.post(
        "/api/v1/ipam/plans", headers=h, json={"name": "p", "space_id": space, "tree": tree}
    )
    assert c.status_code == 201, c.text
    ap = await client.post(f"/api/v1/ipam/plans/{c.json()['id']}/apply", headers=h)
    assert ap.status_code == 200, ap.text
    sub_ids = ap.json()["subnet_ids"]
    own = [await _alloc(client, h, "subnets", sid) for sid in sub_ids]
    assert all(p > 0 for p in own)  # placeholder rows
    per = [p + _NB for p in own]
    bid = ap.json()["block_ids"][-1]
    assert await _alloc(client, h, "blocks", bid) == sum(per)
    assert await _alloc(client, h, "blocks", root) == sum(per)
