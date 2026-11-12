"""A block move refuses to leave two overlapping live subnets in the target space (#3923).

``create_subnet`` and the Trash restore refuse a subnet overlapping a live subnet of
its space; the move only read blocks, so moving a block into a space whose block it
contains left two live subnets of one CIDR. The move (and its preview) now 409s,
naming the subnets. A trashed subnet in the target frees its CIDR, as for a create.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space(db: AsyncSession) -> str:
    space = IPSpace(name=f"sp3923-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    await db.commit()
    return str(space.id)


async def _block(
    client: AsyncClient,
    h: dict[str, str],
    space_id: str,
    network: str,
    parent_id: str | None = None,
) -> str:
    body: dict[str, str] = {"space_id": space_id, "network": network, "name": "b"}
    if parent_id is not None:
        body["parent_block_id"] = parent_id
    r = await client.post("/api/v1/ipam/blocks", headers=h, json=body)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _subnet(
    client: AsyncClient, h: dict[str, str], space_id: str, block_id: str, network: str
) -> str:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": network,
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _address(client: AsyncClient, h: dict[str, str], subnet_id: str, address: str) -> None:
    r = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        headers=h,
        json={"address": address, "hostname": "h3923", "dns_zone_id": ""},
    )
    assert r.status_code == 201, r.text


async def _trash(client: AsyncClient, h: dict[str, str], path: str) -> None:
    r = await client.delete(path, headers=h)
    assert r.status_code == 204, r.text


async def _move_preview_commit(client, h, block_id, network, target_space_id):
    body = {"target_space_id": target_space_id, "target_parent_id": None}
    p = await client.post(f"/api/v1/ipam/blocks/{block_id}/move/preview", headers=h, json=body)
    c = await client.post(
        f"/api/v1/ipam/blocks/{block_id}/move/commit",
        headers=h,
        json={**body, "confirmation_cidr": network},
    )
    return p, c


async def _setup(client, db, h, target_subnet="10.71.97.0/24"):
    d = await _space(db)
    c = await _space(db)
    bd = await _block(client, h, d, "10.71.96.0/22")
    await _subnet(client, h, d, bd, target_subnet)
    bc = await _block(client, h, c, "10.71.96.0/20")
    sc = await _subnet(client, h, c, bc, "10.71.97.0/24")
    await _address(client, h, sc, "10.71.97.10")
    return d, c, bd, bc, sc


async def test_move_refused_when_subnets_overlap_in_target(client, db_session):
    h = await _headers(db_session)
    d, c, bd, bc, sc = await _setup(client, db_session, h)
    p, r = await _move_preview_commit(client, h, bc, "10.71.96.0/20", d)
    assert p.status_code == 409, p.text
    assert "10.71.97.0/24" in p.json()["detail"]
    assert r.status_code == 409, r.text
    assert "overlaps with existing subnet" in r.json()["detail"]
    db_session.expire_all()
    blk = (
        await db_session.execute(select(IPBlock).where(IPBlock.id == uuid.UUID(bc)))
    ).scalar_one()
    assert str(blk.space_id) == c


async def test_move_refused_when_subnets_overlap_partially(client, db_session):
    h = await _headers(db_session)
    d, c, bd, bc, sc = await _setup(client, db_session, h, target_subnet="10.71.97.0/25")
    p, r = await _move_preview_commit(client, h, bc, "10.71.96.0/20", d)
    assert p.status_code == 409 and r.status_code == 409


async def test_move_allowed_when_target_subnet_is_trashed(client, db_session):
    h = await _headers(db_session)
    d, c, bd, bc, sc = await _setup(client, db_session, h)
    r = await client.get("/api/v1/ipam/subnets", headers=h, params={"space_id": d})
    sid = r.json()[0]["id"]
    await _trash(client, h, f"/api/v1/ipam/subnets/{sid}")
    p, r = await _move_preview_commit(client, h, bc, "10.71.96.0/20", d)
    assert p.status_code == 200, p.text
    assert r.status_code == 200, r.text


async def test_move_allowed_when_subnets_do_not_overlap(client, db_session):
    h = await _headers(db_session)
    d, c, bd, bc, sc = await _setup(client, db_session, h, target_subnet="10.71.98.0/24")
    p, r = await _move_preview_commit(client, h, bc, "10.71.96.0/20", d)
    assert p.status_code == 200 and r.status_code == 200, r.text
