"""A block that sits inside another block can be grown (#3382).

Resize scanned every block in the space for overlap except the block itself
and its descendants. Each of the block's ancestors contains it, so each one
overlaps any CIDR the block can grow to: a nested /24 could never become a
/23. The commit answered 409 naming the block's own parent, and the preview
listed the parent as a conflict, which keeps the console's Resize button
disabled. The ancestors are left out of that scan now, as the descendants
already were, and growth past the parent's edge is refused by the parent
check, whose message says so.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space(db: AsyncSession) -> uuid.UUID:
    space = IPSpace(name=f"sp3382-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    space_id = space.id
    await db.commit()
    return space_id


async def _block(
    client: AsyncClient,
    h: dict[str, str],
    space_id: uuid.UUID,
    network: str,
    parent: str | None = None,
) -> str:
    r = await client.post(
        "/api/v1/ipam/blocks",
        headers=h,
        json={"space_id": str(space_id), "network": network, "parent_block_id": parent},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _resize(
    client: AsyncClient, h: dict[str, str], block_id: str, new_cidr: str, *, preview: bool = False
):
    path = f"/api/v1/ipam/blocks/{block_id}/resize" + ("/preview" if preview else "")
    return await client.post(path, headers=h, json={"new_cidr": new_cidr})


async def _network(client: AsyncClient, h: dict[str, str], block_id: str) -> str:
    r = await client.get(f"/api/v1/ipam/blocks/{block_id}", headers=h)
    assert r.status_code == 200, r.text
    return str(r.json()["network"])


async def test_a_nested_block_grows_inside_its_parent(
    client: AsyncClient, db_session: AsyncSession
):
    """The issue's steps: a /24 inside a /16 grows to a /23."""
    h = await _headers(db_session)
    sid = await _space(db_session)
    parent = await _block(client, h, sid, "10.20.0.0/16")
    child = await _block(client, h, sid, "10.20.64.0/24", parent)

    r = await _resize(client, h, child, "10.20.64.0/23")
    assert r.status_code == 200, r.text
    assert r.json()["new_cidr"] == "10.20.64.0/23"
    assert await _network(client, h, child) == "10.20.64.0/23"
    assert await _network(client, h, parent) == "10.20.0.0/16"


async def test_the_preview_of_a_nested_growth_lists_no_conflict(
    client: AsyncClient, db_session: AsyncSession
):
    """The console's Resize dialog commits only when its preview lists no
    conflict, so the preview must agree with the commit."""
    h = await _headers(db_session)
    sid = await _space(db_session)
    parent = await _block(client, h, sid, "10.20.0.0/16")
    child = await _block(client, h, sid, "10.20.64.0/24", parent)

    p = await _resize(client, h, child, "10.20.64.0/23", preview=True)
    assert p.status_code == 200, p.text
    assert p.json()["conflicts"] == []


async def test_every_ancestor_is_left_out_not_only_the_parent(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    sid = await _space(db_session)
    top = await _block(client, h, sid, "10.0.0.0/8")
    mid = await _block(client, h, sid, "10.20.0.0/16", top)
    child = await _block(client, h, sid, "10.20.64.0/24", mid)

    r = await _resize(client, h, child, "10.20.64.0/22")
    assert r.status_code == 200, r.text
    assert await _network(client, h, child) == "10.20.64.0/22"


async def test_growth_past_the_parent_edge_is_refused_by_the_parent_check(
    client: AsyncClient, db_session: AsyncSession
):
    """Past the parent's edge the refusal names the parent's edge, even when
    another block also stands in the new range."""
    h = await _headers(db_session)
    sid = await _space(db_session)
    parent = await _block(client, h, sid, "10.20.0.0/16")
    await _block(client, h, sid, "10.21.0.0/16")  # the parent's neighbour, inside the /15
    child = await _block(client, h, sid, "10.20.64.0/24", parent)

    r = await _resize(client, h, child, "10.20.0.0/15")
    assert r.status_code == 422, r.text
    assert "does not fit inside the parent block 10.20.0.0/16" in r.json()["detail"]
    assert await _network(client, h, child) == "10.20.64.0/24"

    p = await _resize(client, h, child, "10.20.0.0/15", preview=True)
    assert p.status_code == 200, p.text
    conflicts = p.json()["conflicts"]
    assert any(c["type"] == "parent_too_small" for c in conflicts), conflicts
    assert any(
        c["type"] == "block_overlap" and "10.21.0.0/16" in c["detail"] for c in conflicts
    ), conflicts
    assert not any(
        c["type"] == "block_overlap" and "10.20.0.0/16" in c["detail"] for c in conflicts
    ), conflicts


async def test_a_sibling_block_in_the_way_still_blocks(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    sid = await _space(db_session)
    parent = await _block(client, h, sid, "10.20.0.0/16")
    child = await _block(client, h, sid, "10.20.64.0/24", parent)
    await _block(client, h, sid, "10.20.65.0/24", parent)

    r = await _resize(client, h, child, "10.20.64.0/23")
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "10.20.65.0/24" in detail
    assert "10.20.0.0/16" not in detail  # the parent is not in the way
    assert await _network(client, h, child) == "10.20.64.0/24"


async def test_a_subnet_of_the_parent_in_the_way_still_blocks(
    client: AsyncClient, db_session: AsyncSession
):
    """Leaving the ancestors out of the block scan leaves the subnets they
    hold in the subnet scan."""
    h = await _headers(db_session)
    sid = await _space(db_session)
    parent = await _block(client, h, sid, "10.20.0.0/16")
    child = await _block(client, h, sid, "10.20.64.0/24", parent)
    s = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(sid),
            "block_id": parent,
            "network": "10.20.65.0/24",
            "skip_reverse_zone": True,
        },
    )
    assert s.status_code == 201, s.text

    r = await _resize(client, h, child, "10.20.64.0/23")
    assert r.status_code == 409, r.text
    assert "overlaps an existing subnet" in r.json()["detail"]
    assert "10.20.65.0/24" in r.json()["detail"]


async def test_a_top_level_block_still_grows(client: AsyncClient, db_session: AsyncSession):
    h = await _headers(db_session)
    sid = await _space(db_session)
    top = await _block(client, h, sid, "10.30.0.0/24")

    r = await _resize(client, h, top, "10.30.0.0/23")
    assert r.status_code == 200, r.text
    assert await _network(client, h, top) == "10.30.0.0/23"


async def test_a_top_level_neighbour_in_the_way_still_blocks(
    client: AsyncClient, db_session: AsyncSession
):
    """A top-level block has no ancestor to leave out, and its neighbours
    still count."""
    h = await _headers(db_session)
    sid = await _space(db_session)
    top = await _block(client, h, sid, "10.30.0.0/24")
    await _block(client, h, sid, "10.30.1.0/24")

    r = await _resize(client, h, top, "10.30.0.0/23")
    assert r.status_code == 409, r.text
    assert "10.30.1.0/24" in r.json()["detail"]
    assert await _network(client, h, top) == "10.30.0.0/24"
