"""The block move preview counts live child blocks only (#3922)."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_ipam_alias_cname_exclusive_2080 import _headers
from tests.test_ipam_block_move_trashed_subnets_3436 import _block, _space, _trash


async def test_preview_leaves_trashed_child_blocks_out_of_the_count(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _headers(db_session)
    source = await _space(db_session)
    target = await _space(db_session)
    moved = await _block(client, h, source, "10.238.0.0/16")
    live = await _block(client, h, source, "10.238.16.0/20", moved)
    trashed = await _block(client, h, source, "10.238.32.0/20", moved)
    assert live
    await _trash(client, h, f"/api/v1/ipam/blocks/{trashed}")

    r = await client.post(
        f"/api/v1/ipam/blocks/{moved}/move/preview",
        headers=h,
        json={"target_space_id": target, "target_parent_id": None},
    )
    assert r.status_code == 200, r.text
    assert r.json()["descendant_blocks_count"] == 1
    assert r.json()["descendant_blocks_trashed"] == 1
