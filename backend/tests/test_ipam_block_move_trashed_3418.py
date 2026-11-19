"""A block move ignores blocks in the Trash at the destination level (#3418).

``_check_overlap_in_target`` re-runs the create path's sibling rule against the
target space's blocks with raw SQL, and raw SQL bypasses the ORM soft-delete
filter. #490 added ``deleted_at IS NULL`` to the create path's own query
(``_assert_no_block_overlap``) so a trashed block frees its CIDR; the move's copy
of the rule never got it. So a trashed block at the destination level refused the
move with a 409 (the moved block's CIDR, or a supernet of it), or, when it sat
inside the moved block's range, landed on the reparent chain and had its
``parent_block_id`` rewritten by the move.

A move now counts live blocks only: a row in the Trash is left exactly as it was,
and a live sibling still refuses the move or is reparented under it as before.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space(db: AsyncSession) -> str:
    space = IPSpace(name=f"sp3418-{uuid.uuid4().hex[:8]}", description="")
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


async def _trash(client: AsyncClient, h: dict[str, str], block_id: str) -> None:
    r = await client.delete(f"/api/v1/ipam/blocks/{block_id}", headers=h)
    assert r.status_code == 204, r.text


async def _row(db: AsyncSession, block_id: str) -> IPBlock:
    """The block as stored, Trash included."""
    db.expire_all()
    stmt = (
        select(IPBlock)
        .where(IPBlock.id == uuid.UUID(block_id))
        .execution_options(include_deleted=True)
    )
    return (await db.execute(stmt)).scalars().one()


async def _move(
    client: AsyncClient,
    h: dict[str, str],
    block_id: str,
    network: str,
    target_space_id: str,
    target_parent_id: str | None = None,
) -> tuple[Response, Response]:
    """Preview, then commit, the move the Move dialog makes."""
    body = {"target_space_id": target_space_id, "target_parent_id": target_parent_id}
    preview = await client.post(
        f"/api/v1/ipam/blocks/{block_id}/move/preview", headers=h, json=body
    )
    commit = await client.post(
        f"/api/v1/ipam/blocks/{block_id}/move/commit",
        headers=h,
        json={**body, "confirmation_cidr": network},
    )
    return preview, commit


async def test_move_onto_a_trashed_block_of_the_same_cidr(
    client: AsyncClient, db_session: AsyncSession
):
    """A trashed block frees its CIDR for a move, as it does for a create (#490)."""
    h = await _headers(db_session)
    target = await _space(db_session)
    trashed = await _block(client, h, target, "10.241.5.0/24")
    await _trash(client, h, trashed)
    source = await _space(db_session)
    moved = await _block(client, h, source, "10.241.5.0/24")

    preview, commit = await _move(client, h, moved, "10.241.5.0/24", target)
    assert preview.status_code == 200, preview.text
    assert commit.status_code == 200, commit.text
    assert commit.json()["block"]["space_id"] == target
    assert commit.json()["block"]["parent_block_id"] is None

    # The Trash still refuses to bring back a second live block of that CIDR.
    restore = await client.post(f"/api/v1/admin/trash/ip_block/{trashed}/restore", headers=h)
    assert restore.status_code == 409, restore.text
    row = await _row(db_session, trashed)
    assert row.deleted_at is not None
    assert row.parent_block_id is None


async def test_move_beside_a_trashed_supernet(client: AsyncClient, db_session: AsyncSession):
    """A trashed block over the moved one does not ask to be its parent."""
    h = await _headers(db_session)
    target = await _space(db_session)
    trashed = await _block(client, h, target, "10.242.0.0/16")
    await _trash(client, h, trashed)
    source = await _space(db_session)
    moved = await _block(client, h, source, "10.242.5.0/24")

    preview, commit = await _move(client, h, moved, "10.242.5.0/24", target)
    assert preview.status_code == 200, preview.text
    assert commit.status_code == 200, commit.text
    assert commit.json()["block"]["parent_block_id"] is None
    assert (await _row(db_session, trashed)).deleted_at is not None


async def test_move_reparents_the_live_blocks_it_covers_and_not_the_trashed(
    client: AsyncClient, db_session: AsyncSession
):
    """Only a live block is put on the reparent chain; a trashed row is not written."""
    h = await _headers(db_session)
    target = await _space(db_session)
    live = await _block(client, h, target, "10.243.5.0/25")
    trashed = await _block(client, h, target, "10.243.5.128/25")
    await _trash(client, h, trashed)
    source = await _space(db_session)
    moved = await _block(client, h, source, "10.243.5.0/24")

    preview, commit = await _move(client, h, moved, "10.243.5.0/24", target)
    assert preview.status_code == 200, preview.text
    assert preview.json()["reparent_chain_block_ids"] == [live]
    assert commit.status_code == 200, commit.text
    assert commit.json()["reparented_block_ids"] == [live]

    assert (await _row(db_session, live)).parent_block_id == uuid.UUID(moved)
    row = await _row(db_session, trashed)
    assert row.deleted_at is not None
    assert row.parent_block_id is None


async def test_move_into_a_parent_holding_a_trashed_block_of_the_same_cidr(
    client: AsyncClient, db_session: AsyncSession
):
    """The same rule one level down, under a target parent."""
    h = await _headers(db_session)
    target = await _space(db_session)
    parent = await _block(client, h, target, "10.244.0.0/16")
    trashed = await _block(client, h, target, "10.244.5.0/24", parent)
    await _trash(client, h, trashed)
    # Made after the /24 went to the Trash, so it sits beside it under the parent.
    live = await _block(client, h, target, "10.244.5.0/25", parent)
    source = await _space(db_session)
    moved = await _block(client, h, source, "10.244.5.0/24")

    preview, commit = await _move(client, h, moved, "10.244.5.0/24", target, parent)
    assert preview.status_code == 200, preview.text
    assert preview.json()["reparent_chain_block_ids"] == [live]
    assert commit.status_code == 200, commit.text
    assert commit.json()["block"]["parent_block_id"] == parent
    assert commit.json()["reparented_block_ids"] == [live]

    assert (await _row(db_session, live)).parent_block_id == uuid.UUID(moved)
    row = await _row(db_session, trashed)
    assert row.deleted_at is not None
    assert row.parent_block_id == uuid.UUID(parent)


async def test_move_still_refuses_live_blocks_in_the_way(
    client: AsyncClient, db_session: AsyncSession
):
    """Control: a live block of the moved CIDR, or a live supernet of it, still refuses."""
    h = await _headers(db_session)
    target = await _space(db_session)
    await _block(client, h, target, "10.245.5.0/24")
    await _block(client, h, target, "10.246.0.0/16")
    source = await _space(db_session)
    same = await _block(client, h, source, "10.245.5.0/24")
    inside = await _block(client, h, source, "10.246.5.0/24")

    for block_id, network in ((same, "10.245.5.0/24"), (inside, "10.246.5.0/24")):
        preview, commit = await _move(client, h, block_id, network, target)
        assert preview.status_code == 409, preview.text
        assert commit.status_code == 409, commit.text
        assert str((await _row(db_session, block_id)).space_id) == source
