"""A block move takes the subnets in the Trash under the moved block with it (#3436).

``_collect_descendants`` (``app.services.ipam.block_move``) walks the moved block's
descendant blocks with no ``deleted_at`` filter, so a trashed child block moves with
its parent, but it listed the subnets with ``deleted_at IS NULL``. ``commit_move``
rewrites ``space_id`` only on the rows the plan lists, so a subnet in the Trash under
the moved subtree kept the source space while its block moved. Restored, it came back
live in the source space under a block in the target space, and the restore's
overlap check (``default_conflict_check``) looked in the source space, where the
block no longer is. A trashed child block's own subnets, trashed with it in one
batch, were split the same way: the block came back in the target space and its
subnets in the source space.

A move now takes every subnet under the moved subtree, the Trash included. The
preview's counts, the commit's counts and the integration blockers still cover the
live subnets only, as before.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.unifi import UnifiController
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _space(db: AsyncSession) -> str:
    space = IPSpace(name=f"sp3436-{uuid.uuid4().hex[:8]}", description="")
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
        json={"address": address, "hostname": "h3436", "dns_zone_id": ""},
    )
    assert r.status_code == 201, r.text


async def _trash(client: AsyncClient, h: dict[str, str], path: str) -> None:
    r = await client.delete(path, headers=h)
    assert r.status_code == 204, r.text


async def _subnet_row(db: AsyncSession, subnet_id: str) -> Subnet:
    """The subnet as stored, Trash included."""
    db.expire_all()
    stmt = (
        select(Subnet)
        .where(Subnet.id == uuid.UUID(subnet_id))
        .execution_options(include_deleted=True)
    )
    return (await db.execute(stmt)).scalars().one()


async def _block_row(db: AsyncSession, block_id: str) -> IPBlock:
    """The block as stored, Trash included."""
    db.expire_all()
    stmt = (
        select(IPBlock)
        .where(IPBlock.id == uuid.UUID(block_id))
        .execution_options(include_deleted=True)
    )
    return (await db.execute(stmt)).scalars().one()


async def _address_count(db: AsyncSession, subnet_id: str) -> int:
    stmt = (
        select(func.count())
        .select_from(IPAddress)
        .where(IPAddress.subnet_id == uuid.UUID(subnet_id))
    )
    return int((await db.execute(stmt)).scalar_one())


async def _listed(client: AsyncClient, h: dict[str, str], space_id: str) -> set[str]:
    r = await client.get("/api/v1/ipam/subnets", headers=h, params={"space_id": space_id})
    assert r.status_code == 200, r.text
    return {str(s["id"]) for s in r.json()}


async def _move(
    client: AsyncClient,
    h: dict[str, str],
    block_id: str,
    network: str,
    target_space_id: str,
) -> tuple[Response, Response]:
    """Preview, then commit, the move the Move dialog makes."""
    body = {"target_space_id": target_space_id, "target_parent_id": None}
    preview = await client.post(
        f"/api/v1/ipam/blocks/{block_id}/move/preview", headers=h, json=body
    )
    commit = await client.post(
        f"/api/v1/ipam/blocks/{block_id}/move/commit",
        headers=h,
        json={**body, "confirmation_cidr": network},
    )
    return preview, commit


async def test_a_trashed_subnet_moves_with_its_block_and_restores_there(
    client: AsyncClient, db_session: AsyncSession
):
    """The trashed subnet's space follows its block; the counts stay live-only."""
    h = await _headers(db_session)
    source = await _space(db_session)
    target = await _space(db_session)
    moved = await _block(client, h, source, "10.236.0.0/16")
    live = await _subnet(client, h, source, moved, "10.236.2.0/24")
    await _address(client, h, live, "10.236.2.10")
    trashed = await _subnet(client, h, source, moved, "10.236.1.0/24")
    await _address(client, h, trashed, "10.236.1.10")
    await _trash(client, h, f"/api/v1/ipam/subnets/{trashed}")

    preview, commit = await _move(client, h, moved, "10.236.0.0/16", target)
    assert preview.status_code == 200, preview.text
    assert commit.status_code == 200, commit.text

    # What the preview and the commit report covers the live subnet only, as before.
    live_ips = await _address_count(db_session, live)
    assert await _address_count(db_session, trashed) >= 1
    assert preview.json()["descendant_subnets_count"] == 1
    assert preview.json()["descendant_ip_addresses_total"] == live_ips
    assert commit.json()["subnets_moved"] == 1
    assert commit.json()["addresses_in_moved_subtree"] == live_ips

    assert str((await _subnet_row(db_session, live)).space_id) == target
    row = await _subnet_row(db_session, trashed)
    assert row.deleted_at is not None
    assert str(row.block_id) == moved
    assert str(row.space_id) == target, "the trashed subnet stayed in the source space"

    restore = await client.post(f"/api/v1/admin/trash/subnet/{trashed}/restore", headers=h)
    assert restore.status_code == 200, restore.text
    row = await _subnet_row(db_session, trashed)
    assert row.deleted_at is None
    assert str(row.space_id) == str((await _block_row(db_session, moved)).space_id) == target
    assert trashed in await _listed(client, h, target)
    assert trashed not in await _listed(client, h, source)


async def test_a_trashed_child_block_takes_its_subnets_along(
    client: AsyncClient, db_session: AsyncSession
):
    """A block deleted with its subnets restores whole, in one space."""
    h = await _headers(db_session)
    source = await _space(db_session)
    target = await _space(db_session)
    moved = await _block(client, h, source, "10.237.0.0/16")
    child = await _block(client, h, source, "10.237.16.0/20", moved)
    inner = await _subnet(client, h, source, child, "10.237.17.0/24")
    # A block delete takes its subnets to the Trash in the same batch.
    await _trash(client, h, f"/api/v1/ipam/blocks/{child}")
    batch_id = (await _block_row(db_session, child)).deletion_batch_id
    inner_row = await _subnet_row(db_session, inner)
    assert inner_row.deleted_at is not None
    assert batch_id is not None
    assert inner_row.deletion_batch_id == batch_id

    preview, commit = await _move(client, h, moved, "10.237.0.0/16", target)
    assert preview.status_code == 200, preview.text
    assert commit.status_code == 200, commit.text
    assert commit.json()["blocks_moved"] == 2  # the moved block and its trashed child
    assert commit.json()["subnets_moved"] == 0

    assert str((await _block_row(db_session, child)).space_id) == target
    inner_row = await _subnet_row(db_session, inner)
    assert inner_row.deleted_at is not None
    assert str(inner_row.space_id) == target, "the trashed block's subnet stayed behind"

    restore = await client.post(f"/api/v1/admin/trash/ip_block/{child}/restore", headers=h)
    assert restore.status_code == 200, restore.text
    assert restore.json()["restored"] == 2
    inner_row = await _subnet_row(db_session, inner)
    assert inner_row.deleted_at is None
    assert str(inner_row.space_id) == target
    assert inner in await _listed(client, h, target)
    assert inner not in await _listed(client, h, source)


async def test_the_restore_checks_the_moved_subnet_against_its_new_space(
    client: AsyncClient, db_session: AsyncSession
):
    """A live namesake moved with the block refuses the trashed subnet's restore."""
    h = await _headers(db_session)
    source = await _space(db_session)
    target = await _space(db_session)
    moved = await _block(client, h, source, "10.238.0.0/16")
    trashed = await _subnet(client, h, source, moved, "10.238.1.0/24")
    await _trash(client, h, f"/api/v1/ipam/subnets/{trashed}")
    # The Trash frees the CIDR (#490): a live namesake goes in under the same block.
    namesake = await _subnet(client, h, source, moved, "10.238.1.0/24")

    preview, commit = await _move(client, h, moved, "10.238.0.0/16", target)
    assert preview.status_code == 200, preview.text
    assert commit.status_code == 200, commit.text
    assert commit.json()["subnets_moved"] == 1
    assert str((await _subnet_row(db_session, namesake)).space_id) == target

    # Unfixed, this answered 200: one block then held two live 10.238.1.0/24
    # subnets, one in each space.
    restore = await client.post(f"/api/v1/admin/trash/subnet/{trashed}/restore", headers=h)
    assert restore.status_code == 409, restore.text
    assert "already exists in this space" in restore.text
    row = await _subnet_row(db_session, trashed)
    assert row.deleted_at is not None
    assert str(row.space_id) == target


async def test_a_trashed_integration_subnet_moves_and_does_not_block(
    client: AsyncClient, db_session: AsyncSession
):
    """The integration blockers still cover live rows only."""
    h = await _headers(db_session)
    source = await _space(db_session)
    target = await _space(db_session)
    controller = UnifiController(
        name=f"unifi-{uuid.uuid4().hex[:6]}", ipam_space_id=uuid.UUID(source)
    )
    db_session.add(controller)
    await db_session.flush()
    controller_id = controller.id
    moved = await _block(client, h, source, "10.239.0.0/16")
    owned = Subnet(
        space_id=uuid.UUID(source),
        block_id=uuid.UUID(moved),
        network="10.239.1.0/24",
        name="unifi-lan",
        total_ips=254,
        unifi_controller_id=controller_id,
    )
    db_session.add(owned)
    await db_session.commit()
    owned_id = str(owned.id)
    await _trash(client, h, f"/api/v1/ipam/subnets/{owned_id}")

    preview, commit = await _move(client, h, moved, "10.239.0.0/16", target)
    assert preview.status_code == 200, preview.text
    assert preview.json()["integration_blockers"] == []
    assert commit.status_code == 200, commit.text
    row = await _subnet_row(db_session, owned_id)
    assert row.deleted_at is not None
    assert row.unifi_controller_id == controller_id
    assert str(row.space_id) == target
