"""#3354 — every IPAM soft-delete recounts the subnets and blocks it trashed.

The subnet, block and space deletes free their scopes' reservation mirrors and
recount after the soft-delete stamp. The global soft-delete filter hid the
stamped rows from that recount, so the trashed subnets and blocks kept the
counts they held before the mirrors were freed. These drive the real REST
endpoints; ``test_block_delete_recount_trashed_3354`` covers the block path at
the operation level.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from app.services.ipam.utilization import counts_toward_utilization, recount_subnets_and_blocks


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Recount Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _subnet(
    db: AsyncSession, grp: DHCPServerGroup, block: IPBlock, octet: int, *, statics: int = 3
) -> Subnet:
    """A /24 under ``block`` whose scope holds ``statics`` mirrored reservations."""
    subnet = Subnet(
        space_id=block.space_id,
        block_id=block.id,
        network=f"10.{octet}.0.0/24",
        name=f"sn{octet}",
        total_ips=254,
    )
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    for i in range(statics):
        st = DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=f"10.{octet}.0.{10 + i}",
            mac_address=f"aa:bb:cc:01:{octet:02x}:{i:02x}",
            hostname=f"h{octet}-{i}",
            description="",
        )
        db.add(st)
        await db.flush()
        await upsert_ipam_for_static(db, scope, st)
    return subnet


async def _fresh(db: AsyncSession, model: type, row_id: uuid.UUID) -> Any:
    db.expire_all()
    stmt: Any = (
        select(model)
        .where(model.id == row_id)  # type: ignore[attr-defined]
        .execution_options(include_deleted=True, populate_existing=True)
    )
    return (await db.execute(stmt)).scalar_one()


async def _rows(db: AsyncSession, subnet_id: uuid.UUID) -> int:
    return int(
        await db.scalar(
            select(func.count())
            .select_from(IPAddress)
            .where(IPAddress.subnet_id == subnet_id)
            .where(counts_toward_utilization())
        )
        or 0
    )


async def _tree(db: AsyncSession) -> tuple[DHCPServerGroup, IPSpace, IPBlock, IPBlock]:
    """space > outer /8 > inner /9."""
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([grp, space])
    await db.flush()
    outer = IPBlock(space_id=space.id, network="10.0.0.0/8", name="outer")
    db.add(outer)
    await db.flush()
    inner = IPBlock(space_id=space.id, parent_block_id=outer.id, network="10.0.0.0/9", name="in")
    db.add(inner)
    await db.flush()
    return grp, space, outer, inner


async def _seeded(db: AsyncSession, subnets: list[Subnet]) -> None:
    ids = [s.id for s in subnets]
    await recount_subnets_and_blocks(db, ids)
    await db.commit()
    for sid in ids:
        assert (await _fresh(db, Subnet, sid)).allocated_ips == 3


@pytest.mark.asyncio
async def test_subnet_delete_recounts_the_trashed_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _admin(db)
    grp, _space, _outer, inner = await _tree(db)
    s = await _subnet(db, grp, inner, 41)
    sid, inner_id = s.id, inner.id
    await _seeded(db, [s])

    resp = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=h)
    assert resp.status_code == 204, resp.text

    trashed = await _fresh(db, Subnet, sid)
    assert trashed.deleted_at is not None
    rows = await _rows(db, sid)
    assert rows < 3  # the reservation mirrors were freed
    assert trashed.allocated_ips == rows, (trashed.allocated_ips, rows)
    # The live parents stop counting it (#2412).
    assert (await _fresh(db, IPBlock, inner_id)).allocated_ips == 0


@pytest.mark.asyncio
async def test_space_delete_recounts_every_trashed_subnet_and_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db = db_session
    h = await _admin(db)
    grp, space, outer, inner = await _tree(db)
    s1 = await _subnet(db, grp, inner, 42)
    s2 = await _subnet(db, grp, outer, 200)  # directly under the outer block
    s1_id, s2_id, space_id, inner_id, outer_id = s1.id, s2.id, space.id, inner.id, outer.id
    await _seeded(db, [s1, s2])

    resp = await client.delete(f"/api/v1/ipam/spaces/{space_id}", headers=h)
    assert resp.status_code == 204, resp.text

    contrib: dict[uuid.UUID, int] = {}
    for sid in (s1_id, s2_id):
        trashed = await _fresh(db, Subnet, sid)
        assert trashed.deleted_at is not None
        rows = await _rows(db, sid)
        assert rows < 3
        assert trashed.allocated_ips == rows, (trashed.network, trashed.allocated_ips, rows)
        contrib[sid] = rows + 2  # + network and broadcast (#2982)
    t_inner = await _fresh(db, IPBlock, inner_id)
    assert t_inner.deleted_at is not None
    assert t_inner.allocated_ips == contrib[s1_id]
    t_outer = await _fresh(db, IPBlock, outer_id)
    assert t_outer.deleted_at is not None
    assert t_outer.allocated_ips == contrib[s1_id] + contrib[s2_id]


@pytest.mark.asyncio
async def test_block_delete_counts_only_its_own_batch_and_restore_recounts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A subnet trashed EARLIER (its own batch, another deleted_at) is not part
    of the block's batch: the trashed block must not count it, and restoring
    the block brings back only its own subnets, with their counts."""
    db = db_session
    h = await _admin(db)
    grp, _space, outer, inner = await _tree(db)
    s1 = await _subnet(db, grp, inner, 43)
    s_old = await _subnet(db, grp, inner, 44)
    s1_id, old_id, inner_id, outer_id = s1.id, s_old.id, inner.id, outer.id
    await _seeded(db, [s1, s_old])

    resp = await client.delete(f"/api/v1/ipam/subnets/{old_id}", headers=h)
    assert resp.status_code == 204, resp.text
    # Backdate the earlier batch so it can never share the block's timestamp.
    old = await _fresh(db, Subnet, old_id)
    old.deleted_at = old.deleted_at - timedelta(days=1)
    await db.commit()

    resp = await client.delete(f"/api/v1/ipam/blocks/{inner_id}", headers=h)
    assert resp.status_code == 204, resp.text

    rows1 = await _rows(db, s1_id)
    assert (await _fresh(db, Subnet, s1_id)).allocated_ips == rows1 < 3
    t_inner = await _fresh(db, IPBlock, inner_id)
    assert t_inner.deleted_at is not None
    assert t_inner.allocated_ips == rows1 + 2, t_inner.allocated_ips
    assert (await _fresh(db, IPBlock, outer_id)).allocated_ips == 0

    resp = await client.post(f"/api/v1/admin/trash/ip_block/{inner_id}/restore", headers=h)
    assert resp.status_code == 200, resp.text
    live = await _fresh(db, Subnet, s1_id)
    assert live.deleted_at is None
    assert live.allocated_ips == await _rows(db, s1_id) == 3
    assert (await _fresh(db, Subnet, old_id)).deleted_at is not None
    assert (await _fresh(db, IPBlock, inner_id)).allocated_ips == 3 + 2
    assert (await _fresh(db, IPBlock, outer_id)).allocated_ips == 3 + 2
