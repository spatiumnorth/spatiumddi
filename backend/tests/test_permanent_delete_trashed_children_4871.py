"""A permanent delete refuses while a child of the target sits in the Trash (#4871).

The not-empty checks went through the soft-delete filter, so a trashed DHCP
scope / block / subnet was invisible to them and the FK cascade took it with no
audit row.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace
from tests.test_approval_workflows import _auth, _subnet, _user


async def _su(db: AsyncSession) -> dict[str, str]:
    _, token = await _user(db, name="su", superadmin=True)
    return _auth(token)


@pytest.mark.asyncio
async def test_subnet_refused_while_scope_in_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet = await _subnet(db_session)
    group = DHCPServerGroup(name="g")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    scope.deleted_at = datetime.now(UTC)
    await db_session.commit()

    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}?permanent=true", headers=await _su(db_session)
    )
    assert r.status_code == 409, r.text
    assert "1 DHCP scope" in r.json()["detail"]


@pytest.mark.asyncio
async def test_block_and_space_refused_while_child_in_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space = IPSpace(name="sp-4871")
    db_session.add(space)
    await db_session.flush()
    parent = IPBlock(space_id=space.id, network="10.9.0.0/23", name="p")
    db_session.add(parent)
    await db_session.flush()
    child = IPBlock(space_id=space.id, parent_block_id=parent.id, network="10.9.0.0/24", name="c")
    db_session.add(child)
    await db_session.flush()
    child.deleted_at = datetime.now(UTC)
    await db_session.commit()
    h = await _su(db_session)

    r = await client.delete(f"/api/v1/ipam/blocks/{parent.id}?permanent=true", headers=h)
    assert r.status_code == 409, r.text
    assert "child block" in r.json()["detail"]

    # The space holds the parent live; trash it too so only trashed blocks remain.
    parent.deleted_at = datetime.now(UTC)
    await db_session.commit()
    r = await client.delete(f"/api/v1/ipam/spaces/{space.id}?permanent=true", headers=h)
    assert r.status_code == 409, r.text
    assert "2 block" in r.json()["detail"]
