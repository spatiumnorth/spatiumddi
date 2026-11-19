"""spatiumddi#2733 — a DHCP scope restored from the Trash passes #844's group-wide prefix guard.

Scope A (space 1's /24) trashed, scope B created on the same /24 of space 2 in
the same group: restoring A active used to answer 200 and leave two active
scopes on one prefix, of which the bundle builder silently kept the older A.
The restore now refuses with #844's reason, whichever row brings A back.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServerGroup
from tests.test_overlap_guards import _make_token, _space_subnet

CIDR = "10.159.1.0/24"


async def _setup(client: AsyncClient, db: AsyncSession):  # type: ignore[no-untyped-def]
    h = {"Authorization": f"Bearer {await _make_token(db)}"}
    sub_a = await _space_subnet(db, CIDR)
    sub_b = await _space_subnet(db, CIDR)
    grp = DHCPServerGroup(name=f"g2733-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    await db.commit()
    r = await client.post(
        f"/api/v1/dhcp/subnets/{sub_a.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "a"},
    )
    assert r.status_code == 201, r.text
    scope_a = r.json()["id"]
    # Positive control: #844 refuses B while A is active.
    r = await client.post(
        f"/api/v1/dhcp/subnets/{sub_b.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "b"},
    )
    assert r.status_code == 409, r.text
    return h, grp, sub_a, sub_b, scope_a


async def _active_scopes(db: AsyncSession, group_id: uuid.UUID) -> list[str]:
    rows = (
        await db.execute(
            select(DHCPScope.name)
            .where(DHCPScope.group_id == group_id, DHCPScope.is_active.is_(True))
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted(r[0] for r in rows)


@pytest.mark.asyncio
async def test_scope_restore_refuses_an_overlap_with_a_scope_created_meanwhile(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp, _sub_a, sub_b, scope_a = await _setup(client, db_session)
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_a}", headers=h)
    assert r.status_code == 204, r.text
    r = await client.post(
        f"/api/v1/dhcp/subnets/{sub_b.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "b"},
    )
    assert r.status_code == 201, r.text

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_a}/restore", headers=h)
    assert r.status_code == 409, r.text
    reasons = [c["reason"] for c in r.json()["detail"]["conflicts"]]
    assert any("#844" in reason for reason in reasons), reasons
    assert await _active_scopes(db_session, grp.id) == ["b"]


@pytest.mark.asyncio
async def test_scope_restore_with_its_subnet_refuses_the_overlap_too(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A comes back with its subnet's row: the same guard."""
    h, grp, sub_a, sub_b, _scope_a = await _setup(client, db_session)
    r = await client.delete(f"/api/v1/ipam/subnets/{sub_a.id}", headers=h)
    assert r.status_code == 204, r.text
    r = await client.post(
        f"/api/v1/dhcp/subnets/{sub_b.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "b"},
    )
    assert r.status_code == 201, r.text

    r = await client.post(f"/api/v1/admin/trash/subnet/{sub_a.id}/restore", headers=h)
    assert r.status_code == 409, r.text
    assert await _active_scopes(db_session, grp.id) == ["b"]


@pytest.mark.asyncio
async def test_scope_restore_without_an_overlap_still_restores(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Control: B was never created, or is inactive — A comes back."""
    h, grp, _sub_a, sub_b, scope_a = await _setup(client, db_session)
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_a}", headers=h)
    assert r.status_code == 204, r.text
    # An INACTIVE scope on the prefix renders nothing and is no clash.
    r = await client.post(
        f"/api/v1/dhcp/subnets/{sub_b.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "b", "is_active": False},
    )
    assert r.status_code == 201, r.text

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_a}/restore", headers=h)
    assert r.status_code == 200, r.text
    assert await _active_scopes(db_session, grp.id) == ["a"]
