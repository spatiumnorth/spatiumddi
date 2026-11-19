"""#3425: placing a child under a block needs ``write`` on THAT block, in
addition to the check on the thing created or moved."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _holder(db: AsyncSession, permissions: list[dict], superadmin: bool = False) -> dict:
    user = User(
        username=f"tb-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="tb",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _grant(action: str, rtype: str, rid: uuid.UUID | None = None) -> dict:
    g: dict = {"action": action, "resource_type": rtype}
    if rid is not None:
        g["resource_id"] = str(rid)
    return g


async def _world(db: AsyncSession) -> tuple[IPSpace, IPBlock, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    a = IPBlock(space_id=space.id, network="10.0.0.0/16", name="A")
    b = IPBlock(space_id=space.id, network="10.1.0.0/16", name="B")
    db.add_all([a, b])
    await db.flush()
    return space, a, b


@pytest.mark.asyncio
async def test_create_subnet_needs_write_on_target_block(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    space, a, b = await _world(db_session)
    h = await _holder(db_session, [_grant("write", "subnet"), _grant("write", "ip_block", a.id)])
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    r = await client.post(
        "/api/v1/ipam/subnets",
        json={"space_id": str(space.id), "block_id": str(b.id), "network": "10.1.1.0/24"},
        headers=h,
    )
    assert r.status_code == 403, r.text
    # Names the block by the id sent; the caller cannot read B, so not its CIDR.
    assert str(b.id) in r.json()["detail"] and "10.1.0.0/16" not in r.json()["detail"]

    r = await client.post(
        "/api/v1/ipam/subnets",
        json={"space_id": str(space.id), "block_id": str(a.id), "network": "10.0.1.0/24"},
        headers=h,
    )
    assert r.status_code == 201, r.text

    r = await client.post(
        "/api/v1/ipam/subnets",
        json={"space_id": str(space.id), "block_id": str(b.id), "network": "10.1.1.0/24"},
        headers=sa,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_allocate_subnet_needs_write_on_target_block(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, a, b = await _world(db_session)
    h = await _holder(db_session, [_grant("write", "subnet"), _grant("write", "ip_block", a.id)])
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/blocks/{b.id}/allocate-subnet", json={"prefix_len": 24}, headers=h
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        f"/api/v1/ipam/blocks/{a.id}/allocate-subnet", json={"prefix_len": 24}, headers=h
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_move_subnet_needs_write_on_target_block(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    space, a, b = await _world(db_session)
    a2 = IPBlock(space_id=space.id, network="10.0.0.0/20", name="A2", parent_block_id=a.id)
    b2 = IPBlock(space_id=space.id, network="10.1.0.0/20", name="B2", parent_block_id=b.id)
    db_session.add_all([a2, b2])
    await db_session.flush()
    sub_a = Subnet(space_id=space.id, block_id=a.id, network="10.0.1.0/24", name="sa")
    sub_b = Subnet(space_id=space.id, block_id=b.id, network="10.1.1.0/24", name="sb")
    db_session.add_all([sub_a, sub_b])
    h = await _holder(db_session, [_grant("write", "subnet"), _grant("write", "ip_block", a2.id)])
    await db_session.commit()

    r = await client.put(
        f"/api/v1/ipam/subnets/{sub_b.id}", json={"block_id": str(b2.id)}, headers=h
    )
    assert r.status_code == 403, r.text
    assert str(b2.id) in r.json()["detail"]
    r = await client.put(
        f"/api/v1/ipam/subnets/{sub_a.id}", json={"block_id": str(a2.id)}, headers=h
    )
    assert r.status_code == 200, r.text
    # A save that leaves the parent alone is not a move.
    r = await client.put(f"/api/v1/ipam/subnets/{sub_b.id}", json={"description": "x"}, headers=h)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_space_scoped_grant_does_not_cover_blocks(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # The resolver matches ids, not ancestry: a grant on the space is not a
    # grant on its blocks, for this check as for PUT /blocks/{id}.
    space, a, _ = await _world(db_session)
    h = await _holder(
        db_session, [_grant("write", "subnet"), _grant("write", "ip_space", space.id)]
    )
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        json={"space_id": str(space.id), "block_id": str(a.id), "network": "10.0.1.0/24"},
        headers=h,
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_unscoped_block_write_covers_every_block(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    space, _, b = await _world(db_session)
    h = await _holder(db_session, [_grant("write", "subnet"), _grant("write", "ip_block")])
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        json={"space_id": str(space.id), "block_id": str(b.id), "network": "10.1.1.0/24"},
        headers=h,
    )
    assert r.status_code == 201, r.text


def test_require_target_block_write_helper() -> None:
    from fastapi import HTTPException

    from app.api.v1.ipam.router import require_target_block_write

    block = IPBlock(id=uuid.uuid4(), space_id=uuid.uuid4(), network="10.9.0.0/16", name="Z")
    other = uuid.uuid4()

    def user(perms: list[dict]) -> User:
        u = User(username="u", email="u@t.io", display_name="u", hashed_password="x")
        u.is_active = True
        role = Role(name="r", permissions=perms)
        g = Group(name="g")
        g.roles = [role]
        u.groups = [g]
        return u

    require_target_block_write(user([_grant("write", "ip_block", block.id)]), block)
    require_target_block_write(user([{"action": "*", "resource_type": "*"}]), block)
    with pytest.raises(HTTPException) as exc:
        require_target_block_write(user([_grant("write", "ip_block", other)]), block)
    # The caller cannot read the block: the refusal names only the id it sent.
    assert exc.value.status_code == 403 and str(block.id) in exc.value.detail
    assert "10.9.0.0/16" not in exc.value.detail and "(Z," not in exc.value.detail
    with pytest.raises(HTTPException) as exc:
        require_target_block_write(user([_grant("read", "ip_block", block.id)]), block)
    assert "10.9.0.0/16" in exc.value.detail


@pytest.mark.asyncio
async def test_allocate_refuses_before_describing_the_block(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # The free-space answers name the block's CIDR and what is free in it, so
    # the target check comes first, and its words keep an unreadable block's
    # CIDR and name to themselves.
    _, a, b = await _world(db_session)
    h = await _holder(db_session, [_grant("write", "subnet"), _grant("write", "ip_block", a.id)])
    await db_session.commit()
    for prefix_len in (8, 24):  # an invalid size, then a valid one
        r = await client.post(
            f"/api/v1/ipam/blocks/{b.id}/allocate-subnet",
            json={"prefix_len": prefix_len},
            headers=h,
        )
        assert r.status_code == 403, r.text
        assert str(b.id) in r.json()["detail"]
        assert "10.1.0.0/16" not in r.json()["detail"]


# ── Copilot + request portal (allocate_subnet operation) ───────────────────


async def _op_user(db: AsyncSession, permissions: list[dict]) -> tuple[User, str]:
    user = User(
        username=f"op-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="op",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user, create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_allocate_preview_reports_the_target_block_refusal(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.operations import (
        AllocateSubnetArgs,
        get_operation,
        previewing_for_requester,
    )

    _, a, b = await _world(db_session)
    op = get_operation("allocate_subnet")
    assert op is not None
    args = AllocateSubnetArgs(block_id=str(b.id), prefix_len=24)

    # Will apply, may read B, may not write it: refused, by name, as the
    # caller's own refusal (an approve leaves the request pending).
    reader, _ = await _op_user(
        db_session,
        [_grant("write", "subnet"), _grant("read", "ip_block"), _grant("write", "ip_block", a.id)],
    )
    pv = await op.preview(db_session, reader, args)
    assert not pv.ok and pv.forbidden_detail is not None
    assert "10.1.0.0/16" in pv.detail and "write" in pv.detail

    # May not read B either: answered like an unknown id.
    blind, _ = await _op_user(db_session, [_grant("write", "subnet")])
    pv = await op.preview(db_session, blind, args)
    assert not pv.ok and pv.forbidden_detail is not None
    assert "10.1.0.0/16" not in pv.detail and "not found" in pv.detail

    # A portal requester is not judged on it: the approver is.
    with previewing_for_requester():
        pv = await op.preview(db_session, reader, args)
    assert pv.ok, pv.detail

    # May write B: ready.
    writer, _ = await _op_user(
        db_session, [_grant("write", "subnet"), _grant("write", "ip_block", b.id)]
    )
    assert (await op.preview(db_session, writer, args)).ok


@pytest.mark.asyncio
async def test_portal_subnet_request_needs_target_block_write_on_the_approver(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    from sqlalchemy import select

    from app.models.feature_module import FeatureModule
    from app.services import feature_modules

    db_session.add(FeatureModule(id="governance.requests", enabled=True))
    await db_session.flush()
    feature_modules.invalidate_cache()
    _, _, b = await _world(db_session)
    requester = [
        _grant("write", "provisioning_request"),
        _grant("read", "provisioning_request"),
        _grant("read", "ip_block"),
    ]
    # A requester who writes subnets but not B still asks through the portal.
    _, req_token = await _op_user(db_session, [*requester, _grant("write", "subnet")])
    approver = [
        _grant("approve", "change_request"),
        _grant("read", "change_request"),
        _grant("write", "subnet"),
        _grant("read", "subnet"),
        _grant("read", "ip_block"),
    ]
    _, weak_token = await _op_user(db_session, approver)
    _, ok_token = await _op_user(db_session, [*approver, _grant("write", "ip_block", b.id)])
    await db_session.commit()

    r = await client.post(
        "/api/v1/requests",
        headers={"Authorization": f"Bearer {req_token}"},
        json={"kind": "subnet", "args": {"block_id": str(b.id), "prefix_len": 24}},
    )
    assert r.status_code == 201, r.text
    req_id = r.json()["id"]

    # An approver who may not write B is refused; the request waits for one
    # who may, rather than failing.
    r = await client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {weak_token}"},
        json={},
    )
    assert r.status_code == 403, r.text
    assert "10.1.0.0/16" in r.json()["detail"]
    row = await client.get(
        f"/api/v1/requests/{req_id}", headers={"Authorization": f"Bearer {weak_token}"}
    )
    assert row.json()["state"] == "pending", row.text
    assert not (await db_session.execute(select(Subnet))).scalars().all()

    r = await client.post(
        f"/api/v1/requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {ok_token}"},
        json={},
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "executed"
