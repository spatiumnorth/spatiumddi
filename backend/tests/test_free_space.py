"""Free-space finder tests.

Exercises ``app.services.ipam.free_space.find_free_space`` plus the
``POST /api/v1/ipam/spaces/{id}/find-free`` endpoint. Real DB so
overlap arithmetic against existing IPBlock + Subnet rows is checked
end-to-end.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ipam.free_space import find_free_space


async def _make_admin(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"ff-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Free-space Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_space(db: AsyncSession, name: str | None = None) -> IPSpace:
    space = IPSpace(name=name or f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


@pytest.mark.asyncio
async def test_finds_free_in_empty_block(db_session: AsyncSession) -> None:
    """Single empty /16 block — every aligned /24 inside is fair game."""
    space = await _make_space(db_session)
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="test")
    db_session.add(block)
    await db_session.flush()

    result = await find_free_space(
        db_session,
        space_id=space.id,
        prefix_length=24,
        address_family=4,
        count=5,
    )
    assert len(result.candidates) == 5
    cidrs = [c.cidr for c in result.candidates]
    # Aligned /24s in 10.0.0.0/16, sliding-window order.
    assert cidrs == [
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.2.0/24",
        "10.0.3.0/24",
        "10.0.4.0/24",
    ]
    for c in result.candidates:
        assert c.parent_block_id == block.id
        assert c.parent_block_cidr == "10.0.0.0/16"


@pytest.mark.asyncio
async def test_skips_occupied_subnets(db_session: AsyncSession) -> None:
    """A subnet at 10.0.1.0/24 means the /24 sweep skips that one."""
    space = await _make_space(db_session)
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="test")
    db_session.add(block)
    await db_session.flush()
    db_session.add(
        Subnet(
            space_id=space.id,
            block_id=block.id,
            network="10.0.1.0/24",
            name="busy",
        )
    )
    await db_session.flush()

    result = await find_free_space(
        db_session,
        space_id=space.id,
        prefix_length=24,
        count=3,
    )
    cidrs = [c.cidr for c in result.candidates]
    assert "10.0.1.0/24" not in cidrs
    assert cidrs == ["10.0.0.0/24", "10.0.2.0/24", "10.0.3.0/24"]


@pytest.mark.asyncio
async def test_skips_occupied_child_blocks(db_session: AsyncSession) -> None:
    """A child /20 inside the parent /16 carves out its range too."""
    space = await _make_space(db_session)
    parent = IPBlock(space_id=space.id, network="10.0.0.0/16", name="parent")
    db_session.add(parent)
    await db_session.flush()
    child = IPBlock(
        space_id=space.id,
        network="10.0.0.0/20",
        name="child",
        parent_block_id=parent.id,
    )
    db_session.add(child)
    await db_session.flush()

    # /24 sweep of the PARENT block: the sub-block 10.0.0.0/20 covers
    # 10.0.0.0 through 10.0.15.255, so the first available /24 in the
    # parent is 10.0.16.0/24.
    result = await find_free_space(
        db_session,
        space_id=space.id,
        prefix_length=24,
        count=2,
        parent_block_id=parent.id,
    )
    # Subtree walk includes the parent + its child block. Within the
    # child block (which is itself empty), the first /24 candidate is
    # 10.0.0.0/24 — that's a legitimate free CIDR there. Then the parent
    # picks up at 10.0.16.0/24.
    cidrs = [c.cidr for c in result.candidates]
    assert cidrs[0] == "10.0.0.0/24"
    assert cidrs[1] == "10.0.1.0/24"


@pytest.mark.asyncio
async def test_empty_space_yields_warning(db_session: AsyncSession) -> None:
    """No blocks at all → empty list + ``summary.warning``."""
    space = await _make_space(db_session)

    result = await find_free_space(
        db_session,
        space_id=space.id,
        prefix_length=24,
    )
    assert result.candidates == []
    assert result.summary.get("warning") == "space has no blocks"


@pytest.mark.asyncio
async def test_prefix_too_wide_yields_empty(db_session: AsyncSession) -> None:
    """Asking for a /16 inside a /20 block yields nothing — a /16 wouldn't fit."""
    space = await _make_space(db_session)
    db_session.add(IPBlock(space_id=space.id, network="10.0.0.0/20", name="small"))
    await db_session.flush()

    result = await find_free_space(
        db_session,
        space_id=space.id,
        prefix_length=16,
    )
    assert result.candidates == []


@pytest.mark.asyncio
async def test_address_family_filters(db_session: AsyncSession) -> None:
    """An IPv6 block in the space is invisible to a v4 sweep."""
    space = await _make_space(db_session)
    db_session.add(IPBlock(space_id=space.id, network="2001:db8::/32", name="v6"))
    db_session.add(IPBlock(space_id=space.id, network="10.0.0.0/16", name="v4"))
    await db_session.flush()

    v4 = await find_free_space(
        db_session, space_id=space.id, prefix_length=24, address_family=4, count=2
    )
    assert all(":" not in c.cidr for c in v4.candidates)
    assert len(v4.candidates) == 2

    v6 = await find_free_space(
        db_session, space_id=space.id, prefix_length=64, address_family=6, count=2
    )
    assert all(":" in c.cidr for c in v6.candidates)
    assert len(v6.candidates) == 2


@pytest.mark.asyncio
async def test_count_capped_at_100(db_session: AsyncSession) -> None:
    """Even when the caller asks for 9999, we never return more than 100."""
    space = await _make_space(db_session)
    db_session.add(IPBlock(space_id=space.id, network="10.0.0.0/8", name="huge"))
    await db_session.flush()

    result = await find_free_space(db_session, space_id=space.id, prefix_length=24, count=9999)
    assert len(result.candidates) == 100


@pytest.mark.asyncio
async def test_parent_block_id_restricts_sweep(db_session: AsyncSession) -> None:
    """When parent_block_id is set, only candidates from that subtree
    are considered — not other top-level blocks in the same space."""
    space = await _make_space(db_session)
    a = IPBlock(space_id=space.id, network="10.0.0.0/16", name="a")
    b = IPBlock(space_id=space.id, network="172.16.0.0/16", name="b")
    db_session.add_all([a, b])
    await db_session.flush()

    result = await find_free_space(
        db_session,
        space_id=space.id,
        prefix_length=24,
        count=200,
        parent_block_id=a.id,
    )
    for c in result.candidates:
        assert c.cidr.startswith("10.")
        assert c.parent_block_id == a.id


@pytest.mark.asyncio
async def test_endpoint_smoke(client: AsyncClient, db_session: AsyncSession) -> None:
    """End-to-end through HTTP, including auth + permission gate."""
    _, token = await _make_admin(db_session)
    space = await _make_space(db_session)
    db_session.add(IPBlock(space_id=space.id, network="10.0.0.0/16", name="b"))
    await db_session.flush()

    resp = await client.post(
        f"/api/v1/ipam/spaces/{space.id}/find-free",
        headers={"Authorization": f"Bearer {token}"},
        json={"prefix_length": 24, "count": 3},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["candidates"]) == 3
    assert body["candidates"][0]["cidr"] == "10.0.0.0/24"
    assert body["summary"]["candidates_emitted"] == 3


@pytest.mark.asyncio
async def test_endpoint_validates_prefix(client: AsyncClient, db_session: AsyncSession) -> None:
    """Out-of-range prefix is a 422 (pydantic validation)."""
    _, token = await _make_admin(db_session)
    space = await _make_space(db_session)

    resp = await client.post(
        f"/api/v1/ipam/spaces/{space.id}/find-free",
        headers={"Authorization": f"Bearer {token}"},
        json={"prefix_length": 7, "count": 1},  # /7 is below the 8 floor
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_endpoint_rejects_cross_space_block_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """parent_block_id from a different space → 404."""
    _, token = await _make_admin(db_session)
    space_a = await _make_space(db_session)
    space_b = await _make_space(db_session)
    block_in_b = IPBlock(space_id=space_b.id, network="10.0.0.0/16", name="b-block")
    db_session.add(block_in_b)
    await db_session.flush()

    resp = await client.post(
        f"/api/v1/ipam/spaces/{space_a.id}/find-free",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "prefix_length": 24,
            "count": 1,
            "parent_block_id": str(block_in_b.id),
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_candidates_carry_free_addresses_and_min_filter(
    db_session: AsyncSession,
) -> None:
    """Every candidate reports its usable addresses; min_free_addresses
    filters on that (0 never returns fewer than no filter) (#2418)."""
    space = await _make_space(db_session)
    db_session.add(IPBlock(space_id=space.id, network="10.0.0.0/16", name="t"))
    await db_session.flush()

    kw = dict(space_id=space.id, prefix_length=24, address_family=4, count=5)
    base = await find_free_space(db_session, **kw)
    assert len(base.candidates) == 5
    assert all(c.free_addresses == 254 for c in base.candidates)

    zero = await find_free_space(db_session, min_free_addresses=0, **kw)
    assert len(zero.candidates) == 5
    ok = await find_free_space(db_session, min_free_addresses=254, **kw)
    assert len(ok.candidates) == 5
    none = await find_free_space(db_session, min_free_addresses=255, **kw)
    assert none.candidates == []
