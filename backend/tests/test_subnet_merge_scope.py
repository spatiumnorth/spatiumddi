"""Every subnet a merge names must pass the per-subnet write check."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace, Subnet
from tests.test_ipam_subnet_scoped_grant import _rw, _user
from tests.test_token_path_scope_sweep import _owner, _token


async def _pair(db: AsyncSession) -> tuple[Subnet, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    a = Subnet(space_id=space.id, block_id=block.id, network="10.0.0.0/25", name="a", total_ips=126)
    b = Subnet(
        space_id=space.id, block_id=block.id, network="10.0.0.128/25", name="b", total_ips=126
    )
    db.add_all([a, b])
    await db.flush()
    return a, b


async def _bound_token(db: AsyncSession, subnet: Subnet) -> dict[str, str]:
    owner = await _owner(db)
    tok = await _token(
        db, owner, [{"action": "*", "resource_type": "subnet", "resource_id": str(subnet.id)}]
    )
    return {"Authorization": f"Bearer {tok}"}


def _url(s: Subnet, leaf: str) -> str:
    return f"/api/v1/ipam/subnets/{s.id}/merge/{leaf}"


@pytest.mark.asyncio
async def test_bound_token_cannot_name_an_unbound_sibling(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    a, b = await _pair(db_session)
    hdr = await _bound_token(db_session, a)
    await db_session.commit()

    r = await client.post(_url(a, "preview"), json={"sibling_subnet_ids": [str(b.id)]}, headers=hdr)
    assert r.status_code == 403, r.text
    assert str(b.id) not in r.text and "10.0.0.128" not in r.text
    r = await client.post(
        _url(a, "commit"),
        json={"sibling_subnet_ids": [str(b.id)], "confirm_cidr": "10.0.0.0/24"},
        headers=hdr,
    )
    assert r.status_code == 403, r.text
    rows = (await db_session.execute(select(Subnet.id))).scalars().all()
    assert {a.id, b.id} <= set(rows)


@pytest.mark.asyncio
async def test_missing_and_forbidden_sibling_answer_identically(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    a, b = await _pair(db_session)
    hdr = await _bound_token(db_session, a)
    await db_session.commit()

    answers = []
    for sid in (b.id, uuid.uuid4()):
        r = await client.post(
            _url(a, "preview"), json={"sibling_subnet_ids": [str(sid)]}, headers=hdr
        )
        answers.append((r.status_code, r.json()))
    assert answers[0] == answers[1]
    assert answers[0][0] == 403


@pytest.mark.asyncio
async def test_rbac_user_without_write_on_sibling_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    a, b = await _pair(db_session)
    hdr = await _user(db_session, _rw(a))
    await db_session.commit()

    for leaf, extra in (("preview", {}), ("commit", {"confirm_cidr": "10.0.0.0/24"})):
        r = await client.post(
            _url(a, leaf), json={"sibling_subnet_ids": [str(b.id)], **extra}, headers=hdr
        )
        assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_token_bound_to_both_subnets_can_merge(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    a, b = await _pair(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [
            {"action": "*", "resource_type": "subnet", "resource_id": str(a.id)},
            {"action": "*", "resource_type": "subnet", "resource_id": str(b.id)},
        ],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {tok}"}
    r = await client.post(_url(a, "preview"), json={"sibling_subnet_ids": [str(b.id)]}, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["merged_cidr"] == "10.0.0.0/24"
