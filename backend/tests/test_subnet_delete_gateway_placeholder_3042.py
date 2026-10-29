"""spatiumddi#3042 — a fresh subnet's permanent delete is not refused for the
Gateway row its own create added; an edited or hand-made one still blocks."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace


async def _setup(db: AsyncSession, cidr: str) -> tuple[dict[str, str], str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add_all([user, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network=cidr, name="b")
    db.add(block)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, str(space.id), str(block.id)


async def _mk(client: AsyncClient, h: dict[str, str], space: str, block: str, net: str) -> str:
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={"space_id": space, "block_id": block, "network": net, "name": "s"},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _delete(client: AsyncClient, h: dict[str, str], sid: str):
    return await client.delete(f"/api/v1/ipam/subnets/{sid}?permanent=true", headers=h)


@pytest.mark.asyncio
async def test_fresh_v4_subnet_deletes(client: AsyncClient, db_session: AsyncSession) -> None:
    h, sp, bl = await _setup(db_session, "10.224.0.0/16")
    sid = await _mk(client, h, sp, bl, "10.224.1.0/24")
    r = await _delete(client, h, sid)
    assert r.status_code == 204, r.text
    assert (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=h)).status_code == 404


@pytest.mark.asyncio
async def test_fresh_v6_subnet_deletes(client: AsyncClient, db_session: AsyncSession) -> None:
    h, sp, bl = await _setup(db_session, "2001:db8::/32")
    sid = await _mk(client, h, sp, bl, "2001:db8:1::/64")
    r = await _delete(client, h, sid)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "edit",
    [
        {"description": "core router"},
        {"hostname": "rtr1"},
        {"mac_address": "aa:bb:cc:dd:ee:ff"},
        {"status": "allocated"},
        {"tags": {"k": "v"}},
    ],
)
async def test_edited_gateway_row_still_blocks(
    client: AsyncClient, db_session: AsyncSession, edit: dict
) -> None:
    h, sp, bl = await _setup(db_session, "10.225.0.0/16")
    sid = await _mk(client, h, sp, bl, "10.225.1.0/24")
    row = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.status == "reserved"
            )
        )
    ).scalar_one()
    for k, v in edit.items():
        setattr(row, k, v)
    await db_session.commit()
    r = await _delete(client, h, sid)
    assert r.status_code == 409, r.text
    assert "1 allocated IP address" in r.json()["detail"]


@pytest.mark.asyncio
async def test_real_allocation_counts_alone(client: AsyncClient, db_session: AsyncSession) -> None:
    h, sp, bl = await _setup(db_session, "10.226.0.0/16")
    sid = await _mk(client, h, sp, bl, "10.226.1.0/24")
    db_session.add(IPAddress(subnet_id=uuid.UUID(sid), address="10.226.1.50", status="allocated"))
    await db_session.commit()
    r = await _delete(client, h, sid)
    assert r.status_code == 409, r.text
    assert "1 allocated IP address" in r.json()["detail"]


@pytest.mark.asyncio
async def test_hand_made_gateway_lookalike_elsewhere_blocks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, sp, bl = await _setup(db_session, "10.227.0.0/16")
    sid = await _mk(client, h, sp, bl, "10.227.1.0/24")
    db_session.add(
        IPAddress(
            subnet_id=uuid.UUID(sid),
            address="10.227.1.2",
            status="reserved",
            description="Gateway",
            hostname="gateway",
        )
    )
    await db_session.commit()
    r = await _delete(client, h, sid)
    assert r.status_code == 409, r.text
