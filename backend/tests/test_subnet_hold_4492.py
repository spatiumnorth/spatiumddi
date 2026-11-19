"""Subnet holds (#4492): a held CIDR blocks subnet creation until released."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.subnet_hold import SubnetHold
from app.services.ai.tools import REGISTRY


@pytest_asyncio.fixture
async def auth_headers(db_session: AsyncSession) -> dict:
    user = User(
        username=f"hold-{uuid.uuid4().hex[:8]}",
        email=f"hold-{uuid.uuid4().hex[:8]}@t.io",
        display_name="hold admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _space_block(db: AsyncSession) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    return space, block


def _future(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


async def test_hold_blocks_subnet_create_until_released(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
) -> None:
    space, block = await _space_block(db_session)
    r = await client.post(
        "/api/v1/ipam/holds",
        json={
            "space_id": str(space.id),
            "network": "10.0.8.0/22",
            "reason": "Project Falcon",
            "expires_at": _future(),
        },
        headers=auth_headers,
    )
    assert r.status_code == 201, r.text
    hold = r.json()
    assert hold["status"] == "active" and hold["expired"] is False
    # No placeholder rows, no subnet.
    assert (await db_session.execute(select(Subnet))).first() is None
    assert (await db_session.execute(select(IPAddress))).first() is None

    body = {"space_id": str(space.id), "block_id": str(block.id), "network": "10.0.9.0/24"}
    r = await client.post("/api/v1/ipam/subnets", json=body, headers=auth_headers)
    assert r.status_code == 409 and "hold" in r.json()["detail"]

    # An overlapping hold is refused too.
    r = await client.post(
        "/api/v1/ipam/holds",
        json={"space_id": str(space.id), "network": "10.0.9.0/24", "reason": "x"},
        headers=auth_headers,
    )
    assert r.status_code == 409

    r = await client.post(f"/api/v1/ipam/holds/{hold['id']}/release", headers=auth_headers)
    assert r.status_code == 200 and r.json()["status"] == "released"
    r = await client.post("/api/v1/ipam/subnets", json=body, headers=auth_headers)
    assert r.status_code == 201, r.text

    actions = (
        (
            await db_session.execute(
                select(AuditLog.action).where(AuditLog.resource_type == "subnet_hold")
            )
        )
        .scalars()
        .all()
    )
    assert set(actions) == {"create", "release"}


async def test_expired_hold_still_blocks_and_is_flagged(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
) -> None:
    space, block = await _space_block(db_session)
    row = SubnetHold(
        space_id=space.id,
        block_id=block.id,
        network="10.0.4.0/24",
        reason="old",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    db_session.add(row)
    await db_session.commit()

    r = await client.get("/api/v1/ipam/holds?expired=true", headers=auth_headers)
    assert [h["id"] for h in r.json()] == [str(row.id)]
    assert r.json()[0]["expired"] is True
    body = {"space_id": str(space.id), "block_id": str(block.id), "network": "10.0.4.0/25"}
    r = await client.post("/api/v1/ipam/subnets", json=body, headers=auth_headers)
    assert r.status_code == 409
    # Never deleted by itself.
    assert await db_session.get(SubnetHold, row.id) is not None


async def test_convert_hold_creates_subnet(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
) -> None:
    space, _ = await _space_block(db_session)
    r = await client.post(
        "/api/v1/ipam/holds",
        json={"space_id": str(space.id), "network": "10.0.20.0/24", "reason": "r"},
        headers=auth_headers,
    )
    hid = r.json()["id"]
    r = await client.post(
        f"/api/v1/ipam/holds/{hid}/convert", json={"name": "falcon"}, headers=auth_headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "converted" and r.json()["converted_subnet_id"]
    sub = await db_session.get(Subnet, uuid.UUID(r.json()["converted_subnet_id"]))
    assert sub is not None and str(sub.network) == "10.0.20.0/24"


async def test_hold_validation_and_permissions(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
) -> None:
    space, _ = await _space_block(db_session)
    for net, exp in (("192.168.0.0/24", None), ("10.0.1.0/24", "2001-01-01T00:00:00Z")):
        r = await client.post(
            "/api/v1/ipam/holds",
            json={"space_id": str(space.id), "network": net, "reason": "r", "expires_at": exp},
            headers=auth_headers,
        )
        assert r.status_code == 422, r.text
    r = await client.get("/api/v1/ipam/holds")
    assert r.status_code in (401, 403)


def test_mcp_tools_registered() -> None:
    for name in ("find_subnet_holds", "count_subnet_holds", "propose_subnet_hold"):
        assert REGISTRY.get(name) is not None
