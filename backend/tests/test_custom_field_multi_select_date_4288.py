"""#4288 — ``multi_select`` and ``date`` custom field types are definable and enforced."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace


async def _setup(db: AsyncSession) -> tuple[dict[str, str], str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="top")
    db.add(block)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, str(space.id), str(block.id)


async def _define(client: AsyncClient, headers, name, field_type, options=None):
    return await client.post(
        "/api/v1/custom-fields",
        headers=headers,
        json={
            "resource_type": "subnet",
            "name": name,
            "label": name.title(),
            "field_type": field_type,
            "options": options,
        },
    )


async def _subnet(client, headers, sp, blk, net, **cf):
    return await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={"space_id": sp, "block_id": blk, "network": net, "name": net, "custom_fields": cf},
    )


async def test_define_multi_select_and_date(client: AsyncClient, db_session: AsyncSession):
    headers, _, _ = await _setup(db_session)
    r = await _define(client, headers, "sites", "multi_select", ["a", "b", "c"])
    assert r.status_code == 201, r.text
    assert r.json()["options"] == ["a", "b", "c"]
    r = await _define(client, headers, "renewal", "date")
    assert r.status_code == 201, r.text


async def test_multi_select_requires_options(client: AsyncClient, db_session: AsyncSession):
    headers, _, _ = await _setup(db_session)
    assert (await _define(client, headers, "sites", "multi_select")).status_code == 422
    assert (await _define(client, headers, "sites", "multi_select", [])).status_code == 422


async def test_multi_select_value_validated(client: AsyncClient, db_session: AsyncSession):
    headers, sp, blk = await _setup(db_session)
    await _define(client, headers, "sites", "multi_select", ["a", "b"])
    ok = await _subnet(client, headers, sp, blk, "10.1.0.0/24", sites=["a", "b"])
    assert ok.status_code == 201, ok.text
    assert ok.json()["custom_fields"]["sites"] == ["a", "b"]
    bad = await _subnet(client, headers, sp, blk, "10.2.0.0/24", sites=["a", "z"])
    assert bad.status_code == 422
    assert "z" in bad.text
    notlist = await _subnet(client, headers, sp, blk, "10.3.0.0/24", sites="a")
    assert notlist.status_code == 422
    # Update path too.
    sid = ok.json()["id"]
    upd = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {"sites": ["q"]}}
    )
    assert upd.status_code == 422
    clear = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {"sites": None}}
    )
    assert clear.status_code == 200, clear.text


async def test_date_value_validated(client: AsyncClient, db_session: AsyncSession):
    headers, sp, blk = await _setup(db_session)
    await _define(client, headers, "renewal", "date")
    ok = await _subnet(client, headers, sp, blk, "10.1.0.0/24", renewal="2026-12-31")
    assert ok.status_code == 201, ok.text
    for i, v in enumerate(["next tuesday", "2026-13-40", "31/12/2026", 20261231]):
        bad = await _subnet(client, headers, sp, blk, f"10.{i + 2}.0.0/24", renewal=v)
        assert bad.status_code == 422, v
