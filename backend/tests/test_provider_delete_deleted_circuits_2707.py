"""#2707 — soft-deleted circuits no longer pin their provider for good."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_dhcp_scope_group_immutable_2479 import _make_token


async def _setup(client: AsyncClient, db: AsyncSession):
    h = {"Authorization": f"Bearer {await _make_token(db)}"}
    await db.commit()
    r = await client.post(
        "/api/v1/providers",
        headers=h,
        json={"name": f"p-{uuid.uuid4().hex[:6]}", "kind": "transit"},
    )
    assert r.status_code in (200, 201), r.text
    pid = r.json()["id"]
    r = await client.post("/api/v1/circuits", headers=h, json={"name": "c", "provider_id": pid})
    assert r.status_code in (200, 201), r.text
    return h, pid, r.json()["id"]


async def test_live_circuit_still_blocks(client: AsyncClient, db_session: AsyncSession) -> None:
    h, pid, _ = await _setup(client, db_session)
    r = await client.delete(f"/api/v1/providers/{pid}", headers=h)
    assert r.status_code == 409, r.text


async def test_deleted_circuit_no_longer_blocks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pid, cid = await _setup(client, db_session)
    assert (await client.delete(f"/api/v1/circuits/{cid}", headers=h)).status_code == 204
    r = await client.delete(f"/api/v1/providers/{pid}", headers=h)
    assert r.status_code == 204, r.text


async def test_bulk_delete_with_deleted_circuit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pid, cid = await _setup(client, db_session)
    await client.delete(f"/api/v1/circuits/{cid}", headers=h)
    r = await client.post("/api/v1/providers/bulk-delete", headers=h, json={"ids": [pid]})
    assert r.status_code == 200, r.text
    assert r.json()["deleted"] == 1
