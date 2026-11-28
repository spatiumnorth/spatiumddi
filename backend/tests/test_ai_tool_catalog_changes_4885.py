"""PUT /ai/tools/catalog ``changes`` merges into the stored list (#4885)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.ai.tools import REGISTRY

pytestmark = pytest.mark.asyncio

URL = "/api/v1/ai/tools/catalog"


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="Root",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _defaults() -> list[str]:
    return sorted(t.name for t in REGISTRY.all() if t.default_enabled and not t.writes)


async def test_change_keeps_another_clients_earlier_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    x, y = _defaults()[:2]
    # Another client turns X off.
    r = await client.put(URL, json={"changes": {x: False}}, headers=h)
    assert r.status_code == 200
    # A page that never saw that switches Y.
    r = await client.put(URL, json={"changes": {y: False}}, headers=h)
    assert r.status_code == 200
    by = {t["name"]: t["enabled"] for t in r.json()["tools"]}
    assert by[x] is False and by[y] is False
    assert x not in r.json()["platform_override"]


async def test_change_keeps_stored_state_of_a_tool_not_named(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    keep = _defaults()
    r = await client.put(URL, json={"changes": {keep[0]: False}}, headers=h)
    assert set(r.json()["platform_override"]) == set(keep[1:])


async def test_change_refuses_unknown_and_both_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    r = await client.put(URL, json={"changes": {"no_such_tool": True}}, headers=h)
    assert r.status_code == 422 and "no_such_tool" in r.json()["detail"]
    r = await client.put(URL, json={"changes": {}, "enabled": []}, headers=h)
    assert r.status_code == 422
