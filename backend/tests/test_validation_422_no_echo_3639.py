"""A 422 never carries the value the client submitted (#3639)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User

SECRET = "Zq9-never-echo-this-passphrase-" + "x" * 600


async def _token(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password(uuid.uuid4().hex),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_overlong_backup_passphrase_is_not_echoed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _token(db_session)}"}
    r = await client.post(
        "/api/v1/backup/create-and-download",
        headers=h,
        data={"passphrase": SECRET, "passphrase_hint": ""},
    )
    assert r.status_code == 422, r.text
    assert "never-echo" not in r.text
    d = r.json()["detail"]
    assert d[0]["type"] == "string_too_long"
    assert d[0]["loc"] == ["body", "passphrase"]
    assert d[0]["ctx"] == {"max_length": 512}


@pytest.mark.asyncio
async def test_secret_field_on_another_route_is_not_echoed(client: AsyncClient) -> None:
    r = await client.post(
        "/api/v1/auth/login",
        json={"username": "someone", "password": {"value": "never-echo-secret"}},
    )
    assert r.status_code == 422, r.text
    assert "never-echo" not in r.text


@pytest.mark.asyncio
async def test_422_entry_shape_is_pinned(client: AsyncClient) -> None:
    r = await client.post("/api/v1/auth/login", json={"username": 1, "password": 2})
    assert r.status_code == 422
    for entry in r.json()["detail"]:
        assert "input" not in entry
        assert {"type", "loc", "msg"} <= set(entry)
        assert set(entry) <= {"type", "loc", "msg", "ctx", "url"}
