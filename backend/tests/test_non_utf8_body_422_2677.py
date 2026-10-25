"""A non-UTF-8 request body is a 422, not a 500 (#2677)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


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
@pytest.mark.parametrize("ctype", [None, "", "text/plain", "application/octet-stream"])
async def test_non_utf8_body_is_422(
    client: AsyncClient, db_session: AsyncSession, ctype: str | None
) -> None:
    from app.models.diagnostics import InternalError  # noqa: PLC0415

    h = {"Authorization": f"Bearer {await _token(db_session)}"}
    if ctype is not None:
        h["Content-Type"] = ctype
    before = (await db_session.execute(select(func.count()).select_from(InternalError))).scalar()
    r = await client.post("/api/v1/custom-fields", headers=h, content=b"\x80\xff")
    assert r.status_code == 422, r.text
    assert isinstance(r.json()["detail"], list)
    after = (await db_session.execute(select(func.count()).select_from(InternalError))).scalar()
    assert after == before


@pytest.mark.asyncio
async def test_ordinary_validation_422_body_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _token(db_session)}"}
    r = await client.post("/api/v1/custom-fields", headers=h, json={"name": 1})
    assert r.status_code == 422
    d = r.json()["detail"]
    assert d and {"type", "loc", "msg", "input"} <= set(d[0])
    assert d[0]["loc"][0] == "body"
    # Valid-UTF-8 undecodable-JSON bytes still render as the same text.
    r = await client.post(
        "/api/v1/custom-fields",
        headers={**h, "Content-Type": "application/json"},
        content=b"{bad",
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "json_invalid"
