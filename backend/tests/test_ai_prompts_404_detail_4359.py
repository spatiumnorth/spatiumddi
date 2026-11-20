"""#4359 — prompt endpoints answer a missing / invisible prompt with a named 404."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


@pytest.mark.asyncio
async def test_prompt_404s_name_the_object(client: AsyncClient, db_session: AsyncSession) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    missing = uuid.uuid4()
    for method, kwargs in (
        ("get", {}),
        ("delete", {}),
        ("put", {"json": {"name": "x"}}),
    ):
        r = await getattr(client, method)(f"/api/v1/ai/prompts/{missing}", headers=h, **kwargs)
        assert r.status_code == 404, (method, r.text)
        assert r.json()["detail"] == "Prompt not found", method
