"""POST /users with one account's username and another's email is a 409 (#2434)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User


def _user(superadmin: bool = False) -> User:
    tag = uuid.uuid4().hex[:8]
    return User(
        username=f"u-{tag}",
        email=f"{tag}@example.com",
        display_name=tag,
        hashed_password=hash_password("pw-2434"),
        is_superadmin=superadmin,
    )


@pytest.mark.asyncio
async def test_crossed_username_and_email_is_409_not_500(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, a, b = _user(True), _user(), _user()
    db_session.add_all([admin, a, b])
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}

    def body(username: str, email: str) -> dict[str, str]:
        return {
            "username": username,
            "email": email,
            "display_name": "X",
            "password": "Str0ng-Pass-2434!xyz",
        }

    only_user = await client.post(
        "/api/v1/users", headers=headers, json=body(a.username, "new1@example.com")
    )
    only_mail = await client.post("/api/v1/users", headers=headers, json=body("new-2434", b.email))
    crossed = await client.post("/api/v1/users", headers=headers, json=body(a.username, b.email))

    assert only_user.status_code == 409, only_user.text
    assert only_mail.status_code == 409, only_mail.text
    assert crossed.status_code == 409, crossed.text
    assert "already in use" in crossed.json()["detail"]
