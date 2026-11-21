"""Factory-reset catalog text and preview match what the reset does (#4615)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.db import AsyncSessionLocal
from app.main import _BUILTIN_ROLES
from app.models.auth import User, UserSession
from app.models.settings import PlatformSettings
from app.services.factory_reset import runner
from app.services.factory_reset.sections import (
    FACTORY_SECTIONS_BY_KEY,
    builtin_role_names,
    section_description,
)


def test_auth_rbac_card_lists_every_builtin_role() -> None:
    assert builtin_role_names() == list(_BUILTIN_ROLES)
    desc = section_description(FACTORY_SECTIONS_BY_KEY["auth_rbac"])
    assert "{" not in desc
    for name in _BUILTIN_ROLES:
        assert name in desc
    assert "session" in desc


def test_observability_card_and_docs_name_what_is_deleted() -> None:
    section = FACTORY_SECTIONS_BY_KEY["observability_logs"]
    assert "internal_error" in section.tables
    assert "dns_threat_mute" in section.tables
    desc = section.description.lower()
    assert "mute" in desc and "captured error" in desc


async def test_auth_rbac_preview_reports_sessions_ended(db_session: AsyncSession) -> None:
    user = User(
        username="u4615",
        email="u4615@example.com",
        display_name="u",
        hashed_password="x",
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    now = datetime.now(UTC)
    db_session.add(
        UserSession(
            user_id=user.id,
            refresh_token_hash=uuid.uuid4().hex,
            created_at=now,
            expires_at=now + timedelta(days=1),
        )
    )
    await db_session.commit()
    previews = await runner.preview_factory_reset(
        db_session, section_keys=["auth_rbac"], calling_user_id=user.id
    )
    assert previews[0].table_counts["user_session"] == 1
    assert any("session" in n and "ends" in n for n in previews[0].notes)


async def test_preview_live_sessions_match_sessions_page(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The note's live number is what Administration > Sessions lists; the
    row number is the table count (revoked / expired / idle rows included)."""
    async with AsyncSessionLocal() as fresh:
        fresh.add(PlatformSettings(id=1, session_timeout_minutes=1))
        await fresh.commit()
    admin = User(
        username="a4615",
        email="a4615@example.com",
        display_name="a",
        hashed_password=hash_password("Sup3r-secret!"),
        is_superadmin=True,
    )
    db_session.add(admin)
    await db_session.flush()
    now = datetime.now(UTC)

    def _s(**kw: Any) -> UserSession:
        base: dict[str, Any] = {
            "user_id": admin.id,
            "refresh_token_hash": uuid.uuid4().hex,
            "created_at": now,
            "last_seen_at": now,
            "expires_at": now + timedelta(days=1),
        }
        base.update(kw)
        return UserSession(**base)

    db_session.add_all(
        [
            _s(),
            _s(),
            _s(revoked=True),
            _s(expires_at=now - timedelta(hours=1)),
            _s(last_seen_at=now - timedelta(hours=1)),
        ]
    )
    await db_session.commit()
    login = await client.post(
        "/api/v1/auth/login", json={"username": "a4615", "password": "Sup3r-secret!"}
    )
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    listed = await client.get("/api/v1/sessions", headers=headers)
    assert listed.status_code == 200, listed.text
    live = len(listed.json())
    assert live == 3  # two seeded + the login above

    previews = await runner.preview_factory_reset(
        db_session, section_keys=["auth_rbac"], calling_user_id=admin.id
    )
    rows = previews[0].table_counts["user_session"]
    assert rows == 6
    note = next(n for n in previews[0].notes if "login session" in n)
    assert f"{live} live session(s) end" in note
    assert f"({rows} stored session row(s) deleted)" in note
