"""Factory-reset catalog text and preview match what the reset does (#4615)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.main import _BUILTIN_ROLES
from app.models.auth import User, UserSession
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
