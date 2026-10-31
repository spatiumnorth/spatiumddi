"""#3203 — a missing ``platform_settings`` row must behave like the shipped
defaults, not like a hardcoded weaker fallback.

The singleton row is created lazily, so a fresh k8s / Compose install runs its
forced first-login password change before any row exists.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import session_idle
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.account_lockout import LockoutPolicy
from app.services.password_policy import PasswordPolicy

pytestmark = pytest.mark.asyncio


async def test_password_policy_fallback_equals_a_fresh_row() -> None:
    fresh = PlatformSettings()
    # An un-flushed instance carries no column defaults yet; apply them the
    # way the INSERT would, from the mapped columns.
    from app.models.settings import platform_setting_default as d

    for col in PlatformSettings.__table__.c:
        if col.name.startswith(("password_", "lockout_")):
            setattr(fresh, col.name, d(col.name))
    assert PasswordPolicy.from_row(None) == PasswordPolicy.from_row(fresh)
    assert PasswordPolicy.from_row(None).min_length == 12


async def test_lockout_fallback_equals_column_defaults() -> None:
    from app.models.settings import platform_setting_default as d

    assert LockoutPolicy.from_row(None) == LockoutPolicy(
        threshold=d("lockout_threshold"),
        duration_minutes=d("lockout_duration_minutes"),
        reset_minutes=d("lockout_reset_minutes"),
    )


async def _no_row(db: AsyncSession) -> None:
    await db.execute(delete(PlatformSettings))
    await db.commit()


async def test_policy_endpoint_reports_shipped_default_with_no_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _no_row(db_session)
    r = await client.get("/api/v1/auth/password-policy")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["min_length"] == 12
    assert body["require_uppercase"] and body["require_lowercase"] and body["require_digit"]


async def test_change_password_refuses_eight_chars_with_no_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("OldPass123!"),
        auth_source="local",
        is_active=True,
    )
    db_session.add(u)
    await db_session.commit()
    await _no_row(db_session)

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123!", "new_password": "Abcdef12"},
        headers={"Authorization": f"Bearer {create_access_token(str(u.id))}"},
    )
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail["reason"] == "password_policy"
    assert any("12" in e for e in detail["errors"]), detail


async def test_idle_timeout_with_no_row_is_the_column_default(db_session: AsyncSession) -> None:
    await _no_row(db_session)
    session_idle.invalidate_cache()
    from app.models.settings import platform_setting_default as d

    assert await session_idle.get_session_timeout_minutes(db_session) == d(
        "session_timeout_minutes"
    )
    assert d("session_timeout_minutes") == 60
    session_idle.invalidate_cache()
