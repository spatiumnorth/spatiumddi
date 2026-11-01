"""#3203 — a missing ``platform_settings`` row must behave like the shipped
defaults, not like a hardcoded weaker fallback.

The singleton row is created lazily, so a fresh k8s / Compose install runs its
forced first-login password change before any row exists.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import session_idle
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.settings import PlatformSettings, platform_setting_default
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


async def test_fallbacks_equal_a_row_the_orm_inserts(db_session: AsyncSession) -> None:
    """The fallbacks must equal what a real insert stores — the row every
    get-or-create path writes is ``PlatformSettings(id=1)`` (or with one field
    set, as supervisor self-bootstrap does), and the ORM fills the rest."""
    await _no_row(db_session)
    no_row_password = PasswordPolicy.from_row(None)
    no_row_lockout = LockoutPolicy.from_row(None)
    session_idle.invalidate_cache()
    no_row_idle = await session_idle.get_session_timeout_minutes(db_session)

    db_session.add(PlatformSettings(id=1, supervisor_registration_enabled=True))
    await db_session.commit()
    row = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(row)
    session_idle.invalidate_cache()

    assert PasswordPolicy.from_row(row) == no_row_password
    assert LockoutPolicy.from_row(row) == no_row_lockout
    assert await session_idle.get_session_timeout_minutes(db_session) == no_row_idle
    session_idle.invalidate_cache()


async def test_stored_zero_idle_timeout_still_disables(db_session: AsyncSession) -> None:
    await _no_row(db_session)
    db_session.add(PlatformSettings(id=1, session_timeout_minutes=0))
    await db_session.commit()
    session_idle.invalidate_cache()
    assert await session_idle.get_session_timeout_minutes(db_session) == 0
    session_idle.invalidate_cache()


_CALL_SITE = re.compile(r'(?:platform_setting_default|\bd)\(\s*"([a-z0-9_]+)"\s*\)')


def test_every_helper_call_site_resolves_and_agrees_with_server_default() -> None:
    """``platform_setting_default`` raises for a column it cannot read (no
    default, a callable, a SQL expression). Resolve every name the app asks
    for here, so a default changed to one of those fails CI rather than the
    first login on a fresh install. Where the column also has a
    ``server_default`` the two must agree: upgrades backfill from the server
    default, fresh installs insert the ORM default."""
    app_dir = Path(__file__).resolve().parents[1] / "app"
    names: set[str] = set()
    for path in app_dir.rglob("*.py"):
        text = path.read_text()
        if "platform_setting_default" in text and path.name != "settings.py":
            names.update(_CALL_SITE.findall(text))
    assert {"password_min_length", "lockout_threshold", "session_timeout_minutes"} <= names

    for name in sorted(names):
        value = platform_setting_default(name)
        server_default = PlatformSettings.__table__.c[name].server_default
        if server_default is None:
            continue
        text = str(
            server_default.arg.text if hasattr(server_default.arg, "text") else server_default.arg
        )
        expected = str(value).lower() if isinstance(value, bool) else str(value)
        assert text.strip("'").lower() == expected.lower(), (name, value, text)


def test_helper_refuses_a_column_it_cannot_read() -> None:
    # A column with no ORM default, and one whose default is a callable.
    no_default = next(c.name for c in PlatformSettings.__table__.c if c.default is None)
    with pytest.raises(LookupError):
        platform_setting_default(no_default)
    callable_col = next(
        c.name
        for c in PlatformSettings.__table__.c
        if c.default is not None and not c.default.is_scalar
    )
    with pytest.raises(LookupError):
        platform_setting_default(callable_col)
