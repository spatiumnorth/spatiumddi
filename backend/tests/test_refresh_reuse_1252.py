"""Refresh-token reuse detection and the absolute session lifetime (#1252)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import hash_refresh_token
from app.models.audit import AuditLog
from app.models.auth import UserSession
from tests.test_fix_m3_m4_auth_session import _ensure_settings, _user
from tests.test_refresh_rotation_grace_2941 import (  # noqa: F401 — autouse fixture
    _backdate_rotation,
    _cookie_from,
    _login,
    _me,
    _no_login_rate_limit,
    _refresh_with,
    _rotated,
    _row,
)

_PASSWORD = "OldPass123!"


async def _live_count(db: AsyncSession, user) -> int:
    return len(
        (
            await db.execute(
                select(UserSession.id)
                .where(UserSession.user_id == user.id, UserSession.revoked.is_(False))
                .execution_options(populate_existing=True)
            )
        ).all()
    )


async def _reuse_audits(db: AsyncSession) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog).where(AuditLog.action == "session.refresh_reuse_detected")
            )
        ).scalars()
    )


async def test_normal_rotation_still_works(client: AsyncClient, db_session: AsyncSession) -> None:
    user, _ca, _ta, cookie_b, token_b = await _rotated(client, db_session)
    r = await _refresh_with(client, cookie_b)
    assert r.status_code == 200, r.text
    assert await _me(client, r.json()["access_token"]) == 200
    assert await _reuse_audits(db_session) == []


async def test_reuse_after_grace_revokes_the_family_and_audits(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, _ta, cookie_b, token_b = await _rotated(client, db_session)
    await _backdate_rotation(db_session, cookie_a)
    assert await _live_count(db_session, user) == 1

    r = await _refresh_with(client, cookie_a)
    assert r.status_code == 401
    # The legitimate holder's successor died with it.
    assert await _live_count(db_session, user) == 0
    assert (await _refresh_with(client, cookie_b)).status_code == 401
    assert await _me(client, token_b) == 401
    audits = await _reuse_audits(db_session)
    assert len(audits) == 1
    assert audits[0].user_id == user.id
    assert audits[0].new_value["family_revoked"] is True


async def test_reuse_follows_a_longer_chain(client: AsyncClient, db_session: AsyncSession) -> None:
    user, cookie_a, _ta, cookie_b, _tb = await _rotated(client, db_session)
    await _backdate_rotation(db_session, cookie_a)
    r = await _refresh_with(client, cookie_b)
    assert r.status_code == 200
    cookie_c = _cookie_from(r)
    await _backdate_rotation(db_session, cookie_b)

    assert (await _refresh_with(client, cookie_a)).status_code == 401
    assert await _live_count(db_session, user) == 0
    assert (await _refresh_with(client, cookie_c)).status_code == 401


async def test_reuse_inside_grace_is_not_theft(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, _ta, cookie_b, _tb = await _rotated(client, db_session)
    r = await _refresh_with(client, cookie_a)
    assert r.status_code == 200
    assert await _live_count(db_session, user) == 1
    assert await _reuse_audits(db_session) == []
    assert (await _refresh_with(client, cookie_b)).status_code == 200


async def test_reuse_does_not_touch_other_sessions_of_the_user(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, _ta, _cb, _tb = await _rotated(client, db_session)
    _tok, other_cookie = await _login(client, user)
    await _backdate_rotation(db_session, cookie_a)
    assert (await _refresh_with(client, cookie_a)).status_code == 401
    assert (await _refresh_with(client, other_cookie)).status_code == 200


async def test_session_past_the_absolute_lifetime_is_refused(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "session_absolute_max_days", 30)
    await _ensure_settings(db_session)
    user = await _user(db_session, password=_PASSWORD)
    await db_session.commit()
    _t, cookie = await _login(client, user)
    await db_session.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie))
        .values(created_at=datetime.now(UTC) - timedelta(days=31))
    )
    await db_session.commit()
    assert (await _refresh_with(client, cookie)).status_code == 401


async def test_rotation_never_extends_past_the_absolute_lifetime(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "session_absolute_max_days", 30)
    await _ensure_settings(db_session)
    user = await _user(db_session, password=_PASSWORD)
    await db_session.commit()
    _t, cookie = await _login(client, user)
    signed_in = datetime.now(UTC) - timedelta(days=28)
    await db_session.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie))
        .values(created_at=signed_in)
    )
    await db_session.commit()
    r = await _refresh_with(client, cookie)
    assert r.status_code == 200, r.text
    new = await _row(db_session, _cookie_from(r))
    assert new.created_at == signed_in
    assert new.expires_at <= signed_in + timedelta(days=30, seconds=1)


async def test_absolute_lifetime_zero_disables_the_cap(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "session_absolute_max_days", 0)
    await _ensure_settings(db_session)
    user = await _user(db_session, password=_PASSWORD)
    await db_session.commit()
    _t, cookie = await _login(client, user)
    await db_session.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie))
        .values(
            created_at=datetime.now(UTC) - timedelta(days=400),
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )
    await db_session.commit()
    assert (await _refresh_with(client, cookie)).status_code == 200
