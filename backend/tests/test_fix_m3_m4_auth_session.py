"""Regression tests for #400 / GHSA-mj4g-hw3m-62rm — M3 + M4.

M3: changing a password (self-service AND admin reset) must revoke the
    user's other outstanding sessions / refresh tokens. Before the fix a
    session that existed before the change kept working, defeating the
    point of rotating the credential.

M4: ``force_password_change`` (set on fresh accounts, admin resets, and
    flipped on by the login-time max-age check) was advisory only — the
    API served every authenticated request to a must-change-password
    token. After the fix every endpoint 403s EXCEPT the password-recovery
    allowlist (change-password / logout / me / password-policy).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
)
from app.models.auth import User, UserSession
from app.models.settings import PlatformSettings


async def _ensure_settings(db: AsyncSession) -> None:
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
        await db.flush()


async def _user(
    db: AsyncSession,
    *,
    password: str = "OldPass123!",
    force_change: bool = False,
    is_superadmin: bool = False,
) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password(password),
        auth_source="local",
        is_active=True,
        is_superadmin=is_superadmin,
        force_password_change=force_change,
        password_changed_at=datetime.now(UTC),
    )
    db.add(u)
    await db.flush()
    return u


async def _session(db: AsyncSession, user: User) -> UserSession:
    """Create a real ``UserSession`` row and return it (its id is the jti)."""
    _raw, refresh_hash = create_refresh_token(str(user.id))
    now = datetime.now(UTC)
    s = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_hash,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=7),
        revoked=False,
    )
    db.add(s)
    await db.flush()
    return s


def _bearer(user: User, session: UserSession | None = None) -> dict[str, str]:
    jti = str(session.id) if session is not None else None
    return {"Authorization": f"Bearer {create_access_token(str(user.id), jti=jti)}"}


# ── M3: self-service change-password revokes OTHER sessions, spares caller ──


async def test_change_password_revokes_other_sessions_spares_caller(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    user = await _user(db_session)
    caller_session = await _session(db_session, user)
    other_session = await _session(db_session, user)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123!", "new_password": "BrandNewPass1!"},
        headers=_bearer(user, caller_session),
    )
    assert r.status_code == 200, r.text

    await db_session.refresh(other_session)
    await db_session.refresh(caller_session)
    # The other session is revoked; the caller's own session survives.
    assert other_session.revoked is True
    assert caller_session.revoked is False


async def test_change_password_wrong_current_does_not_revoke(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A failed change (wrong current password) must not touch sessions."""
    await _ensure_settings(db_session)
    user = await _user(db_session)
    caller_session = await _session(db_session, user)
    other_session = await _session(db_session, user)
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "WRONG-pass", "new_password": "BrandNewPass1!"},
        headers=_bearer(user, caller_session),
    )
    assert r.status_code == 400, r.text
    await db_session.refresh(other_session)
    assert other_session.revoked is False


# ── M3: admin reset revokes ALL of the target's sessions ────────────────────


async def test_admin_reset_revokes_all_target_sessions(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    admin = await _user(db_session, is_superadmin=True)
    target = await _user(db_session)
    await _session(db_session, target)
    await _session(db_session, target)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/users/{target.id}/reset-password",
        json={"new_password": "AdminSetPass1!"},
        headers=_bearer(admin),
    )
    assert r.status_code == 200, r.text

    rows = (
        (await db_session.execute(select(UserSession).where(UserSession.user_id == target.id)))
        .scalars()
        .all()
    )
    assert rows, "expected the target's sessions to still exist (just revoked)"
    assert all(s.revoked for s in rows)
    # The admin reset forces the target to change their password again.
    await db_session.refresh(target)
    assert target.force_password_change is True


# ── M4: force_password_change gates every non-recovery endpoint ─────────────


async def test_force_change_blocks_normal_endpoint(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    user = await _user(db_session, force_change=True, is_superadmin=True)
    session = await _session(db_session, user)
    await db_session.commit()

    # A normal authenticated endpoint must 403 while the flag is set, even
    # for a superadmin (the flag is independent of RBAC).
    r = await client.get("/api/v1/users", headers=_bearer(user, session))
    assert r.status_code == 403, r.text
    assert "Password change required" in r.text


async def test_force_change_allows_recovery_endpoints(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _ensure_settings(db_session)
    user = await _user(db_session, force_change=True)
    session = await _session(db_session, user)
    await db_session.commit()
    headers = _bearer(user, session)

    # GET /auth/me must still work so the UI can render the change-password screen.
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    assert me.json()["force_password_change"] is True

    # And the change-password endpoint itself must be reachable + clear the flag.
    changed = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "OldPass123!", "new_password": "RecoverPass1!"},
        headers=headers,
    )
    assert changed.status_code == 200, changed.text
    await db_session.refresh(user)
    assert user.force_password_change is False


async def test_cleared_flag_unblocks_endpoints(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Once the flag is cleared a fresh token reaches normal endpoints."""
    await _ensure_settings(db_session)
    user = await _user(db_session, force_change=False, is_superadmin=True)
    session = await _session(db_session, user)
    await db_session.commit()

    r = await client.get("/api/v1/users", headers=_bearer(user, session))
    assert r.status_code == 200, r.text
