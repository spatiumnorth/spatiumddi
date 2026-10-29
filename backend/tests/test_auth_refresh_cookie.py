"""#484 / #400 L1 — the refresh token is delivered ONLY as an HttpOnly cookie.

The structural fix moves the long-lived refresh token out of the JSON body
(where the SPA used to stash it in localStorage, XSS-stealable) into an
HttpOnly + SameSite=Strict cookie the browser manages. This pins the contract:

  * /auth/login returns an access token but NO refresh_token in the body, and
    sets the ``spatium_refresh`` cookie with HttpOnly + SameSite=strict, scoped
    to /api/v1/auth.
  * /auth/refresh reads the cookie (not a body field), rotates it, and returns
    a fresh access token with no refresh_token in the body.
  * /auth/refresh with no cookie is a clean 401, not a 422/500.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token, hash_password, hash_refresh_token
from app.core.session_rotation import ROTATION_GRACE
from app.models.auth import User, UserSession

_PASSWORD = "Sup3r-secret!"


async def _local_user(db: AsyncSession) -> User:
    user = User(
        username=f"cookie-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="Cookie Tester",
        hashed_password=hash_password(_PASSWORD),
        auth_source="local",
        is_active=True,
        is_superadmin=False,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return user


def _refresh_set_cookie(resp) -> str:
    for raw in resp.headers.get_list("set-cookie"):
        if raw.startswith("spatium_refresh="):
            return raw
    raise AssertionError(f"no spatium_refresh Set-Cookie in {resp.headers.get_list('set-cookie')}")


@pytest.mark.asyncio
async def test_login_sets_httponly_refresh_cookie_and_no_body_token(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    user = await _local_user(db_session)

    resp = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Access token present; refresh token NOT in the JSON body.
    assert body["access_token"]
    assert "refresh_token" not in body

    # Cookie carries the refresh token with the hardening flags.
    raw = _refresh_set_cookie(resp)
    lower = raw.lower()
    assert "httponly" in lower
    assert "samesite=strict" in lower
    assert "path=/api/v1/auth" in lower
    # The cookie jar picked it up so it rides the next auth request.
    assert client.cookies.get("spatium_refresh")


@pytest.mark.asyncio
async def test_refresh_reads_cookie_rotates_and_returns_access_only(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    user = await _local_user(db_session)
    login = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    assert login.status_code == 200, login.text
    first_cookie = client.cookies.get("spatium_refresh")

    # No body — the cookie carries the refresh token.
    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert "refresh_token" not in body

    # Rotation: the Set-Cookie value differs from the login cookie.
    rotated = _refresh_set_cookie(resp)
    assert first_cookie not in rotated

    # Single-use: the ORIGINAL (pre-rotation) refresh token must be revoked.
    # Without this a broken rotation that mints a new cookie but forgets
    # ``session.revoked = True`` would still pass the value-differs check
    # above. Inside the #2941 grace window a replay is answered with the
    # SAME successor (no new session, no new cookie); once the window has
    # passed it is a 401.
    old_row = (
        await db_session.execute(
            select(UserSession).where(
                UserSession.refresh_token_hash == hash_refresh_token(first_cookie)
            )
        )
    ).scalar_one()
    assert old_row.revoked is True
    client.cookies.clear()
    client.cookies.set("spatium_refresh", first_cookie)
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 200, replay.text
    assert not any(h.startswith("spatium_refresh=") for h in replay.headers.get_list("set-cookie"))
    assert decode_access_token(replay.json()["access_token"])["jti"] == str(old_row.rotated_to_id)

    await db_session.execute(
        update(UserSession)
        .where(UserSession.id == old_row.id)
        .values(rotated_at=datetime.now(UTC) - ROTATION_GRACE - timedelta(seconds=1))
    )
    await db_session.commit()
    client.cookies.clear()
    client.cookies.set("spatium_refresh", first_cookie)
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401, replay.text


@pytest.mark.asyncio
async def test_refresh_without_cookie_is_401(db_session: AsyncSession, client: AsyncClient) -> None:
    client.cookies.clear()
    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401, resp.text
    assert "refresh" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_logout_clears_refresh_cookie(db_session: AsyncSession, client: AsyncClient) -> None:
    user = await _local_user(db_session)
    login = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    access = login.json()["access_token"]

    resp = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 204, resp.text
    # The logout response instructs the browser to drop the cookie.
    raw = _refresh_set_cookie(resp)
    lower = raw.lower()
    assert 'spatium_refresh="";' in lower.replace(" ", " ") or "max-age=0" in lower
