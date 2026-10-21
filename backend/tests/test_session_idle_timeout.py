"""The Session Timeout setting ends an idle browser session.

``platform_settings.session_timeout_minutes`` is "minutes of inactivity
before session expires (0 = disabled)". A session idle past it is refused on
its next request AND on refresh, since the refresh cookie outlives the access
token. Activity is ``user_session.last_seen_at``; a refresh carries it rather
than restamping it, and a console request reporting the operator's idle time
(``X-Spatium-Idle-Seconds``) records the activity when the operator was last
there, so a page left polling does not keep the session alive. API tokens are
not sessions and are unaffected.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token, generate_api_token, hash_password
from app.db import AsyncSessionLocal
from app.models.auth import APIToken, User, UserSession
from app.models.settings import PlatformSettings

_PASSWORD = "Sup3r-secret!"
_IDLE = "X-Spatium-Idle-Seconds"


async def _user(db: AsyncSession, *, superadmin: bool = False) -> User:
    user = User(
        username=f"idle-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Idle Tester",
        hashed_password=hash_password(_PASSWORD),
        auth_source="local",
        is_active=True,
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.commit()
    return user


async def _set_timeout(minutes: int, warning: int = 0) -> None:
    async with AsyncSessionLocal() as fresh:
        row = await fresh.get(PlatformSettings, 1)
        if row is None:
            fresh.add(
                PlatformSettings(id=1, session_timeout_minutes=minutes, auto_logout_minutes=warning)
            )
        else:
            row.session_timeout_minutes = minutes
            row.auto_logout_minutes = warning
        await fresh.commit()


async def _login(client: AsyncClient, user: User) -> tuple[str, uuid.UUID]:
    r = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return token, uuid.UUID(decode_access_token(token)["jti"])


async def _age(db: AsyncSession, session_id: uuid.UUID, seconds: float) -> None:
    """Make the session's last activity ``seconds`` ago."""
    async with AsyncSessionLocal() as fresh:
        await fresh.execute(
            update(UserSession)
            .where(UserSession.id == session_id)
            .values(last_seen_at=datetime.now(UTC) - timedelta(seconds=seconds))
        )
        await fresh.commit()
    # The test's session is also the request's session: drop its cached rows.
    db.expire_all()


async def _stored_last_seen(session_id: uuid.UUID) -> datetime | None:
    async with AsyncSessionLocal() as fresh:
        return (
            await fresh.execute(
                select(UserSession.last_seen_at).where(UserSession.id == session_id)
            )
        ).scalar_one()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_idle_session_is_refused_on_next_request_and_on_refresh(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _set_timeout(1)
    user = await _user(db_session)
    token, sid = await _login(client, user)
    await _age(db_session, sid, 125)

    me = await client.get("/api/v1/auth/me", headers=_bearer(token))
    assert me.status_code == 401, me.text

    refreshed = await client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 401, refreshed.text


@pytest.mark.asyncio
async def test_zero_disables_the_timeout(db_session: AsyncSession, client: AsyncClient) -> None:
    await _set_timeout(0)
    user = await _user(db_session)
    token, sid = await _login(client, user)
    await _age(db_session, sid, 6 * 3600)

    assert (await client.get("/api/v1/auth/me", headers=_bearer(token))).status_code == 200
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200


@pytest.mark.asyncio
async def test_a_session_inside_the_timeout_keeps_working(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The default 60 minutes: 59 minutes idle is not expired."""
    await _set_timeout(60)
    user = await _user(db_session)
    token, sid = await _login(client, user)
    await _age(db_session, sid, 59 * 60)

    assert (await client.get("/api/v1/auth/me", headers=_bearer(token))).status_code == 200
    await _age(db_session, sid, 59 * 60)
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200


@pytest.mark.asyncio
async def test_a_refresh_does_not_reset_the_idle_clock(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _set_timeout(1)
    user = await _user(db_session)
    _token, sid = await _login(client, user)
    await _age(db_session, sid, 50)
    before = await _stored_last_seen(sid)

    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200, r.text
    new_token = r.json()["access_token"]
    new_sid = uuid.UUID(decode_access_token(new_token)["jti"])

    assert await _stored_last_seen(new_sid) == before
    # So the renewed session still expires when the original would have.
    await _age(db_session, new_sid, 125)
    assert (await client.get("/api/v1/auth/me", headers=_bearer(new_token))).status_code == 401


@pytest.mark.asyncio
async def test_background_poll_does_not_count_as_activity(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _set_timeout(1)
    user = await _user(db_session)
    token, sid = await _login(client, user)
    await _age(db_session, sid, 30)
    before = await _stored_last_seen(sid)

    # The console polling while the operator has been away for 30 s.
    poll = await client.get("/api/v1/auth/me", headers={**_bearer(token), _IDLE: "30"})
    assert poll.status_code == 200, poll.text
    assert await _stored_last_seen(sid) == before

    # The page keeps polling; the session still runs out.
    await _age(db_session, sid, 125)
    poll = await client.get("/api/v1/auth/me", headers={**_bearer(token), _IDLE: "125"})
    assert poll.status_code == 401, poll.text


@pytest.mark.asyncio
async def test_operator_activity_is_recorded(db_session: AsyncSession, client: AsyncClient) -> None:
    await _set_timeout(1)
    user = await _user(db_session)
    token, sid = await _login(client, user)
    await _age(db_session, sid, 50)

    # Touched the page 2 s ago; a request without the header counts as now.
    r = await client.get("/api/v1/auth/me", headers={**_bearer(token), _IDLE: "2"})
    assert r.status_code == 200, r.text
    stored = await _stored_last_seen(sid)
    assert stored is not None
    assert datetime.now(UTC) - stored < timedelta(seconds=10)


@pytest.mark.asyncio
async def test_idle_sessions_are_not_listed_as_live(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _set_timeout(1)
    user = await _user(db_session)
    _old, old_sid = await _login(client, user)
    token, sid = await _login(client, user)
    await _age(db_session, old_sid, 125)

    r = await client.get("/api/v1/sessions/me", headers=_bearer(token))
    assert r.status_code == 200, r.text
    ids = {row["id"] for row in r.json()}
    assert str(sid) in ids
    assert str(old_sid) not in ids


@pytest.mark.asyncio
async def test_api_tokens_are_not_subject_to_the_timeout(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _set_timeout(1)
    owner = await _user(db_session)
    raw, _prefix, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name=f"idle-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
            last_used_at=datetime.now(UTC) - timedelta(days=3),
        )
    )
    await db_session.commit()

    r = await client.get("/api/v1/auth/me", headers=_bearer(raw))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_changing_the_setting_applies_immediately(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    await _set_timeout(0)
    admin = await _user(db_session, superadmin=True)
    token, sid = await _login(client, admin)
    await _age(db_session, sid, 30)
    # Prime the cached value (0 = disabled).
    assert (await client.get("/api/v1/auth/me", headers=_bearer(token))).status_code == 200

    r = await client.put(
        "/api/v1/settings", json={"session_timeout_minutes": 1}, headers=_bearer(token)
    )
    assert r.status_code == 200, r.text
    await _age(db_session, sid, 125)
    assert (await client.get("/api/v1/auth/me", headers=_bearer(token))).status_code == 401


@pytest.mark.asyncio
async def test_negative_warning_is_rejected(db_session: AsyncSession, client: AsyncClient) -> None:
    admin = await _user(db_session, superadmin=True)
    token, _sid = await _login(client, admin)
    r = await client.put(
        "/api/v1/settings", json={"auto_logout_minutes": -1}, headers=_bearer(token)
    )
    assert r.status_code == 422, r.text
