"""#2941 — refresh rotation has a short grace window, for rotations only.

Two console tabs share the HttpOnly refresh cookie. When one refreshes, the
old ``UserSession`` is revoked; without a grace window the other tab's access
token died on the spot, and two tabs refreshing at once with the one cookie
raced, the loser got a 401 and the console sent the operator to /login.

Pinned here:

* a rotated cookie presented inside the window gets the SAME successor (no
  third session, no new cookie), and a 401 once the window has passed;
* two concurrent refreshes with one cookie both succeed on one successor
  (the row lock is what serializes them);
* an access token for the rotated session works inside the window only;
* logout, an admin's force-logout, a password change and disabling the
  account end the session at once, for the old cookie and the old access
  token alike: the grace follows a rotation and nothing else.

The window is crossed by backdating ``rotated_at``, never by sleeping.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_refresh_token, decode_access_token, hash_refresh_token
from app.core.session_rotation import ROTATION_GRACE, rotation_successor
from app.db import get_db
from app.main import app
from app.models.auth import User, UserSession
from tests.conftest import _TestSessionLocal
from tests.test_fix_m3_m4_auth_session import _bearer, _ensure_settings, _user

_PASSWORD = "OldPass123!"
_COOKIE = "spatium_refresh"


@pytest.fixture(autouse=True)
def _no_login_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test here signs in over HTTP from the one test-client address,
    so the file as a whole, or alongside another file that does the same in
    one shard, outruns the per-IP login budget (30 a minute) and the next
    sign-in is a 429. That throttle is not what these tests are about."""
    from app.api.v1.auth import router as auth_router

    async def _not_limited(_ip: str | None) -> bool:
        return False

    monkeypatch.setattr(auth_router, "login_rate_limited", _not_limited)


async def _login(client: AsyncClient, user: User) -> tuple[str, str]:
    """Sign in; return (access token, raw refresh cookie)."""
    client.cookies.clear()
    r = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"], _cookie_from(r)


def _cookie_from(resp) -> str:
    """The refresh cookie a response set (read off the header, so a value
    planted in the jar by ``_refresh_with`` cannot be mistaken for it)."""
    for h in resp.headers.get_list("set-cookie"):
        if h.startswith(f"{_COOKIE}="):
            return h.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError("no refresh cookie set")


async def _refresh_with(client: AsyncClient, cookie: str):
    client.cookies.clear()
    client.cookies.set(_COOKIE, cookie)
    return await client.post("/api/v1/auth/refresh")


def _jti(token: str) -> uuid.UUID:
    return uuid.UUID(decode_access_token(token)["jti"])


def _sets_refresh_cookie(resp) -> bool:
    return any(h.startswith(f"{_COOKIE}=") for h in resp.headers.get_list("set-cookie"))


async def _row(db: AsyncSession, cookie: str) -> UserSession:
    return (
        await db.execute(
            select(UserSession)
            .where(UserSession.refresh_token_hash == hash_refresh_token(cookie))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _session_count(db: AsyncSession, user: User) -> int:
    return (
        await db.execute(select(func.count()).where(UserSession.user_id == user.id))
    ).scalar_one()


async def _rotated(client: AsyncClient, db: AsyncSession) -> tuple[User, str, str, str, str]:
    """A user who signed in (cookie A, token A) and then refreshed once
    (cookie B, token B). Returns (user, cookie_a, token_a, cookie_b, token_b)."""
    await _ensure_settings(db)
    user = await _user(db, password=_PASSWORD)
    await db.commit()
    token_a, cookie_a = await _login(client, user)
    r = await _refresh_with(client, cookie_a)
    assert r.status_code == 200, r.text
    cookie_b = _cookie_from(r)
    assert cookie_b != cookie_a
    return user, cookie_a, token_a, cookie_b, r.json()["access_token"]


async def _backdate_rotation(db: AsyncSession, cookie: str) -> None:
    await db.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie))
        .values(rotated_at=datetime.now(UTC) - ROTATION_GRACE - timedelta(seconds=1))
    )
    await db.commit()


async def _me(client: AsyncClient, token: str) -> int:
    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    return r.status_code


# ── rotation records itself ─────────────────────────────────────────────────


async def test_a_rotation_records_its_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user_, cookie_a, _ta, cookie_b, token_b = await _rotated(client, db_session)
    a = await _row(db_session, cookie_a)
    b = await _row(db_session, cookie_b)
    assert a.revoked is True
    assert a.rotated_at is not None
    assert a.rotated_to_id == b.id == _jti(token_b)
    assert b.revoked is False and b.rotated_at is None and b.rotated_to_id is None


# ── the rotated cookie inside / outside the window ──────────────────────────


async def test_rotated_cookie_in_window_gets_the_same_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, _ta, cookie_b, _tb = await _rotated(client, db_session)
    b = await _row(db_session, cookie_b)

    r = await _refresh_with(client, cookie_a)
    assert r.status_code == 200, r.text
    # The successor, not a third session, and no cookie to overwrite B's.
    assert _jti(r.json()["access_token"]) == b.id
    assert not _sets_refresh_cookie(r)
    assert await _session_count(db_session, user) == 2
    b = await _row(db_session, cookie_b)
    assert b.revoked is False

    # The token it gave out works, and B's own cookie still rotates normally.
    assert await _me(client, r.json()["access_token"]) == 200
    r2 = await _refresh_with(client, cookie_b)
    assert r2.status_code == 200, r2.text
    assert _sets_refresh_cookie(r2)


async def test_rotated_cookie_after_the_window_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, _ta, _cb, _tb = await _rotated(client, db_session)
    await _backdate_rotation(db_session, cookie_a)

    r = await _refresh_with(client, cookie_a)
    assert r.status_code == 401, r.text
    assert await _session_count(db_session, user) == 2


async def test_a_cookie_that_was_never_issued_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    raw, _hash = create_refresh_token(str(uuid.uuid4()))
    r = await _refresh_with(client, raw)
    assert r.status_code == 401


async def test_grace_follows_a_chain_of_rotations_in_the_window(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tab 1 rotates A→B, tab 2 then rotates B→C, tab 3 still holds A."""
    user, cookie_a, token_a, cookie_b, _tb = await _rotated(client, db_session)
    r = await _refresh_with(client, cookie_b)
    assert r.status_code == 200
    c_id = _jti(r.json()["access_token"])

    r = await _refresh_with(client, cookie_a)
    assert r.status_code == 200, r.text
    assert _jti(r.json()["access_token"]) == c_id
    assert await _me(client, token_a) == 200
    assert await _session_count(db_session, user) == 3


# ── concurrency ─────────────────────────────────────────────────────────────


async def test_concurrent_refreshes_with_one_cookie_land_on_one_successor(
    db_session: AsyncSession,
) -> None:
    """The real race: two requests, two DB connections, one cookie. A third
    connection holds the row so both are queued before either runs, which
    makes the interleaving deterministic rather than lucky."""

    async def own_session() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as s:
            yield s

    await _ensure_settings(db_session)
    user = await _user(db_session, password=_PASSWORD)
    await db_session.commit()

    app.dependency_overrides[get_db] = own_session
    try:
        transport = ASGITransport(app=app)
        async with (
            AsyncClient(transport=transport, base_url="http://test") as tab1,
            AsyncClient(transport=transport, base_url="http://test") as tab2,
        ):
            _token, cookie_a = await _login(tab1, user)
            for tab in (tab1, tab2):
                tab.cookies.clear()
                tab.cookies.set(_COOKIE, cookie_a)

            async with _TestSessionLocal() as holder:
                await holder.execute(
                    select(UserSession.id)
                    .where(UserSession.refresh_token_hash == hash_refresh_token(cookie_a))
                    .with_for_update()
                )
                tasks = [
                    asyncio.create_task(tab1.post("/api/v1/auth/refresh")),
                    asyncio.create_task(tab2.post("/api/v1/auth/refresh")),
                ]
                # Wait until both requests are queued on the row lock.
                for _ in range(400):
                    async with _TestSessionLocal() as probe:
                        waiting = (
                            await probe.execute(
                                text(
                                    "SELECT count(*) FROM pg_stat_activity "
                                    "WHERE wait_event_type = 'Lock' "
                                    "AND datname = current_database()"
                                )
                            )
                        ).scalar_one()
                    if waiting >= 2:
                        break
                    await asyncio.sleep(0.025)
                else:  # pragma: no cover — a hang, not the bug under test
                    raise AssertionError("the two refreshes never queued on the lock")
                await holder.rollback()
            r1, r2 = await asyncio.gather(*tasks)
    finally:
        app.dependency_overrides.clear()

    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text
    assert _jti(r1.json()["access_token"]) == _jti(r2.json()["access_token"])
    # Exactly one rotation: the original row and one successor.
    assert await _session_count(db_session, user) == 2
    # Exactly one of them set a new cookie.
    assert [_sets_refresh_cookie(r1), _sets_refresh_cookie(r2)].count(True) == 1


# ── the rotated session's access token ─────────────────────────────────────


async def test_old_access_token_works_in_the_window_and_not_after(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user_, cookie_a, token_a, _cb, token_b = await _rotated(client, db_session)
    assert await _me(client, token_a) == 200
    assert await _me(client, token_b) == 200

    await _backdate_rotation(db_session, cookie_a)
    assert await _me(client, token_a) == 401
    assert await _me(client, token_b) == 200


# ── revocations that are not rotations get no grace ────────────────────────


async def _assert_all_dead(
    client: AsyncClient, cookie_a: str, token_a: str, cookie_b: str, token_b: str
) -> None:
    assert (await _refresh_with(client, cookie_a)).status_code == 401
    assert (await _refresh_with(client, cookie_b)).status_code == 401
    assert await _me(client, token_a) == 401
    assert await _me(client, token_b) == 401


async def test_logout_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_logout_from_the_old_token_ends_the_successor_too(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token_a}"})
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_admin_force_logout_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    b = await _row(db_session, cookie_b)
    r = await client.delete(f"/api/v1/sessions/{b.id}", headers=_bearer(admin))
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_password_change_elsewhere_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    other_token, _other_cookie = await _login(client, user)
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _PASSWORD, "new_password": "BrandNewPass1!"},
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)
    assert await _me(client, other_token) == 200


async def test_password_change_from_the_old_token_spares_the_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A tab whose token is inside the grace changes the password: the
    session its cookie now names (B) is the caller's, and must survive."""
    _u, _ca, token_a, cookie_b, token_b = await _rotated(client, db_session)
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _PASSWORD, "new_password": "BrandNewPass1!"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert r.status_code == 204, r.text
    assert (await _row(db_session, cookie_b)).revoked is False
    assert await _me(client, token_b) == 200


async def test_disabling_the_account_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/users/{user.id}", json={"is_active": False}, headers=_bearer(admin)
    )
    assert r.status_code == 200, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_a_revoked_never_rotated_session_gets_no_grace(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Revoked just now by something other than a rotation: refused."""
    await _ensure_settings(db_session)
    user = await _user(db_session, password=_PASSWORD)
    await db_session.commit()
    token, cookie = await _login(client, user)
    await db_session.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie))
        .values(revoked=True)
    )
    await db_session.commit()
    assert (await _refresh_with(client, cookie)).status_code == 401
    assert await _me(client, token) == 401


# ── the resolver, with an injected clock ────────────────────────────────────


async def test_rotation_successor_honours_the_clock(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, cookie_a, _ta, cookie_b, _tb = await _rotated(client, db_session)
    a = await _row(db_session, cookie_a)
    b = await _row(db_session, cookie_b)
    assert a.rotated_at is not None
    edge = a.rotated_at + ROTATION_GRACE
    assert (await rotation_successor(db_session, a, edge)).id == b.id
    assert await rotation_successor(db_session, a, edge + timedelta(microseconds=1)) is None
    # A clock behind the rotation is not "inside" it.
    assert await rotation_successor(db_session, a, a.rotated_at - timedelta(seconds=1)) is None
    # A live row stands for itself.
    assert (await rotation_successor(db_session, b, edge)).id == b.id


# ── every other revocation path, and the grace never outliving one ─────────


async def test_admin_password_reset_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/users/{user.id}/reset-password",
        json={"new_password": "AdminSetPass1!"},
        headers=_bearer(admin),
    )
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_provider_link_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from tests.test_external_user_sync import _group, _provider

    user, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    provider = await _provider(db_session, await _group(db_session))
    await db_session.execute(
        update(User).where(User.id == user.id).values(auth_source="ldap", external_id="CN=x")
    )
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/users/{user.id}/link-provider",
        json={"auth_provider_id": str(provider.id)},
        headers=_bearer(admin),
    )
    assert r.status_code == 200, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_deleting_the_user_ends_the_rotated_session_at_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    r = await client.delete(f"/api/v1/users/{user.id}", headers=_bearer(admin))
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_force_logout_of_the_rotated_row_revokes_its_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The viewer listed A live; a tab rotated it to B before the operator
    clicked Revoke on A. Revoking A alone would change nothing (it is
    already revoked) and leave B live, with A's cookie graced into it."""
    _u, cookie_a, token_a, cookie_b, token_b = await _rotated(client, db_session)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    a = await _row(db_session, cookie_a)
    r = await client.delete(f"/api/v1/sessions/{a.id}", headers=_bearer(admin))
    assert r.status_code == 204, r.text
    await _assert_all_dead(client, cookie_a, token_a, cookie_b, token_b)


async def test_force_logout_follows_a_stale_row_past_its_window(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A list fetched minutes ago: the chain is followed however old it is."""
    _u, cookie_a, _ta, cookie_b, _tb = await _rotated(client, db_session)
    r = await _refresh_with(client, cookie_b)
    assert r.status_code == 200
    token_c = r.json()["access_token"]
    await _backdate_rotation(db_session, cookie_a)
    await _backdate_rotation(db_session, cookie_b)
    admin = await _user(db_session, is_superadmin=True)
    await db_session.commit()
    a = await _row(db_session, cookie_a)
    r = await client.delete(f"/api/v1/sessions/{a.id}", headers=_bearer(admin))
    assert r.status_code == 204, r.text
    assert await _me(client, token_c) == 401


async def test_force_logout_of_a_logged_out_chain_is_a_no_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, _ta, _cb, token_b = await _rotated(client, db_session)
    r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token_b}"})
    assert r.status_code == 204
    other_token, _oc = await _login(client, user)
    a = await _row(db_session, cookie_a)
    r = await client.delete(f"/api/v1/sessions/{a.id}", headers=_bearer(user))
    assert r.status_code == 204, r.text
    # Nothing else of the user's was touched.
    assert await _me(client, other_token) == 200


async def test_repeated_replay_never_extends_the_window(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, cookie_a, token_a, _cb, _tb = await _rotated(client, db_session)
    rotated_at = (await _row(db_session, cookie_a)).rotated_at
    for _ in range(5):
        r = await _refresh_with(client, cookie_a)
        assert r.status_code == 200, r.text
        assert not _sets_refresh_cookie(r)
    assert (await _row(db_session, cookie_a)).rotated_at == rotated_at
    assert await _session_count(db_session, user) == 2

    await _backdate_rotation(db_session, cookie_a)
    assert (await _refresh_with(client, cookie_a)).status_code == 401
    assert await _me(client, token_a) == 401


async def test_grace_does_not_revive_an_expired_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, cookie_a, token_a, cookie_b, _tb = await _rotated(client, db_session)
    await db_session.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie_b))
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    await db_session.commit()
    assert (await _refresh_with(client, cookie_a)).status_code == 401
    assert await _me(client, token_a) == 401


async def test_grace_does_not_revive_an_idle_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.core import session_idle
    from app.models.settings import PlatformSettings

    _u, cookie_a, token_a, cookie_b, _tb = await _rotated(client, db_session)
    long_ago = datetime.now(UTC) - timedelta(hours=2)
    await db_session.execute(
        update(UserSession)
        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie_b))
        .values(last_seen_at=long_ago, created_at=long_ago)
    )
    await db_session.execute(
        update(PlatformSettings).where(PlatformSettings.id == 1).values(session_timeout_minutes=15)
    )
    await db_session.commit()
    session_idle._cache_loaded_at = 0.0
    try:
        assert (await _refresh_with(client, cookie_a)).status_code == 401
        assert await _me(client, token_a) == 401
        # And the grace answer did not count as activity on the successor.
        assert (await _row(db_session, cookie_b)).last_seen_at == long_ago
    finally:
        session_idle._cache_loaded_at = 0.0


async def test_the_viewer_marks_the_successor_as_the_callers_session(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, _ca, token_a, cookie_b, _tb = await _rotated(client, db_session)
    b = await _row(db_session, cookie_b)
    r = await client.get("/api/v1/sessions/me", headers={"Authorization": f"Bearer {token_a}"})
    assert r.status_code == 200, r.text
    current = [row["id"] for row in r.json() if row["is_current"]]
    assert current == [str(b.id)]


# ── a revocation racing a rotation ─────────────────────────────────────────


async def test_logout_racing_a_rotation_revokes_the_successor(
    db_session: AsyncSession,
) -> None:
    """A refresh has locked A, inserted its successor S and not yet
    committed when logout runs. A single UPDATE would wait on A, find it
    revoked once the refresh commits, and never see S (its snapshot
    predates S), leaving S live and A's cookie graced into it."""

    async def own_session() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as s:
            yield s

    await _ensure_settings(db_session)
    user = await _user(db_session, password=_PASSWORD)
    await db_session.commit()

    app.dependency_overrides[get_db] = own_session
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as tab:
            _token_a, cookie_a = await _login(tab, user)
            other_token, _oc = await _login(tab, user)

            async with _TestSessionLocal() as refresh:
                a = (
                    await refresh.execute(
                        select(UserSession)
                        .where(UserSession.refresh_token_hash == hash_refresh_token(cookie_a))
                        .with_for_update()
                    )
                ).scalar_one()
                _raw, s_hash = create_refresh_token(str(user.id))
                s = UserSession(
                    user_id=user.id,
                    refresh_token_hash=s_hash,
                    created_at=a.created_at,
                    expires_at=a.expires_at,
                )
                refresh.add(s)
                await refresh.flush()
                a.revoked = True
                a.rotated_at = datetime.now(UTC)
                a.rotated_to_id = s.id
                await refresh.flush()
                s_id = s.id

                task = asyncio.create_task(
                    tab.post(
                        "/api/v1/auth/logout",
                        headers={"Authorization": f"Bearer {other_token}"},
                    )
                )
                for _ in range(400):
                    async with _TestSessionLocal() as probe:
                        waiting = (
                            await probe.execute(
                                text(
                                    "SELECT count(*) FROM pg_stat_activity "
                                    "WHERE wait_event_type = 'Lock' "
                                    "AND datname = current_database()"
                                )
                            )
                        ).scalar_one()
                    if waiting >= 1:
                        break
                    await asyncio.sleep(0.025)
                else:  # pragma: no cover — a hang, not the bug under test
                    raise AssertionError("logout never queued on the rotating row")
                await refresh.commit()
            r = await task
    finally:
        app.dependency_overrides.clear()

    assert r.status_code == 204, r.text
    s_row = (
        await db_session.execute(
            select(UserSession)
            .where(UserSession.id == s_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert s_row.revoked is True
