"""MFA enrolment needs a step-up; external accounts honour their state (#1241, #1242).

#1241: ``/auth/mfa/enroll/begin`` needed only a session, so a hijacked one
could attach the attacker's authenticator — passing every TOTP reveal step-up
for an SSO superadmin, and locking a local user out of their own account.
Begin now asks a local user for their password and an external user for a
RECENT sign-in, and a refresh no longer makes a session look recent.

#1242: a disabled external account completed login (session, tokens and a
``success`` audit row) before being refused on every later request; and
``force_password_change`` on an external account, which has no password here
to change, locked it out until an admin cleared the flag.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.user_sync import (
    ExternalAuthResult,
    ExternalSyncRejected,
    sync_external_user,
)
from app.core.security import create_access_token, create_refresh_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, User, UserSession
from app.models.auth_provider import AuthGroupMapping, AuthProvider
from app.services.reauth import (
    MFA_ENROL_SIGN_IN_WINDOW,
    ReauthOutcome,
    reverify_for_mfa_enrolment,
)

_NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def _u(auth_source: str = "local", password: str | None = "pw") -> User:
    return User(
        username="u",
        email="u@example.com",
        display_name="u",
        auth_source=auth_source,
        hashed_password=hash_password(password) if password else None,
    )


# ── #1241: the step-up contract ───────────────────────────────────────


def test_local_user_needs_their_password():
    assert reverify_for_mfa_enrolment(_u(), password="pw", signed_in_at=None) is ReauthOutcome.OK
    for wrong in (None, "", "nope"):
        out = reverify_for_mfa_enrolment(_u(), password=wrong, signed_in_at=_NOW, now=_NOW)
        # A fresh sign-in is NOT a substitute for the password of a local user.
        assert out is ReauthOutcome.BAD_CREDENTIAL


def test_external_user_needs_a_recent_sign_in():
    sso = _u("oidc", password=None)
    fresh = _NOW - MFA_ENROL_SIGN_IN_WINDOW + timedelta(seconds=1)
    stale = _NOW - MFA_ENROL_SIGN_IN_WINDOW - timedelta(seconds=1)
    assert reverify_for_mfa_enrolment(sso, password=None, signed_in_at=fresh, now=_NOW) is (
        ReauthOutcome.OK
    )
    assert reverify_for_mfa_enrolment(sso, password=None, signed_in_at=stale, now=_NOW) is (
        ReauthOutcome.SIGN_IN_TOO_OLD
    )
    # No sign-in time at all (an API token) fails closed.
    assert reverify_for_mfa_enrolment(sso, password="x", signed_in_at=None, now=_NOW) is (
        ReauthOutcome.SIGN_IN_TOO_OLD
    )


# ── #1241: over the API ───────────────────────────────────────────────


async def _session_user(
    db: AsyncSession, *, auth_source: str, signed_in_ago: timedelta, password: str | None = None
) -> tuple[User, UserSession, dict[str, str]]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="u",
        auth_source=auth_source,
        hashed_password=hash_password(password) if password else None,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    signed_in = datetime.now(UTC) - signed_in_ago
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=f"t-{uuid.uuid4().hex}",
        auth_source=auth_source,
        created_at=signed_in,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db.add(session)
    await db.commit()
    token = create_access_token(str(user.id), jti=str(session.id))
    return user, session, {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_local_begin_without_the_password_is_refused_and_audited(
    client: AsyncClient, db_session: AsyncSession
):
    user, _, headers = await _session_user(
        db_session, auth_source="local", signed_in_ago=timedelta(0), password="pw-123456"
    )
    url = "/api/v1/auth/mfa/enroll/begin"

    # 403, not 401: the SPA reads a 401 as an expired token and would
    # refresh + resubmit the wrong password.
    r = await client.post(url, headers=headers)
    assert r.status_code == 403, r.text
    r = await client.post(url, headers=headers, json={"password": "wrong"})
    assert r.status_code == 403, r.text
    denied = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "mfa.enrol_begin", AuditLog.user_id == user.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert [a.result for a in denied] == ["denied", "denied"]

    r = await client.post(url, headers=headers, json={"password": "pw-123456"})
    assert r.status_code == 200, r.text
    assert r.json()["secret"]


@pytest.mark.asyncio
async def test_external_begin_needs_a_recent_sign_in(client: AsyncClient, db_session: AsyncSession):
    url = "/api/v1/auth/mfa/enroll/begin"
    _, _, stale = await _session_user(
        db_session, auth_source="oidc", signed_in_ago=MFA_ENROL_SIGN_IN_WINDOW * 2
    )
    r = await client.post(url, headers=stale)
    assert r.status_code == 403, r.text
    assert "sign in again" in r.json()["detail"]

    status = (await client.get("/api/v1/auth/mfa/status", headers=stale)).json()
    assert status["enrol_requires"] == "recent_sign_in"
    assert status["enrol_sign_in_recent"] is False
    assert status["enrol_sign_in_window_minutes"] == MFA_ENROL_SIGN_IN_WINDOW.total_seconds() // 60

    _, _, fresh = await _session_user(
        db_session, auth_source="oidc", signed_in_ago=timedelta(minutes=1)
    )
    assert (await client.get("/api/v1/auth/mfa/status", headers=fresh)).json()[
        "enrol_sign_in_recent"
    ] is True
    assert (await client.post(url, headers=fresh)).status_code == 200


@pytest.mark.asyncio
async def test_a_refresh_keeps_the_sign_in_time(client: AsyncClient, db_session: AsyncSession):
    # A refresh proves only possession of the refresh cookie — what a stolen
    # session has — so it must not make the session look freshly signed in.
    user, session, _ = await _session_user(
        db_session, auth_source="oidc", signed_in_ago=timedelta(hours=3)
    )
    raw, hashed = create_refresh_token(str(user.id))
    session.refresh_token_hash = hashed
    await db_session.commit()
    signed_in = session.created_at

    r = await client.post("/api/v1/auth/refresh", cookies={"spatium_refresh": raw})
    assert r.status_code == 200, r.text
    rotated = (
        (
            await db_session.execute(
                select(UserSession).where(
                    UserSession.user_id == user.id, UserSession.revoked.is_(False)
                )
            )
        )
        .scalars()
        .one()
    )
    assert rotated.id != session.id
    assert rotated.created_at == signed_in

    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert (await client.post("/api/v1/auth/mfa/enroll/begin", headers=headers)).status_code == 403


# ── #1242: a disabled external account ────────────────────────────────


async def _provider_with_mapping(db: AsyncSession) -> tuple[AuthProvider, Group]:
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    provider = AuthProvider(
        name=f"oidc-{uuid.uuid4().hex[:6]}",
        type="oidc",
        is_enabled=True,
        config={},
        auto_create_users=True,
        auto_update_users=True,
    )
    db.add_all([group, provider])
    await db.flush()
    db.add(
        AuthGroupMapping(
            provider_id=provider.id, external_group="staff", internal_group_id=group.id
        )
    )
    await db.flush()
    return provider, group


@pytest.mark.asyncio
async def test_a_disabled_external_account_is_refused_before_anything_changes(
    db_session: AsyncSession,
):
    provider, _ = await _provider_with_mapping(db_session)
    user = User(
        username="alice",
        email="old@example.com",
        display_name="Old",
        auth_source="oidc",
        external_id="sub-alice",
        is_active=False,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()

    with pytest.raises(ExternalSyncRejected) as info:
        await sync_external_user(
            db_session,
            provider,
            ExternalAuthResult(
                external_id="sub-alice",
                username="alice",
                email="new@example.com",
                display_name="New",
                groups=["staff"],
            ),
        )
    assert info.value.reason == "account_disabled"
    # Carried so the caller's denied audit row is linked to the account.
    assert info.value.user is user
    # Refused BEFORE the refresh: an attempt to use a disabled account does
    # not rewrite its profile or its group membership.
    assert user.email == "old@example.com"
    assert user.display_name == "Old"
    assert (await user.awaitable_attrs.groups) == []


def test_the_login_page_gets_a_distinct_error_code():
    from app.api.v1.auth.router import _login_error_redirect

    location = _login_error_redirect("account_disabled").headers["location"]
    assert location.endswith("error=account_disabled")


# ── #1242: force_password_change on an external account ───────────────


async def _admin(db: AsyncSession) -> dict[str, str]:
    admin = User(
        username=f"admin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    admin.groups = []
    db.add(admin)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}


@pytest.mark.asyncio
async def test_an_external_account_cannot_be_forced_to_change_a_password_it_lacks(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _admin(db_session)
    sso, _, _ = await _session_user(db_session, auth_source="ldap", signed_in_ago=timedelta(0))
    url = f"/api/v1/users/{sso.id}"

    r = await client.put(url, json={"force_password_change": True}, headers=headers)
    assert r.status_code == 400, r.text
    # Clearing it stays allowed — how a row set before the check is tidied.
    r = await client.put(url, json={"force_password_change": False}, headers=headers)
    assert r.status_code == 200, r.text

    r = await client.post(
        f"/api/v1/users/{sso.id}/reset-password",
        json={"new_password": "Another-Passw0rd!"},
        headers=headers,
    )
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_an_external_account_already_flagged_is_not_locked_out(
    client: AsyncClient, db_session: AsyncSession
):
    sso, _, headers = await _session_user(
        db_session, auth_source="saml", signed_in_ago=timedelta(0)
    )
    sso.force_password_change = True  # set before this fix existed
    await db_session.commit()

    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["force_password_change"] is False
    # Still enforced for a local account.
    local, _, local_headers = await _session_user(
        db_session, auth_source="local", signed_in_ago=timedelta(0), password="pw-123456"
    )
    local.force_password_change = True
    await db_session.commit()
    assert (await client.get("/api/v1/dns/groups", headers=local_headers)).status_code == 403


# ── #1241: the step-up is not a password oracle ───────────────────────


@pytest.mark.asyncio
async def test_wrong_step_up_answers_are_counted_and_then_refused(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    """The check runs for a caller who already holds a session — the
    hijacked session it exists to stop — so each wrong answer counts toward
    a per-account budget, and a spent budget is refused BEFORE the password
    is checked, so a blocked guess reveals nothing."""
    import app.api.v1.auth.router as auth_router

    failures: list[object] = []
    blocked = {"now": False}

    async def _record(user_id: object) -> None:
        failures.append(user_id)

    async def _blocked(_user_id: object) -> bool:
        return blocked["now"]

    monkeypatch.setattr(auth_router, "record_stepup_password_failure", _record)
    monkeypatch.setattr(auth_router, "stepup_password_blocked", _blocked)

    user, _, headers = await _session_user(
        db_session, auth_source="local", signed_in_ago=timedelta(0), password="pw-123456"
    )
    url = "/api/v1/auth/mfa/enroll/begin"
    assert (await client.post(url, headers=headers, json={"password": "nope"})).status_code == 403
    assert failures == [user.id]

    blocked["now"] = True
    r = await client.post(url, headers=headers, json={"password": "pw-123456"})
    assert r.status_code == 429, r.text
    assert failures == [user.id]  # the right password was never even checked


# ── #1241 gate walk: the step-up throttle fails CLOSED ────────────────
#
# The ddi-pg walk stopped Redis for 76 s: eight wrong step-up answers in a
# row each got 403 and none got 429. The account lockout counts sign-in
# answers only, so nothing else bounds a hijacked session's guessing.


@pytest.mark.asyncio
async def test_an_unreadable_budget_raises_instead_of_reading_as_unblocked(
    monkeypatch: pytest.MonkeyPatch,
):
    import app.core.auth_throttle as throttle

    def _down(*_a: object, **_k: object) -> object:
        raise ConnectionError("redis down")

    monkeypatch.setattr(throttle, "make_async_redis", _down)
    with pytest.raises(throttle.StepupThrottleUnavailable):
        await throttle.stepup_password_blocked(uuid.uuid4())
    # Counting stays best-effort: the answer was already refused, and the
    # next attempt's check fails closed on its own.
    await throttle.record_stepup_password_failure(uuid.uuid4())


def _throttle_down(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    import app.api.v1.auth.router as auth_router
    from app.core.auth_throttle import StepupThrottleUnavailable

    failures: list[object] = []

    async def _blocked(_user_id: object) -> bool:
        raise StepupThrottleUnavailable

    async def _record(user_id: object) -> None:
        failures.append(user_id)

    monkeypatch.setattr(auth_router, "stepup_password_blocked", _blocked)
    monkeypatch.setattr(auth_router, "record_stepup_password_failure", _record)
    return failures


@pytest.mark.asyncio
async def test_enrolment_is_refused_while_the_budget_cannot_be_read(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    failures = _throttle_down(monkeypatch)
    user, _, headers = await _session_user(
        db_session, auth_source="local", signed_in_ago=timedelta(0), password="pw-123456"
    )
    for password in ("nope", "pw-123456"):
        r = await client.post(
            "/api/v1/auth/mfa/enroll/begin", headers=headers, json={"password": password}
        )
        # 503, not 429: nothing was guessed, the limiter is simply down.
        assert r.status_code == 503, r.text
        assert r.headers.get("retry-after") == "60"
    # Refused BEFORE the credential: no answer was checked, so none counted,
    # and no candidate secret was minted.
    assert failures == []
    await db_session.refresh(user)
    assert user.totp_secret_encrypted is None


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/mfa/disable", "/mfa/recovery-codes/regenerate"])
async def test_disable_and_regenerate_are_refused_while_the_budget_cannot_be_read(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, path: str
):
    from app.services.mfa import encrypt_secret, generate_secret

    failures = _throttle_down(monkeypatch)
    user, _, headers = await _session_user(
        db_session, auth_source="local", signed_in_ago=timedelta(0), password="pw-123456"
    )
    user.totp_enabled = True
    user.totp_secret_encrypted = encrypt_secret(generate_secret())
    await db_session.commit()

    r = await client.post(
        f"/api/v1/auth{path}", headers=headers, json={"password": "nope", "code": "000000"}
    )
    assert r.status_code == 503, r.text
    assert failures == []
    await db_session.refresh(user)
    assert user.totp_enabled is True
