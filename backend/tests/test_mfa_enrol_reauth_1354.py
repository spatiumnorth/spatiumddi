"""Starting an MFA enrolment re-checks an external account at ITS OWN provider (#1354).

#1241 gave an external account (no local password) a stand-in step-up: any
session created in the last 10 minutes. That is a sign-in time, not a check,
and weaker than the "fresh IdP login" the issue asked for. Now:

* LDAP / RADIUS / TACACS+: the password, re-verified at the account's own
  provider, spending the step-up budget when wrong;
* OIDC / SAML: a forced re-authentication at the IdP (``prompt=login`` +
  ``max_age=0`` / ``ForceAuthn``) whose callback leaves a single-use proof
  bound to the user and the sign-in, taken by ``enroll/begin``;
* the 10-minute window only for an account whose provider is gone or off.
"""

from __future__ import annotations

import base64
import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from httpx import AsyncClient
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import router as auth_router
from app.config import settings
from app.core.auth.ldap import LDAPServiceError
from app.core.auth.oidc import OIDCServiceError, _require_fresh_auth_time
from app.core.auth.user_sync import ExternalAuthResult
from app.core.auth_throttle import _stepup_key
from app.core.crypto import encrypt_dict
from app.core.redis_client import make_async_redis
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User, UserSession
from app.models.auth_provider import AuthProvider
from tests import test_saml_acs as saml

pytestmark = pytest.mark.asyncio

BEGIN = "/api/v1/auth/mfa/enroll/begin"
REAUTH = "/api/v1/auth/mfa/enroll/reauth"
STATUS = "/api/v1/auth/mfa/status"
DN = "uid=alice,ou=people,dc=example,dc=com"


async def _provider(db: AsyncSession, type_: str, **config: object) -> AuthProvider:
    provider = AuthProvider(
        name=f"{type_}-{uuid.uuid4().hex[:6]}",
        type=type_,
        is_enabled=True,
        config=config,
        auto_create_users=True,
    )
    db.add(provider)
    await db.flush()
    return provider


async def _account(
    db: AsyncSession,
    provider: AuthProvider | None,
    *,
    external_id: str = DN,
    auth_source: str | None = None,
    signed_in_ago: timedelta = timedelta(minutes=1),
) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="u",
        auth_source=auth_source or (provider.type if provider else "oidc"),
        auth_provider_id=provider.id if provider else None,
        external_id=external_id,
        hashed_password=None,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, await _sign_in(db, user, signed_in_ago)


async def _sign_in(db: AsyncSession, user: User, ago: timedelta) -> dict[str, str]:
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=f"t-{uuid.uuid4().hex}",
        auth_source=user.auth_source,
        created_at=datetime.now(UTC) - ago,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db.add(session)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id), jti=str(session.id))}"}


@pytest.fixture(autouse=True)
async def _clean_budget():
    """The budget is real Redis; user ids are fresh per test, so just make
    sure nothing is left behind."""
    keys: list[str] = []
    yield keys
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        for k in keys:
            await r.delete(k)
    finally:
        await r.aclose()


async def _failures(user: User) -> int:
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        v = await r.get(_stepup_key(user.id))
        return int(v) if v is not None else 0
    finally:
        await r.aclose()


# ── LDAP / RADIUS / TACACS+: the password, at the account's own provider ──


def _fake_directory(monkeypatch: pytest.MonkeyPatch, *, password: str, external_id: str = DN):
    """Stand in for the provider's authenticate function. Records its calls."""
    import app.services.mfa_enrol_stepup as svc

    calls: list[tuple[str, str, str]] = []

    def authenticate(provider, username, pw):
        calls.append((provider.name, username, pw))
        if pw != password:
            return None
        return ExternalAuthResult(external_id=external_id, username=username)

    monkeypatch.setitem(svc._PASSWORD_AUTH, "ldap", (authenticate, LDAPServiceError))
    return calls


async def test_a_fresh_sign_in_no_longer_enrols_an_ldap_account(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    # On main this was 200: a session less than 10 minutes old was the step-up.
    calls = _fake_directory(monkeypatch, password="right")
    provider = await _provider(db_session, "ldap")
    _, headers = await _account(db_session, provider)

    r = await client.post(BEGIN, headers=headers)

    assert r.status_code == 403, r.text
    assert calls == []


async def test_ldap_password_is_reverified_at_its_own_provider(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    calls = _fake_directory(monkeypatch, password="right")
    provider = await _provider(db_session, "ldap")
    user, headers = await _account(db_session, provider)

    status = (await client.get(STATUS, headers=headers)).json()
    assert status["enrol_requires"] == "provider_password"
    assert status["enrol_provider_name"] == provider.name

    r = await client.post(BEGIN, headers=headers, json={"password": "right"})

    assert r.status_code == 200, r.text
    assert r.json()["secret"]
    assert calls == [(provider.name, user.username, "right")]


async def test_a_wrong_ldap_password_is_refused_audited_and_spends_the_budget(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    _fake_directory(monkeypatch, password="right")
    provider = await _provider(db_session, "ldap")
    user, headers = await _account(db_session, provider)

    r = await client.post(BEGIN, headers=headers, json={"password": "wrong"})

    assert r.status_code == 403, r.text
    assert await _failures(user) == 1
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "mfa.enrol_begin", AuditLog.user_id == user.id
            )
        )
    ).scalar_one()
    assert (row.result, row.error_detail) == ("denied", "bad_credential")
    assert row.new_value == {"stepup_method": "provider_password"}


async def test_the_ldap_budget_runs_out_and_then_stops_asking_the_directory(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    calls = _fake_directory(monkeypatch, password="right")
    provider = await _provider(db_session, "ldap")
    _, headers = await _account(db_session, provider)

    for _ in range(5):
        assert (
            await client.post(BEGIN, headers=headers, json={"password": "wrong"})
        ).status_code == 403
    assert len(calls) == 5

    # The sixth is refused before the directory sees it, even with the RIGHT password.
    r = await client.post(BEGIN, headers=headers, json={"password": "right"})
    assert r.status_code == 429, r.text
    assert len(calls) == 5


async def test_the_same_password_for_another_directory_account_is_refused(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    # The directory accepts the username + password, but as a different subject.
    _fake_directory(monkeypatch, password="right", external_id="uid=mallory,dc=example")
    provider = await _provider(db_session, "ldap")
    user, headers = await _account(db_session, provider)

    r = await client.post(BEGIN, headers=headers, json={"password": "right"})

    assert r.status_code == 403, r.text
    assert await _failures(user) == 1


async def test_an_unreachable_directory_is_a_503_and_spends_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
):
    import app.services.mfa_enrol_stepup as svc

    def down(provider, username, pw):
        raise LDAPServiceError("cannot reach LDAP server")

    monkeypatch.setitem(svc._PASSWORD_AUTH, "ldap", (down, LDAPServiceError))
    provider = await _provider(db_session, "ldap")
    user, headers = await _account(db_session, provider)

    for _ in range(7):
        r = await client.post(BEGIN, headers=headers, json={"password": "right"})
        assert r.status_code == 503, r.text
    assert await _failures(user) == 0


async def test_a_local_users_password_is_unchanged(client: AsyncClient, db_session: AsyncSession):
    user = User(
        username=f"l-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="l",
        auth_source="local",
        hashed_password=hash_password("pw-123456"),
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    headers = await _sign_in(db_session, user, timedelta(0))
    assert (await client.get(STATUS, headers=headers)).json()["enrol_requires"] == "password"
    assert (
        await client.post(BEGIN, headers=headers, json={"password": "pw-123456"})
    ).status_code == 200


# ── the window survives only where there is nothing stronger to ask ───────


async def test_an_account_whose_provider_is_gone_or_off_keeps_the_window(
    client: AsyncClient, db_session: AsyncSession
):
    off = await _provider(db_session, "oidc")
    off.is_enabled = False
    for provider in (None, off):
        _, fresh = await _account(db_session, provider, auth_source="oidc")
        status = (await client.get(STATUS, headers=fresh)).json()
        assert status["enrol_requires"] == "recent_sign_in"
        assert (await client.post(BEGIN, headers=fresh)).status_code == 200
        _, stale = await _account(
            db_session, provider, auth_source="oidc", signed_in_ago=timedelta(hours=1)
        )
        assert (await client.post(BEGIN, headers=stale)).status_code == 403


# ── OIDC: prompt=login, max_age=0, and a fresh auth_time ──────────────────


def test_oidc_reauth_asks_the_idp_to_authenticate_again():
    import asyncio

    from app.core.auth.oidc import OIDCConfig, build_authorize_url

    cfg = OIDCConfig(
        discovery_url="https://idp.example.com/.well-known/openid-configuration",
        client_id="c",
        client_secret="s",
        scopes=["openid"],
        claim_username="preferred_username",
        claim_email="email",
        claim_display_name="name",
        claim_groups="groups",
    )
    doc = {"authorization_endpoint": "https://idp.example.com/auth"}
    with patch("app.core.auth.oidc._fetch_discovery", AsyncMock(return_value=doc)):
        plain = asyncio.run(build_authorize_url(cfg, "p", "st", "no", "https://x/cb"))
        forced = asyncio.run(build_authorize_url(cfg, "p", "st", "no", "https://x/cb", reauth=True))
    assert "prompt" not in parse_qs(urlsplit(plain).query)
    q = parse_qs(urlsplit(forced).query)
    assert q["prompt"] == ["login"]
    assert q["max_age"] == ["0"]


def test_oidc_auth_time_must_be_recent_and_present():
    started = int(time.time())
    _require_fresh_auth_time(started + 5, started)
    _require_fresh_auth_time(started - 10, started)  # inside the skew leeway
    for stale in (started - 3600, started - 120):
        with pytest.raises(OIDCServiceError, match="predates"):
            _require_fresh_auth_time(stale, started)
    with pytest.raises(OIDCServiceError, match="future"):
        _require_fresh_auth_time(started + 3600, started)
    for unusable in (None, "yesterday", True, [1]):
        with pytest.raises(OIDCServiceError, match="no usable auth_time"):
            _require_fresh_auth_time(unusable, started)


async def test_exchange_code_refuses_an_id_token_with_a_stale_auth_time():
    # The whole token path with real RSA-signed JWTs (tests.test_oidc).
    from app.core.auth.oidc import OIDCConfig, exchange_code, invalidate_caches
    from tests import test_oidc as t

    invalidate_caches("p-1354")
    cfg = OIDCConfig(
        discovery_url=f"{t.ISSUER}/.well-known/openid-configuration",
        client_id=t.CLIENT_ID,
        client_secret="secret",
        scopes=["openid"],
        claim_username="preferred_username",
        claim_email="email",
        claim_display_name="name",
        claim_groups="groups",
    )
    now = int(time.time())

    async def run(**claims: object):
        token = t._mint(**claims)
        with patch(
            "app.core.auth.oidc.httpx.AsyncClient", t._patched_client(t._make_transport(token))
        ):
            return await exchange_code(
                cfg, "p-1354", "code", "https://x/cb", t.NONCE, fresh_since=now
            )

    assert (await run(auth_time=now + 1)).external_id == "user-1"
    for claims in ({"auth_time": now - 3600}, {}):
        with pytest.raises(OIDCServiceError):
            await run(**claims)
        invalidate_caches("p-1354")
    invalidate_caches("p-1354")


# ── OIDC / SAML: the round trip and the proof it leaves ───────────────────


def _flow_cookie(resp, name: str) -> str:
    return next(
        v.split(";", 1)[0]
        for k, v in resp.headers.multi_items()
        if k.lower() == "set-cookie" and v.startswith(f"{name}=")
    )


async def _oidc_provider(db: AsyncSession) -> AuthProvider:
    provider = await _provider(
        db,
        "oidc",
        discovery_url="https://idp.example.com/.well-known/openid-configuration",
        client_id="c",
    )
    provider.secrets_encrypted = encrypt_dict({"client_secret": "s"})
    await db.commit()
    return provider


async def _start_oidc(client: AsyncClient, headers: dict[str, str]) -> tuple[dict, str, str]:
    """POST /mfa/enroll/reauth; returns (json, flow cookie, state)."""
    authorize = AsyncMock(return_value="https://idp.example.com/auth?x=1")
    with patch.object(auth_router, "oidc_authorize_url", authorize):
        r = await client.post(REAUTH, headers=headers)
    assert r.status_code == 200, r.text
    assert authorize.await_args.kwargs["reauth"] is True
    cookie = _flow_cookie(r, "oidc_flow")
    state = authorize.await_args.args[2]
    return r.json(), cookie, state


async def _oidc_callback(
    client: AsyncClient,
    provider: AuthProvider,
    cookie: str,
    state: str,
    *,
    subject: str = DN,
    capture: list | None = None,
):
    async def exchange(cfg, pid, code, redirect, nonce, *, fresh_since=None):
        if capture is not None:
            capture.append(fresh_since)
        return ExternalAuthResult(external_id=subject, username="x")

    with patch.object(auth_router, "oidc_exchange_code", exchange):
        return await client.get(
            f"/api/v1/auth/{provider.id}/callback",
            params={"code": "c", "state": state},
            headers={"Cookie": cookie},
        )


async def test_oidc_reauth_round_trip_leaves_a_proof_begin_takes_once(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _oidc_provider(db_session)
    user, headers = await _account(db_session, provider, external_id="sub-1")
    assert (await client.get(STATUS, headers=headers)).json()["enrol_requires"] == "provider_reauth"

    # No re-authentication yet: refused, and it says what to do.
    r = await client.post(BEGIN, headers=headers)
    assert r.status_code == 403 and "sign in again at your identity provider" in r.json()["detail"]

    body, cookie, state = await _start_oidc(client, headers)
    assert body["authorize_url"].startswith("https://idp.example.com/auth")
    seen: list = []
    cb = await _oidc_callback(client, provider, cookie, state, subject="sub-1", capture=seen)
    assert cb.status_code == 302 and cb.headers["location"] == "/account?mfa_reauth=ok"
    assert seen and seen[0] > 0  # verified against the flow's own start time

    assert (await client.post(BEGIN, headers=headers)).status_code == 200
    # Single use: the same proof does not start a second enrolment.
    again = await client.post(BEGIN, headers=headers)
    assert again.status_code == 403
    # Not a guess, so the budget is untouched.
    assert await _failures(user) == 0


async def test_an_oidc_proof_survives_the_token_refresh_the_return_trip_causes(
    client: AsyncClient, db_session: AsyncSession
):
    # The IdP round trip reloads the SPA, which refreshes: a new UserSession
    # row, the same sign-in time (#1241). The proof must follow the sign-in.
    provider = await _oidc_provider(db_session)
    user, headers = await _account(db_session, provider, external_id="sub-1")
    _, cookie, state = await _start_oidc(client, headers)
    await _oidc_callback(client, provider, cookie, state, subject="sub-1")

    old = (
        await db_session.execute(select(UserSession).where(UserSession.user_id == user.id))
    ).scalar_one()
    rotated = UserSession(
        user_id=user.id,
        refresh_token_hash=f"t-{uuid.uuid4().hex}",
        auth_source=old.auth_source,
        created_at=old.created_at,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(rotated)
    await db_session.commit()
    new_headers = {
        "Authorization": f"Bearer {create_access_token(str(user.id), jti=str(rotated.id))}"
    }

    assert (await client.post(BEGIN, headers=new_headers)).status_code == 200


async def test_an_oidc_proof_is_for_the_session_that_started_it(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _oidc_provider(db_session)
    user, headers = await _account(db_session, provider, external_id="sub-1")
    _, cookie, state = await _start_oidc(client, headers)
    await _oidc_callback(client, provider, cookie, state, subject="sub-1")

    # A different sign-in of the same user (another browser, a hijacker's).
    other = await _sign_in(db_session, user, timedelta(minutes=3))
    assert (await client.post(BEGIN, headers=other)).status_code == 403
    # ...and it did not consume the owner's proof.
    assert (await client.post(BEGIN, headers=headers)).status_code == 200


async def test_an_oidc_proof_is_for_the_user_who_started_it(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _oidc_provider(db_session)
    alice, a_headers = await _account(db_session, provider, external_id="sub-a")
    _, b_headers = await _account(db_session, provider, external_id="sub-b")
    _, cookie, state = await _start_oidc(client, a_headers)
    await _oidc_callback(client, provider, cookie, state, subject="sub-a")
    assert (await client.post(BEGIN, headers=b_headers)).status_code == 403
    assert alice.id


async def test_a_different_idp_subject_leaves_no_proof(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _oidc_provider(db_session)
    user, headers = await _account(db_session, provider, external_id="sub-1")
    _, cookie, state = await _start_oidc(client, headers)

    cb = await _oidc_callback(client, provider, cookie, state, subject="someone-else")

    assert cb.headers["location"] == "/account?mfa_reauth=failed"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "mfa.enrol_reauth", AuditLog.user_id == user.id
            )
        )
    ).scalar_one()
    assert (row.result, row.error_detail) == ("denied", "identity_mismatch")


async def test_an_idp_that_refuses_the_fresh_login_leaves_no_proof(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _oidc_provider(db_session)
    _, headers = await _account(db_session, provider, external_id="sub-1")
    _, cookie, state = await _start_oidc(client, headers)

    async def stale(*a, **k):
        raise OIDCServiceError("ID token auth_time predates this re-authentication")

    with patch.object(auth_router, "oidc_exchange_code", stale):
        cb = await client.get(
            f"/api/v1/auth/{provider.id}/callback",
            params={"code": "c", "state": state},
            headers={"Cookie": cookie},
        )
    assert cb.headers["location"] == "/account?mfa_reauth=failed"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403


async def test_a_replayed_callback_leaves_no_second_proof(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _oidc_provider(db_session)
    _, headers = await _account(db_session, provider, external_id="sub-1")
    _, cookie, state = await _start_oidc(client, headers)

    first = await _oidc_callback(client, provider, cookie, state, subject="sub-1")
    assert first.headers["location"] == "/account?mfa_reauth=ok"
    assert (await client.post(BEGIN, headers=headers)).status_code == 200
    replay = await _oidc_callback(client, provider, cookie, state, subject="sub-1")
    assert replay.headers["location"] == "/account?mfa_reauth=failed"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403


async def test_a_login_flow_cookie_cannot_pass_as_a_reauth(
    client: AsyncClient, db_session: AsyncSession
):
    # An ordinary sign-in flow (no purpose) still signs in, and leaves no proof.
    provider = await _oidc_provider(db_session)
    _, headers = await _account(db_session, provider, external_id="sub-1")
    with patch.object(auth_router, "oidc_authorize_url", AsyncMock(return_value="https://i/a")):
        r = await client.get(f"/api/v1/auth/{provider.id}/authorize")
    cookie = _flow_cookie(r, "oidc_flow")
    state = auth_router._verify_flow_token(cookie.split("=", 1)[1])["state"]
    assert "purpose" not in auth_router._verify_flow_token(cookie.split("=", 1)[1])
    cb = await _oidc_callback(client, provider, cookie, state, subject="sub-1")
    assert cb.headers["location"] != "/account?mfa_reauth=ok"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403


async def test_reauth_is_refused_for_accounts_it_does_not_apply_to(
    client: AsyncClient, db_session: AsyncSession
):
    provider = await _provider(db_session, "ldap")
    _, headers = await _account(db_session, provider)
    assert (await client.post(REAUTH, headers=headers)).status_code == 400


# ── SAML: ForceAuthn and AuthnInstant ─────────────────────────────────────


def _response_with_authn_instant(*, flow: dict, authn_instant: datetime | None) -> str:
    """The ``test_saml_acs`` signed Response, with the AuthnStatement's
    AuthnInstant chosen by the test."""
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    now = datetime.now(UTC)
    template = saml._ASSERTION
    if authn_instant is None:
        template = template.replace(' AuthnInstant="{now}"', "")
    else:
        template = template.replace(
            'AuthnInstant="{now}"', f'AuthnInstant="{authn_instant.strftime(stamp)}"'
        )
    fields = {
        "issuer": saml.IDP_ENTITY_ID,
        "name_id": saml.NAME_ID,
        "destination": flow["request_acs"],
        "in_response_to": f' InResponseTo="{flow["request_id"]}"',
        "audience": flow["sp_entity_id"],
        "now": now.strftime(stamp),
        "earlier": (now - timedelta(minutes=1)).strftime(stamp),
        "later": (now + timedelta(minutes=5)).strftime(stamp),
    }
    assertion = OneLogin_Saml2_Utils.add_sign(
        template.format(
            assertion_id=OneLogin_Saml2_Utils.generate_unique_id(),
            session_index=OneLogin_Saml2_Utils.generate_unique_id(),
            **fields,
        ),
        saml.IDP_KEY,
        saml.IDP_CERT,
    )
    response = saml._RESPONSE.format(
        response_id=OneLogin_Saml2_Utils.generate_unique_id(),
        assertion=assertion.decode(),
        **fields,
    )
    return base64.b64encode(response.encode()).decode()


async def _saml_reauth(client: AsyncClient, db: AsyncSession):
    provider, _ = await saml._saml_provider(db)
    user, headers = await _account(db, provider, external_id=saml.NAME_ID)
    r = await client.post(REAUTH, headers=headers)
    assert r.status_code == 200, r.text
    query = parse_qs(urlsplit(r.json()["authorize_url"]).query)
    request = OneLogin_Saml2_XML.to_etree(
        OneLogin_Saml2_Utils.decode_base64_and_inflate(query["SAMLRequest"][0])
    )
    flow = {
        "request_acs": request.get("AssertionConsumerServiceURL"),
        "request_id": request.get("ID"),
        "sp_entity_id": request.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text,
        "relay_state": query["RelayState"][0],
        "cookie": _flow_cookie(r, "saml_flow"),
    }
    return provider, user, headers, request, flow


async def test_saml_reauth_sends_force_authn_and_a_fresh_assertion_leaves_a_proof(
    client: AsyncClient, db_session: AsyncSession
):
    provider, user, headers, request, flow = await _saml_reauth(client, db_session)
    assert request.get("ForceAuthn") == "true"

    resp = await saml._deliver(
        client,
        provider,
        flow,
        _response_with_authn_instant(flow=flow, authn_instant=datetime.now(UTC)),
    )

    assert resp.headers["location"] == "/account?mfa_reauth=ok", await saml._rejection(
        db_session, provider
    )
    assert (await client.post(BEGIN, headers=headers)).status_code == 200
    assert (await client.post(BEGIN, headers=headers)).status_code == 403


async def test_a_login_authn_request_does_not_force_authn(
    client: AsyncClient, db_session: AsyncSession
):
    provider, _ = await saml._saml_provider(db_session)
    flow = await saml._start_sign_in(client, provider)
    resp = await client.get(f"/api/v1/auth/{provider.id}/authorize")
    query = parse_qs(urlsplit(resp.headers["location"]).query)
    request = OneLogin_Saml2_XML.to_etree(
        OneLogin_Saml2_Utils.decode_base64_and_inflate(query["SAMLRequest"][0])
    )
    assert request.get("ForceAuthn") in (None, "false")
    assert flow["request_id"]


@pytest.mark.parametrize(
    "authn_instant",
    [
        pytest.param(timedelta(hours=-3), id="stale"),
        pytest.param(timedelta(hours=3), id="future"),
        pytest.param(None, id="absent"),
    ],
)
async def test_saml_assertion_with_a_bad_authn_instant_leaves_no_proof(
    client: AsyncClient, db_session: AsyncSession, authn_instant: timedelta | None
):
    provider, _, headers, _, flow = await _saml_reauth(client, db_session)
    instant = None if authn_instant is None else datetime.now(UTC) + authn_instant

    resp = await saml._deliver(
        client, provider, flow, _response_with_authn_instant(flow=flow, authn_instant=instant)
    )

    assert resp.headers["location"] == "/account?mfa_reauth=failed"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403


async def test_a_saml_assertion_for_another_subject_leaves_no_proof(
    client: AsyncClient, db_session: AsyncSession
):
    provider, user, headers, _, flow = await _saml_reauth(client, db_session)
    user.external_id = "someone-else@example.com"
    await db_session.commit()

    resp = await saml._deliver(
        client,
        provider,
        flow,
        _response_with_authn_instant(flow=flow, authn_instant=datetime.now(UTC)),
    )

    assert resp.headers["location"] == "/account?mfa_reauth=failed"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403


async def test_a_saml_assertion_replay_leaves_no_second_proof(
    client: AsyncClient, db_session: AsyncSession
):
    provider, _, headers, _, flow = await _saml_reauth(client, db_session)
    response = _response_with_authn_instant(flow=flow, authn_instant=datetime.now(UTC))
    first = await saml._deliver(client, provider, flow, response)
    assert first.headers["location"] == "/account?mfa_reauth=ok"
    assert (await client.post(BEGIN, headers=headers)).status_code == 200

    again = await saml._deliver(client, provider, flow, response)
    assert again.headers["location"] == "/account?mfa_reauth=failed"
    assert (await client.post(BEGIN, headers=headers)).status_code == 403
