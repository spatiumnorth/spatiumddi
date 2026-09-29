"""Authentication endpoints: login, refresh, logout, current user,
plus OIDC redirect flow (authorize + callback + provider listing)."""

import asyncio
import secrets as py_secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import structlog
from fastapi import APIRouter, Form, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from jose import JWTError
from jose import jwt as jose_jwt
from pydantic import BaseModel, field_validator
from sqlalchemy import select, update

from app.api.deps import DB, CurrentUser
from app.config import settings
from app.core.auth.ldap import LDAPServiceError, authenticate_ldap
from app.core.auth.oidc import OIDCConfig, OIDCServiceError
from app.core.auth.oidc import build_authorize_url as oidc_authorize_url
from app.core.auth.oidc import exchange_code as oidc_exchange_code
from app.core.auth.radius import RADIUSServiceError, authenticate_radius
from app.core.auth.saml import (
    SAMLConfig,
    SAMLServiceError,
    sp_metadata_xml,
)
from app.core.auth.saml import (
    build_authorize_url as saml_authorize_url,
)
from app.core.auth.saml import (
    consume_assertion as saml_consume_assertion,
)
from app.core.auth.tacacs import TACACSServiceError, authenticate_tacacs
from app.core.auth.user_sync import (
    ExternalAuthResult,
    ExternalSyncRejected,
    sync_external_user,
)
from app.core.auth_throttle import login_rate_limited, mfa_challenge_consume
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import effective_grants, is_effective_superadmin
from app.core.request_meta import clean_user_agent, get_trusted_client_ip
from app.core.responses import XmlResponse
from app.core.security import (
    create_access_token,
    create_mfa_challenge_token,
    create_refresh_token,
    decode_access_token,
    decode_mfa_challenge_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.models.audit import AuditLog
from app.models.auth import User, UserSession
from app.models.auth_provider import PASSWORD_PROVIDER_TYPES, AuthProvider
from app.models.settings import PlatformSettings
from app.services.account_lockout import (
    LockoutPolicy,
    is_locked,
    register_failure,
    register_success,
)
from app.services.mfa import (
    consume_recovery_code,
    decrypt_secret,
    encrypt_recovery_codes,
    encrypt_secret,
    generate_recovery_codes,
    generate_secret,
    otpauth_uri,
    remaining_recovery_codes,
    verify_totp,
)
from app.services.password_policy import (
    PasswordPolicy,
    is_in_history,
    push_history,
)
from app.services.password_policy import (
    is_expired as password_is_expired,
)
from app.services.password_policy import (
    validate as validate_password_policy,
)

logger = structlog.get_logger(__name__)
router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    """Internal carrier for a freshly-minted token pair. The raw refresh
    token NEVER leaves the server in a JSON body — callers set it as an
    HttpOnly cookie via ``_set_refresh_cookie`` and return one of the
    refresh-free response models below (#484 / #400 L1)."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    force_password_change: bool = False


class LoginResponse(BaseModel):
    """Login response. Two shapes the caller has to handle:

    1. **MFA not required.** ``access_token`` is set; ``mfa_required`` is
       False; the caller keeps it in memory and proceeds. The refresh
       token is delivered out-of-band as an HttpOnly cookie (#484), never
       in this body.
    2. **MFA required.** ``access_token`` is NOT set; ``mfa_required`` is
       True; ``mfa_token`` carries a 5-minute JWT (claim
       ``type=mfa``) that the caller must POST to
       ``/auth/login/mfa`` along with a TOTP code or a recovery
       code. The challenge token is useless for any other endpoint.
    """

    access_token: str | None = None
    token_type: str = "bearer"
    force_password_change: bool = False
    mfa_required: bool = False
    mfa_token: str | None = None


class RefreshResponse(BaseModel):
    """Response for ``/auth/refresh``. The rotated refresh token is set as
    an HttpOnly cookie on the same response; only the new access token is
    returned in the body (#484)."""

    access_token: str
    token_type: str = "bearer"
    force_password_change: bool = False


class MfaLoginRequest(BaseModel):
    mfa_token: str
    # Operator submits exactly one of these. Both empty = 422.
    code: str | None = None
    recovery_code: str | None = None


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    display_name: str
    is_superadmin: bool
    force_password_change: bool
    auth_source: str

    model_config = {"from_attributes": True}


class PermissionGrant(BaseModel):
    action: str
    resource_type: str
    resource_id: str | None = None


class MyPermissionsResponse(BaseModel):
    is_superadmin: bool
    grants: list[PermissionGrant]


class ChangePasswordRequest(BaseModel):
    """Self-service password change. Pydantic enforces only non-emptiness
    here so legacy clients keep returning a 422 on obviously-empty input;
    the real policy check runs server-side against ``PlatformSettings``
    and returns 400 with a per-rule error list so the UI can surface them
    all at once."""

    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        # #1004 — NOT a length policy. This is the "obviously empty" floor
        # that keeps a legacy client getting a 422 instead of reaching the
        # handler; every length verdict belongs to the configured policy,
        # which the handler enforces against PlatformSettings.
        #
        # It used to be 8, which was a SECOND minimum contradicting the
        # operator's setting (12 by default) — and the only source of the
        # number 8 anywhere in the flow. Worse, it fired as a pydantic 422
        # whose detail is an error ARRAY, a shape the change-password screen
        # did not parse, so a 7-character password was reported as "check
        # your current password". A floor of 1 cannot collide with a policy
        # minimum (settings clamp it to 6..128), so the two can never
        # disagree again.
        if not v:
            raise ValueError("Password cannot be empty")
        return v


class PasswordPolicyResponse(BaseModel):
    """Public read of the active policy. Returned unauthenticated so the
    login + change-password forms can render the rule list before the
    user even submits — fewer round-trips on a typo, and the rules are
    not sensitive."""

    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_digit: bool
    require_symbol: bool
    history_count: int
    max_age_days: int


def _client_ip(request: Request) -> str | None:
    # Auth-surface source IP: the per-IP login throttle (#4) gates on this,
    # and it also lands in the login audit rows + ``last_login_ip``. Use the
    # spoofing-resistant value (X-Real-IP, not the forgeable
    # X-Forwarded-For-derived peer) so neither the throttle nor the audit
    # trail can be evaded / poisoned by a client-supplied header (#626).
    return get_trusted_client_ip(request)


# SECURITY (#484 / #400 L1): the refresh token is delivered ONLY as an
# HttpOnly + Secure + SameSite=Strict cookie, never in a JSON body or URL
# fragment, so an XSS foothold in the SPA cannot read it. The access token
# stays short-lived and lives in JS memory only (see frontend
# ``lib/authToken.ts``). The cookie is path-scoped to ``/api/v1/auth`` so
# it rides only the refresh + logout calls, not every API request.
_REFRESH_COOKIE = "spatium_refresh"
_REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: Response, request: Request, raw_refresh: str) -> None:
    response.set_cookie(
        _REFRESH_COOKIE,
        raw_refresh,
        max_age=settings.refresh_token_expire_days * 86400,
        httponly=True,
        samesite="strict",
        # Mirror the OIDC/SAML flow cookies: only mark Secure when the
        # request arrived over HTTPS, so plain-HTTP dev on localhost keeps
        # working while real (TLS-terminated) deployments get the flag.
        secure=request.url.scheme == "https",
        path=_REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(_REFRESH_COOKIE, path=_REFRESH_COOKIE_PATH)


async def _issue_tokens(db: DB, request: Request, user: User, auth_source: str) -> TokenResponse:
    """Issue access + refresh tokens, create session, write success audit."""
    # Reset lockout state on every successful login (issue #71). No-op
    # for users who weren't accumulating failures.
    register_success(user)
    raw_refresh, refresh_hash = create_refresh_token(str(user.id))

    # Mint the session row first so we can embed ``session.id`` as the
    # access token's ``jti`` (issue #72). Force-logout works by
    # flipping ``UserSession.revoked`` — the auth dep cross-checks
    # ``jti`` against the session on every request.
    now = datetime.now(UTC)
    session_row = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_hash,
        source_ip=_client_ip(request),
        user_agent=clean_user_agent(request.headers.get("user-agent")),
        auth_source=auth_source,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(session_row)
    await db.flush()  # populate session_row.id before we sign the JWT
    access_token = create_access_token(str(user.id), jti=str(session_row.id))
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=auth_source,
            source_ip=_client_ip(request),
            user_agent=clean_user_agent(request.headers.get("user-agent")),
            action="login",
            resource_type="user",
            resource_id=str(user.id),
            resource_display=user.username,
            result="success",
        )
    )
    user.last_login_at = datetime.now(UTC)
    user.last_login_ip = _client_ip(request)
    await db.commit()

    logger.info(
        "login_success",
        user_id=str(user.id),
        username=user.username,
        auth_source=auth_source,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        force_password_change=user.force_password_change,
    )


async def _audit_login_failure(
    db: DB,
    request: Request,
    username: str,
    reason: str,
    auth_source: str = "local",
    user: User | None = None,
) -> None:
    """Persist a login-failure audit row and, when the failure was
    against a known local user, bump the lockout counter (issue #71).

    The lockout side-effect runs only for ``auth_source == 'local'``
    + bad-credential reasons — locking against ``account_locked`` /
    ``account_disabled`` failures would just keep extending the lock
    while the attacker pokes a locked account, and external-IdP
    failures don't have a SpatiumDDI-side counter to bump.
    """
    just_locked = False
    if (
        user is not None
        and user.auth_source == "local"
        and reason
        in {
            "bad_password",
            "mfa_code_invalid",
            "mfa_challenge_invalid",
        }
    ):
        settings_row = await db.get(PlatformSettings, 1)
        policy = LockoutPolicy.from_row(settings_row)
        just_locked = register_failure(user, policy)

    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else (username or "<unknown>"),
            auth_source=auth_source,
            source_ip=_client_ip(request),
            user_agent=clean_user_agent(request.headers.get("user-agent")),
            action="login",
            resource_type="user",
            resource_id=str(user.id) if user else "",
            resource_display=username or "<unknown>",
            result="failure",
            new_value={"reason": reason},
        )
    )
    if just_locked and user is not None:
        # Distinct audit row so an admin walking the log can tell
        # "5th failure" from "automatically locked because of those
        # 5 failures" without correlating timestamps by hand.
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=auth_source,
                source_ip=_client_ip(request),
                user_agent=clean_user_agent(request.headers.get("user-agent")),
                action="account.locked",
                resource_type="user",
                resource_id=str(user.id),
                resource_display=user.username,
                result="success",
                new_value={
                    "locked_until": (
                        user.failed_login_locked_until.isoformat()
                        if user.failed_login_locked_until
                        else None
                    ),
                    "failed_count": user.failed_login_count,
                },
            )
        )
    await db.commit()
    logger.warning(
        "login_failed",
        username=username,
        reason=reason,
        auth_source=auth_source,
        source_ip=_client_ip(request),
        just_locked=just_locked,
    )


# Password-grant dispatch table. Each entry is the sync authenticate function
# (invoked on a worker thread) plus the provider-type-specific ServiceError
# it may raise. All three functions share the shape
#   (provider, username, password) -> ExternalAuthResult | None
_PasswordAuthFn = Callable[[AuthProvider, str, str], ExternalAuthResult | None]
_PASSWORD_AUTH_DISPATCH: dict[str, tuple[_PasswordAuthFn, type[Exception]]] = {
    "ldap": (authenticate_ldap, LDAPServiceError),
    "radius": (authenticate_radius, RADIUSServiceError),
    "tacacs": (authenticate_tacacs, TACACSServiceError),
}


async def _try_external_password_login(
    db: DB, request: Request, username: str, password: str
) -> TokenResponse | None:
    """Iterate every enabled password-flow provider (LDAP / RADIUS / TACACS+)
    by priority. First success wins. Each provider runs in a worker thread
    with a 20s timeout.

    Returns a TokenResponse on success, None if all providers rejected or
    errored (caller is responsible for emitting the final 401 + audit).
    """
    res = await db.execute(
        select(AuthProvider)
        .where(
            AuthProvider.type.in_(PASSWORD_PROVIDER_TYPES),
            AuthProvider.is_enabled.is_(True),
        )
        .order_by(AuthProvider.priority, AuthProvider.name)
    )
    providers = list(res.unique().scalars().all())
    if not providers:
        return None

    for provider in providers:
        dispatch = _PASSWORD_AUTH_DISPATCH.get(provider.type)
        if dispatch is None:
            # Defensive: PROVIDER_TYPES could include a value not wired here yet.
            logger.warning(
                "password_auth_unknown_type",
                provider=provider.name,
                type=provider.type,
            )
            continue
        authenticate_fn, service_exc = dispatch

        try:
            result: ExternalAuthResult | None = await asyncio.wait_for(
                asyncio.to_thread(authenticate_fn, provider, username, password),
                timeout=20,
            )
        except service_exc as exc:
            # Misconfigured / unreachable — log + continue to next provider.
            logger.warning(
                f"{provider.type}_service_error",
                provider=provider.name,
                error=str(exc),
            )
            db.add(
                AuditLog(
                    user_display_name=username,
                    auth_source=provider.name,
                    source_ip=_client_ip(request),
                    user_agent=clean_user_agent(request.headers.get("user-agent")),
                    action="login",
                    resource_type="auth_provider",
                    resource_id=str(provider.id),
                    resource_display=provider.name,
                    result="error",
                    new_value={"reason": "service_error", "detail": str(exc)[:500]},
                )
            )
            await db.commit()
            continue
        except TimeoutError:
            logger.warning(f"{provider.type}_timeout", provider=provider.name)
            db.add(
                AuditLog(
                    user_display_name=username,
                    auth_source=provider.name,
                    source_ip=_client_ip(request),
                    user_agent=clean_user_agent(request.headers.get("user-agent")),
                    action="login",
                    resource_type="auth_provider",
                    resource_id=str(provider.id),
                    resource_display=provider.name,
                    result="error",
                    new_value={"reason": "timeout"},
                )
            )
            await db.commit()
            continue

        if result is None:
            # Credentials rejected by this provider — try the next one.
            continue

        # Successful external auth. Reconcile into local User table.
        try:
            user = await sync_external_user(db, provider, result)
        except ExternalSyncRejected as exc:
            await _audit_login_failure(
                db,
                request,
                username,
                reason=exc.reason,
                auth_source=provider.name,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            ) from exc

        return await _issue_tokens(db, request, user, auth_source=provider.name)

    return None


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, response: Response, db: DB) -> LoginResponse:
    # Per-IP rate limit (#4) — complements the per-account lockout, which
    # only engages once a valid username is hit. Fails open if Redis is
    # down. 429 with a generic message (no account-existence leak).
    if await login_rate_limited(_client_ip(request)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again shortly.",
        )

    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    # ── Local-first ─────────────────────────────────────────────────────────
    if user is not None and user.auth_source == "local":
        # Lockout short-circuit (issue #71). Runs BEFORE the password
        # check so an attacker who hits a locked account doesn't get to
        # learn whether the supplied password would have worked. Audit
        # row records ``account_locked`` so an admin walking the log
        # can tell brute-force attempts apart from real failed logins.
        if is_locked(user):
            await _audit_login_failure(
                db, request, body.username, reason="account_locked", user=user
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is temporarily locked due to repeated failed logins.",
            )
        if not user.hashed_password or not verify_password(body.password, user.hashed_password):
            await _audit_login_failure(db, request, body.username, reason="bad_password", user=user)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )
        if not user.is_active:
            await _audit_login_failure(
                db, request, body.username, reason="account_disabled", user=user
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
        # Password-policy max-age check (issue #70). If rotation is on
        # and the user's password is older than the threshold we flip
        # ``force_password_change`` so the next session lands on the
        # change-password screen. Doesn't block login — the user still
        # needs to authenticate to reach that screen.
        settings_row = await db.get(PlatformSettings, 1)
        policy = PasswordPolicy.from_row(settings_row)
        if password_is_expired(user, policy) and not user.force_password_change:
            user.force_password_change = True
        # MFA gate (issue #69). Local users only — external providers
        # rely on their own IdP for MFA and don't run TOTP here. We don't
        # write an audit row for the password-success-but-MFA-pending case
        # because a successful login is what crosses the audit boundary;
        # ``/login/mfa`` is what fires the ``login`` action.
        if user.totp_enabled and user.totp_secret_encrypted is not None:
            challenge = create_mfa_challenge_token(str(user.id))
            return LoginResponse(mfa_required=True, mfa_token=challenge)
        tokens = await _issue_tokens(db, request, user, auth_source="local")
        _set_refresh_cookie(response, request, tokens.refresh_token)
        return LoginResponse(
            access_token=tokens.access_token,
            force_password_change=tokens.force_password_change,
        )

    # ── External provider fallthrough (LDAP / RADIUS / TACACS+) ─────────────
    external_response = await _try_external_password_login(
        db, request, body.username, body.password
    )
    if external_response is not None:
        _set_refresh_cookie(response, request, external_response.refresh_token)
        return LoginResponse(
            access_token=external_response.access_token,
            force_password_change=external_response.force_password_change,
        )

    # Existing-but-external user with no matching provider → fall through to
    # the generic 401 so we don't leak account-existence information.
    await _audit_login_failure(
        db,
        request,
        body.username,
        reason="no_match",
        user=user,
        auth_source=user.auth_source if user else "local",
    )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@router.post("/login/mfa", response_model=LoginResponse)
async def login_mfa(
    body: MfaLoginRequest, request: Request, response: Response, db: DB
) -> LoginResponse:
    """Complete a TOTP-gated login. Body carries the challenge token
    minted by ``/login`` plus a 6-digit TOTP code or a one-time recovery
    code. Either is accepted; both = 422.

    The challenge token is single-use in spirit but stateless — once
    spent it can technically be replayed within the 5 min TTL, but
    only against a successful TOTP/recovery code, so an attacker who
    captures the challenge token still needs the second factor.
    """
    # Same per-IP budget as /login (#4) — the MFA step is the other half
    # of the credential surface.
    if await login_rate_limited(_client_ip(request)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again shortly.",
        )

    if (body.code and body.recovery_code) or (not body.code and not body.recovery_code):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide exactly one of: code, recovery_code",
        )

    try:
        payload = decode_mfa_challenge_token(body.mfa_token)
        user_id: str = payload["sub"]
    except (JWTError, KeyError) as exc:
        await _audit_login_failure(db, request, "<mfa>", reason="mfa_challenge_invalid")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge",
        ) from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge",
        )
    if not user.totp_enabled or user.totp_secret_encrypted is None:
        # Defence in depth — the challenge token says this user has MFA,
        # but the column does not. Could only happen if MFA was disabled
        # between mint + redeem. Fail closed.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA not enabled for this user",
        )

    # ── Validate the second factor ─────────────────────────────────────────
    matched = False
    used_recovery = False
    if body.code is not None:
        try:
            secret = decrypt_secret(user.totp_secret_encrypted)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFA secret could not be decrypted — admin must reset",
            )
        matched = verify_totp(secret, body.code)
    elif body.recovery_code is not None:
        if user.recovery_codes_encrypted is None:
            matched = False
        else:
            ok, new_blob = consume_recovery_code(user.recovery_codes_encrypted, body.recovery_code)
            if ok:
                matched = True
                used_recovery = True
                user.recovery_codes_encrypted = new_blob
                db.add(
                    AuditLog(
                        user_id=user.id,
                        user_display_name=user.display_name,
                        auth_source="local",
                        source_ip=_client_ip(request),
                        user_agent=clean_user_agent(request.headers.get("user-agent")),
                        action="mfa.recovery_used",
                        resource_type="user",
                        resource_id=str(user.id),
                        resource_display=user.username,
                        result="success",
                        new_value={
                            "remaining": remaining_recovery_codes(user.recovery_codes_encrypted),
                        },
                    )
                )

    if not matched:
        await _audit_login_failure(db, request, user.username, reason="mfa_code_invalid", user=user)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    # Single-use guard (#7): claim the challenge jti now that the factor
    # matched. A wrong code above never reaches here, so a legit user can
    # still retry a fat-fingered code with the same challenge — but once a
    # valid code is accepted, the challenge can't be replayed (the
    # attacker who captured challenge+code loses the race / gets rejected).
    # Fails open if Redis is down (reverts to the prior stateless behavior).
    if not await mfa_challenge_consume(payload.get("jti")):
        await _audit_login_failure(
            db, request, user.username, reason="mfa_challenge_replayed", user=user
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA challenge already used",
        )

    # ── Success — issue real tokens ────────────────────────────────────────
    tokens = await _issue_tokens(db, request, user, auth_source="local")
    _set_refresh_cookie(response, request, tokens.refresh_token)
    if used_recovery:
        # The audit row was written before _issue_tokens committed; the
        # _issue_tokens commit covers it. No extra commit needed.
        logger.info("mfa_recovery_used", user_id=str(user.id))
    return LoginResponse(
        access_token=tokens.access_token,
        force_password_change=tokens.force_password_change,
    )


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token_endpoint(request: Request, response: Response, db: DB) -> RefreshResponse:
    """Exchange the HttpOnly refresh cookie for a new access token (with
    token rotation). The refresh token is read from the cookie set at login
    — never from the request body — so it stays invisible to JS (#484)."""
    raw_refresh = request.cookies.get(_REFRESH_COOKIE)
    if not raw_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token"
        )
    token_hash = hash_refresh_token(raw_refresh)

    result = await db.execute(
        select(UserSession)
        .where(UserSession.refresh_token_hash == token_hash)
        .where(UserSession.revoked.is_(False))
        .where(UserSession.expires_at > datetime.now(UTC))
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive"
        )

    # Rotate: revoke old session, issue new tokens. The new session
    # row's UUID becomes the new access token's ``jti`` (issue #72).
    session.revoked = True
    raw_refresh, refresh_hash = create_refresh_token(str(user.id))

    now = datetime.now(UTC)
    new_session = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_hash,
        source_ip=session.source_ip,
        user_agent=session.user_agent,
        auth_source=session.auth_source,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=settings.refresh_token_expire_days),
    )
    db.add(new_session)
    await db.flush()
    access_token = create_access_token(str(user.id), jti=str(new_session.id))
    await db.commit()

    _set_refresh_cookie(response, request, raw_refresh)
    logger.info("token_refreshed", user_id=str(user.id))
    return RefreshResponse(
        access_token=access_token,
        force_password_change=user.force_password_change,
    )


@router.get("/password-policy", response_model=PasswordPolicyResponse)
async def get_password_policy(db: DB) -> PasswordPolicyResponse:
    """Public read of the active password policy. Unauthenticated so the
    login + change-password forms can render the rule list immediately;
    no secrets are exposed."""
    settings_row = await db.get(PlatformSettings, 1)
    policy = PasswordPolicy.from_row(settings_row)
    return PasswordPolicyResponse(
        min_length=policy.min_length,
        require_uppercase=policy.require_uppercase,
        require_lowercase=policy.require_lowercase,
        require_digit=policy.require_digit,
        require_symbol=policy.require_symbol,
        history_count=policy.history_count,
        max_age_days=policy.max_age_days,
    )


def _current_session_jti(request: Request) -> str | None:
    """Best-effort extraction of the access token's ``jti`` from the
    incoming Authorization header, so the self-service change-password
    path can spare the caller's own session when it revokes the rest.

    Returns None for API-token auth, or anything that fails to decode
    (including a token with no ``jti``, #1222) — in which case we simply
    revoke every session, which is the safe direction (the caller just has
    to log in again)."""
    header = request.headers.get("authorization") or ""
    scheme, _, raw = header.partition(" ")
    if scheme.lower() != "bearer" or not raw:
        return None
    try:
        payload = decode_access_token(raw)
    except JWTError:
        return None
    jti = payload.get("jti")
    return str(jti) if jti is not None else None


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest,
    current_user: CurrentUser,
    request: Request,
    db: DB,
) -> None:
    forbid_in_demo_mode("Password change is disabled")
    if not current_user.hashed_password or not verify_password(
        body.current_password, current_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect"
        )

    settings_row = await db.get(PlatformSettings, 1)
    policy = PasswordPolicy.from_row(settings_row)
    result = validate_password_policy(body.new_password, policy)
    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"reason": "password_policy", "errors": result.errors},
        )
    if policy.history_count > 0 and is_in_history(
        body.new_password, current_user.password_history_encrypted
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "reason": "password_history",
                "errors": [
                    f"Password matches one of the last {policy.history_count} "
                    "passwords; choose a new one."
                ],
            },
        )

    new_hash = hash_password(body.new_password)
    new_history = push_history(
        new_hash, current_user.password_history_encrypted, policy.history_count
    )
    current_user.hashed_password = new_hash
    current_user.force_password_change = False
    current_user.password_changed_at = datetime.now(UTC)
    current_user.password_history_encrypted = new_history

    # SECURITY (#400 / M3): a password change must revoke every other
    # outstanding session + refresh token for this user. Without this a
    # stolen/leaked session that triggered the rotation (or any old session
    # that existed before the change) keeps working — defeating the whole
    # point of changing the password. Reuses the exact revocation statement
    # ``/auth/logout`` uses; we spare the caller's *current* session so a
    # routine self-service change doesn't immediately log the user out.
    current_jti = _current_session_jti(request)
    revoke_stmt = update(UserSession).where(
        UserSession.user_id == current_user.id, UserSession.revoked.is_(False)
    )
    if current_jti is not None:
        revoke_stmt = revoke_stmt.where(UserSession.id != current_jti)
    await db.execute(revoke_stmt.values(revoked=True))

    audit = AuditLog(
        user_id=current_user.id,
        user_display_name=current_user.display_name,
        auth_source=current_user.auth_source,
        action="update",
        resource_type="user",
        resource_id=str(current_user.id),
        resource_display=current_user.username,
        changed_fields=["hashed_password", "force_password_change", "password_changed_at"],
        result="success",
    )
    db.add(audit)
    await db.commit()
    logger.info("password_changed", user_id=str(current_user.id))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(current_user: CurrentUser, response: Response, db: DB) -> None:
    _clear_refresh_cookie(response)
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.revoked.is_(False))
        .values(revoked=True)
    )
    audit = AuditLog(
        user_id=current_user.id,
        user_display_name=current_user.display_name,
        auth_source=current_user.auth_source,
        action="logout",
        resource_type="user",
        resource_id=str(current_user.id),
        resource_display=current_user.username,
        result="success",
    )
    db.add(audit)
    await db.commit()


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser) -> UserResponse:
    # #351 — ``is_superadmin`` here reports the *effective* status (the legacy
    # column OR a group → Superadmin-role ``{*, *}`` wildcard), NOT the raw
    # column. OIDC / LDAP / SAML users mapped into a Superadmin-role group have
    # ``is_superadmin=False`` on the row (the column is only set on the seeded
    # ``admin`` account + explicit admin-form flags), so reporting the column
    # locked them out of every frontend superadmin gate (Fleet, Pairing,
    # SNMP / NTP / LLDP, Sessions, Settings, …) even though the backend route
    # gates already admit them via ``is_effective_superadmin``. This aligns what
    # ``/me`` advertises with what those gates actually allow. The literal
    # column stays available to admins via the users endpoint.
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        display_name=current_user.display_name,
        is_superadmin=is_effective_superadmin(current_user),
        force_password_change=current_user.force_password_change,
        auth_source=current_user.auth_source,
    )


@router.get("/me/permissions", response_model=MyPermissionsResponse)
async def get_my_permissions(current_user: CurrentUser) -> MyPermissionsResponse:
    """Return the calling credential's effective permission grants (issue #449).

    Self-only introspection: reads only ``current_user`` (no user-id param, no
    DB query by id), so a caller can never enumerate another user's grants. The
    payload is the *effective* set — static role permissions ∪ live time-bound
    grants (issue #65), then narrowed by the active credential's API-token
    resource grants (issue #374) — assembled by ``effective_grants`` along the
    exact resolution path ``user_has_permission`` enforces. ``is_superadmin``
    reports the *effective* status (legacy column OR RBAC ``{*, *}`` wildcard),
    matching ``/auth/me``; the client short-circuits on it and treats the user
    as omnipotent without inspecting ``grants``.

    Read-only introspection → **no audit row** (consistent with ``/auth/me`` and
    ``/auth/mfa/status``). The grant triples are already stashed on
    ``current_user`` by the auth dependency, so the body performs no DB or
    network IO.

    Explicit non-coverage decisions:

    * **MCP (#13):** no MCP tool is warranted. This is caller-credential-scoped
      self-data with no resource ``find_*`` / ``count_*`` semantics; the MCP
      transport exposes the read-only tool registry, not per-credential
      introspection.
    * **Feature module (#14):** not a new top-level resource family — it is an
      introspection read on the existing ``/auth`` router, so no ``ModuleSpec``
      gating applies.
    """
    return MyPermissionsResponse(
        is_superadmin=is_effective_superadmin(current_user),
        grants=[PermissionGrant(**g) for g in effective_grants(current_user)],
    )


# ── MFA — TOTP enrolment + management (issue #69) ───────────────────────────
#
# Local users only. The flow:
#
#   POST /auth/mfa/enroll/begin   → server generates a candidate secret +
#                                    recovery codes; persists the *secret*
#                                    encrypted on the user row but does NOT
#                                    flip ``totp_enabled``. Returns the
#                                    raw secret + otpauth URI + the 10
#                                    recovery codes.
#   POST /auth/mfa/enroll/verify  → operator submits the first 6-digit code
#                                    from their authenticator. On success
#                                    we persist the encrypted recovery
#                                    codes + flip ``totp_enabled = true``.
#                                    Audit-logged as ``mfa.enabled``.
#   POST /auth/mfa/disable        → password + current code required. Clears
#                                    all three columns. Audit-logged.
#   POST /auth/mfa/recovery-codes/regenerate → password + current code.
#                                    Returns a fresh set + replaces stored
#                                    hashes. Audit-logged.
#
# Recovery-code consumption is folded into ``/auth/login/mfa`` above; the
# endpoint accepts either ``code`` or ``recovery_code``.


class MfaEnrolBeginResponse(BaseModel):
    secret: str
    otpauth_uri: str
    recovery_codes: list[str]


class MfaEnrolVerifyRequest(BaseModel):
    code: str


class MfaPasswordCodeRequest(BaseModel):
    """Body shape for disable + recovery-code regen. Local users supply
    their current password AND a current TOTP code (two-factor reauth);
    external-auth users (no local password, #408) supply just the TOTP
    code, so ``password`` is optional."""

    password: str | None = None
    code: str


class MfaStatusResponse(BaseModel):
    enabled: bool
    enrolment_pending: bool
    recovery_codes_remaining: int


@router.get("/mfa/status", response_model=MfaStatusResponse)
async def mfa_status(current_user: CurrentUser) -> MfaStatusResponse:
    """Surface current MFA state for the Settings panel. ``enrolment_pending``
    is True when the operator has called ``begin`` but not ``verify`` —
    handy for the UI to render a "Resume enrolment" affordance."""
    return MfaStatusResponse(
        enabled=current_user.totp_enabled,
        enrolment_pending=(
            not current_user.totp_enabled and current_user.totp_secret_encrypted is not None
        ),
        recovery_codes_remaining=remaining_recovery_codes(current_user.recovery_codes_encrypted),
    )


@router.post("/mfa/enroll/begin", response_model=MfaEnrolBeginResponse)
async def mfa_enroll_begin(current_user: CurrentUser, db: DB) -> MfaEnrolBeginResponse:
    """Mint a candidate TOTP secret + recovery codes. Persists the secret
    on the user row encrypted (so /verify can compare without taking it
    over the wire twice) but leaves ``totp_enabled`` false.

    Calling begin a second time before verify replaces the candidate —
    operator scanned a half-broken QR code, fine, just start over.

    #408 — open to every auth source (was local-only). An external-auth
    (OIDC / SAML / LDAP / …) superadmin needs TOTP to re-confirm sensitive
    reveals, since they have no local password; the authenticated session
    is the enrolment auth (begin only mints a candidate secret)."""
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled — disable it first to re-enrol",
        )
    secret = generate_secret()
    codes = generate_recovery_codes()
    current_user.totp_secret_encrypted = encrypt_secret(secret)
    # Stash the recovery codes on the row right now so the operator can
    # resume verify without losing them. They're only "active" once
    # ``totp_enabled`` flips below.
    current_user.recovery_codes_encrypted = encrypt_recovery_codes(codes)
    await db.commit()
    return MfaEnrolBeginResponse(
        secret=secret,
        otpauth_uri=otpauth_uri(secret, current_user.username),
        recovery_codes=codes,
    )


@router.post("/mfa/enroll/verify", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_enroll_verify(
    body: MfaEnrolVerifyRequest, current_user: CurrentUser, request: Request, db: DB
) -> None:
    """Confirm enrolment by submitting the first 6-digit TOTP code. Until
    this succeeds ``totp_enabled`` stays false and login skips the MFA
    gate. On success we audit-log and the next ``/login`` will MFA-gate.

    #408 — open to every auth source (was local-only)."""
    if current_user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA already enabled")
    if current_user.totp_secret_encrypted is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No enrolment in progress — call /mfa/enroll/begin first",
        )
    secret = decrypt_secret(current_user.totp_secret_encrypted)
    if not verify_totp(secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    current_user.totp_enabled = True
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            source_ip=_client_ip(request),
            user_agent=clean_user_agent(request.headers.get("user-agent")),
            action="mfa.enabled",
            resource_type="user",
            resource_id=str(current_user.id),
            resource_display=current_user.username,
            result="success",
        )
    )
    await db.commit()


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(
    body: MfaPasswordCodeRequest, current_user: CurrentUser, request: Request, db: DB
) -> None:
    """Disable MFA. Local users supply the current password AND a current
    TOTP code (neither alone suffices); external-auth users (no local
    password, #408) supply just the current TOTP code. Clears the secret
    and recovery codes."""
    if not current_user.totp_enabled or current_user.totp_secret_encrypted is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not currently enabled"
        )
    # Password is required + checked ONLY for local accounts (which have
    # one). External-auth accounts re-confirm with the TOTP code alone.
    if current_user.auth_source == "local" and current_user.hashed_password:
        if not body.password or not verify_password(body.password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
    secret = decrypt_secret(current_user.totp_secret_encrypted)
    if not verify_totp(secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    current_user.totp_enabled = False
    current_user.totp_secret_encrypted = None
    current_user.recovery_codes_encrypted = None
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            source_ip=_client_ip(request),
            user_agent=clean_user_agent(request.headers.get("user-agent")),
            action="mfa.disabled",
            resource_type="user",
            resource_id=str(current_user.id),
            resource_display=current_user.username,
            result="success",
        )
    )
    await db.commit()


@router.post(
    "/mfa/recovery-codes/regenerate",
    response_model=MfaEnrolBeginResponse,
)
async def mfa_regenerate_recovery_codes(
    body: MfaPasswordCodeRequest, current_user: CurrentUser, request: Request, db: DB
) -> MfaEnrolBeginResponse:
    """Replace the recovery-code list. Same two-factor reauth as
    ``/disable``. Returns the new codes ONCE — operator must record them.
    The existing ``secret`` is kept so the authenticator app entry stays
    valid; only the recovery-code list rotates. Same reauth shape as
    ``/disable``: local users supply password + TOTP, external-auth users
    (no local password, #408) supply just the TOTP code."""
    if not current_user.totp_enabled or current_user.totp_secret_encrypted is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not currently enabled"
        )
    if current_user.auth_source == "local" and current_user.hashed_password:
        if not body.password or not verify_password(body.password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
    secret = decrypt_secret(current_user.totp_secret_encrypted)
    if not verify_totp(secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    codes = generate_recovery_codes()
    current_user.recovery_codes_encrypted = encrypt_recovery_codes(codes)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            source_ip=_client_ip(request),
            user_agent=clean_user_agent(request.headers.get("user-agent")),
            action="mfa.recovery_regenerated",
            resource_type="user",
            resource_id=str(current_user.id),
            resource_display=current_user.username,
            result="success",
        )
    )
    await db.commit()
    return MfaEnrolBeginResponse(
        secret=secret,
        otpauth_uri=otpauth_uri(secret, current_user.username),
        recovery_codes=codes,
    )


# ── OIDC / SAML redirect flow ────────────────────────────────────────────────


class PublicProviderInfo(BaseModel):
    id: uuid.UUID
    name: str
    type: str


@router.get("/providers", response_model=list[PublicProviderInfo])
async def list_public_providers(db: DB) -> list[PublicProviderInfo]:
    """Public (unauthenticated) list of enabled OIDC/SAML providers so the
    login page can render "Sign in with …" buttons. LDAP is excluded — those
    providers authenticate via the ordinary username+password form."""
    res = await db.execute(
        select(AuthProvider)
        .where(AuthProvider.is_enabled.is_(True))
        .where(AuthProvider.type.in_(["oidc", "saml"]))
        .order_by(AuthProvider.priority, AuthProvider.name)
    )
    return [
        PublicProviderInfo(id=p.id, name=p.name, type=p.type) for p in res.unique().scalars().all()
    ]


_OIDC_FLOW_COOKIE = "oidc_flow"
_OIDC_FLOW_TTL = 300  # 5 minutes
_SAML_FLOW_COOKIE = "saml_flow"
_SAML_FLOW_TTL = 300


def _saml_flow_cookie_kwargs(base: str) -> dict:
    """Attributes shared by the set + delete of the SAML flow cookie.

    SECURITY / CORRECTNESS (#873). Unlike OIDC — whose IdP hands the browser
    back with a cross-site *GET* redirect, which SameSite=Lax permits — SAML's
    Web Browser SSO profile returns the assertion as a cross-site **POST** to
    our ACS, and Lax cookies are never sent on a cross-site POST. So a Lax
    flow cookie is simply absent at the ACS for every IdP that does not share
    our registrable domain — i.e. every hosted IdP (Okta / Entra / Google) —
    and the login dies with ``saml_state_missing``. Only ``SameSite=None``
    survives that POST, and browsers honour None only alongside ``Secure``.

    Hence the policy is chosen from the deployment's own scheme rather than
    fixed: over HTTPS we can (and must) set None + Secure; over plain HTTP
    None would be dropped by the browser at *set* time, so Lax is strictly
    better there — it is what a same-site IdP needs, and that is the only
    kind of IdP that can work over HTTP at all. ``saml_callback`` turns the
    remaining cross-site-IdP-on-HTTP case into an actionable
    ``saml_requires_https`` instead of a bare state error.

    ``base`` is the deployment's external URL (see ``_app_base_url``) — the
    origin the SP metadata advertises as the ACS, i.e. the one the browser
    actually posts to — not necessarily the origin of this request.
    """
    https = base.lower().startswith("https://")
    return {
        "httponly": True,
        "samesite": "none" if https else "lax",
        "secure": https,
        "path": "/api/v1/auth/",
    }


_LOGIN_CALLBACK_PATH = "/login/callback"
_LOGIN_ERROR_PATH = "/login"


async def _app_base_url(db: DB, request: Request) -> str:
    """Admin-configured external URL (preferred) or the incoming request base."""
    row = await db.get(PlatformSettings, 1)
    configured = (row.app_base_url if row else "").rstrip("/")
    if configured:
        return configured
    return str(request.base_url).rstrip("/")


def _oidc_callback_url(base: str, provider_id: uuid.UUID) -> str:
    return f"{base}/api/v1/auth/{provider_id}/callback"


def _sign_flow_token(payload: dict) -> str:
    return jose_jwt.encode(payload, settings.secret_key, algorithm="HS256")


def _verify_flow_token(token: str) -> dict:
    try:
        return jose_jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError as exc:
        raise ValueError("invalid flow token") from exc


# Closed set of reason codes used in the /login?error=... redirect. Anything
# outside this set gets mapped to "unknown" before the redirect URL is built,
# so IdP-supplied / exception-supplied values never flow into the URL — the
# redirect target is always assembled from a literal in this set. Prevents
# CWE-601 (open-redirect) at the source: if a CodeQL taint trace ever reports
# user input reaching `RedirectResponse` from this helper, the trace is
# wrong.
_LOGIN_ERROR_REASONS = frozenset(
    {
        # OIDC
        "oidc_misconfigured",
        "oidc_discovery_failed",
        "oidc_state_missing",
        "oidc_state_invalid",
        "oidc_state_mismatch",
        "oidc_no_code",
        "oidc_exchange_failed",
        "oidc_idp_error",
        "oidc_rejected",
        # SAML
        "saml_misconfigured",
        "saml_requires_https",
        "saml_build_failed",
        "saml_state_missing",
        "saml_state_invalid",
        "saml_state_mismatch",
        "saml_assertion_rejected",
        "saml_rejected",
        # Fallback
        "unknown",
    }
)


def _login_error_redirect(reason: str) -> RedirectResponse:
    """Redirect to the login page with ``?error=<reason>``.

    ``reason`` MUST be one of the allowlisted values in
    ``_LOGIN_ERROR_REASONS``; anything else is coerced to ``"unknown"``.
    Since the redirect URL is assembled from a literal path plus a value
    selected from a closed set of literals, no user- or provider-supplied
    string ever flows into the URL — CWE-601 sanitization by construction.
    The actual IdP error is preserved in the server log and audit row.
    """
    if reason not in _LOGIN_ERROR_REASONS:
        logger.warning("login_error_redirect_unknown_reason", reason=reason)
        reason = "unknown"
    url = f"{_LOGIN_ERROR_PATH}?{urlencode({'error': reason})}"
    return RedirectResponse(url, status_code=302)


@router.get("/{provider_id}/authorize")
async def authorize(provider_id: uuid.UUID, request: Request, db: DB) -> RedirectResponse:
    provider = await db.get(AuthProvider, provider_id)
    if provider is None or not provider.is_enabled:
        raise HTTPException(status_code=404, detail="Provider not found")
    if provider.type == "oidc":
        return await _oidc_start(provider, request, db)
    if provider.type == "saml":
        return await _saml_start(provider, request, db)
    raise HTTPException(
        status_code=400,
        detail=f"Provider type {provider.type!r} does not use the redirect flow",
    )


async def _oidc_start(provider: AuthProvider, request: Request, db: DB) -> RedirectResponse:
    try:
        cfg = OIDCConfig.from_provider(provider)
    except OIDCServiceError as exc:
        logger.warning("oidc_authorize_config_error", provider=provider.name, error=str(exc))
        return _login_error_redirect("oidc_misconfigured")

    state = py_secrets.token_urlsafe(32)
    nonce = py_secrets.token_urlsafe(32)
    base = await _app_base_url(db, request)
    redirect_uri = _oidc_callback_url(base, provider.id)

    try:
        authorize_url = await oidc_authorize_url(cfg, str(provider.id), state, nonce, redirect_uri)
    except OIDCServiceError as exc:
        logger.warning("oidc_authorize_build_error", provider=provider.name, error=str(exc))
        return _login_error_redirect("oidc_discovery_failed")

    flow_token = _sign_flow_token(
        {
            "provider_id": str(provider.id),
            "state": state,
            "nonce": nonce,
            "exp": int(datetime.now(UTC).timestamp()) + _OIDC_FLOW_TTL,
        }
    )
    response = RedirectResponse(authorize_url, status_code=302)
    response.set_cookie(
        _OIDC_FLOW_COOKIE,
        flow_token,
        max_age=_OIDC_FLOW_TTL,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/api/v1/auth/",
    )
    return response


async def _saml_start(provider: AuthProvider, request: Request, db: DB) -> RedirectResponse:
    base = await _app_base_url(db, request)
    if not base.lower().startswith("https://"):
        # Not fatal on its own — a same-site IdP still round-trips the Lax
        # cookie this yields — but it is the precondition for the failure
        # ``saml_callback`` reports as ``saml_requires_https`` (#873), so
        # leave the operator a breadcrumb here rather than only at the ACS.
        logger.warning(
            "saml_authorize_insecure_base_url",
            provider=provider.name,
            base_url=base,
        )
    try:
        cfg = SAMLConfig.from_provider(provider, base)
    except SAMLServiceError as exc:
        logger.warning("saml_authorize_config_error", provider=provider.name, error=str(exc))
        return _login_error_redirect("saml_misconfigured")

    relay_state = py_secrets.token_urlsafe(32)
    try:
        authorize_url = saml_authorize_url(cfg, base, relay_state)
    except Exception as exc:  # noqa: BLE001 — python3-saml surfaces plain Exception
        logger.warning("saml_authorize_build_error", provider=provider.name, error=str(exc))
        return _login_error_redirect("saml_build_failed")

    flow_token = _sign_flow_token(
        {
            "provider_id": str(provider.id),
            "relay_state": relay_state,
            "exp": int(datetime.now(UTC).timestamp()) + _SAML_FLOW_TTL,
        }
    )
    response = RedirectResponse(authorize_url, status_code=302)
    response.set_cookie(
        _SAML_FLOW_COOKIE,
        flow_token,
        max_age=_SAML_FLOW_TTL,
        **_saml_flow_cookie_kwargs(base),
    )
    return response


@router.get("/{provider_id}/callback")
async def oidc_callback(
    provider_id: uuid.UUID,
    request: Request,
    db: DB,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    provider = await db.get(AuthProvider, provider_id)
    if provider is None or provider.type != "oidc":
        raise HTTPException(status_code=404, detail="Provider not found")

    flow_cookie = request.cookies.get(_OIDC_FLOW_COOKIE)
    if not flow_cookie:
        return _login_error_redirect("oidc_state_missing")
    try:
        flow = _verify_flow_token(flow_cookie)
    except ValueError:
        return _login_error_redirect("oidc_state_invalid")
    if flow.get("provider_id") != str(provider_id):
        return _login_error_redirect("oidc_state_mismatch")
    if state != flow.get("state"):
        return _login_error_redirect("oidc_state_mismatch")
    if error:
        logger.warning("oidc_idp_error", provider=provider.name, error=error)
        return _login_error_redirect("oidc_idp_error")
    if not code:
        return _login_error_redirect("oidc_no_code")

    try:
        cfg = OIDCConfig.from_provider(provider)
        base = await _app_base_url(db, request)
        redirect_uri = _oidc_callback_url(base, provider.id)
        result = await oidc_exchange_code(cfg, str(provider.id), code, redirect_uri, flow["nonce"])
    except OIDCServiceError as exc:
        logger.warning("oidc_exchange_failed", provider=provider.name, error=str(exc))
        db.add(
            AuditLog(
                user_display_name="<unknown>",
                auth_source=provider.name,
                source_ip=_client_ip(request),
                user_agent=clean_user_agent(request.headers.get("user-agent")),
                action="login",
                resource_type="auth_provider",
                resource_id=str(provider.id),
                resource_display=provider.name,
                result="error",
                new_value={"reason": "oidc_exchange", "detail": str(exc)[:500]},
            )
        )
        await db.commit()
        return _login_error_redirect("oidc_exchange_failed")

    try:
        user = await sync_external_user(db, provider, result)
    except ExternalSyncRejected as exc:
        await _audit_login_failure(
            db,
            request,
            result.username or result.external_id,
            reason=exc.reason,
            auth_source=provider.name,
        )
        return _login_error_redirect("oidc_rejected")

    tokens = await _issue_tokens(db, request, user, auth_source=provider.name)

    # Only the short-lived access token rides the URL fragment (invisible to
    # the server, cleared by the callback page on arrival). The refresh token
    # is set as an HttpOnly cookie on this redirect, never exposed to JS (#484).
    frag = urlencode(
        {
            "access_token": tokens.access_token,
            "force_password_change": str(tokens.force_password_change).lower(),
        }
    )
    response = RedirectResponse(f"{_LOGIN_CALLBACK_PATH}#{frag}", status_code=302)
    _set_refresh_cookie(response, request, tokens.refresh_token)
    response.delete_cookie(_OIDC_FLOW_COOKIE, path="/api/v1/auth/")
    return response


@router.post("/{provider_id}/callback")
async def saml_callback(
    provider_id: uuid.UUID,
    request: Request,
    db: DB,
    SAMLResponse: str = Form(...),  # noqa: N803 - SAML spec mandates this casing
    RelayState: str | None = Form(default=None),  # noqa: N803 - SAML spec mandates this casing
) -> RedirectResponse:
    provider = await db.get(AuthProvider, provider_id)
    if provider is None or provider.type != "saml":
        raise HTTPException(status_code=404, detail="Provider not found")

    base = await _app_base_url(db, request)

    flow_cookie = request.cookies.get(_SAML_FLOW_COOKIE)
    if not flow_cookie:
        # Classify the absence (#873). Over plain HTTP the flow cookie can
        # only be Lax (see ``_saml_flow_cookie_kwargs``), which the browser
        # withholds from a *cross-site* POST — so on an HTTP deployment a
        # missing cookie here is the signature of a hosted IdP, and the fix
        # is TLS, not "try again". Over HTTPS the cookie is SameSite=None and
        # should have arrived, so absence means an expired or dropped flow.
        if not base.lower().startswith("https://"):
            logger.warning(
                "saml_callback_requires_https",
                provider=provider.name,
                base_url=base,
            )
            return _login_error_redirect("saml_requires_https")
        return _login_error_redirect("saml_state_missing")
    try:
        flow = _verify_flow_token(flow_cookie)
    except ValueError:
        return _login_error_redirect("saml_state_invalid")
    if flow.get("provider_id") != str(provider_id):
        return _login_error_redirect("saml_state_mismatch")
    if RelayState != flow.get("relay_state"):
        return _login_error_redirect("saml_state_mismatch")

    try:
        cfg = SAMLConfig.from_provider(provider, base)
        consumed = saml_consume_assertion(
            cfg, base, {"SAMLResponse": SAMLResponse, "RelayState": RelayState}
        )
    except SAMLServiceError as exc:
        logger.warning("saml_assertion_rejected", provider=provider.name, error=str(exc))
        db.add(
            AuditLog(
                user_display_name="<unknown>",
                auth_source=provider.name,
                source_ip=_client_ip(request),
                user_agent=clean_user_agent(request.headers.get("user-agent")),
                action="login",
                resource_type="auth_provider",
                resource_id=str(provider.id),
                resource_display=provider.name,
                result="error",
                new_value={"reason": "saml_rejected", "detail": str(exc)[:500]},
            )
        )
        await db.commit()
        return _login_error_redirect("saml_assertion_rejected")

    try:
        user = await sync_external_user(db, provider, consumed.result)
    except ExternalSyncRejected as exc:
        await _audit_login_failure(
            db,
            request,
            consumed.result.username or consumed.result.external_id,
            reason=exc.reason,
            auth_source=provider.name,
        )
        return _login_error_redirect("saml_rejected")

    tokens = await _issue_tokens(db, request, user, auth_source=provider.name)
    # Only the short-lived access token rides the URL fragment; the refresh
    # token is set as an HttpOnly cookie on this redirect (#484).
    frag = urlencode(
        {
            "access_token": tokens.access_token,
            "force_password_change": str(tokens.force_password_change).lower(),
        }
    )
    response = RedirectResponse(f"{_LOGIN_CALLBACK_PATH}#{frag}", status_code=302)
    _set_refresh_cookie(response, request, tokens.refresh_token)
    # Clear with the attributes it was set with. Not strictly required —
    # a cookie is identified by (name, domain, path), so the attributes
    # play no part in matching — but keeping set and clear in one helper
    # stops the pair drifting apart (#873).
    response.delete_cookie(_SAML_FLOW_COOKIE, **_saml_flow_cookie_kwargs(base))
    return response


@router.get(
    "/{provider_id}/metadata",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=XmlResponse,
    responses={200: {"description": "SAML SP metadata document"}},
)
async def saml_metadata(provider_id: uuid.UUID, request: Request, db: DB) -> Response:
    """Expose the SP metadata XML so admins can register SpatiumDDI with
    their IdP. Superadmin gate is not required: metadata is not sensitive and
    many IdPs fetch it unauthenticated."""
    provider = await db.get(AuthProvider, provider_id)
    if provider is None or provider.type != "saml":
        raise HTTPException(status_code=404, detail="Provider not found")

    base = await _app_base_url(db, request)
    try:
        cfg = SAMLConfig.from_provider(provider, base)
        xml = sp_metadata_xml(cfg)
    except SAMLServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(content=xml, media_type="application/xml")
