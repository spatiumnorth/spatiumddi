"""Shared FastAPI dependencies injected into route handlers."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

import structlog
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.core.security import decode_access_token, hash_api_token
from app.db import AsyncSessionLocal, get_db
from app.models.auth import APIToken, User, UserSession
from app.services.api_token_scopes import scope_matches_request

logger = structlog.get_logger(__name__)

_bearer = HTTPBearer(auto_error=False)

# API tokens issued by SpatiumDDI all carry this prefix so the auth
# middleware can distinguish them from JWTs without an extra DB round-trip
# on every request. See ``app.core.security.generate_api_token``.
_API_TOKEN_PREFIX = "sddi_"

# SECURITY (#400 / M4): when ``User.force_password_change`` is set (a fresh
# account, an admin-forced reset, or a max-age-expired password), the user
# must be barred from every authenticated endpoint EXCEPT the handful needed
# to actually rotate the password and read enough state to do so. Without
# this gate the flag was advisory only — the frontend honoured it, but the
# API happily served every other request to a token minted for a
# must-change-password account. These suffixes are matched against the
# request path so a forced user can still reach the recovery flow.
_FORCE_PW_CHANGE_ALLOWLIST: tuple[str, ...] = (
    "/auth/change-password",
    "/auth/logout",
    "/auth/me",
    "/auth/password-policy",
)


def _path_in_recovery_allowlist(path: str) -> bool:
    """True when ``path`` ends with one of the password-recovery endpoints
    a ``force_password_change`` user is still allowed to reach. Suffix match
    so the API ``/api/v1`` prefix (and any mount-point reverse-proxy rewrite)
    doesn't matter — the allowlisted set is unambiguous on its tail."""
    return any(path.rstrip("/").endswith(suffix) for suffix in _FORCE_PW_CHANGE_ALLOWLIST)


# #1158 — a token's use is written at most once a minute: the cadence
# ``get_current_user`` keeps for a session's ``last_seen_at``.
_TOKEN_LAST_USED_INTERVAL = timedelta(seconds=60)


async def _record_api_token_use(token: APIToken, now: datetime) -> None:
    """Write ``token.last_used_at`` in a transaction of its own (#1158).

    It used to be set on the request's session and left for the handler to
    commit. Read handlers never commit (``get_db`` only closes the session),
    so a token used only for reads, the usual monitoring or export
    integration, showed "Last Used: —" forever. Like the session path's
    ``last_seen_at``, the write is throttled to once a minute and committed
    on its own. It uses a short-lived session rather than the request's:

    - a handler that rolls back cannot undo it;
    - a failed write cannot roll the request's session back.

    That rollback would expire the ``token`` and ``user`` this request has
    already loaded, and the next attribute read on either would need a lazy
    load, which async SQLAlchemy refuses. The session path avoids this only
    because it commits before it loads the User.

    Best-effort: a failure is logged, never a 500.
    """
    last = token.last_used_at
    if last is not None and now - last < _TOKEN_LAST_USED_INTERVAL:
        return
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(
                update(APIToken).where(APIToken.id == token.id).values(last_used_at=now)
            )
            await db.commit()
    except Exception as exc:  # noqa: BLE001 — recording the use is best-effort
        logger.warning("api_token_last_used_write_failed", token_id=str(token.id), error=str(exc))
        return
    # Let this request see its own write without marking the row dirty: a
    # dirty attribute would make a write handler's commit repeat the UPDATE.
    set_committed_value(token, "last_used_at", now)


async def _resolve_api_token(db: AsyncSession, raw: str, request: Request) -> User:
    """Validate an ``sddi_*`` bearer and return the owning user.

    Raises the same 401/403 pattern as JWT auth so callers can't
    distinguish "no token" from "expired token" from "revoked token".
    Successful lookups also bump ``last_used_at`` so operators have a
    single column they can glance at to see which tokens are live
    vs. dead.

    The ``request`` arg lets us enforce ``token.scopes`` BEFORE the
    RBAC check downstream — see ``app.services.api_token_scopes``. A
    "read-only" token can never reach a write handler, even if the
    owner's RBAC would allow it.
    """
    token_hash = hash_api_token(raw)
    token = (
        await db.execute(select(APIToken).where(APIToken.token_hash == token_hash))
    ).scalar_one_or_none()
    if token is None or not token.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API token",
        )
    now = datetime.now(UTC)
    if token.expires_at is not None and token.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API token has expired",
        )
    # Coarse-grained scope gate. Empty list = no restriction; the
    # vocabulary check happens at create time so we can trust the
    # stored values here.
    scopes = list(token.scopes or [])
    if scopes and not scope_matches_request(scopes, request.method, request.url.path):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token scope insufficient for this request",
        )
    if token.user_id is None:
        # Scope "global" isn't wired through permissions yet — reject
        # until we add a synthetic service-account path. Today's UI
        # only issues user-scoped tokens so this is defensive.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Global-scope API tokens are not yet supported",
        )
    # Record WHICH token authenticated this request. API-token auth resolves
    # to the owning User, so without this a handler cannot tell a PBX's
    # service token from the same person's browser session — and #972's
    # location lookups have to log who asked about which identity, where
    # "a token belonging to Alice" and "Alice at a keyboard" are different
    # answers. Additive: nothing else reads it, and no behaviour changes.
    request.state.api_token_id = token.id

    user = (await db.execute(select(User).where(User.id == token.user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled"
        )
    # SECURITY (#400 / M4): the must-change-password gate applies to API
    # tokens too — a token minted for an account that later gets a forced
    # reset (or whose password expires) must not be a bypass around the
    # interactive lockout. Same recovery allowlist (the recovery endpoints
    # are session-only, so in practice this just 403s the token).
    if user.force_password_change and not _path_in_recovery_allowlist(request.url.path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before continuing",
        )
    # Record the use in a transaction of its own (#1158): a read handler
    # never commits the request's session, so a bump left on it was lost.
    await _record_api_token_use(token, now)
    await _load_time_bound_grants(db, user)
    # Stash this token's resource grants (issue #374) so the permission layer
    # can intersect them with the owner's RBAC. Empty/None = unrestricted.
    user._api_token_resource_grants = list(token.resource_grants or [])
    return user


async def get_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
) -> User:
    """
    Validate a Bearer credential and return the authenticated User.

    Accepts either:
      * a JWT access token issued by ``/auth/login`` (user sessions), or
      * an API token issued by ``/api-tokens`` (machine / script access).

    Raises 401 if missing or invalid; 403 if the user is inactive.
    """
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    raw = credentials.credentials
    # Fast path for API tokens — they carry a distinct prefix so we
    # never try to JWT-decode one (which would just 401 on signature
    # mismatch anyway, but this is cleaner error messaging).
    if raw.startswith(_API_TOKEN_PREFIX):
        return await _resolve_api_token(db, raw, request)

    try:
        payload = decode_access_token(raw)
        user_id: str = payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    # Issue #72 — session viewer / force-logout. Tokens minted after
    # the session-viewer landing carry a ``jti`` claim that maps to a
    # ``UserSession`` row. We reject if that row is revoked or expired,
    # which is the force-logout effect: the superadmin flips
    # ``revoked``, every in-flight access token using that jti starts
    # 401-ing on the next request. Tokens without a ``jti`` (legacy or
    # in-flight at deploy time) are allowed through — they expire on
    # their own short TTL.
    jti = payload.get("jti")
    if jti is not None:
        session = await db.get(UserSession, jti)
        if session is None or session.revoked or session.expires_at <= datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session revoked or expired",
            )
        # Bump ``last_seen_at`` no more than once per minute per
        # session — gives the admin viewer a recent timestamp without
        # a write on every authenticated request.
        now = datetime.now(UTC)
        if session.last_seen_at is None or (now - session.last_seen_at) > timedelta(seconds=60):
            session.last_seen_at = now
            try:
                await db.commit()
            except Exception:  # noqa: BLE001 — last_seen is best-effort
                await db.rollback()

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled"
        )

    # SECURITY (#400 / M4): enforce the must-change-password gate server-side.
    # ``force_password_change`` is set on fresh accounts, on admin resets, and
    # is flipped on by the login-time max-age check (issue #70), so honouring
    # it here closes both the "must change" and the "password expired" cases.
    # We reject every request EXCEPT the password-recovery allowlist so the
    # user can still rotate their password and log out — anything else 403s.
    if user.force_password_change and not _path_in_recovery_allowlist(request.url.path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change required before continuing",
        )

    await _load_time_bound_grants(db, user)
    return user


async def _load_time_bound_grants(db: AsyncSession, user: User) -> None:
    """Stash the caller's live time-bound grants (issue #65) on the User so
    ``app.core.permissions.user_has_permission`` can union them over the
    static role grants. Best-effort — a failure here must never block an
    otherwise-authenticated request, so we log and leave the empty default.

    Lazy import: ``app.services.time_bound_grants`` pulls in
    ``app.core.permissions`` which imports ``CurrentUser`` / ``get_db`` from
    this module at top level, so an eager import would close the circular
    graph at uvicorn startup.
    """
    from app.services.time_bound_grants import load_active_grants_for_groups

    try:
        group_ids = [g.id for g in user.groups]
        user._active_time_bound_grants = await load_active_grants_for_groups(db, group_ids)
    except Exception as exc:  # noqa: BLE001 — grant load must not break auth
        logger.warning("time_bound_grant_load_failed", error=str(exc))
        user._active_time_bound_grants = []


def require_superadmin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """FastAPI dependency: 403 unless the user is an *effective* superadmin.

    Delegates to :func:`app.core.permissions.is_effective_superadmin`, which
    admits both:

    * the legacy ``User.is_superadmin=True`` (seeded ``admin`` / anyone
      explicitly flagged), and
    * group → role grants of the ``{action: "*", resource_type: "*"}``
      wildcard permission (built-in ``Superadmin`` role or any clone of it).

    Without the wildcard path, users provisioned via LDAP / OIDC / SAML and
    mapped to a Superadmin-role group pass every ``require_permission`` gate
    but get 403 on ``SuperAdmin``-only endpoints — a split-brain between the
    legacy flag and the RBAC model. The helper unifies them; this dependency
    is just the gate-style wrapper for routes that pre-Depend.

    Endpoints that already have a hand-rolled ``_require_superadmin`` helper
    should call ``is_effective_superadmin(user)`` directly from inside the
    handler — same check, same behaviour.
    """
    # Lazy import: `app.core.permissions` imports ``CurrentUser`` / ``get_db``
    # from this module at top-level, so an eager import here triggers a
    # circular-import crash at uvicorn startup. Local import side-steps it
    # because by the time this function is called the module graph is fully
    # initialised.
    from app.core.permissions import is_effective_superadmin

    if is_effective_superadmin(current_user):
        return current_user
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin required")


# Type aliases for injection
CurrentUser = Annotated[User, Depends(get_current_user)]
SuperAdmin = Annotated[User, Depends(require_superadmin)]
DB = Annotated[AsyncSession, Depends(get_db)]
