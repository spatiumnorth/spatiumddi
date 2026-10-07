"""System-wide maintenance mode (issue #57).

When an operator flips ``PlatformSettings.maintenance_mode_enabled`` the
whole platform goes read-only: every mutating request
(POST/PUT/PATCH/DELETE) is answered with a 503 + ``Retry-After`` and a
structured body, *except*:

* effective superadmins (so an admin can still flip the switch back off
  and run recovery tasks), and
* an exempt-path allow-list — auth (so admins can log in), the settings
  router (so the toggle itself is reachable), health / metrics probes,
  and the agent-facing endpoints (DNS / DHCP / supervisor) so a
  maintenance window never severs an agent's config-caching path
  (non-negotiable #5).

**Performance.** The middleware runs on every request, so the hot path
is kept dead-cheap:

* Reads (GET / HEAD / OPTIONS / …) pass straight through with zero work.
* When maintenance mode is *off* — the overwhelmingly common case — a
  mutating request also passes through immediately after a single
  process-local cache read. No bearer decode, no DB round-trip.
* Only when maintenance mode is *on* do we do the exempt-path check and
  the (potentially DB-touching) superadmin bypass.

The enabled flag + message are held in a short-TTL process-local cache
mirroring ``app.services.feature_modules`` — the toggle endpoint calls
:func:`invalidate_cache` so the flipping worker sees the change instantly;
other workers converge within ``_CACHE_TTL_S``.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Final

import structlog
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = structlog.get_logger(__name__)

# Methods that mutate state. Everything else (GET / HEAD / OPTIONS /
# TRACE) is read-only and always passes through.
_MUTATING_METHODS: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Path prefixes that stay reachable even during a maintenance window.
# Mutating requests to these are never blocked:
#   * /api/v1/auth        — admins must be able to log in to recover.
#   * /api/v1/settings    — the maintenance toggle itself lives here.
#   * /health, /metrics   — liveness/readiness + Prometheus scrape.
#   * agent endpoints     — DNS / DHCP / supervisor config-caching path
#                           (non-negotiable #5): an agent heartbeating /
#                           long-polling / acking ops must never be cut
#                           off, or it can't pick up its last-known-good
#                           config when the window ends.
EXEMPT_PREFIXES: Final[tuple[str, ...]] = (
    "/api/v1/auth",
    "/api/v1/settings",
    "/health",
    "/metrics",
    "/api/v1/dns/agents",
    "/api/v1/dhcp/agents",
    # Supervisor agent surface — /supervisor/register, /supervisor/poll,
    # /supervisor/heartbeat, /supervisor/k8s-proxy/* (config-caching +
    # desired-state delivery, non-negotiable #5).
    "/api/v1/appliance/supervisor",
    # Local-supervisor self-bootstrap (full-stack / frontend-core appliances
    # mint their own one-shot pairing code here). Unauthenticated + host-
    # gated; if a maintenance window 503'd it the appliance's own supervisor
    # could never register against its control plane (non-negotiable #5).
    "/api/v1/appliance/self-register-bootstrap",
    # HELD (#972). A change window must not stop answering "which room is
    # this phone in" — a PBX asking on behalf of a 911 call is the one
    # caller that cannot wait for the window to close, and the equivalent
    # GET /api/v1/e911/location kept working throughout, so 503ing only the
    # standards-track path was incoherent as well as dangerous. Read-only
    # either way: neither HELD route mutates anything a maintenance window
    # is protecting.
    "/held",
)

_API_TOKEN_PREFIX: Final[str] = "sddi_"

# ── process-local short-TTL cache ───────────────────────────────────
#
# Mirrors the feature_modules cache pattern. The maintenance flag
# changes rarely, so caching it for a short TTL keeps the off-path
# (every request, every worker) from ever touching the DB.

_CACHE_TTL_S: Final[float] = 5.0
_cache_loaded_at: float = 0.0
_cached_enabled: bool = False
_cached_message: str = ""
_cached_started_at: datetime | None = None


def invalidate_cache() -> None:
    """Drop the cached maintenance state. Called from the toggle endpoint
    so the flipping worker sees the change instantly; other workers pick
    it up at their next TTL expiry."""
    global _cache_loaded_at
    _cache_loaded_at = 0.0


async def get_maintenance_state(db: AsyncSession) -> tuple[bool, str, datetime | None]:
    """Return ``(enabled, message, started_at)`` from the short-TTL cache,
    refreshing from the DB when the TTL has expired."""
    global _cache_loaded_at, _cached_enabled, _cached_message, _cached_started_at
    now = time.monotonic()
    if now - _cache_loaded_at < _CACHE_TTL_S:
        return _cached_enabled, _cached_message, _cached_started_at

    # Lazy import — the model graph isn't needed at module import time and
    # keeping it local avoids any import-order coupling with app boot.
    from app.models.settings import PlatformSettings  # noqa: PLC0415

    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        _cached_enabled = False
        _cached_message = ""
        _cached_started_at = None
    else:
        _cached_enabled = bool(row.maintenance_mode_enabled)
        _cached_message = row.maintenance_message or ""
        _cached_started_at = row.maintenance_started_at
    _cache_loaded_at = now
    return _cached_enabled, _cached_message, _cached_started_at


async def is_maintenance_mode(db: AsyncSession) -> bool:
    """Convenience wrapper — just the enabled flag."""
    enabled, _msg, _started = await get_maintenance_state(db)
    return enabled


def _is_exempt_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)


async def _bearer_is_effective_superadmin(token: str, method: str, path: str) -> bool:
    """Best-effort: decode the bearer (JWT or ``sddi_`` API token), look
    up the owning user, and report whether they're an effective
    superadmin *and* the bearer is actually allowed to perform this
    request. ANY failure (missing/invalid token, unknown user, inactive,
    decode error, revoked/expired session, scope-forbidden, DB error)
    yields ``False`` — no bypass.

    ``method`` + ``path`` are the request's verb + path so the API-token
    branch can enforce ``token.scopes`` BEFORE granting a bypass — a
    read-only-scoped token (even a superadmin's) can never reach a write
    handler, mirroring ``app.api.deps._resolve_api_token``'s invariant.

    Deliberately self-contained: it spins its own session via
    ``AsyncSessionLocal`` rather than reaching for the request-scoped
    ``get_db`` dependency (middleware runs before dependency
    resolution)."""
    # Lazy imports — avoid pulling the auth/permission/model graph into
    # this module's import path (and any circular-import risk at boot).
    from jose import JWTError  # noqa: PLC0415
    from sqlalchemy.orm import selectinload  # noqa: PLC0415

    from app.core.permissions import is_effective_superadmin  # noqa: PLC0415
    from app.core.security import (  # noqa: PLC0415
        decode_access_token,
        hash_api_token,
        live_access_session,
    )
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.auth import APIToken, Group, User  # noqa: PLC0415
    from app.services.api_token_scopes import scope_matches_request  # noqa: PLC0415

    # Eager-load groups → roles so the synchronous ``is_effective_superadmin``
    # → ``user_has_permission`` RBAC walk doesn't trigger an async lazy load
    # (which would raise on the detached middleware session). The legacy
    # ``is_superadmin`` flag short-circuits before this is even touched.
    _user_opts = (selectinload(User.groups).selectinload(Group.roles),)

    try:
        async with AsyncSessionLocal() as db:
            if token.startswith(_API_TOKEN_PREFIX):
                # Mirror deps._resolve_api_token's lookup (minimal slice —
                # we only need the owning user + active state + scopes).
                token_hash = hash_api_token(token)
                api_token = (
                    await db.execute(select(APIToken).where(APIToken.token_hash == token_hash))
                ).scalar_one_or_none()
                if api_token is None or not api_token.is_active or api_token.user_id is None:
                    return False
                if api_token.expires_at is not None:
                    from datetime import UTC  # noqa: PLC0415
                    from datetime import datetime as _dt

                    if api_token.expires_at <= _dt.now(UTC):
                        return False
                # Scope gate — mirror deps._resolve_api_token's invariant
                # (deps.py:60-65): a non-empty ``scopes`` list is enforced
                # BEFORE RBAC, so a read-only-scoped token can never reach
                # a write handler even when its owner is a superadmin. No
                # match = no bypass (the request falls through to the 503).
                scopes = list(api_token.scopes or [])
                if scopes and not scope_matches_request(scopes, method, path):
                    return False
                user = (
                    await db.execute(
                        select(User).where(User.id == api_token.user_id).options(*_user_opts)
                    )
                ).scalar_one_or_none()
            else:
                try:
                    payload = decode_access_token(token)
                    user_id = payload["sub"]
                except (JWTError, KeyError):
                    return False
                # Session gate — the same ``live_access_session`` the auth dep
                # uses. A force-logged-out superadmin (``revoked``) whose JWT is
                # still unexpired must NOT bypass maintenance mode, nor may a
                # token whose session belongs to another user. A token with no
                # ``jti`` was already refused by ``decode_access_token`` (#1222).
                try:
                    await live_access_session(db, payload)
                except JWTError:
                    return False
                user = (
                    await db.execute(select(User).where(User.id == user_id).options(*_user_opts))
                ).scalar_one_or_none()

            if user is None or not user.is_active:
                return False
            return is_effective_superadmin(user)
    except Exception:  # noqa: BLE001 — any failure means "no bypass"
        return False


class MaintenanceModeMiddleware(BaseHTTPMiddleware):
    """503 every mutating request while maintenance mode is on, except
    exempt paths + effective superadmins. See module docstring."""

    async def dispatch(self, request: Request, call_next: object) -> Response:  # type: ignore[override]
        method = request.method.upper()

        # Fast path #1: reads never blocked.
        if method not in _MUTATING_METHODS:
            return await call_next(request)  # type: ignore[operator,no-any-return]

        # Read the cached flag. When OFF (the common case) we do ZERO
        # extra work — no bearer decode, no DB — and pass straight through.
        from app.db import AsyncSessionLocal  # noqa: PLC0415

        async with AsyncSessionLocal() as db:
            enabled, message, started_at = await get_maintenance_state(db)
        if not enabled:
            return await call_next(request)  # type: ignore[operator,no-any-return]

        # Maintenance mode is ON. Exempt paths still flow.
        path = request.url.path
        if _is_exempt_path(path):
            return await call_next(request)  # type: ignore[operator,no-any-return]

        # Superadmin bypass — decode the bearer if present. Any failure
        # yields no bypass.
        auth_header = request.headers.get("Authorization") or ""
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
            if token and await _bearer_is_effective_superadmin(token, method, path):
                return await call_next(request)  # type: ignore[operator,no-any-return]

        logger.info(
            "maintenance_mode_blocked",
            method=method,
            path=path,
        )
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    message
                    or "SpatiumDDI is in maintenance mode — the platform is "
                    "read-only. Try again shortly."
                ),
                "maintenance": True,
                "message": message,
                "started_at": started_at.isoformat() if started_at else None,
            },
            headers={"Retry-After": "120"},
        )
