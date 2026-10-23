"""Periodic re-validation of the caller behind a long-lived streaming response.

A route's auth dependency runs once, when the request arrives. A streaming
response (server-sent events: cluster health, pod logs, nmap progress, the
AI chat) then keeps sending for as long as the connection stays open — so
without a re-check, signing the session out, disabling the account, revoking
the API token or removing the role behind the permission would not stop data
that is already flowing.

:class:`StreamAuthGuard` holds the credential the stream was opened with and
re-runs the same checks :func:`app.api.deps.get_current_user` applies (via
:func:`app.api.deps.authenticate_bearer`), plus the route's permission, at
most once every :data:`STREAM_AUTH_RECHECK_SECONDS`. The generator asks
:meth:`StreamAuthGuard.still_authorized` before it sends anything and ends
the stream when the answer is no. The check is time-based rather than
per-event so a fast stream costs one small query batch per interval, not one
per frame.

The access token's own ``exp`` is part of the check, so a stream opened with
a JWT also ends once that token expires; clients reconnect with a current
token.
"""

from __future__ import annotations

import time

import structlog
from fastapi import HTTPException, Request

from app.api.deps import authenticate_bearer
from app.core.permissions import user_has_permission
from app.db import AsyncSessionLocal

logger = structlog.get_logger(__name__)

# How often an open stream re-validates its caller. Bounds how long a revoked
# session / disabled account / removed permission keeps receiving frames.
STREAM_AUTH_RECHECK_SECONDS = 15.0

# A re-check that fails for a reason other than the caller (the database is
# mid-failover, say) keeps the stream open for at most this many intervals
# past the last successful check, then ends it.
_TRANSIENT_FAILURE_INTERVALS = 4


def bearer_from_request(request: Request) -> str | None:
    """The raw ``Authorization: Bearer`` credential on ``request``, if any."""
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth[len("bearer ") :].strip()
        return token or None
    return None


class StreamAuthGuard:
    """Re-validates a stream's caller on a bounded cadence.

    Construct it in the handler (after the route's own auth has accepted the
    request) and call :meth:`still_authorized` from the stream generator
    before each send. ``permission`` is an ``(action, resource_type)`` pair
    re-checked alongside authentication, or ``None`` for a stream that needs
    only a signed-in caller.
    """

    def __init__(
        self,
        request: Request,
        *,
        permission: tuple[str, str] | None,
        credential: str | None = None,
    ) -> None:
        self._request = request
        self._permission = permission
        self._credential = credential if credential is not None else bearer_from_request(request)
        now = time.monotonic()
        # The route's dependency has just authorised the request, so the
        # first re-check is due one interval from now.
        self._checked_at = now
        self._verified_at = now
        self._denied = self._credential is None

    async def still_authorized(self) -> bool:
        """False once the caller is no longer allowed to receive this stream.

        Cheap between re-checks (no I/O). Once it returns False it keeps
        returning False.
        """
        if self._denied:
            return False
        now = time.monotonic()
        if now - self._checked_at < STREAM_AUTH_RECHECK_SECONDS:
            return True
        self._checked_at = now
        assert self._credential is not None  # _denied covers None
        try:
            async with AsyncSessionLocal() as db:
                user = await authenticate_bearer(
                    db, self._credential, self._request, record_activity=False
                )
                allowed = self._permission is None or user_has_permission(
                    user, self._permission[0], self._permission[1]
                )
        except HTTPException as exc:
            logger.info(
                "stream_auth_revoked",
                path=self._request.url.path,
                status=exc.status_code,
                reason=exc.detail,
            )
            self._denied = True
            return False
        except Exception as exc:  # noqa: BLE001 — the database, not the caller
            if now - self._verified_at > STREAM_AUTH_RECHECK_SECONDS * _TRANSIENT_FAILURE_INTERVALS:
                logger.warning(
                    "stream_auth_recheck_unavailable_closing",
                    path=self._request.url.path,
                    error=str(exc),
                )
                self._denied = True
                return False
            logger.info(
                "stream_auth_recheck_unavailable", path=self._request.url.path, error=str(exc)
            )
            return True
        if not allowed:
            logger.info(
                "stream_auth_revoked",
                path=self._request.url.path,
                status=403,
                reason="permission removed",
            )
            self._denied = True
            return False
        self._verified_at = now
        return True


__all__ = ["STREAM_AUTH_RECHECK_SECONDS", "StreamAuthGuard", "bearer_from_request"]
