"""Single-use proof of a fresh identity-provider re-authentication (#1354).

Starting an MFA enrolment for an OIDC / SAML account used to accept any
session created in the last 10 minutes. It now needs a round trip through the
user's own IdP, forced to authenticate again (``prompt=login`` + ``max_age=0``
for OIDC, ``ForceAuthn`` for SAML). The callback that verifies the IdP's answer
cannot act on the enrolment itself: it is a browser redirect with no bearer
token. So it leaves this proof, which ``POST /auth/mfa/enroll/begin`` takes.

The proof is bound to the USER and the SESSION that started the round trip
(both are in the key), lives five minutes, and is taken with ``GETDEL`` so it
is spent by whoever reads it first. Every function here fails CLOSED: a Redis
failure raises :class:`ProofUnavailable`, never a "yes".
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from app.config import settings
from app.core.redis_client import make_async_redis

logger = structlog.get_logger(__name__)

#: How long a verified re-authentication stays usable.
PROOF_TTL_SECONDS = 300
#: How long a started round trip may take to come back (matches the flow cookie).
FLOW_TTL_SECONDS = 300


class ProofUnavailable(Exception):
    """Redis could not be read or written; the step-up must be refused."""


def session_key(signed_in_at: datetime | None) -> str | None:
    """What identifies "this session" across a token refresh.

    A refresh rotates the ``UserSession`` row and its id, and a round trip to
    the IdP reloads the SPA, which refreshes: so the row id cannot carry the
    binding. The sign-in time can: a refresh carries it forward unchanged
    (#1241), and a new sign-in has a new one. None for a request with no
    session (an API token), which can therefore never hold a proof."""
    return signed_in_at.astimezone(UTC).isoformat() if signed_in_at is not None else None


def _proof_key(user_id: object, session_id: object) -> str:
    return f"mfa_enrol_proof:{user_id}:{session_id}"


def _flow_key(flow_id: str) -> str:
    return f"mfa_enrol_flow:{flow_id}"


async def grant_proof(user_id: object, session_id: object) -> None:
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            await r.set(_proof_key(user_id, session_id), "1", ex=PROOF_TTL_SECONDS)
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — any Redis failure means "no proof was stored"
        logger.warning("mfa_enrol_proof_redis_unavailable", error=str(exc))
        raise ProofUnavailable from exc


async def consume_proof(user_id: object, session_id: object) -> bool:
    """True exactly once per granted proof; False when there is none."""
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            return (await r.getdel(_proof_key(user_id, session_id))) is not None
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — an unreadable proof is not a proof
        logger.warning("mfa_enrol_proof_redis_unavailable", error=str(exc))
        raise ProofUnavailable from exc


async def claim_flow(flow_id: str) -> bool:
    """Spend a started round trip. True on its first callback, False on a
    replay of the same ``state`` + code (or relay state + Response)."""
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            return bool(await r.set(_flow_key(flow_id), "1", ex=FLOW_TTL_SECONDS * 2, nx=True))
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — an unclaimable flow is refused
        logger.warning("mfa_enrol_proof_redis_unavailable", error=str(exc))
        raise ProofUnavailable from exc
