"""Per-token call counts and last client address (#4491).

A request authenticated by an API token costs one pipelined Redis round trip
(``HINCRBY`` on the day's hash, ``HSET`` of the caller's address) and no
database write. ``tasks.api_token_usage`` folds the counters into
``api_token_usage_daily`` every few minutes and copies the addresses onto
``api_token.last_client_ip``. Recording is best-effort: a Redis outage loses
counts, never a request.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import structlog
from sqlalchemy import ColumnElement, and_, or_

from app.config import settings
from app.core.redis_client import make_async_redis

logger = structlog.get_logger(__name__)

CALLS_PREFIX = "apitok:calls:"  # + YYYY-MM-DD → hash {token_id: pending calls}
LAST_IP_KEY = "apitok:lastip"  # hash {token_id: address}
_CALLS_TTL_SECONDS = 3 * 86400
RETENTION_DAYS = 90

_client = None


def _redis():  # type: ignore[no-untyped-def]
    global _client
    if _client is None:
        _client = make_async_redis(settings.redis_url, socket_timeout=1.0)
    return _client


def calls_key(day: date) -> str:
    return CALLS_PREFIX + day.isoformat()


async def record_call(token_id: object, client_ip: str | None) -> None:
    """Count one call. Never raises."""
    try:
        r = _redis()
        key = calls_key(datetime.now(UTC).date())
        pipe = r.pipeline(transaction=False)
        pipe.hincrby(key, str(token_id), 1)
        pipe.expire(key, _CALLS_TTL_SECONDS)
        if client_ip:
            pipe.hset(LAST_IP_KEY, str(token_id), client_ip[:45])
        await pipe.execute()
    except Exception as exc:  # noqa: BLE001 — usage counting is best-effort
        logger.warning("api_token_usage_record_failed", error=str(exc))


IDLE_DEFAULT_DAYS = 90


def live_idle_clause(now: datetime, days: int) -> ColumnElement[bool]:
    """SQL predicate: an active, unexpired token with no call in ``days`` days.

    A token never used counts from ``created_at``. Revoked (``is_active`` false)
    and expired tokens are excluded: they cannot be called, so "unused" is not
    a finding for them. Shared by the ``api_token_unused`` alert rule and the
    Security dashboard tile (#4491).
    """
    from app.models.auth import APIToken  # noqa: PLC0415

    cutoff = now - timedelta(days=days)
    return and_(
        APIToken.is_active.is_(True),
        or_(APIToken.expires_at.is_(None), APIToken.expires_at > now),
        or_(
            APIToken.last_used_at < cutoff,
            and_(APIToken.last_used_at.is_(None), APIToken.created_at < cutoff),
        ),
    )
