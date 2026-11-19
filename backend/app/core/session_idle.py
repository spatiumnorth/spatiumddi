"""Idle-session timeout (``PlatformSettings.session_timeout_minutes``).

A browser session (a ``UserSession`` row) that has seen no activity for
longer than the configured timeout is refused: its access token stops
working on the next request and its refresh cookie can no longer mint a new
one. ``0`` disables the timeout. API tokens are not sessions and are not
affected.

**What counts as activity.** ``UserSession.last_seen_at``. It is stamped at
sign-in and bumped by the auth dependency on authenticated requests. A
refresh carries it forward rather than restamping it, because the console
refreshes on its own whenever an access token expires.

The console also polls in the background (dashboards, status chips), and a
poll is not the operator. So every console request carries
``X-Spatium-Idle-Seconds``: how long ago the operator last touched the
page. The auth dependency records the activity at ``now - idle`` instead of
``now``, so a page left open keeps reporting a growing idle time and the
session still expires. The header can only move the recorded activity
EARLIER than the request itself, never later, so a client sending a wrong
value can shorten its own session and nothing else. A request without the
header (a script holding a session token, an older console) counts as
activity now, which is what it did before.

**Precision.** ``last_seen_at`` is written at most once per
:func:`activity_write_interval`, so it can trail the real activity by up to
that much. The refusal therefore allows the same margin on top of the
timeout: a session is never cut off early, and at most one interval late.

The timeout is held in a short-TTL process-local cache (the
``maintenance_mode`` pattern); the settings endpoint invalidates it.
"""

from __future__ import annotations

import math
import time
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

IDLE_HEADER: Final[str] = "X-Spatium-Idle-Seconds"

# The longest idle time a client can report. Anything larger is clamped;
# a client claiming more idle time only shortens its own session.
_MAX_REPORTED_IDLE_S: Final[float] = 366 * 86400.0

# How often ``last_seen_at`` may be written for one session.
_WRITE_INTERVAL: Final[timedelta] = timedelta(seconds=60)

_CACHE_TTL_S: Final[float] = 5.0
_cache_loaded_at: float = 0.0
_cached_timeout_minutes: int = 0


def invalidate_cache() -> None:
    """Drop the cached timeout. Called when the setting changes."""
    global _cache_loaded_at
    _cache_loaded_at = 0.0


async def get_session_timeout_minutes(db: AsyncSession) -> int:
    """The configured idle timeout in minutes; ``0`` means disabled."""
    global _cache_loaded_at, _cached_timeout_minutes
    now = time.monotonic()
    if now - _cache_loaded_at < _CACHE_TTL_S:
        return _cached_timeout_minutes

    from app.models.settings import PlatformSettings, platform_setting_default  # noqa: PLC0415

    value = (
        await db.execute(
            select(PlatformSettings.session_timeout_minutes).where(PlatformSettings.id == 1)
        )
    ).scalar_one_or_none()
    # No settings row yet: the column default applies, as it will once the
    # row is created (#3203). ``0`` stays "disabled" when explicitly stored.
    if value is None:
        value = platform_setting_default("session_timeout_minutes")
    _cached_timeout_minutes = max(int(value), 0)
    _cache_loaded_at = now
    return _cached_timeout_minutes


def activity_write_interval(timeout_minutes: int) -> timedelta:
    """How often a session's ``last_seen_at`` may be written.

    Once a minute, or a quarter of the timeout when that is shorter, so a
    one-minute timeout is not dominated by the write throttle.
    """
    if timeout_minutes <= 0:
        return _WRITE_INTERVAL
    return min(_WRITE_INTERVAL, timedelta(minutes=timeout_minutes) / 4)


def last_activity(session: Any) -> datetime:
    """When the session was last active. Rows from before ``last_seen_at``
    existed fall back to their sign-in time."""
    return session.last_seen_at or session.created_at  # type: ignore[no-any-return]


def idle_cutoff(timeout_minutes: int, now: datetime) -> datetime | None:
    """Sessions whose last activity is at or before this are idle-expired.

    ``None`` when the timeout is disabled.
    """
    if timeout_minutes <= 0:
        return None
    return now - timedelta(minutes=timeout_minutes) - activity_write_interval(timeout_minutes)


def is_idle_expired(session: Any, timeout_minutes: int, now: datetime) -> bool:
    cutoff = idle_cutoff(timeout_minutes, now)
    return cutoff is not None and last_activity(session) <= cutoff


def request_activity_at(headers: Any, now: datetime) -> datetime:
    """When the operator behind this request was last active.

    ``now`` unless the request carries a valid :data:`IDLE_HEADER`, in
    which case ``now`` minus the reported idle time. Never later than now.
    """
    raw = headers.get(IDLE_HEADER)
    if raw is None:
        return now
    try:
        idle = float(raw)
    except (TypeError, ValueError):
        return now
    if not math.isfinite(idle) or idle <= 0:
        return now
    return now - timedelta(seconds=min(idle, _MAX_REPORTED_IDLE_S))
