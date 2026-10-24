"""Is a blocklist feed refreshing? One answer for the list row and the alert (#2313).

``last_synced_at`` is stamped on a failed fetch too, so it says when the
refresh was last *tried*. Staleness is judged from ``last_success_at``, which
moves on success only, against ``STALE_AFTER_INTERVALS`` x the list's own
``update_interval_hours``. A manual-refresh list (interval 0) is never
"stale" -- nobody promised it would refresh.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.dns import DNSBlockList

STALE_AFTER_INTERVALS = 3


def stale_since(bl: DNSBlockList) -> datetime | None:
    """When the clock on this feed started: its last success, else its creation.

    A feed that has never succeeded is measured from creation, so one just
    added (its first refresh still queued) is not reported as failing.
    """
    return bl.last_success_at or bl.created_at


def is_feed_stale(bl: DNSBlockList, now: datetime | None = None) -> bool:
    """True for a feed whose refresh has not succeeded within 3 intervals."""
    if not bl.feed_url or bl.update_interval_hours <= 0:
        return False
    since = stale_since(bl)
    if since is None:
        return False
    now = now or datetime.now(UTC)
    return now - since > timedelta(hours=bl.update_interval_hours * STALE_AFTER_INTERVALS)


def feed_sync_state(bl: DNSBlockList, now: datetime | None = None) -> str | None:
    """``ok`` | ``error`` | ``stale`` | ``never``; None for a list with no feed."""
    if not bl.feed_url:
        return None
    if bl.last_sync_status == "error":
        return "error"
    if bl.last_success_at is None:
        return "never"
    if is_feed_stale(bl, now):
        return "stale"
    return "ok"
