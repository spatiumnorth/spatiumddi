"""Is a blocklist feed refreshing? One answer for the list row and the alert (#2313).

``last_synced_at`` is stamped on a failed fetch too, so it says when the
refresh was last *tried*. Staleness is judged from ``last_success_at``, which
moves on success only, against ``STALE_AFTER_INTERVALS`` x the list's own
``update_interval_hours``. A manual-refresh list (interval 0) is never
"stale" -- nobody promised it would refresh.

Whether a list is assigned to a group is deliberately not a condition (#2313):
the issue asks for a failing or never-synced feed to be visible from the list,
and an unassigned feed is exactly the one an operator is about to assign.
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
    if not bl.feed_url or not bl.enabled or bl.update_interval_hours <= 0:
        return False
    since = stale_since(bl)
    if since is None:
        return False
    now = now or datetime.now(UTC)
    return now - since > timedelta(hours=bl.update_interval_hours * STALE_AFTER_INTERVALS)


def feed_sync_state(bl: DNSBlockList, now: datetime | None = None) -> str | None:
    """``ok`` | ``error`` | ``stale`` | ``never``; None for a list with no feed.

    A failed last refresh is reported for any feed list, enabled or not, manual
    or scheduled: it is a fact about the last attempt. ``never`` and ``stale``
    are promises about a schedule, so a disabled or manual-only list (interval
    0) reads ``ok`` for them and shows no chip.
    """
    if not bl.feed_url:
        return None
    if bl.last_sync_status == "error":
        return "error"
    if not bl.enabled or bl.update_interval_hours <= 0:
        return "ok"
    if bl.last_success_at is None:
        return "never"
    if is_feed_stale(bl, now):
        return "stale"
    return "ok"
