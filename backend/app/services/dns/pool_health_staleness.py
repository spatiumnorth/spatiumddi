"""How old is a pool member's health verdict? (#2312)

The pool health-check task re-checks every member each
``max(30, hc_interval_seconds)``. If that dispatcher stops (dns queue backed
up, worker down) nothing refreshes ``last_check_at``, and a member last seen
``healthy`` keeps being rendered. Serving deliberately stays fail-open
(``pool_apply``: dropping every member would be an outage of its own), so the
protection is visibility: a verdict older than ``STALE_AFTER_INTERVALS`` x the
interval is *stale*, shown with its age and alerted on.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.dns import DNSPool, DNSPoolMember

STALE_AFTER_INTERVALS = 3
# The task's own floor (tasks/dns_pool_healthcheck.py): an interval of 10 s is
# still checked every 30 s, so staleness is measured against what really runs.
MIN_EFFECTIVE_INTERVAL_SECONDS = 30


def stale_after_seconds(pool: DNSPool) -> int:
    interval = max(MIN_EFFECTIVE_INTERVAL_SECONDS, int(pool.hc_interval_seconds or 0))
    return interval * STALE_AFTER_INTERVALS


def member_check_age_seconds(member: DNSPoolMember, now: datetime | None = None) -> int | None:
    """Seconds since the verdict was last refreshed; None if never checked."""
    if member.last_check_at is None:
        return None
    now = now or datetime.now(UTC)
    return max(0, int((now - member.last_check_at).total_seconds()))


def is_member_check_stale(
    pool: DNSPool, member: DNSPoolMember, now: datetime | None = None
) -> bool:
    """A checked member whose verdict is older than 3 intervals.

    A disabled pool or member is not being checked on purpose, and a member
    never checked has no verdict to be stale (it reads ``unknown`` and is not
    rendered).
    """
    if not pool.enabled or not member.enabled:
        return False
    age = member_check_age_seconds(member, now)
    return age is not None and age > stale_after_seconds(pool)
