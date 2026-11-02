"""Account lockout after N failed logins (issue #71).

Pure functions over a ``LockoutPolicy`` snapshot read from
``PlatformSettings``. The auth router calls these on every login
attempt — `is_locked` short-circuits before the password check, and
`register_failure` / `register_success` mutate the user row in place
(commit is the caller's responsibility).

Windowed counter semantics: the threshold counts failures inside the
rolling ``reset_minutes`` window. If the previous failure is older
than that, the counter starts fresh — so 1 fail every 6 minutes never
accumulates into a lockout while 5 fails inside 5 minutes does.

Separately, the MFA step of sign-in has a per-account wrong-code budget
that applies whether or not lockout is enabled (``MFA_FAIL_MAX`` wrong
codes per ``MFA_FAIL_WINDOW_MINUTES``). It lives on the user row rather
than in Redis so it holds when Redis is unavailable, and the login
handler reads it under a row lock so concurrent attempts cannot all see
an under-budget count.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog

from app.models.auth import User
from app.models.settings import PlatformSettings, platform_setting_default

logger = structlog.get_logger(__name__)

# Wrong second-factor answers (TOTP or recovery code) allowed per account
# inside the window before the MFA step refuses further attempts. Applies
# even with lockout disabled. A person mistyping gets several goes; a
# script guessing codes gets five per quarter-hour.
MFA_FAIL_MAX = 5
MFA_FAIL_WINDOW_MINUTES = 15


@dataclass(frozen=True)
class LockoutPolicy:
    threshold: int
    duration_minutes: int
    reset_minutes: int

    @property
    def enabled(self) -> bool:
        return self.threshold > 0

    @classmethod
    def from_row(cls, row: PlatformSettings | None) -> LockoutPolicy:
        if row is None:
            d = platform_setting_default
            return cls(
                threshold=int(d("lockout_threshold")),
                duration_minutes=int(d("lockout_duration_minutes")),
                reset_minutes=int(d("lockout_reset_minutes")),
            )
        return cls(
            threshold=int(row.lockout_threshold),
            duration_minutes=int(row.lockout_duration_minutes),
            reset_minutes=int(row.lockout_reset_minutes),
        )


def is_locked(user: User, now: datetime | None = None) -> bool:
    """True when ``failed_login_locked_until`` is set and still in the
    future. Independent of ``LockoutPolicy.enabled`` so a previously-
    locked user stays locked even if an admin disables the feature
    mid-incident — they just have to wait it out (or be unlocked)."""
    if user.failed_login_locked_until is None:
        return False
    now = now or datetime.now(UTC)
    return user.failed_login_locked_until > now


def register_failure(user: User, policy: LockoutPolicy, now: datetime | None = None) -> bool:
    """Bump the failure counter and lock the account if it crossed the
    threshold. Returns True iff the account just transitioned to locked
    so the caller can write a distinct audit row.

    Caller still commits.
    """
    if not policy.enabled:
        return False
    now = now or datetime.now(UTC)

    # Windowed reset: any failure older than ``reset_minutes`` is
    # considered to have aged out. We can't track every individual
    # failure timestamp without a separate table, so we approximate:
    # if the prior failure is past the window, drop the counter to
    # zero before incrementing.
    if user.last_failed_login_at is not None and (now - user.last_failed_login_at) > timedelta(
        minutes=policy.reset_minutes
    ):
        user.failed_login_count = 0

    user.failed_login_count = (user.failed_login_count or 0) + 1
    user.last_failed_login_at = now

    if user.failed_login_count >= policy.threshold:
        user.failed_login_locked_until = now + timedelta(minutes=policy.duration_minutes)
        logger.warning(
            "account_locked",
            user_id=str(user.id),
            username=user.username,
            until=user.failed_login_locked_until.isoformat(),
            threshold=policy.threshold,
        )
        return True
    return False


def register_success(user: User) -> None:
    """Reset the lockout state on successful login. Caller commits."""
    if user.failed_login_count or user.failed_login_locked_until:
        user.failed_login_count = 0
        user.failed_login_locked_until = None
        user.last_failed_login_at = None
    if user.mfa_failed_count or user.mfa_last_failed_at:
        user.mfa_failed_count = 0
        user.mfa_last_failed_at = None


def _mfa_window_open(user: User, now: datetime) -> bool:
    return user.mfa_last_failed_at is not None and (now - user.mfa_last_failed_at) <= timedelta(
        minutes=MFA_FAIL_WINDOW_MINUTES
    )


def mfa_attempts_exhausted(user: User, now: datetime | None = None) -> bool:
    """True while the account has used its wrong-code budget for the MFA
    step. The budget frees up ``MFA_FAIL_WINDOW_MINUTES`` after the last
    counted failure; refused attempts are not counted, so waiting is
    enough."""
    now = now or datetime.now(UTC)
    return (user.mfa_failed_count or 0) >= MFA_FAIL_MAX and _mfa_window_open(user, now)


def mfa_retry_after_seconds(user: User, now: datetime | None = None) -> int:
    """Seconds until ``mfa_attempts_exhausted`` turns false."""
    now = now or datetime.now(UTC)
    if user.mfa_last_failed_at is None:
        return 0
    left = user.mfa_last_failed_at + timedelta(minutes=MFA_FAIL_WINDOW_MINUTES) - now
    return max(1, int(left.total_seconds()) + 1)


def register_mfa_failure(user: User, now: datetime | None = None) -> bool:
    """Count one wrong MFA answer against the per-account budget. Returns
    True iff this failure used up the budget. Caller commits."""
    now = now or datetime.now(UTC)
    if not _mfa_window_open(user, now):
        user.mfa_failed_count = 0
    user.mfa_failed_count = (user.mfa_failed_count or 0) + 1
    user.mfa_last_failed_at = now
    return user.mfa_failed_count == MFA_FAIL_MAX


def unlock(user: User) -> bool:
    """Clear the lockout state. Returns True iff anything actually
    changed so the admin endpoint can decide whether to write an
    audit row vs. surface "already unlocked"."""
    if (
        user.failed_login_count == 0
        and user.failed_login_locked_until is None
        and user.last_failed_login_at is None
        and not user.mfa_failed_count
        and user.mfa_last_failed_at is None
    ):
        return False
    user.failed_login_count = 0
    user.failed_login_locked_until = None
    user.last_failed_login_at = None
    user.mfa_failed_count = 0
    user.mfa_last_failed_at = None
    return True
