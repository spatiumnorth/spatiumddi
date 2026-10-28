"""Refresh-rotation grace window (#2941).

``POST /auth/refresh`` rotates a session: the old ``UserSession`` row is
revoked and a successor is minted. The tabs of one browser share the
HttpOnly refresh cookie, and each holds an access token whose ``jti`` names
the session it was minted for. Without a grace window, one tab's refresh
kills every other tab's access token on the spot, and two tabs refreshing
at the same moment race on the one cookie: the loser gets a 401 and the
console sends the operator to ``/login``.

So for :data:`ROTATION_GRACE` after a rotation, the rotated-away session
stands for its successor:

* a refresh presenting the rotated cookie is answered with the SAME
  successor (a new access token for it), never a third session;
* an access token naming the rotated session is accepted as the successor.

The grace follows ONLY a rotation. A row records that it was revoked by
rotation in ``rotated_at`` + ``rotated_to_id``, which nothing else writes.
Every other revocation (logout, an admin's force-logout, a password change,
disabling the account, unlinking a provider) flips ``revoked`` on the LIVE
row, which has no ``rotated_at``, so the walk below stops there and refuses
at once. Revoking the successor therefore also ends the grace of every row
that rotated into it: the grace never outlives the session it points to.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Final

#: How long a rotated-away session keeps standing for its successor. Long
#: enough for a concurrent refresh from another tab, and for requests already
#: in flight with the old access token, to land; short enough that a cookie
#: or token captured from a rotated session is useless almost at once.
ROTATION_GRACE: Final[timedelta] = timedelta(seconds=10)

# A chain longer than this inside one grace window is not tabs racing.
_MAX_HOPS: Final[int] = 4


def in_rotation_grace(session: Any, now: datetime) -> bool:
    """True when ``session`` was revoked by a rotation within the window."""
    rotated_at = session.rotated_at
    return (
        bool(session.revoked)
        and rotated_at is not None
        and session.rotated_to_id is not None
        and timedelta(0) <= now - rotated_at <= ROTATION_GRACE
    )


async def rotation_successor(db: Any, session: Any, now: datetime) -> Any:
    """The session a revoked row stands for, or ``None``.

    ``session`` itself when it is not revoked. For a row revoked by a
    rotation within :data:`ROTATION_GRACE`, the successor, followed while it
    too was rotated within its own window. ``None`` for any other
    revocation, a window that has passed, or a successor that has itself
    been revoked by anything but a rotation. The caller still applies the
    expiry, idle and account checks to what is returned.
    """
    from app.models.auth import UserSession  # noqa: PLC0415 — keep import-light

    current = session
    for _ in range(_MAX_HOPS + 1):
        if not current.revoked:
            return current
        if not in_rotation_grace(current, now):
            return None
        nxt = await db.get(UserSession, current.rotated_to_id)
        if nxt is None:
            return None
        current = nxt
    return None


async def resolve_live_session_id(db: Any, jti: str | None, now: datetime) -> str | None:
    """The id of the session an access token's ``jti`` currently stands for.

    The jti itself for a live session, the successor's id for one inside
    its rotation grace. Used by the paths that spare "the caller's own
    session" when revoking the rest, which must spare the session the
    caller's refresh cookie now names, not the one their access token was
    minted for. Returns ``jti`` unchanged when it resolves to nothing.
    """
    from app.models.auth import UserSession  # noqa: PLC0415

    if jti is None:
        return None
    try:
        session_id = uuid.UUID(str(jti))
    except ValueError:
        return jti
    session = await db.get(UserSession, session_id)
    if session is None:
        return jti
    live = await rotation_successor(db, session, now)
    return str(live.id) if live is not None else jti
