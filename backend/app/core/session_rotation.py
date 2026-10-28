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


# A force-logout follows a rotation chain to its live end. Unlike the grace
# walk this is not time-limited (a session viewer opened minutes ago names a
# row that has since rotated), so the cap is looser: it only has to stop a
# walk over corrupt data, never an honest chain from a stale list.
_MAX_REVOKE_HOPS: Final[int] = 64


async def revoke_live_sessions(db: Any, *criteria: Any) -> int:
    """Revoke every live ``UserSession`` matching ``criteria``; return how many.

    The bulk revocations (logout, password change and reset, disabling an
    account, unlinking or deleting a provider) used to be one ``UPDATE …
    WHERE NOT revoked``. Under READ COMMITTED that statement's snapshot is
    taken when it starts, so a refresh rotating one of those rows at the
    same moment slipped a successor past it: the UPDATE waited on the row
    the refresh had locked, found it already revoked once the refresh
    committed, and never saw the successor the refresh had just inserted,
    which stayed live, along with the rotated cookie's grace into it (#2941).

    So the matching rows are locked first, in id order (two revocations of
    one account must not deadlock on each other), and the UPDATE runs as a
    second statement. Waiting on a row a refresh holds means that refresh
    has committed by the time the UPDATE takes its snapshot, so its
    successor matches; a refresh arriving after the lock waits, and then
    finds its row revoked by something that is not a rotation and gets a
    401.
    """
    from sqlalchemy import select, update  # noqa: PLC0415

    from app.models.auth import UserSession  # noqa: PLC0415

    live = (UserSession.revoked.is_(False), *criteria)
    await db.execute(select(UserSession.id).where(*live).order_by(UserSession.id).with_for_update())
    result = await db.execute(update(UserSession).where(*live).values(revoked=True))
    return int(result.rowcount or 0)


async def revoke_session_chain(db: Any, session_id: uuid.UUID) -> Any:
    """Force-logout the session ``session_id`` names; return the row revoked.

    A session id is a moment in a chain of rotations: the viewer lists the
    row live when it was fetched, and by the time an operator clicks
    Revoke, a refresh may have rotated it into a successor. Revoking the
    named row then changes nothing (it is already revoked), the successor
    stays live, and so does the rotated cookie's grace into it. So the
    revocation follows ``rotated_to_id`` to the end of the chain and
    revokes that, locking each row as it goes, so a rotation in flight is
    waited for and followed rather than raced.

    Returns None when the chain ends in a row revoked some other way (it
    was already logged out), or is broken or too long. Only ever revokes a
    session of the SAME user as the named row: the caller has authorised
    that user, and a successor naming anyone else is corrupt data.
    """
    from sqlalchemy import select  # noqa: PLC0415

    from app.models.auth import UserSession  # noqa: PLC0415

    owner = None
    current_id: uuid.UUID | None = session_id
    for _ in range(_MAX_REVOKE_HOPS):
        if current_id is None:
            return None
        row = (
            await db.execute(
                select(UserSession)
                .where(UserSession.id == current_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        if owner is None:
            owner = row.user_id
        elif row.user_id != owner:
            return None
        if not row.revoked:
            row.revoked = True
            return row
        if row.rotated_at is None:
            return None
        current_id = row.rotated_to_id
    return None


def request_session_jti(request: Any) -> str | None:
    """The ``jti`` of the access token on ``request``, best effort.

    None for an API token, a missing header, or anything that does not
    decode. The caller resolves it through the grace with
    :func:`resolve_live_session_id` to learn which session is the caller's.
    """
    from jose import JWTError  # noqa: PLC0415

    from app.core.security import decode_access_token  # noqa: PLC0415

    header = request.headers.get("authorization") or ""
    scheme, _, raw = header.partition(" ")
    if scheme.lower() != "bearer" or not raw:
        return None
    try:
        payload = decode_access_token(raw)
    except JWTError:
        return None
    jti = payload.get("jti")
    return str(jti) if jti is not None else None
