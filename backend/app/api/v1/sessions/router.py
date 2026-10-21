"""Active session viewer + force-logout (issue #72).

The auth flow already creates a ``UserSession`` row on every login +
refresh, with the access token's ``jti`` set to the session's UUID.
This router lets the operator see those rows and revoke any of them;
revocation flips ``UserSession.revoked = True``, which the auth dep
checks on every request — so an in-flight access token with that jti
401s on its next call.

Two read scopes:

* ``GET /sessions/me`` — current user's own sessions. Available to
  anyone authenticated; lets a regular user spot a session they
  didn't recognise and revoke it themselves.
* ``GET /sessions`` — all sessions across all users. Superadmin only.

One write:

* ``DELETE /sessions/{id}`` — revokes the session. The owner can
  always revoke their own session; only a superadmin can revoke
  someone else's.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.core.permissions import user_has_permission
from app.core.session_idle import get_session_timeout_minutes, idle_cutoff
from app.models.audit import AuditLog
from app.models.auth import User, UserSession

logger = structlog.get_logger(__name__)
router = APIRouter()


class SessionRow(BaseModel):
    id: str
    user_id: str
    username: str
    display_name: str
    auth_source: str
    source_ip: str | None
    user_agent: str | None
    # Real ``datetime``s (#907) — typed as strings these published without
    # ``format: date-time`` and went out in a shape no other timestamp in the
    # API uses.
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    revoked: bool
    is_current: bool

    @field_validator("id", "user_id", mode="before")
    @classmethod
    def coerce_id(cls, v: object) -> str:
        return str(v)


def _row(
    s: UserSession, *, username: str, display_name: str, current_jti: str | None
) -> SessionRow:
    return SessionRow(
        id=str(s.id),
        user_id=str(s.user_id),
        username=username,
        display_name=display_name,
        auth_source=s.auth_source or "local",
        source_ip=s.source_ip,
        user_agent=s.user_agent,
        created_at=s.created_at,
        last_seen_at=s.last_seen_at,
        expires_at=s.expires_at,
        revoked=bool(s.revoked),
        is_current=current_jti is not None and str(s.id) == current_jti,
    )


async def _exclude_idle(stmt: Select[Any], db: AsyncSession, now: datetime) -> Select[Any]:
    """Leave out sessions idle past the configured Session Timeout. The auth
    layer already refuses them, so listing them as live would be wrong."""
    cutoff = idle_cutoff(await get_session_timeout_minutes(db), now)
    if cutoff is None:
        return stmt
    return stmt.where(func.coalesce(UserSession.last_seen_at, UserSession.created_at) > cutoff)


def _is_superadmin(user: User) -> bool:
    return bool(user.is_superadmin) or user_has_permission(user, "*", "*")


@router.get("/me", response_model=list[SessionRow])
async def list_my_sessions(
    current_user: CurrentUser,
    db: DB,
    include_expired: bool = Query(default=False),
) -> list[SessionRow]:
    """Sessions the current user owns. Excludes expired, revoked and
    idle-timed-out rows by default — operator can pass
    ``include_expired=true`` for the full audit history."""
    now = datetime.now(UTC)
    stmt = select(UserSession).where(UserSession.user_id == current_user.id)
    if not include_expired:
        stmt = stmt.where(UserSession.revoked.is_(False)).where(UserSession.expires_at > now)
        stmt = await _exclude_idle(stmt, db, now)
    stmt = stmt.order_by(UserSession.created_at.desc())
    rows = (await db.execute(stmt)).scalars().all()
    return [
        _row(
            s,
            username=current_user.username,
            display_name=current_user.display_name,
            current_jti=None,  # /me doesn't carry the live jti — UI flags via comparison
        )
        for s in rows
    ]


@router.get("", response_model=list[SessionRow])
async def list_all_sessions(
    current_user: CurrentUser,
    db: DB,
    include_expired: bool = Query(default=False),
) -> list[SessionRow]:
    """All live sessions across every user (superadmin only)."""
    if not _is_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superadmin required to list other users' sessions",
        )
    now = datetime.now(UTC)
    stmt = select(UserSession, User).join(User, UserSession.user_id == User.id)
    if not include_expired:
        stmt = stmt.where(UserSession.revoked.is_(False)).where(UserSession.expires_at > now)
        stmt = await _exclude_idle(stmt, db, now)
    stmt = stmt.order_by(UserSession.created_at.desc())
    rows = (await db.execute(stmt)).all()
    return [
        _row(
            session,
            username=user.username,
            display_name=user.display_name,
            current_jti=None,
        )
        for session, user in rows
    ]


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> None:
    """Force-logout a session. Owner can revoke their own; only a
    superadmin can revoke someone else's. Idempotent — already-revoked
    rows return 204 without writing a duplicate audit row."""
    session = await db.get(UserSession, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    is_self = session.user_id == current_user.id
    if not is_self and not _is_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot revoke another user's session without superadmin",
        )

    if session.revoked:
        return  # idempotent
    session.revoked = True
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="session.revoked",
            resource_type="user_session",
            resource_id=str(session.id),
            resource_display=f"{session.source_ip or '?'} ({session.auth_source})",
            result="success",
            new_value={
                "target_user_id": str(session.user_id),
                "is_self": is_self,
            },
        )
    )
    await db.commit()
    logger.info(
        "session_revoked",
        session_id=str(session.id),
        target_user_id=str(session.user_id),
        actor=current_user.username,
        is_self=is_self,
    )
