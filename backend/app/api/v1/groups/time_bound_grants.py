"""Time-bound grant CRUD — issue #65.

Mounted under ``/api/v1/groups`` (alongside the groups router). A grant
attaches one temporary ``{action, resource_type, resource_id?}`` permission
to a group until ``expires_at``; ``user_has_permission`` unions live grants
over the static role grants.

Authorization mirrors how role permissions are edited today: ``admin`` on
``group`` is sufficient to create / revoke a grant. Listing needs only
``read`` on ``group``.

SECURITY (#400, finding C4): creating a grant adds a temporary permission to a
group, so it must respect the same privilege ceiling as role authoring — a
non-superadmin may only grant a triple they already hold, never a wildcard.
``caller_can_grant`` (in ``app.core.permissions``) enforces this; effective
superadmins bypass it. The pre-#400 "no extra privilege-escalation guard"
stance (issue #65) is superseded.

Every mutation writes an ``audit_log`` row with ``action='permission_change'``
before the response is returned (CLAUDE.md non-negotiable #4).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.stepup import require_stepup_if_granting_superadmin
from app.api.v1.roles.router import _VALID_ACTIONS
from app.core.permissions import caller_can_grant, require_permission
from app.models.audit import AuditLog
from app.models.auth import Group
from app.models.time_bound_grant import TimeBoundGrant
from app.services.superadmin_grant import SuperadminModel, permissions_grant_superadmin

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────


class TimeBoundGrantCreate(BaseModel):
    group_id: uuid.UUID
    action: str
    resource_type: str
    resource_id: str | None = None
    expires_at: datetime
    reason: str = ""
    # #1412 — the caller's step-up, needed only when the grant is ``*`` / ``*``
    # and the group has members who are not already superadmins.
    stepup_password: str | None = None
    stepup_totp_code: str | None = None

    @field_validator("action")
    @classmethod
    def _action(cls, v: str) -> str:
        v = v.strip()
        if v not in _VALID_ACTIONS:
            raise ValueError(
                f"action must be one of {sorted(_VALID_ACTIONS)}; see docs/PERMISSIONS.md"
            )
        return v

    @field_validator("resource_type")
    @classmethod
    def _resource_type(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("resource_type cannot be empty")
        return v

    @field_validator("resource_id")
    @classmethod
    def _resource_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class TimeBoundGrantResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    action: str
    resource_type: str
    resource_id: str | None
    expires_at: datetime
    revoked_at: datetime | None
    reason: str
    granted_by_user_id: uuid.UUID | None
    is_active: bool
    created_at: datetime


# ── Helpers ───────────────────────────────────────────────────────────────────


def _to_response(g: TimeBoundGrant) -> TimeBoundGrantResponse:
    now = datetime.now(UTC)
    expires = g.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    is_active = g.revoked_at is None and expires > now
    return TimeBoundGrantResponse(
        id=g.id,
        group_id=g.group_id,
        action=g.action,
        resource_type=g.resource_type,
        resource_id=g.resource_id,
        expires_at=g.expires_at,
        revoked_at=g.revoked_at,
        reason=g.reason,
        granted_by_user_id=g.granted_by_user_id,
        is_active=is_active,
        created_at=g.created_at,
    )


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get(
    "/time-bound-grants",
    response_model=list[TimeBoundGrantResponse],
    dependencies=[Depends(require_permission("read", "group"))],
)
async def list_time_bound_grants(
    db: DB,
    _: CurrentUser,
    group_id: uuid.UUID | None = Query(default=None),
    include_expired: bool = Query(default=False),
) -> list[TimeBoundGrantResponse]:
    """List time-bound grants.

    By default returns only grants that are still live (``revoked_at IS NULL``
    AND ``expires_at > now()``). ``include_expired=true`` returns the full
    history (revoked + expired rows) so the UI can show an audit trail.
    """
    stmt = select(TimeBoundGrant).order_by(TimeBoundGrant.created_at.desc())
    if group_id is not None:
        stmt = stmt.where(TimeBoundGrant.group_id == group_id)
    if not include_expired:
        now = datetime.now(UTC)
        stmt = stmt.where(TimeBoundGrant.revoked_at.is_(None)).where(
            TimeBoundGrant.expires_at > now
        )
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(g) for g in rows]


@router.post(
    "/time-bound-grants",
    response_model=TimeBoundGrantResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("admin", "group"))],
)
async def create_time_bound_grant(
    body: TimeBoundGrantCreate, current_user: CurrentUser, db: DB
) -> TimeBoundGrantResponse:
    group = await db.get(Group, body.group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    expires = body.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="expires_at must be in the future",
        )

    # SECURITY (#400, finding C4): privilege ceiling. A grant unions a temporary
    # permission onto a group, so a non-superadmin may only grant a triple they
    # already hold and may never mint a wildcard — same rule as role authoring.
    requested = [
        {
            "action": body.action,
            "resource_type": body.resource_type,
            "resource_id": body.resource_id,
        }
    ]
    if not caller_can_grant(current_user, requested):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "You can only grant a permission you already hold, and only a "
                "superadmin can grant wildcard ('*') permissions."
            ),
        )

    # A ``*`` / ``*`` grant makes every member a superadmin until it expires
    # (#1412). Checked before the row is written: a refused step-up commits
    # its audit row.
    method: str | None = None
    granted = 0
    if permissions_grant_superadmin(requested):
        group_id = body.group_id

        def _change(model: SuperadminModel) -> None:
            model.granted_groups.add(group_id)

        method, granted = await require_stepup_if_granting_superadmin(
            db,
            current_user,
            password=body.stepup_password,
            totp_code=body.stepup_totp_code,
            change=_change,
            action="permission_change",
            resource_type="time_bound_grant",
            resource_id=str(body.group_id),
            resource_display=f"grant * on * to group {group.name}",
        )

    grant = TimeBoundGrant(
        group_id=body.group_id,
        action=body.action,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        expires_at=expires,
        reason=body.reason,
        granted_by_user_id=current_user.id,
    )
    db.add(grant)
    await db.flush()

    summary = (
        f"Granted {body.action} on {body.resource_type}"
        f"{('/' + body.resource_id) if body.resource_id else ''} "
        f"to group {group.name} until {expires.isoformat()}"
    )
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="permission_change",
            resource_type="time_bound_grant",
            resource_id=str(grant.id),
            resource_display=summary,
            new_value={
                "group_id": str(body.group_id),
                "action": body.action,
                "resource_type": body.resource_type,
                "resource_id": body.resource_id,
                "expires_at": expires.isoformat(),
                "reason": body.reason,
                **({"granted_superadmin": granted, "stepup_method": method} if granted else {}),
            },
        )
    )
    await db.commit()
    await db.refresh(grant)
    logger.info(
        "time_bound_grant_created",
        grant_id=str(grant.id),
        group=group.name,
        action=body.action,
        resource_type=body.resource_type,
        by=current_user.username,
    )
    return _to_response(grant)


@router.delete(
    "/time-bound-grants/{grant_id}",
    response_model=TimeBoundGrantResponse,
    dependencies=[Depends(require_permission("admin", "group"))],
)
async def revoke_time_bound_grant(
    grant_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> TimeBoundGrantResponse:
    """Soft-revoke a grant now — sets ``revoked_at`` and keeps the row for
    audit / history. Idempotent: re-revoking an already-revoked grant is a
    no-op (returns the existing row) so a double-click can't 500."""
    grant = await db.get(TimeBoundGrant, grant_id)
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grant not found")

    if grant.revoked_at is not None:
        return _to_response(grant)

    grant.revoked_at = datetime.now(UTC)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="permission_change",
            resource_type="time_bound_grant",
            resource_id=str(grant.id),
            resource_display=(
                f"Revoked {grant.action} on {grant.resource_type}"
                f"{('/' + grant.resource_id) if grant.resource_id else ''} "
                f"for group {grant.group_id}"
            ),
            old_value={"revoked_at": None},
            new_value={"revoked_at": grant.revoked_at.isoformat(), "reason": "manual_revoke"},
        )
    )
    await db.commit()
    await db.refresh(grant)
    logger.info(
        "time_bound_grant_revoked",
        grant_id=str(grant.id),
        by=current_user.username,
    )
    return _to_response(grant)
