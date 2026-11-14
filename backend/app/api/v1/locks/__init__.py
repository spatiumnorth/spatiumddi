"""Resource locks API (#3361): list, set and clear edit / delete locks.

Locking and unlocking need ``lock`` on the object's type, a grant of its own:
``write`` does not imply it and ``admin`` does not either (a ``*`` grant does,
which is how a superadmin can always unlock). A reason is required both ways,
and every lock and unlock is audited with it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Select, select

from app.api.deps import DB, CurrentUser
from app.core.permissions import user_has_permission
from app.services import locks as lock_svc

router = APIRouter()


class LockRequest(BaseModel):
    level: Literal["delete", "edit"]
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime | None = None

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a reason is required")
        return v


class UnlockRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("a reason is required")
        return v


class LockEntry(BaseModel):
    resource_type: str
    resource_id: uuid.UUID
    display: str
    level: str
    locked_by: str | None
    locked_at: datetime | None
    reason: str | None
    expires_at: datetime | None


class LockListResponse(BaseModel):
    items: list[LockEntry]
    total: int
    limit: int
    offset: int


def _entry(resource_type: str, obj: object) -> LockEntry:
    info = lock_svc.active_lock(obj)
    assert info is not None
    return LockEntry(
        resource_type=resource_type,
        resource_id=obj.id,  # type: ignore[attr-defined]
        display=lock_svc.display(resource_type, obj),
        level=info.level,
        locked_by=info.locked_by,
        locked_at=info.locked_at,
        reason=info.reason,
        expires_at=info.expires_at,
    )


@router.get("", response_model=LockListResponse)
async def list_locks(
    current_user: CurrentUser,
    db: DB,
    resource_type: Annotated[str | None, Query()] = None,
    level: Annotated[Literal["delete", "edit"] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> LockListResponse:
    """Every object locked right now, across the lockable types the caller can
    read. The handler filters by the caller's ``read`` grant per type."""
    if resource_type is not None and resource_type not in lock_svc.SPECS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{resource_type} is not lockable")
    types = [resource_type] if resource_type else list(lock_svc.SPECS)
    entries: list[LockEntry] = []
    for rtype in types:
        spec = lock_svc.SPECS[rtype]
        if not user_has_permission(current_user, "read", spec.permission_type):
            continue
        stmt: Select[Any] = select(spec.model).where(lock_svc.active_lock_where(spec.model))
        if level is not None:
            stmt = stmt.where(spec.model.lock_level == level)  # type: ignore[attr-defined]
        for obj in (await db.execute(stmt)).scalars().all():
            entries.append(_entry(rtype, obj))
    entries.sort(key=lambda e: (e.locked_at is None, e.locked_at), reverse=True)
    return LockListResponse(
        items=entries[offset : offset + limit], total=len(entries), limit=limit, offset=offset
    )


async def _target(
    db: DB, current_user: CurrentUser, resource_type: str, resource_id: uuid.UUID
) -> object:
    spec = lock_svc.SPECS.get(resource_type)
    if spec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{resource_type} is not lockable")
    obj = await lock_svc.load_lockable(db, resource_type, resource_id)
    if obj is None or getattr(obj, "deleted_at", None) is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{resource_type} not found")
    if not user_has_permission(current_user, "lock", spec.permission_type, resource_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Permission denied: need 'lock' on '{spec.permission_type}'",
        )
    return obj


@router.put("/{resource_type}/{resource_id}", response_model=LockEntry)
async def set_lock(
    resource_type: str,
    resource_id: uuid.UUID,
    body: LockRequest,
    current_user: CurrentUser,
    db: DB,
) -> LockEntry:
    obj = await _target(db, current_user, resource_type, resource_id)
    if body.expires_at is not None and body.expires_at <= datetime.now(body.expires_at.tzinfo):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "expires_at is in the past")
    lock_svc.set_lock(
        db,
        current_user,
        resource_type,
        obj,
        level=body.level,
        reason=body.reason,
        expires_at=body.expires_at,
    )
    await db.commit()
    return _entry(resource_type, obj)


@router.post("/{resource_type}/{resource_id}/unlock", status_code=status.HTTP_204_NO_CONTENT)
async def clear_lock(
    resource_type: str,
    resource_id: uuid.UUID,
    body: UnlockRequest,
    current_user: CurrentUser,
    db: DB,
) -> None:
    obj = await _target(db, current_user, resource_type, resource_id)
    if getattr(obj, "lock_level", None) is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This object is not locked.")
    lock_svc.clear_lock(db, current_user, resource_type, obj, reason=body.reason)
    await db.commit()
