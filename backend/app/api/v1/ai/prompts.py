"""Operator Copilot prompts library (issue #90 Phase 2).

Reusable prompt rows the operator can load into the chat drawer with
one click. Two visibility modes per row (see :class:`AIPrompt` model
docstring).

Permissions:
    * **List / get**: any authenticated user with chat access.
        - Sees every ``is_shared = true`` row.
        - Sees their own ``is_shared = false`` rows.
    * **Create**:
        - Shared: superadmin only.
        - Private: any authenticated user.
    * **Update / Delete**: superadmin OR ``created_by_user_id == me``.

Audit: every mutation writes an ``ai.prompt.<verb>`` row through the
shared ``write_audit`` helper so the audit log + webhooks see them
just like any other resource.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.core.permissions import is_effective_superadmin
from app.models.ai import AIPrompt

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────


class PromptCreate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    prompt_text: str = Field(min_length=1)
    is_shared: bool = False


class PromptUpdate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    prompt_text: str | None = Field(default=None, min_length=1)
    is_shared: bool | None = None


class PromptResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    prompt_text: str
    is_shared: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    modified_at: datetime
    # Convenience flag — true iff the current request user owns this
    # row. Lets the UI show / hide the edit + delete buttons without
    # a second round-trip.
    is_owner: bool = False


def _to_response(p: AIPrompt, *, is_owner: bool) -> PromptResponse:
    return PromptResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        prompt_text=p.prompt_text,
        is_shared=p.is_shared,
        created_by_user_id=p.created_by_user_id,
        created_at=p.created_at,
        modified_at=p.modified_at,
        is_owner=is_owner,
    )


# ── Endpoints ────────────────────────────────────────────────────────────


@router.get("/prompts", response_model=list[PromptResponse])
async def list_prompts(current_user: CurrentUser, db: DB) -> list[PromptResponse]:
    """Returns every shared prompt + every prompt the current user
    created. Ordered by name so the picker reads alphabetically.
    """
    stmt = (
        select(AIPrompt)
        .where(
            or_(
                AIPrompt.is_shared.is_(True),
                AIPrompt.created_by_user_id == current_user.id,
            )
        )
        .order_by(AIPrompt.is_shared.desc(), AIPrompt.name.asc())
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(p, is_owner=p.created_by_user_id == current_user.id) for p in rows]


@router.post(
    "/prompts",
    response_model=PromptResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_prompt(body: PromptCreate, current_user: CurrentUser, db: DB) -> PromptResponse:
    if body.is_shared and not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmins can create shared prompts",
        )
    row = AIPrompt(
        name=body.name,
        description=body.description,
        prompt_text=body.prompt_text,
        is_shared=body.is_shared,
        created_by_user_id=current_user.id,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        # Hits one of the partial-unique indexes
        # (uq_ai_prompt_shared_name or uq_ai_prompt_private_name_per_user).
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A prompt named {body.name!r} already exists in that visibility scope",
        ) from exc
    write_audit(
        db,
        user=current_user,
        action="create",
        resource_type="ai.prompt",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={"is_shared": row.is_shared, "name": row.name},
    )
    await db.commit()
    await db.refresh(row)
    return _to_response(row, is_owner=True)


@router.get("/prompts/{prompt_id}", response_model=PromptResponse)
async def get_prompt(prompt_id: uuid.UUID, current_user: CurrentUser, db: DB) -> PromptResponse:
    row = await db.get(AIPrompt, prompt_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Prompt not found")
    if not row.is_shared and row.created_by_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Prompt not found")
    return _to_response(row, is_owner=row.created_by_user_id == current_user.id)


@router.put("/prompts/{prompt_id}", response_model=PromptResponse)
async def update_prompt(
    prompt_id: uuid.UUID,
    body: PromptUpdate,
    current_user: CurrentUser,
    db: DB,
) -> PromptResponse:
    row = await db.get(AIPrompt, prompt_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Prompt not found")
    is_owner = row.created_by_user_id == current_user.id
    # Resolve effective-superadmin once — it walks the RBAC group→role graph,
    # and this handler gates on it three times (#354 review).
    is_admin = is_effective_superadmin(current_user)
    if not (is_admin or is_owner):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    # Operators can't promote a private prompt into the shared bucket
    # without superadmin, since shared prompts go in the curated list.
    if body.is_shared is not None and body.is_shared != row.is_shared:
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superadmins can change the shared/private flag",
            )
    update_fields = body.model_dump(exclude_unset=True)
    for k, v in update_fields.items():
        setattr(row, k, v)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A prompt with that name already exists in that visibility scope",
        ) from exc
    write_audit(
        db,
        user=current_user,
        action="update",
        resource_type="ai.prompt",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(update_fields.keys()),
    )
    await db.commit()
    await db.refresh(row)
    return _to_response(row, is_owner=is_owner or is_admin)


@router.delete("/prompts/{prompt_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_prompt(prompt_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    row = await db.get(AIPrompt, prompt_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Prompt not found")
    is_owner = row.created_by_user_id == current_user.id
    if not (is_effective_superadmin(current_user) or is_owner):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    name = row.name
    await db.delete(row)
    write_audit(
        db,
        user=current_user,
        action="delete",
        resource_type="ai.prompt",
        resource_id=str(prompt_id),
        resource_display=name,
    )
    await db.commit()
