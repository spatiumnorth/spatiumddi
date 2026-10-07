"""Custom field definitions — admin CRUD (superadmin only for writes)."""

from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_resource_permission
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import CustomFieldDefinition

logger = structlog.get_logger(__name__)
router = APIRouter(dependencies=[Depends(require_resource_permission("custom_field"))])

_VALID_RESOURCE_TYPES = {"ip_space", "ip_block", "subnet", "ip_address"}
_VALID_FIELD_TYPES = {"text", "number", "boolean", "select", "url", "email"}


# ── Schemas ────────────────────────────────────────────────────────────────────


class CustomFieldResponse(BaseModel):
    id: str
    resource_type: str
    name: str
    label: str
    field_type: str
    options: list[str] | None
    is_required: bool
    is_searchable: bool
    default_value: str | None
    display_order: int
    description: str

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm(cls, obj: CustomFieldDefinition) -> CustomFieldResponse:
        return cls(
            id=str(obj.id),
            resource_type=obj.resource_type,
            name=obj.name,
            label=obj.label,
            field_type=obj.field_type,
            options=obj.options if isinstance(obj.options, list) else None,
            is_required=obj.is_required,
            is_searchable=obj.is_searchable,
            default_value=obj.default_value,
            display_order=obj.display_order,
            description=obj.description,
        )


class CustomFieldCreate(BaseModel):
    resource_type: str
    name: str
    label: str
    field_type: str
    options: list[str] | None = None
    is_required: bool = False
    is_searchable: bool = False
    default_value: str | None = None
    display_order: int = 0
    description: str = ""

    @field_validator("resource_type")
    @classmethod
    def validate_resource_type(cls, v: str) -> str:
        if v not in _VALID_RESOURCE_TYPES:
            raise ValueError(
                f"resource_type must be one of: {', '.join(sorted(_VALID_RESOURCE_TYPES))}"
            )
        return v

    @field_validator("field_type")
    @classmethod
    def validate_field_type(cls, v: str) -> str:
        if v not in _VALID_FIELD_TYPES:
            raise ValueError(f"field_type must be one of: {', '.join(sorted(_VALID_FIELD_TYPES))}")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        import re

        if not re.match(r"^[a-z][a-z0-9_]*$", v):
            raise ValueError(
                "name must be lowercase letters, digits, and underscores, starting with a letter"
            )
        return v


class CustomFieldUpdate(BaseModel):
    label: str | None = None
    options: list[str] | None = None
    is_required: bool | None = None
    is_searchable: bool | None = None
    default_value: str | None = None
    display_order: int | None = None
    description: str | None = None


# ── Audit ──────────────────────────────────────────────────────────────────────


def _snapshot(field: CustomFieldDefinition) -> dict:
    """Audit snapshot of a custom field definition (no secrets live here)."""
    return {
        "resource_type": field.resource_type,
        "name": field.name,
        "label": field.label,
        "field_type": field.field_type,
        "options": field.options if isinstance(field.options, list) else None,
        "is_required": field.is_required,
        "is_searchable": field.is_searchable,
        "default_value": field.default_value,
        "display_order": field.display_order,
        "description": field.description,
    }


def _audit(
    db: DB,
    *,
    user: User,
    action: str,
    field: CustomFieldDefinition,
    old_value: dict | None = None,
    new_value: dict | None = None,
    changed_fields: list[str] | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type="custom_field",
            resource_id=str(field.id),
            resource_display=field.name,
            old_value=old_value,
            new_value=new_value,
            changed_fields=changed_fields,
        )
    )


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get("", response_model=list[CustomFieldResponse])
async def list_custom_fields(
    current_user: CurrentUser,
    db: DB,
    resource_type: str | None = None,
) -> list[CustomFieldResponse]:
    stmt = select(CustomFieldDefinition).order_by(
        CustomFieldDefinition.resource_type,
        CustomFieldDefinition.display_order,
        CustomFieldDefinition.name,
    )
    if resource_type:
        stmt = stmt.where(CustomFieldDefinition.resource_type == resource_type)
    result = await db.execute(stmt)
    fields = result.scalars().all()
    return [CustomFieldResponse.from_orm(f) for f in fields]


@router.post("", response_model=CustomFieldResponse, status_code=status.HTTP_201_CREATED)
async def create_custom_field(
    body: CustomFieldCreate,
    current_user: CurrentUser,
    db: DB,
) -> CustomFieldResponse:
    # Permission check happens at router-level (custom_field write).
    # Check uniqueness
    existing = await db.execute(
        select(CustomFieldDefinition).where(
            CustomFieldDefinition.resource_type == body.resource_type,
            CustomFieldDefinition.name == body.name,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A custom field named '{body.name}' already exists for {body.resource_type}",
        )

    field = CustomFieldDefinition(
        resource_type=body.resource_type,
        name=body.name,
        label=body.label,
        field_type=body.field_type,
        options=body.options,
        is_required=body.is_required,
        is_searchable=body.is_searchable,
        default_value=body.default_value,
        display_order=body.display_order,
        description=body.description,
    )
    db.add(field)
    await db.flush()
    _audit(db, user=current_user, action="create", field=field, new_value=_snapshot(field))
    await db.commit()
    await db.refresh(field)
    logger.info(
        "custom_field_created",
        user=current_user.username,
        id=str(field.id),
        name=field.name,
        resource_type=field.resource_type,
    )
    return CustomFieldResponse.from_orm(field)


@router.get("/{field_id}", response_model=CustomFieldResponse)
async def get_custom_field(
    field_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> CustomFieldResponse:
    field = await db.get(CustomFieldDefinition, field_id)
    if field is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom field not found")
    return CustomFieldResponse.from_orm(field)


@router.put("/{field_id}", response_model=CustomFieldResponse)
async def update_custom_field(
    field_id: uuid.UUID,
    body: CustomFieldUpdate,
    current_user: CurrentUser,
    db: DB,
) -> CustomFieldResponse:
    # Permission check happens at router-level (custom_field write).
    field = await db.get(CustomFieldDefinition, field_id)
    if field is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom field not found")

    old_value = _snapshot(field)
    changes = body.model_dump(exclude_none=True)
    for attr, value in changes.items():
        setattr(field, attr, value)

    _audit(
        db,
        user=current_user,
        action="update",
        field=field,
        old_value=old_value,
        new_value=_snapshot(field),
        changed_fields=sorted(changes),
    )
    await db.commit()
    await db.refresh(field)
    logger.info(
        "custom_field_updated", user=current_user.username, id=str(field.id), changes=changes
    )
    return CustomFieldResponse.from_orm(field)


@router.delete("/{field_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_field(
    field_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> None:
    # Permission check happens at router-level (custom_field delete).
    field = await db.get(CustomFieldDefinition, field_id)
    if field is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom field not found")

    _audit(
        db,
        user=current_user,
        action="delete",
        field=field,
        old_value=_snapshot(field),
    )
    await db.delete(field)
    await db.commit()
    logger.info("custom_field_deleted", user=current_user.username, id=str(field_id))
