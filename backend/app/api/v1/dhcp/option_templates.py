"""DHCP option template CRUD — group-scoped.

Templates bundle option-code → value pairs under a name (e.g. "VoIP
phones", "PXE BIOS clients") that can be applied to a scope's options
in one click. Apply is a server-side merge into the scope's existing
options dict; subsequent template edits do NOT propagate back to scopes
that already used it (apply is a stamp, not a binding).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import (
    DHCPOptionTemplate,
    DHCPScope,
    DHCPServerGroup,
)
from app.services.dhcp.option_validation import normalize_options

router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_option_template"))],
)

_VALID_FAMILIES = {"ipv4", "ipv6"}


class OptionTemplateCreate(BaseModel):
    name: str
    description: str = ""
    address_family: str = "ipv4"
    options: Any = None

    @field_validator("address_family")
    @classmethod
    def _af(cls, v: str) -> str:
        if v not in _VALID_FAMILIES:
            raise ValueError(f"address_family must be one of {sorted(_VALID_FAMILIES)}")
        return v


class OptionTemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    address_family: str | None = None
    options: Any = None

    @field_validator("address_family")
    @classmethod
    def _af(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_FAMILIES:
            raise ValueError(f"address_family must be one of {sorted(_VALID_FAMILIES)}")
        return v


class OptionTemplateResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    description: str
    address_family: str
    options: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


def _to_response(t: DHCPOptionTemplate) -> OptionTemplateResponse:
    return OptionTemplateResponse(
        id=t.id,
        group_id=t.group_id,
        name=t.name,
        description=t.description,
        address_family=t.address_family,
        options=dict(t.options or {}),
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


@router.get(
    "/server-groups/{group_id}/option-templates",
    response_model=list[OptionTemplateResponse],
)
async def list_templates(
    group_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[OptionTemplateResponse]:
    res = await db.execute(
        select(DHCPOptionTemplate)
        .where(DHCPOptionTemplate.group_id == group_id)
        .order_by(DHCPOptionTemplate.name)
    )
    return [_to_response(t) for t in res.scalars().all()]


@router.post(
    "/server-groups/{group_id}/option-templates",
    response_model=OptionTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_template(
    group_id: uuid.UUID,
    body: OptionTemplateCreate,
    db: DB,
    user: SuperAdmin,
) -> OptionTemplateResponse:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")
    existing = await db.execute(
        select(DHCPOptionTemplate).where(
            DHCPOptionTemplate.group_id == group_id,
            DHCPOptionTemplate.name == body.name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A template with that name exists")
    options = normalize_options(body.options)
    validate_dhcp_options(options, address_family=body.address_family)
    tpl = DHCPOptionTemplate(
        group_id=group_id,
        name=body.name,
        description=body.description,
        address_family=body.address_family,
        options=options,
        created_by_user_id=user.id,
    )
    db.add(tpl)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_option_template",
        resource_id=str(tpl.id),
        resource_display=tpl.name,
        new_value={
            "name": tpl.name,
            "description": tpl.description,
            "address_family": tpl.address_family,
            "options": options,
        },
    )
    await db.commit()
    await db.refresh(tpl)
    return _to_response(tpl)


@router.put(
    "/option-templates/{template_id}",
    response_model=OptionTemplateResponse,
)
async def update_template(
    template_id: uuid.UUID,
    body: OptionTemplateUpdate,
    db: DB,
    user: SuperAdmin,
) -> OptionTemplateResponse:
    tpl = await db.get(DHCPOptionTemplate, template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    payload = body.model_dump(exclude_none=True)
    if "name" in payload and payload["name"] != tpl.name:
        clash = await db.execute(
            select(DHCPOptionTemplate).where(
                DHCPOptionTemplate.group_id == tpl.group_id,
                DHCPOptionTemplate.name == payload["name"],
                DHCPOptionTemplate.id != tpl.id,
            )
        )
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="A template with that name exists")
    family = payload.get("address_family", tpl.address_family)
    if "options" in payload or family != tpl.address_family:
        options = normalize_options(payload["options"]) if "options" in payload else tpl.options
        # Validate only changed options (#597, #1228) so a round-tripped
        # grandfathered value doesn't block an unrelated edit — unless the
        # family changed, which makes every option new to the template.
        validate_dhcp_options(
            options or {},
            address_family=family,
            previous=(tpl.options or {}) if family == tpl.address_family else None,
        )
        if "options" in payload:
            payload["options"] = options
    for k, v in payload.items():
        setattr(tpl, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_option_template",
        resource_id=str(tpl.id),
        resource_display=tpl.name,
        changed_fields=list(payload.keys()),
        new_value=payload,
    )
    await db.commit()
    await db.refresh(tpl)
    return _to_response(tpl)


@router.delete("/option-templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(template_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    tpl = await db.get(DHCPOptionTemplate, template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_option_template",
        resource_id=str(tpl.id),
        resource_display=tpl.name,
    )
    await db.delete(tpl)
    await db.commit()


# ── Apply ────────────────────────────────────────────────────────────────────


class ApplyTemplateRequest(BaseModel):
    template_id: uuid.UUID
    mode: str = "merge"  # "merge" (template wins on conflict) | "replace" (drop existing)

    @field_validator("mode")
    @classmethod
    def _m(cls, v: str) -> str:
        if v not in ("merge", "replace"):
            raise ValueError("mode must be 'merge' or 'replace'")
        return v


class ApplyTemplateResponse(BaseModel):
    scope_id: uuid.UUID
    options: dict[str, Any]
    overwritten_keys: list[str]


@router.post(
    "/scopes/{scope_id}/apply-option-template",
    response_model=ApplyTemplateResponse,
)
async def apply_template_to_scope(
    scope_id: uuid.UUID,
    body: ApplyTemplateRequest,
    db: DB,
    user: SuperAdmin,
) -> ApplyTemplateResponse:
    scope = await db.get(DHCPScope, scope_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    tpl = await db.get(DHCPOptionTemplate, body.template_id)
    if tpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    if tpl.group_id != scope.group_id:
        raise HTTPException(
            status_code=400,
            detail="Template and scope belong to different groups",
        )
    current = dict(scope.options or {})
    tpl_options = dict(tpl.options or {})
    overwritten = sorted(k for k in tpl_options if k in current and current[k] != tpl_options[k])
    if body.mode == "replace":
        new_options: dict[str, Any] = dict(tpl_options)
    else:
        new_options = {**current, **tpl_options}
    # The template was checked against its own family, which need not be the
    # scope's (#1228), and may predate the check entirely.
    validate_dhcp_options(
        new_options, address_family=scope.address_family or "ipv4", previous=current
    )
    scope.options = new_options
    # Applying a template mutates the scope's rendered options, so wake
    # the scope's group long-poll. ``group_id`` is a direct column on
    # DHCPScope (no lazy relationship access).
    collect_wake(dhcp_group_channel(scope.group_id))
    write_audit(
        db,
        user=user,
        action="apply_option_template",
        resource_type="dhcp_scope",
        resource_id=str(scope.id),
        resource_display=scope.name or str(scope.id),
        changed_fields=["options"],
        new_value={
            "template_id": str(tpl.id),
            "template_name": tpl.name,
            "mode": body.mode,
            "overwritten_keys": overwritten,
            "options": new_options,
        },
    )
    await db.commit()
    await db.refresh(scope)
    return ApplyTemplateResponse(
        scope_id=scope.id,
        options=new_options,
        overwritten_keys=overwritten,
    )
