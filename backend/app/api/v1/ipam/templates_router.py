"""IPAM template classes — CRUD + apply/reapply (issue #26).

Templates STAMP block / subnet defaults onto carriers at apply
time. ``applies_to`` locks each template to one of the two
carriers — same template can't stamp both because the apply-time
semantics diverge.

Mounted under ``/ipam`` by the parent IPAM router.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.core.permissions import require_resource_permission, user_has_permission
from app.models.dns import DNS_TTL_MAX
from app.models.ipam import IPAMTemplate, IPBlock, Subnet
from app.services.ipam.templates import (
    TemplateError,
    apply_template_to_block,
    apply_template_to_subnet,
    carve_children,
    find_block_instances,
    find_subnet_instances,
)
from app.services.ipam.zone_binding import check_zone_uuid, check_zone_uuid_list

router = APIRouter(
    prefix="/templates",
    tags=["ipam"],
    dependencies=[Depends(require_resource_permission("manage_ipam_templates"))],
)


# ── Schemas ──────────────────────────────────────────────────────────────


_VALID_APPLIES_TO = frozenset({"block", "subnet"})
_DDNS_POLICIES = frozenset(
    {"client_provided", "client_or_generated", "always_generate", "disabled"}
)
# Tokens supported in child-layout name templates (mirror of bulk-allocate).
_VALID_NAME_TOKENS = frozenset({"n", "oct1", "oct2", "oct3", "oct4"})
_NAME_TOKEN_RE = re.compile(r"\{([^{}:!]+)(?::[^{}]*)?\}")


def _validate_child_layout(layout: dict[str, Any] | None) -> dict[str, Any] | None:
    """Lightweight pre-validation of child_layout shape. Prefix vs.
    parent comparison happens at apply time when the carrier is
    known.
    """
    if layout is None:
        return None
    if not isinstance(layout, dict):
        raise ValueError("child_layout must be an object.")
    children = layout.get("children")
    if not isinstance(children, list) or not children:
        raise ValueError("child_layout.children must be a non-empty array.")
    cleaned_children: list[dict[str, Any]] = []
    for idx, raw in enumerate(children):
        if not isinstance(raw, dict):
            raise ValueError(f"child_layout.children[{idx}] must be an object.")
        prefix = raw.get("prefix")
        if not isinstance(prefix, int) or not (0 < prefix <= 128):
            raise ValueError(f"child_layout.children[{idx}].prefix must be an int in 1..128.")
        name_template = raw.get("name_template", "") or ""
        if not isinstance(name_template, str):
            raise ValueError(f"child_layout.children[{idx}].name_template must be a string.")
        for token in _NAME_TOKEN_RE.findall(name_template):
            if token not in _VALID_NAME_TOKENS:
                raise ValueError(
                    f"child_layout.children[{idx}].name_template references "
                    f"unknown token {{{token}}}; valid: "
                    f"{sorted(_VALID_NAME_TOKENS)}"
                )
        entry: dict[str, Any] = {
            "prefix": prefix,
            "name_template": name_template,
            "description": raw.get("description", "") or "",
            "tags": raw.get("tags") or {},
            "custom_fields": raw.get("custom_fields") or {},
        }
        cleaned_children.append(entry)
    return {"children": cleaned_children}


class IPAMTemplateBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    applies_to: str
    tags: dict[str, Any] = {}
    custom_fields: dict[str, Any] = {}
    dns_group_id: uuid.UUID | None = None
    dns_zone_id: str | None = None
    dns_additional_zone_ids: list[str] = []
    dhcp_group_id: uuid.UUID | None = None
    ddns_enabled: bool = False
    ddns_hostname_policy: str = "client_or_generated"
    ddns_domain_override: str | None = None
    ddns_ttl: int | None = Field(None, ge=0, le=DNS_TTL_MAX)  # #2073
    child_layout: dict[str, Any] | None = None

    @field_validator("dns_zone_id")
    @classmethod
    def _v_dns_zone_id(cls, v: str | None) -> str | None:
        # The template stamps this onto a block / subnet: refuse a value that
        # names no zone rather than store it there (#2923).
        return check_zone_uuid(v, blank=None)

    @field_validator("dns_additional_zone_ids")
    @classmethod
    def _v_dns_additional_zone_ids(cls, v: list[str] | None) -> list[str] | None:
        return check_zone_uuid_list(v, field="dns_additional_zone_ids")

    @field_validator("applies_to")
    @classmethod
    def _v_applies_to(cls, v: str) -> str:
        if v not in _VALID_APPLIES_TO:
            raise ValueError(f"applies_to must be one of: {', '.join(sorted(_VALID_APPLIES_TO))}")
        return v

    @field_validator("ddns_hostname_policy")
    @classmethod
    def _v_ddns_policy(cls, v: str) -> str:
        if v not in _DDNS_POLICIES:
            raise ValueError(
                f"ddns_hostname_policy must be one of: " f"{', '.join(sorted(_DDNS_POLICIES))}"
            )
        return v

    @field_validator("child_layout")
    @classmethod
    def _v_child_layout(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_child_layout(v)

    @model_validator(mode="after")
    def _v_layout_only_for_blocks(self) -> IPAMTemplateBase:
        if self.child_layout is not None and self.applies_to != "block":
            raise ValueError("child_layout is only valid when applies_to='block'.")
        return self


class IPAMTemplateCreate(IPAMTemplateBase):
    pass


class IPAMTemplateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    # applies_to is intentionally NOT updatable — switching it would
    # invalidate every existing applied_template_id reference.
    tags: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None
    dns_group_id: uuid.UUID | None = None
    dns_zone_id: str | None = None
    dns_additional_zone_ids: list[str] | None = None
    dhcp_group_id: uuid.UUID | None = None
    ddns_enabled: bool | None = None
    ddns_hostname_policy: str | None = None
    ddns_domain_override: str | None = None
    ddns_ttl: int | None = Field(None, ge=0, le=DNS_TTL_MAX)  # #2073
    child_layout: dict[str, Any] | None = None
    # Disambiguates "set to null" (clear_*=True) from "field not
    # supplied" (None default of an optional field) for nullable
    # columns.
    clear_dns_group_id: bool = False
    clear_dhcp_group_id: bool = False
    clear_dns_zone_id: bool = False
    clear_dns_additional_zone_ids: bool = False
    clear_child_layout: bool = False
    clear_ddns_domain_override: bool = False
    clear_ddns_ttl: bool = False

    @field_validator("dns_zone_id")
    @classmethod
    def _v_dns_zone_id(cls, v: str | None) -> str | None:
        # The template stamps this onto a block / subnet: refuse a value that
        # names no zone rather than store it there (#2923).
        return check_zone_uuid(v, blank=None)

    @field_validator("dns_additional_zone_ids")
    @classmethod
    def _v_dns_additional_zone_ids(cls, v: list[str] | None) -> list[str] | None:
        return check_zone_uuid_list(v, field="dns_additional_zone_ids")

    @field_validator("ddns_hostname_policy")
    @classmethod
    def _v_ddns_policy(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _DDNS_POLICIES:
            raise ValueError(
                f"ddns_hostname_policy must be one of: " f"{', '.join(sorted(_DDNS_POLICIES))}"
            )
        return v

    @field_validator("child_layout")
    @classmethod
    def _v_child_layout(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_child_layout(v)


class IPAMTemplateResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    applies_to: str
    tags: dict[str, Any]
    custom_fields: dict[str, Any]
    dns_group_id: uuid.UUID | None
    dns_zone_id: str | None
    dns_additional_zone_ids: list[str] | None
    dhcp_group_id: uuid.UUID | None
    ddns_enabled: bool
    ddns_hostname_policy: str
    ddns_domain_override: str | None
    ddns_ttl: int | None
    child_layout: dict[str, Any] | None
    applied_count: int = 0
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class TemplateApplyRequest(BaseModel):
    block_id: uuid.UUID | None = None
    subnet_id: uuid.UUID | None = None
    force: bool = False
    carve_children: bool = True

    @model_validator(mode="after")
    def _v_one_target(self) -> TemplateApplyRequest:
        if (self.block_id is None) == (self.subnet_id is None):
            raise ValueError("Exactly one of block_id / subnet_id must be supplied.")
        return self


class TemplateApplyResponse(BaseModel):
    template_id: uuid.UUID
    target_kind: str  # "block" | "subnet"
    target_id: uuid.UUID
    fields_written: list[str]
    children_carved: list[dict[str, Any]] = []


class TemplateReapplyAllResponse(BaseModel):
    template_id: uuid.UUID
    target_kind: str
    instances_total: int
    instances_processed: int
    instances_skipped: int
    cap_reached: bool


# ── Helpers ──────────────────────────────────────────────────────────────


_REAPPLY_CAP = 200


async def _serialize(db: Any, row: IPAMTemplate) -> IPAMTemplateResponse:
    if row.applies_to == "block":
        count = await db.scalar(
            select(func.count(IPBlock.id)).where(
                IPBlock.applied_template_id == row.id,
                IPBlock.deleted_at.is_(None),
            )
        )
    else:
        count = await db.scalar(
            select(func.count(Subnet.id)).where(
                Subnet.applied_template_id == row.id,
                Subnet.deleted_at.is_(None),
            )
        )
    resp = IPAMTemplateResponse.model_validate(row)
    resp.applied_count = int(count or 0)
    return resp


# ── Endpoints ────────────────────────────────────────────────────────────


@router.get("", response_model=list[IPAMTemplateResponse])
async def list_templates(
    current_user: CurrentUser,
    db: DB,
    applies_to: str | None = Query(default=None),
    search: str | None = Query(default=None),
) -> list[IPAMTemplateResponse]:
    stmt = select(IPAMTemplate).order_by(IPAMTemplate.name.asc())
    if applies_to is not None:
        if applies_to not in _VALID_APPLIES_TO:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"applies_to must be one of: {sorted(_VALID_APPLIES_TO)}",
            )
        stmt = stmt.where(IPAMTemplate.applies_to == applies_to)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(IPAMTemplate.name).like(like),
                func.lower(IPAMTemplate.description).like(like),
            )
        )
    rows = (await db.execute(stmt)).scalars().all()
    return [await _serialize(db, r) for r in rows]


@router.post("", response_model=IPAMTemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_template(
    body: IPAMTemplateCreate, current_user: CurrentUser, db: DB
) -> IPAMTemplateResponse:
    row = IPAMTemplate(**body.model_dump())
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Template name {body.name!r} already exists.",
        ) from exc
    write_audit(
        db,
        user=current_user,
        action="create",
        resource_type="ipam_template",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return await _serialize(db, row)


@router.get("/{template_id}", response_model=IPAMTemplateResponse)
async def get_template(
    template_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> IPAMTemplateResponse:
    row = await db.get(IPAMTemplate, template_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    return await _serialize(db, row)


@router.put("/{template_id}", response_model=IPAMTemplateResponse)
async def update_template(
    template_id: uuid.UUID,
    body: IPAMTemplateUpdate,
    current_user: CurrentUser,
    db: DB,
) -> IPAMTemplateResponse:
    row = await db.get(IPAMTemplate, template_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    changes = body.model_dump(exclude_unset=True)
    clear_flags = {k: v for k, v in changes.items() if k.startswith("clear_") and v}
    direct_changes = {k: v for k, v in changes.items() if not k.startswith("clear_")}
    old_state = {
        "name": row.name,
        "description": row.description,
        "tags": dict(row.tags) if row.tags else {},
        "custom_fields": dict(row.custom_fields) if row.custom_fields else {},
        "dns_group_id": str(row.dns_group_id) if row.dns_group_id else None,
        "dns_zone_id": row.dns_zone_id,
        "dns_additional_zone_ids": list(row.dns_additional_zone_ids or []),
        "dhcp_group_id": str(row.dhcp_group_id) if row.dhcp_group_id else None,
        "ddns_enabled": row.ddns_enabled,
        "ddns_hostname_policy": row.ddns_hostname_policy,
        "ddns_domain_override": row.ddns_domain_override,
        "ddns_ttl": row.ddns_ttl,
        "child_layout": row.child_layout,
    }
    for k, v in direct_changes.items():
        setattr(row, k, v)
    if clear_flags.get("clear_dns_group_id"):
        row.dns_group_id = None
    if clear_flags.get("clear_dhcp_group_id"):
        row.dhcp_group_id = None
    if clear_flags.get("clear_dns_zone_id"):
        row.dns_zone_id = None
    if clear_flags.get("clear_dns_additional_zone_ids"):
        row.dns_additional_zone_ids = None
    if clear_flags.get("clear_child_layout"):
        row.child_layout = None
    if clear_flags.get("clear_ddns_domain_override"):
        row.ddns_domain_override = None
    if clear_flags.get("clear_ddns_ttl"):
        row.ddns_ttl = None
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Template name conflict.",
        ) from exc
    write_audit(
        db,
        user=current_user,
        action="update",
        resource_type="ipam_template",
        resource_id=str(row.id),
        resource_display=row.name,
        old_value=old_state,
        new_value=changes,
    )
    await db.commit()
    await db.refresh(row)
    return await _serialize(db, row)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(template_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    row = await db.get(IPAMTemplate, template_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
    write_audit(
        db,
        user=current_user,
        action="delete",
        resource_type="ipam_template",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.delete(row)
    await db.commit()
    return None


def _require_target_write(
    user: Any, resource_type: str, resource_id: uuid.UUID | None = None
) -> None:
    """403 unless ``user`` may write the block or subnet a template is stamped
    onto (#3058). The router gate asks only ``manage_ipam_templates``, which
    is the right to author templates, not to change the blocks and subnets
    they are applied to (nor to carve new subnets into a block)."""
    if not user_has_permission(user, "write", resource_type, resource_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: need 'write' on '{resource_type}'",
        )


@router.post("/{template_id}/apply", response_model=TemplateApplyResponse)
async def apply_template(
    template_id: uuid.UUID,
    body: TemplateApplyRequest,
    current_user: CurrentUser,
    db: DB,
) -> TemplateApplyResponse:
    template = await db.get(IPAMTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

    if body.block_id is not None:
        if template.applies_to != "block":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Template applies to {template.applies_to!r}, not 'block'.",
            )
        block = await db.get(IPBlock, body.block_id)
        if block is None or block.deleted_at is not None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Block not found")
        _require_target_write(current_user, "ip_block", block.id)
        if body.carve_children and template.child_layout is not None:
            _require_target_write(current_user, "subnet")
        try:
            written = apply_template_to_block(template, block, force=body.force)
        except TemplateError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        carved: list[dict[str, Any]] = []
        if body.carve_children and template.child_layout is not None:
            try:
                results = await carve_children(db, template, block)
            except TemplateError as exc:
                await db.rollback()
                raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
            carved = [{"cidr": r.cidr, "name": r.name, "skipped": r.skipped} for r in results]
        write_audit(
            db,
            user=current_user,
            action="apply",
            resource_type="ipam_template",
            resource_id=str(template.id),
            resource_display=template.name,
            new_value={
                "target_kind": "block",
                "target_id": str(block.id),
                "fields_written": written,
                "children_carved": carved,
                "force": body.force,
            },
        )
        await db.commit()
        return TemplateApplyResponse(
            template_id=template.id,
            target_kind="block",
            target_id=block.id,
            fields_written=written,
            children_carved=carved,
        )

    # subnet target
    if template.applies_to != "subnet":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Template applies to {template.applies_to!r}, not 'subnet'.",
        )
    subnet = await db.get(Subnet, body.subnet_id)
    if subnet is None or subnet.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subnet not found")
    _require_target_write(current_user, "subnet", subnet.id)
    try:
        written = apply_template_to_subnet(template, subnet, force=body.force)
    except TemplateError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    write_audit(
        db,
        user=current_user,
        action="apply",
        resource_type="ipam_template",
        resource_id=str(template.id),
        resource_display=template.name,
        new_value={
            "target_kind": "subnet",
            "target_id": str(subnet.id),
            "fields_written": written,
            "force": body.force,
        },
    )
    await db.commit()
    return TemplateApplyResponse(
        template_id=template.id,
        target_kind="subnet",
        target_id=subnet.id,
        fields_written=written,
    )


@router.post("/{template_id}/reapply-all", response_model=TemplateReapplyAllResponse)
async def reapply_all(
    template_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> TemplateReapplyAllResponse:
    """Stamp the template across every recorded instance with
    ``force=True``. Capped at 200 instances/call — for templates with
    a wider blast radius the operator should run multiple calls or
    fall back to per-row ``/apply``.
    """
    template = await db.get(IPAMTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

    # Every recorded instance is rewritten, so type-level write on the
    # instances' type (and on subnets, where the layout carves children).
    if template.applies_to == "block":
        _require_target_write(current_user, "ip_block")
        if template.child_layout is not None:
            _require_target_write(current_user, "subnet")
    else:
        _require_target_write(current_user, "subnet")

    processed = 0
    skipped = 0
    if template.applies_to == "block":
        block_instances = await find_block_instances(db, template.id)
        total = len(block_instances)
        cap_reached = total > _REAPPLY_CAP
        for block_target in block_instances[:_REAPPLY_CAP]:
            try:
                apply_template_to_block(template, block_target, force=True)
                if template.child_layout is not None:
                    await carve_children(db, template, block_target)
                processed += 1
            except TemplateError:
                skipped += 1
    else:
        subnet_instances = await find_subnet_instances(db, template.id)
        total = len(subnet_instances)
        cap_reached = total > _REAPPLY_CAP
        for subnet_target in subnet_instances[:_REAPPLY_CAP]:
            try:
                apply_template_to_subnet(template, subnet_target, force=True)
                processed += 1
            except TemplateError:
                skipped += 1
    write_audit(
        db,
        user=current_user,
        action="reapply_all",
        resource_type="ipam_template",
        resource_id=str(template.id),
        resource_display=template.name,
        new_value={
            "target_kind": template.applies_to,
            "instances_total": total,
            "instances_processed": processed,
            "instances_skipped": skipped,
            "cap_reached": cap_reached,
        },
    )
    await db.commit()
    return TemplateReapplyAllResponse(
        template_id=template.id,
        target_kind=template.applies_to,
        instances_total=total,
        instances_processed=processed,
        instances_skipped=skipped,
        cap_reached=cap_reached,
    )
