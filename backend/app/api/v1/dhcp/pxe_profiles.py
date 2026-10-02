"""PXE / iPXE profile CRUD — group-scoped (issue #51).

A PXE profile bundles ``next_server`` + N arch-matches under a name
that can be bound to a DHCP scope via ``DHCPScope.pxe_profile_id``.
The Kea driver renders one client-class per (profile × arch-match)
pair on the next bundle push.

Match-list semantics: ``PUT /pxe-profiles/{id}`` REPLACES the
existing match list (mirrors how ``dhcp_pool`` / ``dhcp_static``
PUT semantics work — operators get an atomic replace, not a
partial patch). Saves a round-trip on rebuilds.

Standard vendor-class strings:
  * ``PXEClient``  — first-stage TFTP boot
  * ``iPXE``       — chained iPXE config GET
  * ``HTTPClient`` — UEFI HTTP boot

Standard arch-codes (DHCP option 93):
  0  BIOS / Legacy x86
  6  UEFI x86 (32-bit)
  7  UEFI x86-64
  9  UEFI x86-64
  10 ARM 32-bit UEFI
  11 ARM 64-bit UEFI
  15 HTTP boot UEFI
  16 HTTP boot UEFI x86-64
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.models.dhcp import (
    DHCPPXEArchMatch,
    DHCPPXEProfile,
    DHCPServerGroup,
)
from app.services.dhcp.option_validation import check_vendor_class_match

router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_scope"))],
)

_VALID_MATCH_KINDS = {"first_stage", "ipxe_chain"}


# ── Schemas ─────────────────────────────────────────────────────────────────


class ArchMatchInput(BaseModel):
    """Input shape for one arch-match. ``priority`` defaults to 100;
    operators raise / lower it to control evaluation order
    (lower = higher priority)."""

    priority: int = 100
    match_kind: str = "first_stage"
    vendor_class_match: str | None = Field(default=None, max_length=255)
    arch_codes: list[int] | None = None
    boot_filename: str = Field(..., min_length=1, max_length=512)
    boot_file_url_v6: str | None = None

    # #1357 — rendered inside Kea's ``=='<match>'`` literal, same as a phone
    # profile's (#1294): a ``'`` or a control character rejects the group's
    # whole config.
    _vendor_match = field_validator("vendor_class_match")(check_vendor_class_match)

    @field_validator("match_kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in _VALID_MATCH_KINDS:
            raise ValueError(f"match_kind must be one of {sorted(_VALID_MATCH_KINDS)}")
        return v

    @field_validator("arch_codes")
    @classmethod
    def _archs(cls, v: list[int] | None) -> list[int] | None:
        if v is None:
            return v
        # Option-93 values are 0..255 — anything outside that is a typo.
        for c in v:
            if c < 0 or c > 255:
                raise ValueError(f"arch code {c} out of range (0..255)")
        return v


class ArchMatchResponse(BaseModel):
    id: uuid.UUID
    profile_id: uuid.UUID
    priority: int
    match_kind: str
    vendor_class_match: str | None
    arch_codes: list[int] | None
    boot_filename: str
    boot_file_url_v6: str | None
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


class PXEProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    next_server: str = Field(..., min_length=1, max_length=45)
    enabled: bool = True
    tags: dict[str, Any] = {}
    matches: list[ArchMatchInput] = []


class PXEProfileUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    next_server: str | None = Field(None, min_length=1, max_length=45)
    enabled: bool | None = None
    tags: dict[str, Any] | None = None
    # When non-None, REPLACES the entire match list. Pass ``[]`` to
    # clear; omit the field to leave matches untouched.
    matches: list[ArchMatchInput] | None = None


class PXEProfileResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    description: str
    next_server: str
    enabled: bool
    tags: dict[str, Any]
    matches: list[ArchMatchResponse]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}


def _to_response(p: DHCPPXEProfile) -> PXEProfileResponse:
    return PXEProfileResponse(
        id=p.id,
        group_id=p.group_id,
        name=p.name,
        description=p.description,
        next_server=p.next_server,
        enabled=p.enabled,
        tags=dict(p.tags or {}),
        matches=[
            ArchMatchResponse(
                id=m.id,
                profile_id=m.profile_id,
                priority=m.priority,
                match_kind=m.match_kind,
                vendor_class_match=m.vendor_class_match,
                arch_codes=list(m.arch_codes or []) if m.arch_codes is not None else None,
                boot_filename=m.boot_filename,
                boot_file_url_v6=m.boot_file_url_v6,
                created_at=m.created_at,
                modified_at=m.modified_at,
            )
            for m in sorted(p.matches, key=lambda x: (x.priority, str(x.id)))
        ],
        created_at=p.created_at,
        modified_at=p.modified_at,
    )


def _replace_matches(p: DHCPPXEProfile, rows: list[ArchMatchInput]) -> None:
    """Drop existing matches and re-create from input. Cascade delete
    on the relationship handles the orphan rows."""
    p.matches.clear()
    for r in rows:
        p.matches.append(
            DHCPPXEArchMatch(
                priority=r.priority,
                match_kind=r.match_kind,
                vendor_class_match=r.vendor_class_match,
                arch_codes=r.arch_codes,
                boot_filename=r.boot_filename,
                boot_file_url_v6=r.boot_file_url_v6,
            )
        )


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get(
    "/server-groups/{group_id}/pxe-profiles",
    response_model=list[PXEProfileResponse],
)
async def list_profiles(group_id: uuid.UUID, db: DB, _: CurrentUser) -> list[PXEProfileResponse]:
    res = await db.execute(
        select(DHCPPXEProfile)
        .where(DHCPPXEProfile.group_id == group_id)
        .options(selectinload(DHCPPXEProfile.matches))
        .order_by(DHCPPXEProfile.name)
    )
    return [_to_response(p) for p in res.scalars().all()]


@router.post(
    "/server-groups/{group_id}/pxe-profiles",
    response_model=PXEProfileResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_profile(
    group_id: uuid.UUID,
    body: PXEProfileCreate,
    db: DB,
    user: SuperAdmin,
) -> PXEProfileResponse:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")

    existing = await db.execute(
        select(DHCPPXEProfile).where(
            DHCPPXEProfile.group_id == group_id,
            DHCPPXEProfile.name == body.name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A PXE profile with that name exists")

    # Construct the profile with its matches in one shot so SQLAlchemy
    # never lazy-loads ``matches`` on the just-added row (which would
    # try a sync DB read inside the async session and trip
    # MissingGreenlet).
    prof = DHCPPXEProfile(
        group_id=group_id,
        name=body.name,
        description=body.description,
        next_server=body.next_server,
        enabled=body.enabled,
        tags=dict(body.tags or {}),
        matches=[
            DHCPPXEArchMatch(
                priority=r.priority,
                match_kind=r.match_kind,
                vendor_class_match=r.vendor_class_match,
                arch_codes=r.arch_codes,
                boot_filename=r.boot_filename,
                boot_file_url_v6=r.boot_file_url_v6,
            )
            for r in body.matches
        ],
    )
    db.add(prof)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_pxe_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
        new_value={
            "name": prof.name,
            "next_server": prof.next_server,
            "enabled": prof.enabled,
            "match_count": len(body.matches),
        },
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    # Re-fetch with matches eager-loaded for response
    res = await db.execute(
        select(DHCPPXEProfile)
        .where(DHCPPXEProfile.id == prof.id)
        .options(selectinload(DHCPPXEProfile.matches))
    )
    refreshed = res.scalar_one()
    return _to_response(refreshed)


@router.get("/pxe-profiles/{profile_id}", response_model=PXEProfileResponse)
async def get_profile(profile_id: uuid.UUID, db: DB, _: CurrentUser) -> PXEProfileResponse:
    res = await db.execute(
        select(DHCPPXEProfile)
        .where(DHCPPXEProfile.id == profile_id)
        .options(selectinload(DHCPPXEProfile.matches))
    )
    prof = res.scalar_one_or_none()
    if prof is None:
        raise HTTPException(status_code=404, detail="PXE profile not found")
    return _to_response(prof)


@router.put("/pxe-profiles/{profile_id}", response_model=PXEProfileResponse)
async def update_profile(
    profile_id: uuid.UUID,
    body: PXEProfileUpdate,
    db: DB,
    user: SuperAdmin,
) -> PXEProfileResponse:
    res = await db.execute(
        select(DHCPPXEProfile)
        .where(DHCPPXEProfile.id == profile_id)
        .options(selectinload(DHCPPXEProfile.matches))
    )
    prof = res.scalar_one_or_none()
    if prof is None:
        raise HTTPException(status_code=404, detail="PXE profile not found")

    payload = body.model_dump(exclude_none=True)
    if "name" in payload and payload["name"] != prof.name:
        clash = await db.execute(
            select(DHCPPXEProfile).where(
                DHCPPXEProfile.group_id == prof.group_id,
                DHCPPXEProfile.name == payload["name"],
                DHCPPXEProfile.id != prof.id,
            )
        )
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="A PXE profile with that name exists")

    matches_input = body.matches  # may be None if not provided
    payload.pop("matches", None)
    if "tags" in payload:
        payload["tags"] = dict(payload["tags"] or {})

    for k, v in payload.items():
        setattr(prof, k, v)

    if matches_input is not None:
        _replace_matches(prof, matches_input)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_pxe_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
        changed_fields=list(payload.keys()) + (["matches"] if matches_input is not None else []),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    collect_wake(dhcp_group_channel(prof.group_id))
    await db.commit()
    res = await db.execute(
        select(DHCPPXEProfile)
        .where(DHCPPXEProfile.id == profile_id)
        .options(selectinload(DHCPPXEProfile.matches))
    )
    return _to_response(res.scalar_one())


@router.delete("/pxe-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(profile_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    prof = await db.get(DHCPPXEProfile, profile_id)
    if prof is None:
        raise HTTPException(status_code=404, detail="PXE profile not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_pxe_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
    )
    collect_wake(dhcp_group_channel(prof.group_id))
    await db.delete(prof)
    await db.commit()
