"""VoIP phone profile CRUD — group-scoped (issue #112 phase 1).

A phone profile bundles a vendor-class-id substring match + a curated
DHCP option set under a name that can be attached to one or more DHCP
scopes via the ``dhcp_phone_profile_scope`` join table. The Kea driver
emits one client-class per profile on the next bundle push.

Match-list semantics are simpler than PXE — a phone profile carries a
single ``vendor_class_match`` substring (option-60 prefix) plus the
option set. The starter-pack endpoint pre-populates the five most
common vendor recipes from the curated VoIP options catalog.

The starter pack is **opt-in**, not auto-seeded — operators who don't
need VoIP shouldn't see phantom profiles cluttering the UI.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.dns_names import contains_control_chars
from app.core.permissions import require_resource_permission
from app.models.dhcp import (
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPScope,
    DHCPServerGroup,
)
from app.services.dhcp.option_validation import validate_phone_options
from app.services.dhcp.voip_options import load_catalog as load_voip_catalog

router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_scope"))],
)


# ── Schemas ─────────────────────────────────────────────────────────────────


class PhoneOptionInput(BaseModel):
    """One DHCP option delivered when a phone profile match fires.

    ``code`` is the DHCP option-code (e.g. 66 for tftp-server-name) and
    decides what is delivered (#1294). ``name`` is a label; a canonical
    SpatiumDDI name that contradicts the code is refused. ``value`` is the
    Kea-format string: an address, a hostname or URL, or plain hex digits
    with no ``0x`` for a binary option such as 43.
    """

    code: int = Field(..., ge=1, le=254)
    name: str | None = None
    value: str = Field(..., max_length=2048)


class PhoneOptionResponse(BaseModel):
    code: int
    name: str | None = None
    value: str


def _check_vendor_match(v: str | None) -> str | None:
    """The match renders inside a Kea string literal (``=='<match>'``); a
    ``'`` ends the literal early and Kea rejects the WHOLE config (measured,
    kea-dhcp4 3.0.3). Control characters have no business in option 60."""
    if v is not None and ("'" in v or contains_control_chars(v)):
        raise ValueError("vendor_class_match may not contain ' or control characters")
    return v


class PhoneProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    enabled: bool = True
    vendor: str | None = Field(default=None, max_length=64)
    vendor_class_match: str | None = Field(default=None, max_length=255)
    option_set: list[PhoneOptionInput] = []
    tags: dict[str, Any] = {}

    _vendor_match = field_validator("vendor_class_match")(_check_vendor_match)
    # Optional: attach to scopes immediately on create. Each id must
    # belong to the same DHCPServerGroup as the profile.
    scope_ids: list[uuid.UUID] = []


class PhoneProfileUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    enabled: bool | None = None
    vendor: str | None = Field(None, max_length=64)
    vendor_class_match: str | None = Field(None, max_length=255)
    option_set: list[PhoneOptionInput] | None = None
    tags: dict[str, Any] | None = None

    _vendor_match = field_validator("vendor_class_match")(_check_vendor_match)


class PhoneProfileResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    description: str
    enabled: bool
    vendor: str | None
    vendor_class_match: str | None
    option_set: list[PhoneOptionResponse]
    tags: dict[str, Any]
    scope_ids: list[uuid.UUID]
    created_at: datetime
    modified_at: datetime


class PhoneProfileScopeAttach(BaseModel):
    scope_ids: list[uuid.UUID]


def _check_options(
    rows: list[dict], *, previous: Any = None, going_live: bool, enabled: bool = False
) -> None:
    """422 naming the first option Kea could not load (#1294). A profile being
    enabled gets the full check, placeholders included; any other edit checks
    only the options it changes, so a stored profile stays editable. A changed
    option on an enabled profile may not be a placeholder either."""
    try:
        validate_phone_options(rows, previous=previous, going_live=going_live, enabled=enabled)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _option_set_payload(rows: list[PhoneOptionInput]) -> list[dict]:
    return [r.model_dump() for r in rows]


def _to_option_response(rows: list[dict]) -> list[PhoneOptionResponse]:
    out: list[PhoneOptionResponse] = []
    for r in rows or []:
        try:
            out.append(
                PhoneOptionResponse(
                    code=int(r.get("code", 0)),
                    name=r.get("name"),
                    value=str(r.get("value", "")),
                )
            )
        except (TypeError, ValueError):
            continue
    return out


async def _scope_ids_for(db: DB, profile_id: uuid.UUID) -> list[uuid.UUID]:
    res = await db.execute(
        select(DHCPPhoneProfileScope.scope_id).where(DHCPPhoneProfileScope.profile_id == profile_id)
    )
    return [row[0] for row in res.all()]


async def _to_response(db: DB, p: DHCPPhoneProfile) -> PhoneProfileResponse:
    return PhoneProfileResponse(
        id=p.id,
        group_id=p.group_id,
        name=p.name,
        description=p.description,
        enabled=p.enabled,
        vendor=p.vendor,
        vendor_class_match=p.vendor_class_match,
        option_set=_to_option_response(list(p.option_set or [])),
        tags=dict(p.tags or {}),
        scope_ids=await _scope_ids_for(db, p.id),
        created_at=p.created_at,
        modified_at=p.modified_at,
    )


async def _validate_scope_ids(db: DB, group_id: uuid.UUID, scope_ids: list[uuid.UUID]) -> None:
    if not scope_ids:
        return
    # ``group_id``, not ``server_group_id`` — the latter is not a column on
    # DHCPScope, so every call with a non-empty ``scope_ids`` raised
    # AttributeError and answered 500 (#923). The validation this function
    # exists to perform therefore never ran: assigning a phone profile to any
    # scope at all was unreachable. mypy does not catch an unknown attribute
    # on a declarative model, which is why this survived review.
    res = await db.execute(
        select(DHCPScope.id).where(DHCPScope.id.in_(scope_ids), DHCPScope.group_id == group_id)
    )
    found = {row[0] for row in res.all()}
    missing = [str(s) for s in scope_ids if s not in found]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Scopes not found in this group: {', '.join(missing)}",
        )


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get(
    "/server-groups/{group_id}/phone-profiles",
    response_model=list[PhoneProfileResponse],
)
async def list_profiles(group_id: uuid.UUID, db: DB, _: CurrentUser) -> list[PhoneProfileResponse]:
    res = await db.execute(
        select(DHCPPhoneProfile)
        .where(DHCPPhoneProfile.group_id == group_id)
        .order_by(DHCPPhoneProfile.name)
    )
    profiles = list(res.scalars().all())
    return [await _to_response(db, p) for p in profiles]


@router.post(
    "/server-groups/{group_id}/phone-profiles",
    response_model=PhoneProfileResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_profile(
    group_id: uuid.UUID,
    body: PhoneProfileCreate,
    db: DB,
    user: SuperAdmin,
) -> PhoneProfileResponse:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")

    existing = await db.execute(
        select(DHCPPhoneProfile).where(
            DHCPPhoneProfile.group_id == group_id,
            DHCPPhoneProfile.name == body.name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A phone profile with that name exists")

    await _validate_scope_ids(db, group_id, body.scope_ids)
    _check_options(_option_set_payload(body.option_set), going_live=body.enabled)

    prof = DHCPPhoneProfile(
        group_id=group_id,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        vendor=body.vendor,
        vendor_class_match=body.vendor_class_match,
        option_set=_option_set_payload(body.option_set),
        tags=dict(body.tags or {}),
    )
    db.add(prof)
    await db.flush()

    for sid in body.scope_ids:
        db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=sid))
    await db.flush()

    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_phone_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
        new_value={
            "name": prof.name,
            "vendor": prof.vendor,
            "vendor_class_match": prof.vendor_class_match,
            "option_count": len(body.option_set),
            "scope_count": len(body.scope_ids),
        },
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    await db.refresh(prof)
    return await _to_response(db, prof)


@router.get("/phone-profiles/{profile_id}", response_model=PhoneProfileResponse)
async def get_profile(profile_id: uuid.UUID, db: DB, _: CurrentUser) -> PhoneProfileResponse:
    prof = await db.get(DHCPPhoneProfile, profile_id)
    if prof is None:
        raise HTTPException(status_code=404, detail="Phone profile not found")
    return await _to_response(db, prof)


@router.put("/phone-profiles/{profile_id}", response_model=PhoneProfileResponse)
async def update_profile(
    profile_id: uuid.UUID,
    body: PhoneProfileUpdate,
    db: DB,
    user: SuperAdmin,
) -> PhoneProfileResponse:
    prof = await db.get(DHCPPhoneProfile, profile_id)
    if prof is None:
        raise HTTPException(status_code=404, detail="Phone profile not found")

    payload = body.model_dump(exclude_none=True)
    if "name" in payload and payload["name"] != prof.name:
        clash = await db.execute(
            select(DHCPPhoneProfile).where(
                DHCPPhoneProfile.group_id == prof.group_id,
                DHCPPhoneProfile.name == payload["name"],
                DHCPPhoneProfile.id != prof.id,
            )
        )
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="A phone profile with that name exists")

    going_live = bool(payload.get("enabled")) and not prof.enabled
    if "option_set" in payload:
        payload["option_set"] = _option_set_payload(body.option_set or [])
        _check_options(
            payload["option_set"],
            previous=prof.option_set or [],
            going_live=going_live,
            enabled=bool(payload.get("enabled", prof.enabled)),
        )
    elif going_live:
        _check_options(prof.option_set or [], going_live=True)
    if "tags" in payload:
        payload["tags"] = dict(payload["tags"] or {})

    for k, v in payload.items():
        setattr(prof, k, v)

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_phone_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
        changed_fields=list(payload.keys()),
        new_value=body.model_dump(mode="json", exclude_none=True),
    )
    collect_wake(dhcp_group_channel(prof.group_id))
    await db.commit()
    await db.refresh(prof)
    return await _to_response(db, prof)


@router.delete("/phone-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(profile_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    prof = await db.get(DHCPPhoneProfile, profile_id)
    if prof is None:
        raise HTTPException(status_code=404, detail="Phone profile not found")

    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_phone_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
    )
    collect_wake(dhcp_group_channel(prof.group_id))
    await db.delete(prof)
    await db.commit()


@router.put(
    "/phone-profiles/{profile_id}/scopes",
    response_model=PhoneProfileResponse,
)
async def replace_scope_attachments(
    profile_id: uuid.UUID,
    body: PhoneProfileScopeAttach,
    db: DB,
    user: SuperAdmin,
) -> PhoneProfileResponse:
    """Replace the profile's scope attachments with the provided list.

    Atomic — passes through validation that every scope id belongs to
    the same group as the profile, then deletes existing rows and
    inserts the new set in one transaction.
    """
    prof = await db.get(DHCPPhoneProfile, profile_id)
    if prof is None:
        raise HTTPException(status_code=404, detail="Phone profile not found")

    await _validate_scope_ids(db, prof.group_id, body.scope_ids)

    await db.execute(
        delete(DHCPPhoneProfileScope).where(DHCPPhoneProfileScope.profile_id == profile_id)
    )
    for sid in body.scope_ids:
        db.add(DHCPPhoneProfileScope(profile_id=profile_id, scope_id=sid))

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_phone_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
        changed_fields=["scope_attachments"],
        new_value={"scope_count": len(body.scope_ids)},
    )
    collect_wake(dhcp_group_channel(prof.group_id))
    await db.commit()
    await db.refresh(prof)
    return await _to_response(db, prof)


# ── Starter pack ────────────────────────────────────────────────────────────


@router.post(
    "/server-groups/{group_id}/phone-profiles/seed-starter-pack",
    response_model=list[PhoneProfileResponse],
)
async def seed_starter_pack(
    group_id: uuid.UUID,
    db: DB,
    user: SuperAdmin,
) -> list[PhoneProfileResponse]:
    """Seed the curated 9-vendor starter pack into this group.

    Each entry is created **disabled** so operators can review the
    options + add their own provisioning-server values before the
    profile starts firing on the wire. Skips any vendor whose name
    already exists in the group (idempotent — safe to re-run).

    The provisioning-server values are placeholders (``CHANGE-ME``)
    that operators must override; the catalog populates the option
    *codes* + *names*, not the operator-supplied data.
    """
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")

    existing = await db.execute(
        select(DHCPPhoneProfile.name).where(DHCPPhoneProfile.group_id == group_id)
    )
    have_names = {row[0] for row in existing.all()}

    out: list[DHCPPhoneProfile] = []
    for vendor in load_voip_catalog():
        if vendor.vendor in have_names:
            continue
        prof = DHCPPhoneProfile(
            group_id=group_id,
            name=vendor.vendor,
            description=vendor.description,
            enabled=False,
            vendor=vendor.vendor,
            vendor_class_match=vendor.match_hint or None,
            option_set=[
                {"code": o.code, "name": o.name, "value": "CHANGE-ME"} for o in vendor.options
            ],
            tags={},
        )
        db.add(prof)
        out.append(prof)

    if out:
        await db.flush()
        write_audit(
            db,
            user=user,
            action="create",
            resource_type="dhcp_phone_profile",
            resource_id=str(group_id),
            resource_display=f"Starter pack for {grp.name}",
            new_value={"seeded_count": len(out)},
        )
        collect_wake(dhcp_group_channel(group_id))
        await db.commit()

    return [await _to_response(db, p) for p in out]
