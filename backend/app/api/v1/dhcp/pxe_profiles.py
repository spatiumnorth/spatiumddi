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
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.core.update_nulls import changed_keys, snapshot
from app.models.dhcp import (
    DHCPPXEArchMatch,
    DHCPPXEProfile,
    DHCPServerGroup,
)
from app.services.dhcp.class_refs import (
    describe_pools,
    pools_restricted_to,
    pxe_pool_refs,
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

    # #3374 — the id of the stored rule this input edits. The Kea class name
    # embeds it, so an edit that names the row keeps the class a pool is bound
    # to even when its selector (vendor class / arch codes) changes. Omitted
    # (API callers, new rules): paired by content, then by selector.
    id: uuid.UUID | None = None
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


def _match_key(
    priority: int,
    match_kind: str,
    vendor_class_match: str | None,
    arch_codes: list[int] | None,
    boot_filename: str,
    boot_file_url_v6: str | None,
) -> tuple[Any, ...]:
    return (
        priority,
        match_kind,
        vendor_class_match,
        None if arch_codes is None else tuple(arch_codes),
        boot_filename,
        boot_file_url_v6,
    )


def _row_key(m: DHCPPXEArchMatch) -> tuple[Any, ...]:
    return _match_key(
        m.priority,
        m.match_kind,
        m.vendor_class_match,
        m.arch_codes,
        m.boot_filename,
        m.boot_file_url_v6,
    )


def _input_key(r: ArchMatchInput) -> tuple[Any, ...]:
    return _match_key(
        r.priority,
        r.match_kind,
        r.vendor_class_match,
        r.arch_codes,
        r.boot_filename,
        r.boot_file_url_v6,
    )


def _selector(key: tuple[Any, ...]) -> tuple[Any, ...]:
    """The part of a match key that says WHICH clients the rule selects
    (kind, vendor class, arch codes) — priority and boot files aside."""
    return key[1:4]


def _replace_matches(
    p: DHCPPXEProfile, rows: list[ArchMatchInput]
) -> tuple[bool, list[DHCPPXEArchMatch]]:
    """Reconcile the stored matches with the input; return ``(changed,
    removed)`` — whether anything differed (#3367) and the rows now deleted.

    An input row that carries an ``id`` edits that stored row in place, selector
    included (#3374): the Kea class name embeds the match id, so a rule whose
    arch codes or vendor class are edited keeps the class a pool's
    ``class_restriction`` names. An id that is not one of this profile's rules
    is a 422 (an id from another profile must never be adopted).

    Rows without an id (API callers, new rules) are paired as before: rows
    whose content is already stored are kept as they are, ids included — the
    class name embeds the id, so re-creating an identical row renamed its class,
    shifted the bundle ETag and pushed a config to every agent for a Save that
    changed nothing. A leftover is updated in place only onto a stored row that
    selects the same clients (same kind, vendor class and arch codes), so an
    edited priority or boot file keeps its class name; any other leftover is
    created anew, since reusing an id across selectors would silently move a
    pool onto a different set of clients. Stored rows nothing refers to are
    deleted.
    """
    existing = sorted(p.matches, key=lambda x: (x.priority, str(x.id)))
    by_id = {m.id: m for m in existing}
    seen_ids: set[uuid.UUID] = set()
    for r in rows:
        if r.id is None:
            continue
        if r.id not in by_id:
            raise HTTPException(
                status_code=422,
                detail=f"Boot rule {r.id} does not belong to this PXE profile",
            )
        if r.id in seen_ids:
            raise HTTPException(
                status_code=422, detail=f"Boot rule {r.id} is listed more than once"
            )
        seen_ids.add(r.id)

    changed = False
    free: list[DHCPPXEArchMatch] = [m for m in existing if m.id not in seen_ids]
    for r in rows:
        if r.id is None:
            continue
        m = by_id[r.id]
        if _row_key(m) != _input_key(r):
            changed = True
            m.priority = r.priority
            m.match_kind = r.match_kind
            m.vendor_class_match = r.vendor_class_match
            m.arch_codes = r.arch_codes
            m.boot_filename = r.boot_filename
            m.boot_file_url_v6 = r.boot_file_url_v6

    unmatched_rows: list[ArchMatchInput] = []
    for r in rows:
        if r.id is not None:
            continue
        k = _input_key(r)
        for m in free:
            if _row_key(m) == k:
                free.remove(m)
                break
        else:
            unmatched_rows.append(r)
    for r in unmatched_rows:
        changed = True
        sel = _selector(_input_key(r))
        for m in free:
            if _selector(_row_key(m)) == sel:
                free.remove(m)
                m.priority = r.priority
                m.boot_filename = r.boot_filename
                m.boot_file_url_v6 = r.boot_file_url_v6
                break
        else:
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
    for m in free:
        p.matches.remove(m)
    return changed or bool(free), list(free)


async def _refuse_if_pool_bound(
    db: AsyncSession, p: DHCPPXEProfile, removed: list[DHCPPXEArchMatch], verb: str
) -> None:
    """409 when a rule about to go has a generated class a pool's
    ``class_restriction`` still names (#3374) — Kea would accept the pool and
    never match it. Covers a Save that drops a rule and deleting the whole
    profile. Same refusal shape as deleting a client class (#2285)."""
    for m in removed:
        name = f"pxe-{str(p.id)[:8]}-{str(m.id)[:8]}"
        pools = await pools_restricted_to(db, p.group_id, name)
        if pools:
            detail = (
                f"Cannot {verb}: boot rule '{m.boot_filename}' generates class "
                f"'{name}', which is still referenced by {len(pools)} pool(s) "
                f"({describe_pools(pools)}). Kea accepts a reference to an undefined "
                "class and the pool would silently match no client. Clear or change "
                "those references first."
            )
            # Drop the in-session edits so a refused Save leaves nothing staged.
            await db.rollback()
            raise HTTPException(status_code=409, detail=detail)


async def refuse_if_pxe_pools_lose_class(
    db: AsyncSession,
    p: DHCPPXEProfile,
    verb: str,
    *,
    scope_id: uuid.UUID | None = None,
) -> None:
    """409 when disabling the profile, or unbinding it from ``scope_id``, would
    take a class away from a pool that names it (#3388). A PXE class reaches
    only the scopes bound to its profile (#2731), so those pools are the ones
    at stake: every bound scope's for a disable, ``scope_id``'s own for an
    unbind, however many other scopes stay bound. A profile already disabled
    renders nothing, so nothing is taken away."""
    if not p.enabled:
        return
    for name, pools in await pxe_pool_refs(db, p, scope_id=scope_id):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot {verb}: PXE profile '{p.name}' generates class '{name}', which is "
                f"still referenced by {len(pools)} pool(s) ({describe_pools(pools)}). Kea "
                "accepts a reference to an undefined class and the pool would silently "
                "match no client. Clear or change those references first."
            ),
        )


def _clients_selected(vendor_class_match: str | None, arch_codes: list[int] | None) -> Any:
    """Which clients a rule's rendered ``test`` matches
    (``_build_pxe_match_expression``): the vendor class and the SET of arch
    codes. ``match_kind`` and priority never reach the test."""
    return (vendor_class_match or None, frozenset(arch_codes or ()))


def _reject_duplicate_selectors(
    rows: list[ArchMatchInput], stored: list[DHCPPXEArchMatch] | None = None
) -> None:
    """422 on two rules selecting the same clients (#3388): Kea takes the boot
    fields from the first matching class, so the second rule never boots anything.
    Two rules differing only in ``match_kind`` or priority still collide.

    A duplicate the profile already ``stored`` (saved before this check) is
    let through rather than failing every later Save of it (#3367); adding a
    new one is not."""
    allowed: dict[Any, int] = {}
    for m in stored or ():
        sel = _clients_selected(m.vendor_class_match, m.arch_codes)
        allowed[sel] = allowed.get(sel, 0) + 1
    seen: dict[Any, int] = {}
    for r in rows:
        sel = _clients_selected(r.vendor_class_match, r.arch_codes)
        seen[sel] = seen.get(sel, 0) + 1
        if seen[sel] > max(1, allowed.get(sel, 0)):
            raise HTTPException(
                status_code=422,
                detail=(
                    "Two boot rules in this profile select the same clients "
                    "(same vendor class and architecture codes)"
                ),
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
    user: CurrentUser,
) -> PXEProfileResponse:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")

    existing = await db.execute(
        select(DHCPPXEProfile.id).where(
            DHCPPXEProfile.group_id == group_id,
            DHCPPXEProfile.name == body.name,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A PXE profile with that name exists")

    _reject_duplicate_selectors(body.matches)
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
    user: CurrentUser,
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
            select(DHCPPXEProfile.id).where(
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

    if payload.get("enabled") is False:
        await refuse_if_pxe_pools_lose_class(db, prof, f"disable PXE profile '{prof.name}'")
    if matches_input is not None:
        _reject_duplicate_selectors(matches_input, list(prof.matches))

    before = snapshot(prof, payload)
    for k, v in payload.items():
        setattr(prof, k, v)

    matches_changed = False
    if matches_input is not None:
        matches_changed, removed = _replace_matches(prof, matches_input)
        await _refuse_if_pool_bound(db, prof, removed, "remove that boot rule")

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_pxe_profile",
        resource_id=str(prof.id),
        resource_display=prof.name,
        changed_fields=changed_keys(before, payload) + (["matches"] if matches_changed else []),
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
async def delete_profile(profile_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    res = await db.execute(
        select(DHCPPXEProfile)
        .where(DHCPPXEProfile.id == profile_id)
        .options(selectinload(DHCPPXEProfile.matches))
    )
    prof = res.scalar_one_or_none()
    if prof is None:
        raise HTTPException(status_code=404, detail="PXE profile not found")
    # The rules go with the profile (cascade), and so do their classes.
    await _refuse_if_pool_bound(db, prof, list(prof.matches), f"delete PXE profile '{prof.name}'")
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
