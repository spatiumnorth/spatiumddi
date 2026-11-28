"""DHCP client class CRUD — group-centric."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, computed_field
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.api.v1.dhcp.scopes import validate_dhcp_options
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.permissions import require_resource_permission
from app.core.update_nulls import changed_keys, resolve_update_changes, snapshot
from app.drivers.dhcp.registry import get_driver
from app.models.dhcp import DHCPClientClass, DHCPPool, DHCPScope, DHCPServerGroup
from app.services.api_token_scopes import read_only_post
from app.services.dhcp.class_refs import (
    classes_testing_membership,
    describe_pools,
    pools_restricted_to,
    reserved_name_reason,
    trash_hint,
)
from app.services.dhcp.option_spelling import group_drivers
from app.services.dhcp.option_validation import normalize_options, validate_class_test
from app.services.dhcp.relay_match import RelayMatchSpecModel, spec_warnings

# Which Kea daemons the class renders into (#1229). ``dual`` sends each option
# to whichever family it is valid in (#1295).
ClassFamily = Literal["ipv4", "ipv6", "dual"]

router = APIRouter(
    tags=["dhcp"], dependencies=[Depends(require_resource_permission("dhcp_client_class"))]
)


class ClientClassCreate(BaseModel):
    name: str
    match_expression: str = ""
    # Structured option-82 match (#54). When set, ``match_expression`` is the
    # compiled test: omit it, or send exactly what ``compile-match`` returned.
    match_spec: RelayMatchSpecModel | None = None
    description: str = ""
    address_family: ClassFamily = "ipv4"
    options: dict[str, Any] = {}


class ClientClassUpdate(BaseModel):
    name: str | None = None
    match_expression: str | None = None
    # Explicit ``null`` converts a builder class to a hand-written one (#54).
    match_spec: RelayMatchSpecModel | None = None
    description: str | None = None
    address_family: ClassFamily | None = None
    options: dict[str, Any] | None = None


class CompileMatchRequest(BaseModel):
    match_spec: RelayMatchSpecModel


class CompileMatchWindows(BaseModel):
    supported: bool
    reason: str


class CompileMatchResponse(BaseModel):
    expression: str
    warnings: list[str]
    windows: CompileMatchWindows


class ClientClassResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    name: str
    match_expression: str
    match_spec: dict[str, Any] | None = None
    description: str
    address_family: ClassFamily
    options: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reserved_name(self) -> bool:
        """True for a row stored before #2296 whose name is now reserved.

        Such a row keeps rendering (refusing to would break an existing
        install's bundle); it is flagged so the operator can rename it.
        """
        return reserved_name_reason(self.name) is not None


def _check_name(name: str) -> None:
    reason = reserved_name_reason(name)
    if reason is not None:
        raise HTTPException(status_code=422, detail=f"Client class name is reserved: {reason}")


def _check_test(expression: str, family: str) -> None:
    try:
        validate_class_test(expression, family)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _compile_spec(db: DB, group_id: uuid.UUID, family: str, spec: RelayMatchSpecModel) -> str:
    """The Kea test for ``spec``, after the refusals that make it renderable (#54)."""
    if family != "ipv4":
        raise HTTPException(
            status_code=422,
            detail=(
                "an option 82 match is DHCPv4 only (relay4); set the class's address "
                "family to ipv4 or write the expression by hand"
            ),
        )
    drivers = await group_drivers(db, group_id)
    if drivers and "kea" not in drivers:
        raise HTTPException(
            status_code=422,
            detail=(
                "option 82 matching is rendered by Kea only; this group's servers are "
                f"{', '.join(sorted(drivers))}. Manage option 82 policies on the server itself."
            ),
        )
    return get_driver("kea").compile_relay_match(spec.to_def())


def _refuse_conflicting_expression(sent: str | None, compiled: str) -> None:
    if sent and sent != compiled:
        raise HTTPException(
            status_code=422,
            detail=(
                "this class is built from match_spec, which compiles to its match_expression; "
                "send one or the other. To write the expression by hand, send match_spec: null."
            ),
        )


def class_families(family: str) -> set[str]:
    return {"ipv4", "ipv6"} if family == "dual" else {family}


async def _refuse_orphaned_pools(db: DB, cc: DHCPClientClass, family: str) -> None:
    """Refuse a family change that would leave a pool restricted to a class
    its daemon no longer defines (#1229). Kea accepts the reference, so
    nothing would fail: the pool would simply stop matching anyone."""
    dropped = class_families(cc.address_family) - class_families(family)
    if not dropped:
        return
    rows = (
        await db.execute(
            select(DHCPPool.start_ip, DHCPPool.end_ip, DHCPScope.address_family)
            .join(DHCPScope, DHCPPool.scope_id == DHCPScope.id)
            .where(
                DHCPScope.group_id == cc.group_id,
                DHCPScope.address_family.in_(dropped),
                DHCPPool.class_restriction == cc.name,
            )
        )
    ).all()
    if rows:
        pools = ", ".join(f"{r.start_ip}-{r.end_ip}" for r in rows[:5])
        more = f" and {len(rows) - 5} more" if len(rows) > 5 else ""
        raise HTTPException(
            status_code=409,
            detail=(
                f"Client class '{cc.name}' restricts {len(rows)} pool(s) in "
                f"{'/'.join(sorted(dropped))} scopes ({pools}{more}); after this "
                "change their daemon would not define the class and those pools "
                "would match no client. Clear or change the pools' class first."
            ),
        )


async def refuse_if_name_referenced(
    db: DB, group_id: uuid.UUID, name: str, verb: str, *, exclude_class_id: uuid.UUID | None = None
) -> None:
    """409 while a pool (or another class's ``member()`` test) still names ``name`` (#2285).

    Refuse rather than cascade the rename: a pool's ``class_restriction`` is
    an operator decision (often a quarantine boundary), and silently
    rewriting it, or leaving it dangling, changes who a pool serves. Same
    posture as the DNS ACL reference guard and the family-change guard above.
    """
    pools = await pools_restricted_to(db, group_id, name, include_trashed=True)
    members = await classes_testing_membership(db, group_id, name, exclude_class_id)
    if not pools and not members:
        return
    parts = []
    if pools:
        parts.append(f"{len(pools)} pool(s) ({describe_pools(pools)})")
    if members:
        parts.append(f"the test of client class(es) {', '.join(members[:5])}")
    raise HTTPException(
        status_code=409,
        detail=(
            f"Cannot {verb} '{name}': it is still referenced by {' and '.join(parts)}. "
            "Kea accepts a reference to an undefined class and the pool would "
            "silently match no client. Clear or change those references first." + trash_hint(pools)
        ),
    )


@router.post("/client-classes/compile-match", response_model=CompileMatchResponse)
@read_only_post
async def compile_match(body: CompileMatchRequest) -> CompileMatchResponse:
    """Compile an option-82 ``match_spec`` to the Kea test, writing nothing (#54).

    The UI previews with this so the compiler lives in one place. ``windows``
    says whether Windows DHCP could express the same match; it is not
    rendered there in this release.
    """
    spec = body.match_spec.to_def()
    ok, reason = get_driver("windows_dhcp").relay_match_support(spec)
    return CompileMatchResponse(
        expression=get_driver("kea").compile_relay_match(spec),
        warnings=spec_warnings(body.match_spec),
        windows=CompileMatchWindows(supported=ok, reason=reason),
    )


@router.get("/server-groups/{group_id}/client-classes", response_model=list[ClientClassResponse])
async def list_classes(group_id: uuid.UUID, db: DB, _: CurrentUser) -> list[DHCPClientClass]:
    res = await db.execute(select(DHCPClientClass).where(DHCPClientClass.group_id == group_id))
    return list(res.scalars().all())


async def validate_new_class(db: DB, group_id: uuid.UUID, body: ClientClassCreate) -> None:
    """Every refusal of a create, no write. Fills in the compiled test and the
    normalised options on ``body``. Shared with the copilot's
    ``create_dhcp_client_class`` operation so the two cannot drift."""
    _check_name(body.name)
    existing = await db.execute(
        select(DHCPClientClass).where(
            DHCPClientClass.group_id == group_id, DHCPClientClass.name == body.name
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A client class with that name exists")
    if body.match_spec is not None:
        compiled = await _compile_spec(db, group_id, body.address_family, body.match_spec)
        _refuse_conflicting_expression(body.match_expression, compiled)
        body.match_expression = compiled
    _check_test(body.match_expression, body.address_family)
    body.options = normalize_options(body.options)
    # A client class is rendered by Kea / FortiGate only: the Kea raw-code rule (#1296).
    await validate_dhcp_options(db, body.options, group_id=None, address_family=body.address_family)


@router.post(
    "/server-groups/{group_id}/client-classes",
    response_model=ClientClassResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_class(
    group_id: uuid.UUID, body: ClientClassCreate, db: DB, user: CurrentUser
) -> DHCPClientClass:
    grp = await db.get(DHCPServerGroup, group_id)
    if grp is None:
        raise HTTPException(status_code=404, detail="DHCP server group not found")
    await validate_new_class(db, group_id, body)
    spec = body.match_spec.stored() if body.match_spec is not None else None
    cc = DHCPClientClass(
        group_id=group_id, **body.model_dump(exclude={"match_spec"}), match_spec=spec
    )
    db.add(cc)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
        new_value={**body.model_dump(mode="json", exclude={"match_spec"}), "match_spec": spec},
    )
    collect_wake(dhcp_group_channel(group_id))
    await db.commit()
    await db.refresh(cc)
    return cc


@router.put("/client-classes/{class_id}", response_model=ClientClassResponse)
async def update_class(
    class_id: uuid.UUID, body: ClientClassUpdate, db: DB, user: CurrentUser
) -> DHCPClientClass:
    cc = await db.get(DHCPClientClass, class_id)
    if cc is None:
        raise HTTPException(status_code=404, detail="Client class not found")
    # ``match_spec`` is resolved below: an explicit null is meaningful for it only.
    changes = resolve_update_changes(body, exclude={"match_spec"})
    spec_sent = "match_spec" in body.model_fields_set
    family = changes.get("address_family", cc.address_family)
    family_changed = family != cc.address_family
    new_name = changes.get("name")
    if new_name is not None and new_name != cc.name:
        # Only a RENAME is checked: a row already stored with a reserved name
        # keeps saving its other fields (#2296).
        _check_name(new_name)
        dupe = await db.execute(
            select(DHCPClientClass.id).where(
                DHCPClientClass.group_id == cc.group_id, DHCPClientClass.name == new_name
            )
        )
        if dupe.first() is not None:
            raise HTTPException(status_code=409, detail="A client class with that name exists")
        await refuse_if_name_referenced(
            db, cc.group_id, cc.name, "rename client class", exclude_class_id=cc.id
        )
    if family_changed:
        await _refuse_orphaned_pools(db, cc, family)
    if spec_sent and body.match_spec is not None:
        compiled = await _compile_spec(db, cc.group_id, family, body.match_spec)
        _refuse_conflicting_expression(changes.get("match_expression"), compiled)
        changes["match_expression"] = compiled
        changes["match_spec"] = body.match_spec.stored()
    elif spec_sent:
        changes["match_spec"] = None  # converts to a hand-written class
    elif cc.match_spec is not None:
        if "match_expression" in changes and changes["match_expression"] != cc.match_expression:
            raise HTTPException(
                status_code=422,
                detail=(
                    "this class is built from match_spec; send a new match_spec, or "
                    "match_spec: null to convert it to a hand-written expression"
                ),
            )
        if family != "ipv4":
            raise HTTPException(
                status_code=422,
                detail=(
                    "this class is built from an option 82 match_spec, which is DHCPv4 "
                    "only; send match_spec: null to write the expression by hand first"
                ),
            )
    if family_changed or "match_expression" in changes:
        _check_test(changes.get("match_expression", cc.match_expression), family)
    if "options" in changes or family_changed:
        # Validate only changed options (#597, #1228) vs the stored value —
        # unless the family changed, which makes every option new to it.
        options = (
            normalize_options(changes["options"]) if "options" in changes else cc.options or {}
        )
        await validate_dhcp_options(
            db,
            options,
            group_id=None,  # rendered by Kea / FortiGate only (#1296)
            address_family=family,
            previous=None if family_changed else cc.options or {},
        )
        if "options" in changes:
            changes["options"] = options
    before = snapshot(cc, changes)
    for k, v in changes.items():
        setattr(cc, k, v)
    write_audit(
        db,
        user=user,
        action="update",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
        changed_fields=changed_keys(before, changes),
        new_value={
            **body.model_dump(mode="json", exclude_none=True, exclude={"match_spec"}),
            **{k: changes[k] for k in ("match_spec", "match_expression") if k in changes},
        },
    )
    collect_wake(dhcp_group_channel(cc.group_id))
    await db.commit()
    await db.refresh(cc)
    return cc


@router.delete("/client-classes/{class_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_class(class_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    cc = await db.get(DHCPClientClass, class_id)
    if cc is None:
        raise HTTPException(status_code=404, detail="Client class not found")
    await refuse_if_name_referenced(
        db, cc.group_id, cc.name, "delete client class", exclude_class_id=cc.id
    )
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="dhcp_client_class",
        resource_id=str(cc.id),
        resource_display=cc.name,
    )
    collect_wake(dhcp_group_channel(cc.group_id))
    await db.delete(cc)
    await db.commit()
