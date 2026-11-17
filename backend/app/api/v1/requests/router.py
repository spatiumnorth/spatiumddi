"""Self-service request portal API (issue #696).

The #62 approval engine as a *brake* gates risky deletes. This router is the
same machinery pointed the other way: a low-privilege user asks for something
they cannot do themselves, an approver reviews it with the operation's own
preview in front of them, and approving **executes the provisioning**.

* ``GET  /catalog`` — what may be asked for (the allow-list + arg schemas).
* ``GET  /resource-options`` — permission-filtered typeahead options for the
  ``x-resource`` reference fields in those schemas (#759). No matching MCP
  tool on purpose: the Copilot already has the full ``find_*`` read tools for
  these resources — this endpoint exists only to narrow them to the caller's
  read grants for the portal form (explicit NN #13 decision).
* ``POST /`` — submit a request. Needs ``create,provisioning_request``; does
  **not** need the underlying operation's permission, which is the entire
  point (see ``services/requests/service.py``).
* ``GET  /`` list, ``GET /{id}`` — the queue. Same read rule as #62: a caller
  who cannot approve sees only their own rows, and an unreadable id 404s
  rather than 403s so existence is not confirmed.
* ``POST /{id}/approve|reject|cancel`` — thin delegations to the **shared**
  ``services.approvals.service`` spine. Every server-side invariant lives
  there: FOR UPDATE + pending guard, fail-closed on a deleted requester,
  self-approval block, approver holds ``{approve, change_request}`` AND the
  operation's ``required_permission``, re-preview stale guard, ``apply()``
  under the approver's identity, audit rows on every transition.

There is deliberately no second state machine here (#696), and no provisioning
code — the catalog maps each kind onto an ``Operation`` that already calls the
same service-layer functions the REST handlers do.

Gated behind the ``governance.requests`` feature module (NN #14) on the
include in ``api/v1/router.py``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import String, or_, select
from sqlalchemy import cast as sa_cast
from sqlalchemy.sql import Select

from app.api.deps import DB, CurrentUser
from app.core.permissions import (
    RESOURCE_TYPE_CHANGE_REQUEST,
    RESOURCE_TYPE_PROVISIONING_REQUEST,
    is_effective_superadmin,
    user_has_permission,
)
from app.models.auth import User
from app.models.change_request import ChangeRequest
from app.models.dhcp import DHCPScope
from app.models.dns import DNSView, DNSZone
from app.models.ipam import IPAMTemplate, IPBlock, Subnet
from app.services.api_token_scopes import enforce_operation_token_scope
from app.services.approvals.service import (
    ChangeRequestStateError,
    DecisionError,
    _refusal_text,
    approve_change_request,
    count_change_requests,
    get_change_request,
    list_change_requests,
    mark_cancelled,
    reject_change_request,
)
from app.services.requests.catalog import all_kinds, resolve_operation
from app.services.requests.service import MAX_JUSTIFICATION_CHARS, submit_request

router = APIRouter()

_ORIGIN = "portal"


# ── Schemas ────────────────────────────────────────────────────────────────


class RequestKindResponse(BaseModel):
    kind: str
    label: str
    description: str
    category: str
    operation: str
    # JSON Schema of the operation's args model, so the form can be rendered
    # (and validated client-side) from the same source the server validates
    # against — there is no second schema to drift.
    args_schema: dict[str, Any]


class SubmitRequestBody(BaseModel):
    kind: str = Field(..., description="Catalog kind id, e.g. 'dns_record'")
    args: dict[str, Any] = Field(default_factory=dict)
    # No ``max_length`` here on purpose — the bound is enforced in
    # ``submit_request`` so every caller hits the same rule and gets the same
    # readable 400 rather than a schema 422 from one path and a 400 from
    # another. MAX_JUSTIFICATION_CHARS is still referenced in the description
    # so the OpenAPI schema documents the limit.
    justification: str | None = Field(
        default=None,
        description=(
            "Why the requester needs this; shown to the approver. "
            f"Max {MAX_JUSTIFICATION_CHARS} characters."
        ),
    )


class DecisionBody(BaseModel):
    decision_note: str | None = Field(default=None, max_length=2000)


class ProvisioningRequestResponse(BaseModel):
    id: uuid.UUID
    operation: str
    resource_type: str
    resource_display: str
    args: dict[str, Any]
    preview_text: str
    justification: str | None
    state: str
    requested_by_user_id: uuid.UUID | None
    requested_by_display: str
    decided_by_user_id: uuid.UUID | None
    decided_by_display: str | None
    decision_note: str | None
    result: dict[str, Any] | None
    error: str | None
    expires_at: datetime
    decided_at: datetime | None
    executed_at: datetime | None
    created_at: datetime
    modified_at: datetime
    # Name of the IPAM template ``args.template_id`` names (#3649). Resolved
    # server-side so a viewer without read on IPAM templates (the built-in
    # Requester and Change Approver) still sees which template approval will
    # stamp. Only the name is exposed, never the template body. None when the
    # request names no template or it no longer exists.
    template_name: str | None = None


def _template_id(cr: ChangeRequest) -> uuid.UUID | None:
    raw = (cr.args or {}).get("template_id")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


async def _template_names(db: DB, rows: list[ChangeRequest]) -> dict[uuid.UUID, str]:
    ids = {tid for r in rows if (tid := _template_id(r)) is not None}
    if not ids:
        return {}
    res = await db.execute(
        select(IPAMTemplate.id, IPAMTemplate.name).where(IPAMTemplate.id.in_(ids))
    )
    return {row[0]: row[1] for row in res.all()}


async def _respond_all(db: DB, rows: list[ChangeRequest]) -> list[ProvisioningRequestResponse]:
    names = await _template_names(db, rows)
    return [_to_response(r, names.get(tid) if (tid := _template_id(r)) else None) for r in rows]


async def _respond(db: DB, cr: ChangeRequest) -> ProvisioningRequestResponse:
    return (await _respond_all(db, [cr]))[0]


def _to_response(
    cr: ChangeRequest, template_name: str | None = None
) -> ProvisioningRequestResponse:
    return ProvisioningRequestResponse(
        id=cr.id,
        operation=cr.operation,
        resource_type=cr.resource_type,
        resource_display=cr.resource_display,
        args=cr.args or {},
        preview_text=cr.preview_text,
        justification=cr.justification,
        state=cr.state,
        requested_by_user_id=cr.requested_by_user_id,
        requested_by_display=cr.requested_by_display,
        decided_by_user_id=cr.decided_by_user_id,
        decided_by_display=cr.decided_by_display,
        decision_note=cr.decision_note,
        result=cr.result,
        error=cr.error,
        expires_at=cr.expires_at,
        decided_at=cr.decided_at,
        executed_at=cr.executed_at,
        created_at=cr.created_at,
        modified_at=cr.modified_at,
        template_name=template_name,
    )


# ── Authorization helpers ──────────────────────────────────────────────────


def _require_submit(user: User) -> None:
    if is_effective_superadmin(user):
        return
    if not user_has_permission(user, "write", RESOURCE_TYPE_PROVISIONING_REQUEST):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(f"Permission denied: need 'write' on '{RESOURCE_TYPE_PROVISIONING_REQUEST}'"),
        )


def _require_read(user: User) -> None:
    """Reading the portal needs ``read,provisioning_request`` — or the ability
    to decide requests, since an approver must be able to see the queue."""
    if is_effective_superadmin(user):
        return
    if user_has_permission(user, "read", RESOURCE_TYPE_PROVISIONING_REQUEST):
        return
    if user_has_permission(user, "approve", RESOURCE_TYPE_CHANGE_REQUEST):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=("Permission denied: need 'read' on " f"'{RESOURCE_TYPE_PROVISIONING_REQUEST}'"),
    )


def _can_see_all(user: User) -> bool:
    """Who sees the whole portal queue rather than only their own rows.

    Mirrors #62's read rule exactly: a request row leaks the frozen args, the
    preview, the requester and the approver, so only an effective superadmin
    or a holder of ``{approve, change_request}`` — someone who needs the queue
    to do their job — sees everyone's. A plain requester sees their own.
    """
    return is_effective_superadmin(user) or user_has_permission(
        user, "approve", RESOURCE_TYPE_CHANGE_REQUEST
    )


async def _load_visible(
    db: DB, req_id: uuid.UUID, user: User, *, for_update: bool = False
) -> ChangeRequest:
    """Fetch a portal row the caller is allowed to see, or 404.

    404 (not 403) on an invisible row so a caller cannot probe which request
    ids exist. Also 404s a gate row: the two queues are disjoint, and a portal
    endpoint must not be a side door into #62's surface.
    """
    cr = await get_change_request(db, req_id, for_update=for_update)
    if (
        cr is None
        or cr.origin != _ORIGIN
        or (not _can_see_all(user) and cr.requested_by_user_id != user.id)
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return cr


# ── Resource picker (issue #759) ───────────────────────────────────────────
#
# Typeahead options for the resource-reference fields (``x-resource`` in the
# catalog arg schemas). The submit path deliberately does not require the
# underlying operation's permission, so a picker naively backed by the admin
# list endpoints would hand a Requester the complete estate inventory —
# resources they hold no read grant for, from the one screen designed for
# people without grants. Every candidate row is therefore individually
# filtered through ``user_has_permission(read, <type>, <id>)``; the
# ``x-resource`` value IS the RBAC resource_type, so there is one vocabulary
# and no mapping table to drift. This is the issue's primary acceptance
# criterion, not an optimization.

_PICKER_PAGE = 200  # rows fetched per scan page
_PICKER_SCAN_CAP = 2000  # bound the per-request work for narrow grants
_PICKER_MAX = 50


class ResourceOption(BaseModel):
    id: str
    label: str
    sublabel: str | None = None


class ResourceOptionsResponse(BaseModel):
    options: list[ResourceOption]
    # True when more readable rows match than ``options`` holds (one more was
    # found past ``limit``) or the permission scan hit its cap before filling
    # ``limit`` — the UI should say "keep typing to narrow", not "no matches".
    truncated: bool


def _like(q: str) -> str:
    """``%<q>%`` with ILIKE metacharacters escaped so the user searches
    literally — ``_``-led zone names are routine in AD estates."""
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _subnet_query(q: str) -> Select:
    # The id tiebreaker matters: none of these sort keys are unique (the same
    # CIDR is legal in two IP spaces), and the scan re-executes the query per
    # page — without a total order, a readable row straddling a page boundary
    # can be skipped or duplicated between executions.
    stmt = select(Subnet).order_by(Subnet.network, Subnet.id)
    if q:
        like = _like(q)
        stmt = stmt.where(or_(Subnet.name.ilike(like), sa_cast(Subnet.network, String).ilike(like)))
    return stmt


def _subnet_option(row: object) -> ResourceOption:
    sub = row[0]  # type: ignore[index]
    return ResourceOption(id=str(sub.id), label=str(sub.network), sublabel=sub.name or None)


def _block_query(q: str) -> Select:
    stmt = select(IPBlock).order_by(IPBlock.network, IPBlock.id)
    if q:
        like = _like(q)
        stmt = stmt.where(
            or_(IPBlock.name.ilike(like), sa_cast(IPBlock.network, String).ilike(like))
        )
    return stmt


def _block_option(row: object) -> ResourceOption:
    blk = row[0]  # type: ignore[index]
    return ResourceOption(id=str(blk.id), label=str(blk.network), sublabel=blk.name or None)


def _zone_query(q: str) -> Select:
    # Primary zones only — records can only be created in zones the control
    # plane authors; offering a secondary/forward zone would produce a request
    # whose approval can only fail.
    # The same zone name legitimately exists per view (split-horizon), so
    # join the view for a disambiguating sublabel and tiebreak on id.
    stmt = (
        select(DNSZone, DNSView.name)
        .outerjoin(DNSView, DNSView.id == DNSZone.view_id)
        .where(DNSZone.zone_type == "primary")
        .order_by(DNSZone.name, DNSZone.id)
    )
    if q:
        stmt = stmt.where(DNSZone.name.ilike(_like(q)))
    return stmt


def _zone_option(row: object) -> ResourceOption:
    zone = row[0]  # type: ignore[index]
    view_name = row[1]  # type: ignore[index]
    parts = [p for p in (view_name, "reverse" if zone.kind == "reverse" else None) if p]
    return ResourceOption(
        id=str(zone.id),
        label=zone.name,
        sublabel=" · ".join(parts) or None,
    )


def _scope_query(q: str) -> Select:
    # Active scopes only — a reservation in a deactivated scope would never
    # serve. The subnet join supplies the range for the label.
    stmt = (
        select(DHCPScope, Subnet.network)
        .join(Subnet, Subnet.id == DHCPScope.subnet_id)
        .where(DHCPScope.is_active.is_(True))
        .order_by(Subnet.network, DHCPScope.id)
    )
    if q:
        like = _like(q)
        stmt = stmt.where(
            or_(DHCPScope.name.ilike(like), sa_cast(Subnet.network, String).ilike(like))
        )
    return stmt


def _scope_option(row: Any) -> ResourceOption:
    scope: DHCPScope = row[0]
    network = row[1]
    return ResourceOption(
        id=str(scope.id),
        label=scope.name or str(network),
        sublabel=str(network) if scope.name else None,
    )


# resource → (query builder, RBAC resource_type, row → option). The key is the
# exact ``x-resource`` value the arg schemas carry.
_RESOURCE_PICKERS: dict[str, tuple] = {
    "subnet": (_subnet_query, "subnet", _subnet_option),
    "ip_block": (_block_query, "ip_block", _block_option),
    "dns_zone": (_zone_query, "dns_zone", _zone_option),
    "dhcp_scope": (_scope_query, "dhcp_scope", _scope_option),
}


@router.get("/resource-options", response_model=ResourceOptionsResponse)
async def resource_options(
    db: DB,
    current_user: CurrentUser,
    resource: str,
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=20, ge=1, le=_PICKER_MAX),
) -> ResourceOptionsResponse:
    """Permission-filtered typeahead options for one ``x-resource`` field.

    Requires submit permission (like ``/catalog`` — the picker exists to fill
    the request form), and returns only rows the caller holds a ``read`` grant
    for. Scans candidates in pages so a caller with narrow per-resource grants
    still fills their ``limit`` when the first page happens to contain none of
    their rows; the scan is capped so a huge estate can't turn one keystroke
    into a full-table permission sweep.
    """
    _require_submit(current_user)
    picker = _RESOURCE_PICKERS.get(resource)
    if picker is None:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown resource {resource!r} — expected one of "
            f"{sorted(_RESOURCE_PICKERS)}",
        )
    query_fn, rtype, to_option = picker
    out: list[ResourceOption] = []
    offset = 0
    exhausted = False
    # Collect ONE past ``limit``: a readable match beyond the page is the only
    # proof the list is cut (#3938).
    while len(out) <= limit and offset < _PICKER_SCAN_CAP:
        rows = (await db.execute(query_fn(q).offset(offset).limit(_PICKER_PAGE))).all()
        if not rows:
            exhausted = True
            break
        offset += len(rows)
        for row in rows:
            rid = row[0].id
            if not user_has_permission(current_user, "read", rtype, rid):
                continue
            out.append(to_option(row))
            if len(out) > limit:
                break
        if len(rows) < _PICKER_PAGE:
            exhausted = True
            break
    # ``truncated`` = the caller's readable rows may exist beyond what is
    # returned: a further readable match was found past ``limit``, or the scan
    # cap was hit first. The UI shows "keep typing to narrow" instead of a
    # dead-end "no matches" or a list that reads as complete.
    more = len(out) > limit
    out = out[:limit]
    return ResourceOptionsResponse(
        options=out, truncated=more or (not exhausted and len(out) < limit)
    )


# ── Catalog ────────────────────────────────────────────────────────────────


@router.get("/catalog", response_model=list[RequestKindResponse])
async def get_catalog(current_user: CurrentUser) -> list[RequestKindResponse]:
    """What this caller may ask for, with the arg schema for each kind.

    Requires submit permission rather than read: the catalog exists to drive
    the request form, and a caller who cannot submit has no use for it.
    """
    _require_submit(current_user)
    out: list[RequestKindResponse] = []
    for entry in all_kinds():
        resolved = resolve_operation(entry.kind)
        if resolved is None:
            # Catalog entry naming an unregistered operation — skip it rather
            # than 500 the whole form over one bad entry.
            continue
        _, op = resolved
        out.append(
            RequestKindResponse(
                kind=entry.kind,
                label=entry.label,
                description=entry.description,
                category=entry.category,
                operation=op.name,
                args_schema=op.args_model.model_json_schema(),
            )
        )
    return out


# ── Queue ──────────────────────────────────────────────────────────────────


@router.get("", response_model=list[ProvisioningRequestResponse])
async def list_requests(
    current_user: CurrentUser,
    db: DB,
    response: Response,
    state: str | None = None,
    mine: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> list[ProvisioningRequestResponse]:
    """List self-service requests, newest first.

    A caller who cannot approve is ALWAYS scoped to their own rows regardless
    of ``mine`` — same rule as #62's queue. Still a bare list, but ``offset``
    pages past ``limit`` and ``X-Total-Count`` carries the number of requests
    matching the filters *before* the window, so a client can say "100 of 101"
    instead of presenting a cut list as the whole queue (#3937).
    """
    _require_read(current_user)
    if _can_see_all(current_user):
        scope_user_id = current_user.id if mine else None
    else:
        scope_user_id = current_user.id
    response.headers["X-Total-Count"] = str(
        await count_change_requests(
            db, state=state, requested_by_user_id=scope_user_id, origin=_ORIGIN
        )
    )
    rows = await list_change_requests(
        db,
        state=state,
        requested_by_user_id=scope_user_id,
        origin=_ORIGIN,
        limit=max(1, min(limit, 500)),
        offset=max(0, offset),
    )
    return await _respond_all(db, list(rows))


@router.post("", response_model=ProvisioningRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_request(
    body: SubmitRequestBody,
    current_user: CurrentUser,
    db: DB,
    request: Request,
) -> ProvisioningRequestResponse:
    """Submit a request. Provisions nothing — it queues a pending row that a
    *different*, suitably-permissioned approver must accept."""
    _require_submit(current_user)
    resolved = resolve_operation(body.kind)
    if resolved is not None:  # an unknown kind is submit_request's 400
        enforce_operation_token_scope(request, resolved[1].name)  # #3302
    cr = await submit_request(
        db,
        user=current_user,
        request=request,
        kind=body.kind,
        args=body.args,
        justification=body.justification,
    )
    await db.commit()
    await db.refresh(cr)
    return await _respond(db, cr)


@router.get("/{req_id}", response_model=ProvisioningRequestResponse)
async def get_request(
    req_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ProvisioningRequestResponse:
    _require_read(current_user)
    return await _respond(db, await _load_visible(db, req_id, current_user))


class CurrentPreviewResponse(BaseModel):
    """What approving the request would do if pressed now (#3934)."""

    # The preview re-run against the estate as it is now.
    preview_text: str
    # False when the operation can no longer be applied as submitted; ``detail``
    # then says why. Pressing Approve would end the request ``failed``.
    ok: bool
    detail: str | None = None
    # True when ``preview_text`` differs from the one stored at submit.
    changed: bool


@router.get("/{req_id}/current-preview", response_model=CurrentPreviewResponse)
async def get_current_preview(
    req_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> CurrentPreviewResponse:
    """Re-run the operation's preview now, as the caller.

    The stored ``preview_text`` was composed at submit; the approval runs
    against the estate as it is at the press (a subnet may have been bound to
    another DNS zone since), so the Approve dialog reads this instead (#3934).
    Read-only. A request that is no longer pending answers its stored text.
    """
    _require_read(current_user)
    cr = await _load_visible(db, req_id, current_user)
    stored = CurrentPreviewResponse(preview_text=cr.preview_text, ok=True, changed=False)
    if cr.state != "pending":
        return stored
    from app.services.ai import operations  # noqa: PLC0415

    op = operations.get_operation(cr.operation)
    if op is None:
        return CurrentPreviewResponse(
            preview_text=cr.preview_text,
            ok=False,
            detail="Operation is not registered.",
            changed=False,
        )
    try:
        args = op.args_model.model_validate(cr.args or {})
        preview = await op.preview(db, current_user, args)
    except HTTPException as exc:
        await db.rollback()
        return CurrentPreviewResponse(
            preview_text=cr.preview_text, ok=False, detail=_refusal_text(exc.detail), changed=False
        )
    except Exception as exc:  # noqa: BLE001 — a refused preview is data, not a 500
        await db.rollback()
        return CurrentPreviewResponse(
            preview_text=cr.preview_text,
            ok=False,
            detail=str(exc) or "The operation can no longer be applied.",
            changed=False,
        )
    if not preview.ok:
        return CurrentPreviewResponse(
            preview_text=cr.preview_text,
            ok=False,
            detail=preview.detail or "The operation can no longer be applied.",
            changed=False,
        )
    return CurrentPreviewResponse(
        preview_text=preview.preview_text,
        ok=True,
        changed=preview.preview_text != cr.preview_text,
    )


# ── Decisions (delegated to the shared #62 spine) ──────────────────────────


@router.post("/{req_id}/approve", response_model=ProvisioningRequestResponse)
async def approve_request(
    req_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
    request: Request,
    body: DecisionBody | None = None,
) -> ProvisioningRequestResponse:
    """Approve and provision.

    Every invariant is enforced by ``approve_change_request`` — the same
    function #62's router calls — so the two surfaces cannot diverge on
    authorization. Notably the approver must hold the underlying operation's
    own permission: approving a subnet request requires ``write,subnet``, so
    a request can never provision something the approver could not have
    created themselves.
    """
    # Visibility first, so an unauthorized caller gets 404 rather than a
    # permission error that confirms the id exists.
    await _load_visible(db, req_id, current_user)
    note = body.decision_note if body is not None else None
    try:
        cr = await approve_change_request(
            db, req_id, approver=current_user, request=request, note=note
        )
    except DecisionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return await _respond(db, cr)


@router.post("/{req_id}/reject", response_model=ProvisioningRequestResponse)
async def reject_request(
    req_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
    request: Request,
    body: DecisionBody | None = None,
) -> ProvisioningRequestResponse:
    """Decline a request. Like approve, the decider may not be the requester —
    withdrawing your own request is ``cancel``."""
    await _load_visible(db, req_id, current_user)
    note = body.decision_note if body is not None else None
    try:
        cr = await reject_change_request(
            db, req_id, approver=current_user, request=request, note=note
        )
    except DecisionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return await _respond(db, cr)


@router.post("/{req_id}/cancel", response_model=ProvisioningRequestResponse)
async def cancel_request(
    req_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
    request: Request,
    body: DecisionBody | None = None,
) -> ProvisioningRequestResponse:
    """Withdraw your own pending request (superadmins may cancel any)."""
    _require_read(current_user)
    cr = await _load_visible(db, req_id, current_user, for_update=True)
    enforce_operation_token_scope(request, cr.operation)  # #3302
    is_requester = (
        cr.requested_by_user_id is not None and current_user.id == cr.requested_by_user_id
    )
    if not is_requester and not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the requester or a superadmin can cancel this request",
        )
    note = body.decision_note if body is not None else None
    try:
        await mark_cancelled(db, cr, user=current_user, request=request, note=note)
    except ChangeRequestStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.commit()
    await db.refresh(cr)
    return await _respond(db, cr)


__all__ = ["router"]
