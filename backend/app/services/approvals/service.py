"""Change-request service — data access + audited state machine (#62).

This module owns the ``change_request`` row lifecycle: create a pending
request, read/list it, and the guarded ``mark_*`` transitions an approver
/ requester / sweep drives. Every mutation writes an ``audit_log`` row
before returning (non-negotiable #4); the caller owns the commit so the
audit row and the state change land atomically.

The gate (``gate.py``) + the approve/reject/cancel API router + the
Celery expiry sweep all call into here. Two-person authorization (approver
!= requester, approver holds ``{approve, change_request}`` AND the
operation's ``required_permission``) is enforced by the API layer *before*
calling :func:`mark_approved` / :func:`mark_executed`; this module owns
the *state-machine* invariants (a request only ever transitions out of
``pending``, and only once, under ``SELECT ... FOR UPDATE``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collecting_wakes
from app.core.permissions import is_effective_superadmin
from app.core.request_meta import clean_user_agent, client_ip
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.change_request import CHANGE_REQUEST_ORIGINS, ChangeRequest

logger = structlog.get_logger(__name__)

# Audit action strings — PLAIN verbs (#10). The event publisher maps
# resource_type ``change_request`` → namespace ``change_request`` and, for a
# verb outside the create/update/delete trio, passes the action through as
# the verb, yielding ``change_request.<verb>`` (e.g. ``change_request.requested``).
# Using already-namespaced strings here would double the namespace
# (``change_request.change_request.requested``) — so keep these bare verbs.
_ACTION_REQUESTED = "requested"
_ACTION_APPROVED = "approved"
_ACTION_REJECTED = "rejected"
_ACTION_CANCELLED = "cancelled"
_ACTION_EXECUTED = "executed"
_ACTION_FAILED = "failed"
_ACTION_EXPIRED = "expired"

# #8: per-user pending-request cap. Bounds change_request table + expiry-sweep
# growth from a single noisy requester (or a script). A requester at the cap
# must let some of their pending requests resolve (approve / reject / cancel /
# expire) before queuing more. Sized generously — a human operator rarely has
# this many open at once; it's a runaway guard, not a workflow throttle.
_MAX_PENDING_PER_USER = 50


class ChangeRequestStateError(Exception):
    """A transition was attempted from an illegal current state.

    The API layer translates this into a 409 Conflict — e.g. two
    approvers race and the second one finds the row already
    ``approved``/``executed``.
    """


def _audit(
    db: AsyncSession,
    *,
    user: User | None,
    request: Request | None,
    action: str,
    cr: ChangeRequest,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
) -> None:
    """Append an ``audit_log`` row for a change-request transition.

    ``user`` is the actor (None only for the system-driven expiry sweep,
    which records a synthetic ``system`` actor). ``request`` is None on
    non-HTTP paths (the Celery sweep) — source_ip / user_agent stay NULL.
    """
    db.add(
        AuditLog(
            user_id=user.id if user is not None else None,
            user_display_name=user.display_name if user is not None else "system",
            auth_source=user.auth_source if user is not None else "system",
            source_ip=client_ip(request) if request is not None else None,
            user_agent=(
                clean_user_agent(request.headers.get("user-agent")) if request is not None else None
            ),
            action=action,
            resource_type="change_request",
            resource_id=str(cr.id),
            resource_display=cr.resource_display,
            old_value=old_value,
            new_value=new_value,
        )
    )


# ── Create / read ────────────────────────────────────────────────────────


async def create_change_request(
    db: AsyncSession,
    *,
    user: User,
    request: Request,
    operation: str,
    resource_type: str,
    resource_id: str | None,
    resource_display: str,
    args: dict[str, Any],
    preview_text: str,
    risk_reason: str,
    ttl_hours: int,
    origin: str = "gate",
    justification: str | None = None,
) -> ChangeRequest:
    """Persist a new ``pending`` change request + its ``requested`` audit row.

    The caller (the gate) owns the commit. ``ttl_hours`` comes from the
    matched policy; ``expires_at`` is stamped now + ttl.

    #8: refuses (429) when the requester already holds ``_MAX_PENDING_PER_USER``
    pending requests — a per-user cap that bounds table + sweep growth.
    """
    # #696 — reject an unknown origin rather than persisting a row that would
    # be invisible on BOTH queues (each filters by origin) yet still
    # executable through the spine. Cheap guard; the column has no CHECK
    # because the value is service-assigned, never user-supplied.
    if origin not in CHANGE_REQUEST_ORIGINS:
        raise ValueError(
            f"invalid change_request origin {origin!r}; "
            f"expected one of {sorted(CHANGE_REQUEST_ORIGINS)}"
        )

    # #8: per-user pending quota — fail before persisting anything.
    pending_count = (
        await db.execute(
            select(func.count(ChangeRequest.id)).where(
                ChangeRequest.requested_by_user_id == user.id,
                ChangeRequest.state == "pending",
            )
        )
    ).scalar_one()
    if pending_count >= _MAX_PENDING_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"You already have {pending_count} pending change requests "
                f"(max {_MAX_PENDING_PER_USER}). Resolve or cancel some before "
                "submitting more."
            ),
        )

    now = datetime.now(UTC)
    cr = ChangeRequest(
        operation=operation,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_display=resource_display,
        args=args,
        preview_text=preview_text,
        risk_reason=risk_reason,
        origin=origin,
        justification=justification,
        state="pending",
        requested_by_user_id=user.id,
        requested_by_display=user.display_name,
        expires_at=now + timedelta(hours=ttl_hours),
    )
    db.add(cr)
    # Flush so the row gets its id before the audit row references it.
    await db.flush()
    _audit(
        db,
        user=user,
        request=request,
        action=_ACTION_REQUESTED,
        cr=cr,
        new_value={
            "operation": operation,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "risk_reason": risk_reason,
            "origin": origin,
            "state": "pending",
        },
    )
    logger.info(
        "change_request.created",
        change_request_id=str(cr.id),
        operation=operation,
        resource_type=resource_type,
        requested_by=str(user.id),
    )
    return cr


async def get_change_request(
    db: AsyncSession, cr_id: UUID, *, for_update: bool = False
) -> ChangeRequest | None:
    """Load one change request. ``for_update`` takes a row-level lock so a
    transition is race-safe against a concurrent approver (#62 concurrency
    edge-case)."""
    stmt = select(ChangeRequest).where(ChangeRequest.id == cr_id)
    if for_update:
        stmt = stmt.with_for_update()
    return (await db.execute(stmt)).scalar_one_or_none()


async def list_change_requests(
    db: AsyncSession,
    *,
    state: str | None = None,
    resource_type: str | None = None,
    requested_by_user_id: UUID | None = None,
    origin: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[ChangeRequest]:
    """List change requests newest-first with optional filters.

    ``origin`` splits the #62 gate queue from the #696 portal queue — both
    live in this table, and each surface passes its own value so neither
    ever renders the other's rows.
    """
    stmt = select(ChangeRequest)
    if origin is not None:
        stmt = stmt.where(ChangeRequest.origin == origin)
    if state is not None:
        stmt = stmt.where(ChangeRequest.state == state)
    if resource_type is not None:
        stmt = stmt.where(ChangeRequest.resource_type == resource_type)
    if requested_by_user_id is not None:
        stmt = stmt.where(ChangeRequest.requested_by_user_id == requested_by_user_id)
    stmt = stmt.order_by(ChangeRequest.created_at.desc()).limit(limit).offset(offset)
    return list((await db.execute(stmt)).scalars().all())


# ── State transitions (each guarded + audited) ─────────────────────────────


def _require_state(cr: ChangeRequest, expected: str) -> None:
    if cr.state != expected:
        raise ChangeRequestStateError(
            f"change request {cr.id} is {cr.state!r}, expected {expected!r}"
        )


async def mark_approved(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    approver: User,
    request: Request | None,
    note: str | None,
) -> ChangeRequest:
    """``pending`` → ``approved``. Caller must have already loaded ``cr``
    with ``for_update=True`` and enforced two-person RBAC. Records the
    approver + decision time; execution (``apply()``) is a separate
    :func:`mark_executed` / :func:`mark_failed` call by the API layer."""
    _require_state(cr, "pending")
    cr.state = "approved"
    cr.decided_by_user_id = approver.id
    cr.decided_by_display = approver.display_name
    cr.decision_note = note
    cr.decided_at = datetime.now(UTC)
    _audit(
        db,
        user=approver,
        request=request,
        action=_ACTION_APPROVED,
        cr=cr,
        old_value={"state": "pending"},
        new_value={"state": "approved", "note": note},
    )
    return cr


async def mark_rejected(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    approver: User,
    request: Request | None,
    note: str | None,
) -> ChangeRequest:
    """``pending`` → ``rejected`` (terminal)."""
    _require_state(cr, "pending")
    cr.state = "rejected"
    cr.decided_by_user_id = approver.id
    cr.decided_by_display = approver.display_name
    cr.decision_note = note
    cr.decided_at = datetime.now(UTC)
    _audit(
        db,
        user=approver,
        request=request,
        action=_ACTION_REJECTED,
        cr=cr,
        old_value={"state": "pending"},
        new_value={"state": "rejected", "note": note},
    )
    return cr


async def mark_cancelled(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    user: User,
    request: Request | None,
    note: str | None = None,
) -> ChangeRequest:
    """``pending`` → ``cancelled`` (terminal). Driven by the requester (or
    a superadmin); the API layer enforces who may cancel.

    #5: the optional cancellation ``note`` is stamped on the row AND carried
    into the audit ``new_value`` here — previously the router set
    ``cr.decision_note`` only AFTER this wrote the audit row, so the note never
    reached ``audit_log`` (unlike approve/reject)."""
    _require_state(cr, "pending")
    cr.state = "cancelled"
    cr.decided_by_user_id = user.id
    cr.decided_by_display = user.display_name
    cr.decision_note = note
    cr.decided_at = datetime.now(UTC)
    _audit(
        db,
        user=user,
        request=request,
        action=_ACTION_CANCELLED,
        cr=cr,
        old_value={"state": "pending"},
        new_value={"state": "cancelled", "note": note},
    )
    return cr


async def mark_executed(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    approver: User,
    requester_id: UUID | None,
    request: Request | None,
    result: dict[str, Any],
) -> ChangeRequest:
    """``approved`` → ``executed`` (terminal). The operation's ``apply()``
    ran successfully under the approver's identity. The audit row sets
    ``user_id=approver`` and ``old_value.requested_by=<requester>`` so the
    two-person trail is queryable (#62)."""
    _require_state(cr, "approved")
    cr.state = "executed"
    cr.result = result
    cr.executed_at = datetime.now(UTC)
    _audit(
        db,
        user=approver,
        request=request,
        action=_ACTION_EXECUTED,
        cr=cr,
        old_value={
            "state": "approved",
            "requested_by": str(requester_id) if requester_id is not None else None,
        },
        new_value={"state": "executed", "result": result},
    )
    logger.info(
        "change_request.executed",
        change_request_id=str(cr.id),
        operation=cr.operation,
        approved_by=str(approver.id),
        requested_by=str(requester_id) if requester_id is not None else None,
    )
    return cr


async def mark_failed(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    approver: User,
    requester_id: UUID | None,
    request: Request | None,
    error: str,
) -> ChangeRequest:
    """``approved`` → ``failed`` (terminal). ``apply()`` (or its
    re-preview stale-state guard) failed at execution time. Like
    :func:`mark_executed`, the audit row carries the requester→approver
    correlation (#14): ``user_id=approver`` + ``old_value.requested_by``."""
    _require_state(cr, "approved")
    cr.state = "failed"
    cr.error = error
    cr.executed_at = datetime.now(UTC)
    _audit(
        db,
        user=approver,
        request=request,
        action=_ACTION_FAILED,
        cr=cr,
        old_value={
            "state": "approved",
            "requested_by": str(requester_id) if requester_id is not None else None,
        },
        new_value={"state": "failed", "error": error},
    )
    logger.warning(
        "change_request.failed",
        change_request_id=str(cr.id),
        operation=cr.operation,
        error=error,
    )
    return cr


async def mark_expired(db: AsyncSession, cr: ChangeRequest) -> ChangeRequest:
    """``pending`` → ``expired`` (terminal). System-driven by the Celery
    sweep; no HTTP request / human actor."""
    _require_state(cr, "pending")
    cr.state = "expired"
    cr.decided_at = datetime.now(UTC)
    _audit(
        db,
        user=None,
        request=None,
        action=_ACTION_EXPIRED,
        cr=cr,
        old_value={"state": "pending"},
        new_value={"state": "expired"},
    )
    logger.info("change_request.expired", change_request_id=str(cr.id))
    return cr


# ── Shared approve / reject orchestration (the two-person spine) ───────────
#
# These functions own the full two-person decision flow so the HTTP router
# (api/v1/change_requests/router.py) and the AI propose→apply path
# (services/ai/operations.py: approve_change_request / reject_change_request)
# enforce the *identical* invariants without copy-pasting them. The
# invariants are enforced here, never trusting the caller:
#
#   1. Row loaded ``FOR UPDATE`` + must still be ``pending`` (racing
#      approver loses → ``DecisionConflict``); an expired row flips to
#      ``expired`` and raises ``DecisionConflict``.
#   2. Self-approval blocked — approver != requester (``DecisionForbidden``).
#   3. Approver holds ``{approve, change_request}`` (``DecisionForbidden``).
#   4. Approver holds the underlying op's ``required_permission``
#      (``DecisionForbidden``) — can't rubber-stamp a delete you couldn't do.
#   5. ``preview()`` re-runs (stale-state guard); if not ok the op does NOT
#      execute (``DecisionConflict``), the row stays ``pending``.
#   6. ``apply()`` dispatches under the **approver's** identity; the audit
#      ``executed`` row carries approver as actor + requester in
#      ``old_value.requested_by``.
#
# The error subclasses carry an HTTP-ish ``status_code`` so the two call
# sites translate them uniformly. ``request`` is optional — None on the
# AI propose→apply path (no FastAPI Request there); audit source_ip /
# user_agent stay NULL exactly like the Celery sweep.


class DecisionError(Exception):
    """Base for a refused approve/reject decision. ``status_code`` lets the
    caller map it to the right HTTP response."""

    status_code: int = 400


class DecisionNotFound(DecisionError):
    status_code = 404


class DecisionForbidden(DecisionError):
    status_code = 403


class DecisionConflict(DecisionError):
    status_code = 409


class DecisionUnprocessable(DecisionError):
    status_code = 422


def _decision_for_status(status_code: int, detail: str) -> DecisionError:
    """Map an HTTP 4xx ``apply()`` raised to the matching DecisionError so the
    approve callers surface the precondition status (#11)."""
    mapping: dict[int, type[DecisionError]] = {
        403: DecisionForbidden,
        404: DecisionNotFound,
        409: DecisionConflict,
        422: DecisionUnprocessable,
    }
    return mapping.get(status_code, DecisionConflict)(detail)


async def _safe_rollback(db: AsyncSession) -> None:
    """Roll back, swallowing a rollback-time failure (#15).

    If ``apply()`` already rolled back (or the connection is wedged) a second
    rollback can itself raise; letting that propagate would mask the original
    error and could strand the row. Best-effort + log, never re-raise.
    """
    try:
        await db.rollback()
    except Exception as exc:  # noqa: BLE001
        logger.warning("change_request.rollback_failed", error=str(exc))


async def _relock_after_failed_apply(
    db: AsyncSession, cr_id: UUID, *, approver: User
) -> tuple[ChangeRequest, bool]:
    """Re-lock the row after the spine rolled back a failed ``apply()``.

    Returns ``(cr, approval_committed)``. The row is normally ``pending``
    again: the ``approved`` stamp was rolled back with ``apply()``. But
    ``apply()`` runs its own ``db.commit()``, and that commit persists the
    stamp too — so an ``apply()`` that committed and THEN raised leaves the
    row ``approved`` by this approver, never executed. That is this
    approval's own failure, not another actor's decision, and reporting it as
    "changed state mid-apply" would strand the row ``approved``: the expiry
    sweep only touches ``pending`` and nobody can decide it (#2911).

    Any other state means another actor decided the row between the rollback
    (which released our ``FOR UPDATE``) and this re-lock — a concurrent
    reject, cancel, expiry or approve. That is a :class:`DecisionConflict`,
    and the row is left exactly as they left it.
    """
    # The caller's rollback expired every loaded object, the signed-in
    # approver's ``User`` included. Reading ``approver.id`` on an expired
    # instance triggers a synchronous refresh, which raises MissingGreenlet
    # under asyncpg (#2911). Refresh it here, awaited, so the stamp (and the
    # caller's own reference to the user) reads loaded values again. A user
    # not attached to this session was never expired by its rollback.
    if approver in db:
        await db.refresh(approver)
    cr = await get_change_request(db, cr_id, for_update=True)
    if cr is None:
        raise DecisionConflict("Change request vanished mid-apply — investigate")
    if cr.state == "pending":
        return cr, False
    if cr.state == "approved" and cr.decided_by_user_id == approver.id and cr.executed_at is None:
        return cr, True
    raise DecisionConflict(
        f"Change request was decided by someone else while it was being applied "
        f"(state={cr.state!r})"
    )


async def _stamp_apply_failed(
    db: AsyncSession,
    cr_id: UUID,
    *,
    approver: User,
    request: Request | None,
    note: str | None,
    error: str,
) -> ChangeRequest:
    """Re-lock the (rolled-back) row and stamp ``pending → approved → failed``.

    Shared by the approve spine's 5xx and generic-exception paths. The
    approval transition was rolled back alongside ``apply()``, so replay it
    before ``mark_failed`` — unless ``apply()`` had already committed it, in
    which case only the failure is stamped (one ``approved`` audit row, not
    two). Raises :class:`DecisionConflict` if the row vanished or another
    actor decided it mid-apply."""
    cr, approval_committed = await _relock_after_failed_apply(db, cr_id, approver=approver)
    return await _stamp_failed_locked(
        db,
        cr,
        approver=approver,
        request=request,
        note=note,
        error=error,
        approval_committed=approval_committed,
    )


async def _stamp_failed_locked(
    db: AsyncSession,
    cr: ChangeRequest,
    *,
    approver: User,
    request: Request | None,
    note: str | None,
    error: str,
    approval_committed: bool,
) -> ChangeRequest:
    """Stamp a row :func:`_relock_after_failed_apply` locked as ``failed``,
    replaying ``approved`` first unless ``apply()`` already committed it."""
    requester_id = cr.requested_by_user_id
    if not approval_committed:
        await mark_approved(db, cr, approver=approver, request=request, note=note)
    await mark_failed(
        db, cr, approver=approver, requester_id=requester_id, request=request, error=error
    )
    await db.commit()
    # ``modified_at`` is a server-side onupdate, so the flush expired it; the
    # callers serialise the row, and a sync lazy-load there is MissingGreenlet.
    await db.refresh(cr)
    logger.warning(
        "change_request.apply_failed",
        change_request_id=str(cr.id),
        operation=cr.operation,
        error=error,
    )
    return cr


async def approve_change_request(
    db: AsyncSession,
    cr_id: UUID,
    *,
    approver: User,
    request: Request | None,
    note: str | None,
) -> ChangeRequest:
    """Approve + execute a pending change request — the two-person spine.

    Loads the row ``FOR UPDATE``, enforces every server-side invariant
    (steps 1–6 above), runs the underlying operation's ``apply()`` under
    ``approver``'s identity, and **commits**. On a successful apply the row
    is ``executed`` (with ``result``); on an apply-time failure the row is
    ``failed`` (with ``error``) and the function returns normally (the
    caller surfaces the terminal row). Raises a :class:`DecisionError`
    subclass for every refused-decision case before any mutation lands.
    """
    # Local import — operations imports this module's siblings, so importing
    # it at module top would risk a cycle.
    from app.services.ai import operations  # noqa: PLC0415
    from app.services.ai.operations import OperationPermissionError  # noqa: PLC0415

    # 1. Row lock + state guard — race-safe against a second approver.
    cr = await get_change_request(db, cr_id, for_update=True)
    if cr is None:
        raise DecisionNotFound(f"Change request {cr_id} not found")
    if cr.state != "pending":
        raise DecisionConflict(f"Change request is not pending (state={cr.state!r})")
    # #10: one expiry convention everywhere — ``expires_at <= now`` means expired
    # (matches the sweep select + recheck), so a request can't be approved in the
    # same instant the sweep would expire it.
    if cr.expires_at <= datetime.now(UTC):
        # #13: route through the audited mark_expired transition (not a raw
        # field poke) so the change_request.expired audit row lands.
        await mark_expired(db, cr)
        await db.commit()
        raise DecisionConflict("Change request has expired")

    # 2a. Fail CLOSED when the requester row is gone (#5). ON DELETE SET NULL
    #     nulls ``requested_by_user_id`` if the requester is deleted; the
    #     self-approval guard below would then fail OPEN (None != approver.id
    #     is always true), letting anyone rubber-stamp an orphaned request and
    #     defeating two-person. Refuse instead — the requester must recreate.
    if cr.requested_by_user_id is None:
        raise DecisionConflict(
            "Requester no longer exists; cancel and recreate this change request"
        )

    # 2b. Self-approval is forbidden — the whole point of two-person.
    if approver.id == cr.requested_by_user_id:
        raise DecisionForbidden("You cannot approve your own change request")

    op = operations.get_operation(cr.operation)
    if op is None:
        raise DecisionError(f"Operation {cr.operation!r} is not registered")

    # 3. Approver holds the approve capability.
    if not _can_approve(approver):
        raise DecisionForbidden(
            "Permission denied: need 'approve' on 'change_request'",
        )

    # 4. Approver holds the underlying operation's own permission.
    try:
        operations.enforce_operation_permission(approver, op)
    except OperationPermissionError as exc:
        raise DecisionForbidden(str(exc)) from exc

    # 4b. Self-governance control ops (#62) are SUPERADMIN-ONLY to approve —
    #     IN ADDITION to the {approve, change_request} + required_permission
    #     checks above. A control op weakens the approval control plane
    #     itself, so only a *different* superadmin may sign off (the
    #     "different" half is the step-2b self-approval block above; this
    #     half is the superadmin requirement). Without this, a plain
    #     {approve, change_request} + {admin, approval_control} holder could
    #     rubber-stamp turning the whole workflow off.
    from app.services.ai.operations_control import (  # noqa: PLC0415
        CONTROL_OPERATION_NAMES,
    )

    if cr.operation in CONTROL_OPERATION_NAMES and not is_effective_superadmin(approver):
        raise DecisionForbidden(
            "Approving a control-plane change to the approval workflow requires superadmin"
        )

    # Re-validate frozen args (guards the rare redeploy-mid-flight schema change).
    # #6: never echo the Pydantic ValidationError back to the client — it
    # interpolates ``input_value`` (the frozen args). Log the detail
    # server-side and surface a generic message.
    try:
        args = op.args_model.model_validate(cr.args or {})
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "change_request.args_revalidation_failed",
            change_request_id=str(cr.id),
            operation=cr.operation,
            error=str(exc),
        )
        raise DecisionUnprocessable("Stored args no longer validate for this operation") from exc

    # 4c. Control-op gate-premise re-assertion (#62, #6). A queued control op
    #     (modify_approval_control) was created BECAUSE the self-protection lock
    #     was on; if the lock is now off (e.g. a concurrent break-glass unlock
    #     landed first), the second-superadmin protection premise has
    #     evaporated. Resolve the request idempotently rather than executing a
    #     weakening change under approver authority whose rationale is gone. The
    #     flag is read FOR UPDATE so this can't race a concurrent flip.
    from app.services.ai.operations_control import (  # noqa: PLC0415
        ModifyApprovalControlArgs,
        control_gate_premise_lost,
    )

    if cr.operation in CONTROL_OPERATION_NAMES and isinstance(args, ModifyApprovalControlArgs):
        if await control_gate_premise_lost(db, args):
            requester_id = cr.requested_by_user_id
            await mark_approved(db, cr, approver=approver, request=request, note=note)
            await mark_executed(
                db,
                cr,
                approver=approver,
                requester_id=requester_id,
                request=request,
                result={
                    "idempotent": True,
                    "note": "self-protection lock already off; gated change no longer applies",
                },
            )
            await db.commit()
            await db.refresh(cr)
            logger.info(
                "change_request.control_premise_lost",
                change_request_id=str(cr.id),
                operation=cr.operation,
                approver=str(approver.id),
            )
            return cr

    # 5. Stale-state re-check — do NOT execute a doomed op; leave it pending.
    preview = await op.preview(db, approver, args)
    if not preview.ok:
        logger.info(
            "change_request.stale",
            change_request_id=str(cr.id),
            operation=cr.operation,
            detail=preview.detail,
            approver=str(approver.id),
        )
        raise DecisionConflict(preview.detail)

    # 5a. Idempotent resolution (#62 concurrent break-glass). When the op's
    #     preview reports the target is ALREADY in the desired end-state
    #     (``idempotent=True``) — e.g. a break-glass deleted the policy / flipped
    #     the lock between request and approval — the effect this request asked
    #     for already happened. Resolve the request as EXECUTED with an
    #     "already in desired state" note WITHOUT re-running apply() (there's
    #     nothing left to do) and WITHOUT the scope-drift guard 409'ing on the
    #     changed preview text. This unwedges a CR whose effect was achieved out
    #     of band, instead of leaving it stuck pending / marking it failed.
    if preview.idempotent:
        requester_id = cr.requested_by_user_id
        cr.preview_text = preview.preview_text
        await mark_approved(db, cr, approver=approver, request=request, note=note)
        await mark_executed(
            db,
            cr,
            approver=approver,
            requester_id=requester_id,
            request=request,
            result={
                "idempotent": True,
                "note": "already in desired state",
                "detail": preview.detail,
            },
        )
        await db.commit()
        await db.refresh(cr)
        logger.info(
            "change_request.idempotent",
            change_request_id=str(cr.id),
            operation=cr.operation,
            approver=str(approver.id),
            detail=preview.detail,
        )
        return cr

    # 5b. Scope-drift guard (#3b — TOCTOU). The frozen ``cr.preview_text`` is
    #     what the approver saw rendered when the request was created; each
    #     delete op's preview_text now embeds the CURRENT blast radius (#3a).
    #     If the fresh preview_text differs, the blast radius CHANGED between
    #     request and approval (e.g. the requester added 50 IPs to a subnet
    #     queued for soft-delete) — refuse so the approver never rubber-stamps
    #     a scope larger than the one they reviewed. Treat any drift as stale;
    #     the requester must cancel and re-submit to capture the new scope.
    #     This closes the TOCTOU for both soft and permanent paths via one rule.
    #
    #     GATE ROWS ONLY (#696). The rule assumes the preview describes a
    #     blast radius over EXISTING state, which is true for a delete: if it
    #     moved, the approver is being asked to sign off on more than they
    #     read. A self-service provisioning request is the opposite shape —
    #     nothing exists yet, and the preview embeds the answer the allocator
    #     WOULD pick right now (e.g. the lowest free /26 in a block). Any
    #     unrelated carve elsewhere in that block changes that string, so a
    #     byte comparison would make the request permanently un-approvable
    #     through no fault of anyone's — and with a 14-day TTL that is the
    #     common case, not the edge case.
    #
    #     What actually protects a portal row is that its ``args`` are frozen
    #     and re-validated, and its preview is re-run and must still succeed
    #     (step 5a above) — so a request that has become impossible still
    #     fails. The approver is deciding "may this person have a /26 from
    #     this block", not "must it be 10.20.0.0/26"; which one they get is
    #     the same race-safe carve a manual create performs. The fresh text is
    #     written back below so the executed record shows what was really done.
    if cr.origin == "gate" and preview.preview_text != cr.preview_text:
        logger.info(
            "change_request.scope_drift",
            change_request_id=str(cr.id),
            operation=cr.operation,
            approver=str(approver.id),
            frozen_preview=cr.preview_text,
            fresh_preview=preview.preview_text,
        )
        raise DecisionConflict(
            "The change's scope changed since it was requested — cancel and "
            "re-submit to capture the new scope."
        )

    requester_id = cr.requested_by_user_id

    # #3b transparency: surface the freshly-rendered preview on the returned
    # row, so the executed record reflects exactly what was re-validated at
    # approve time. For a GATE row this equals the frozen text (any drift
    # 409'd above). For a PORTAL row (#696) it may legitimately differ — the
    # drift guard is skipped there — and this write-back is what records the
    # answer the allocator actually chose rather than the one previewed at
    # submit time.
    cr.preview_text = preview.preview_text

    # Record the approval transition (pending → approved, audited).
    await mark_approved(db, cr, approver=approver, request=request, note=note)

    # 6. Dispatch apply() under the approver's identity. apply() runs its own
    #    mutation + audit + commit; on success mark_executed writes the
    #    change_request.executed audit row carrying both ids.
    try:
        # #2040 — neither /change-requests nor /requests mounts
        # ``wake_publishing``, so open the collector here: an approved op's
        # ``collect_wake`` publishes after apply() commits (dropped on raise)
        # instead of being a silent no-op.
        async with collecting_wakes():
            result = await op.apply(db, approver, args)
    except OperationPermissionError as exc:
        await _safe_rollback(db)
        raise DecisionForbidden(str(exc)) from exc
    except HTTPException as exc:
        # #11: a client 4xx from apply() is NOT an execution failure — it's a
        # raced precondition the op rejected (e.g. the subnet became
        # non-empty, or the row vanished, between preview and apply). Surface
        # the same status, leave the request PENDING (the requester can cancel
        # or retry once the precondition clears). Only a 5xx (server fault)
        # falls through to mark_failed below.
        await _safe_rollback(db)
        sc = exc.status_code
        if 400 <= sc < 500:
            detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            # Leaving it pending is only possible while it IS pending. If
            # apply() committed (persisting the approved stamp) before it
            # raised, the row is approved and nothing would ever move it
            # again — record the refusal as this approval's failure instead.
            cr, approval_committed = await _relock_after_failed_apply(db, cr_id, approver=approver)
            if approval_committed:
                return await _stamp_failed_locked(
                    db,
                    cr,
                    approver=approver,
                    request=request,
                    note=note,
                    error=detail,
                    approval_committed=True,
                )
            # Release the re-lock. Nothing changed, and committing (rather
            # than rolling back again) keeps the refreshed approver loaded
            # for whatever the caller reads next.
            await db.commit()
            logger.info(
                "change_request.apply_precondition",
                change_request_id=str(cr_id),
                operation=op.name,
                status_code=sc,
                detail=detail,
            )
            raise _decision_for_status(sc, detail) from exc
        return await _stamp_apply_failed(
            db, cr_id, approver=approver, request=request, note=note, error=str(exc.detail)
        )
    except Exception as exc:  # noqa: BLE001
        # apply() rolled back its own transaction; reload + lock to stamp the
        # failure (the approval transition was rolled back too).
        await _safe_rollback(db)
        return await _stamp_apply_failed(
            db, cr_id, approver=approver, request=request, note=note, error=str(exc)
        )

    await mark_executed(
        db,
        cr,
        approver=approver,
        requester_id=requester_id,
        request=request,
        result=result,
    )
    await db.commit()
    await db.refresh(cr)
    return cr


async def reject_change_request(
    db: AsyncSession,
    cr_id: UUID,
    *,
    approver: User,
    request: Request | None,
    note: str | None,
) -> ChangeRequest:
    """Decline a pending change request (``pending`` → ``rejected``).

    Needs ``approve,change_request``; like approve, the rejecter may not be
    the requester (a self-reject is a cancel). Commits + returns the terminal
    row, or raises a :class:`DecisionError` subclass for a refused decision.
    """
    if not _can_approve(approver):
        raise DecisionForbidden("Permission denied: need 'approve' on 'change_request'")
    cr = await get_change_request(db, cr_id, for_update=True)
    if cr is None:
        raise DecisionNotFound(f"Change request {cr_id} not found")
    if cr.requested_by_user_id is not None and approver.id == cr.requested_by_user_id:
        raise DecisionForbidden("You cannot reject your own request — cancel it instead")
    try:
        await mark_rejected(db, cr, approver=approver, request=request, note=note)
    except ChangeRequestStateError as exc:
        raise DecisionConflict(str(exc)) from exc
    await db.commit()
    await db.refresh(cr)
    return cr


def _can_approve(user: User) -> bool:
    """True when ``user`` holds ``{approve, change_request}``. Local import
    of the permission helper avoids an import cycle at module load."""
    from app.core.permissions import (  # noqa: PLC0415
        RESOURCE_TYPE_CHANGE_REQUEST,
        user_has_permission,
    )

    return user_has_permission(user, "approve", RESOURCE_TYPE_CHANGE_REQUEST)


__all__ = [
    "ChangeRequestStateError",
    "DecisionConflict",
    "DecisionError",
    "DecisionForbidden",
    "DecisionNotFound",
    "DecisionUnprocessable",
    "approve_change_request",
    "create_change_request",
    "get_change_request",
    "list_change_requests",
    "mark_approved",
    "mark_cancelled",
    "mark_executed",
    "mark_expired",
    "mark_failed",
    "mark_rejected",
    "reject_change_request",
]
