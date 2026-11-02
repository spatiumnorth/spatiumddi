"""Self-service request submit path (issue #696).

This module owns exactly one thing the #62 approval spine did not already do:
turning a *requester's* form submission into a pending row. Everything after
that — the FOR UPDATE state guard, the self-approval block, the approver's
permission checks, the re-preview stale guard, ``apply()`` under the
approver's identity, the audit rows, the expiry sweep — is
``services.approvals.service`` unchanged. #696 explicitly asks not to grow a
second state machine, and this is how that promise is kept.

The one asymmetry worth naming: the submit path does **not** require the
caller to hold the operation's ``required_permission``. That inverts #62,
where the requester was a permitted operator whose action got intercepted.
Here the requester is by definition someone who cannot do the thing — that is
what makes it a request. The permission is enforced on the *approver* instead,
by the shared spine, which is where it belongs. The blast radius of that
inversion is bounded by the catalog allow-list (see ``catalog.py``).
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.change_request import ChangeRequest
from app.services.ai.operations import unreadable_target_detail
from app.services.approvals.service import create_change_request
from app.services.requests.catalog import resolve_operation

logger = structlog.get_logger(__name__)

# How long a submitted request waits for a decision before the shared expiry
# sweep retires it. Deliberately longer than a gate request's typical policy
# TTL: a gate request interrupts someone mid-task and wants a fast decision,
# whereas a provisioning request is often queued against a weekly review. The
# sweep is the same one #62 ships (``tasks/change_request_expiry.py``); it is
# origin-agnostic, so portal rows expire through the audited ``mark_expired``
# transition exactly like gate rows.
PORTAL_REQUEST_TTL_HOURS = 336  # 14 days

# Bound on the free-text justification. Long enough for a paragraph of real
# context, short enough that the column cannot be used as a data smuggling
# channel into a surface approvers read.
MAX_JUSTIFICATION_CHARS = 2000


def _field_error(err: Any) -> dict[str, Any]:
    """One Pydantic error as a FastAPI 422 entry (``type`` / ``loc`` / ``msg``).

    The ``input`` is left out, and ``ctx`` keeps only plain values: a
    validator's ``ctx.error`` is the exception object itself, which neither
    serialises nor tells a client anything the ``msg`` does not.
    """
    out: dict[str, Any] = {
        "type": err["type"],
        "loc": ["body", "args", *err["loc"]],
        "msg": err["msg"],
    }
    ctx = {
        k: v for k, v in (err.get("ctx") or {}).items() if isinstance(v, (str, int, float, bool))
    }
    if ctx:
        out["ctx"] = ctx
    return out


async def submit_request(
    db: AsyncSession,
    *,
    user: User,
    request: Request,
    kind: str,
    args: dict[str, Any],
    justification: str | None,
) -> ChangeRequest:
    """Validate + persist a self-service request in ``pending``.

    Raises ``HTTPException`` when the kind is unknown (400), the args don't
    validate against the operation's schema (422, field errors), or the
    operation's own ``preview()`` rejects them (400). Refusing at *submit*
    time rather than at approve time is deliberate: the requester is present
    to fix it, whereas an approver hours later can only reject something that
    was never going to work. It also keeps the ``failed`` terminal state for
    genuine execute-time surprises rather than for typos.
    """
    resolved = resolve_operation(kind)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown request kind {kind!r}",
        )
    entry, op = resolved

    # Validate the payload against the operation's own args model, so the
    # portal and the REST/Copilot paths accept exactly the same shapes.
    try:
        parsed = op.args_model.model_validate(args)
    except ValidationError as exc:
        # Field-level errors in FastAPI's own 422 shape, located under
        # ``body.args``, so the portal form can name each field as it labels it
        # and word the refusal from the error ``type`` instead of parsing
        # Pydantic's English (#3253).
        raise HTTPException(
            status_code=422,
            detail=[_field_error(e) for e in exc.errors(include_url=False)[:8]],
        ) from exc

    # The requester must be able to READ every resource the payload names
    # (the same per-resource check the request form's picker applies). One
    # they cannot read is answered exactly like an id that does not exist, so
    # submitting is no way to learn what a resource is called, or that it
    # exists. Superadmin reads everything.
    hidden = unreadable_target_detail(user, op, parsed)
    if hidden is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=hidden)

    # Run the operation's read-only preview under the REQUESTER's identity.
    # Two things fall out of that: the approver gets a concrete description of
    # what approving will do, and the request is implicitly scoped to what the
    # requester can already see — a preview that reads a subnet the requester
    # has no visibility of fails here rather than leaking it into the queue.
    preview = await op.preview(db, user, parsed)
    if not preview.ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=preview.detail,
        )

    # Refuse what the REST create would refuse (#2903): the preview is shared
    # with the copilot and only hints at conflicts, so the portal runs the
    # operation's own submit check, whose 4xx reaches the requester as-is and
    # queues nothing.
    if op.validate_submit is not None:
        await op.validate_submit(db, user, parsed)

    # Length is enforced HERE rather than only on the request schema so every
    # caller gets the same rule + the same readable message — the HTTP body
    # model deliberately does not carry a ``max_length``, which would 422
    # first and make this branch dead code.
    note = (justification or "").strip() or None
    if note is not None and len(note) > MAX_JUSTIFICATION_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Justification is {len(note)} characters " f"(max {MAX_JUSTIFICATION_CHARS})."
            ),
        )

    action, resource_type = op.required_permission or ("write", entry.category)

    cr = await create_change_request(
        db,
        user=user,
        request=request,
        operation=op.name,
        resource_type=resource_type,
        # A provisioning request has no existing target — the row it will
        # create does not exist yet. NULL matches how the gate treats ops with
        # no single target (e.g. factory_reset).
        resource_id=None,
        # The HEADLINE the approver, the audit row and the MCP result all
        # show. Must be ``preview_text``, not ``detail``: every catalog
        # operation's preview returns the bare sentinel ``detail="ready"``,
        # so using detail made every portal row read "ready" everywhere.
        resource_display=(preview.preview_text or preview.detail)[:500],
        args=parsed.model_dump(mode="json"),
        preview_text=preview.preview_text or preview.detail,
        # The gate's ``risk_reason`` is policy-derived; the portal's is fixed
        # and states the direction of travel, so an approver reading a mixed
        # audit log can tell a brake from a provisioning request at a glance.
        risk_reason=f"Self-service request: {entry.label}",
        ttl_hours=PORTAL_REQUEST_TTL_HOURS,
        origin="portal",
        justification=note,
    )
    logger.info(
        "provisioning_request.submitted",
        change_request_id=str(cr.id),
        kind=kind,
        operation=op.name,
        requested_by=str(user.id),
        required_permission=f"{action},{resource_type}",
    )
    return cr


__all__ = [
    "MAX_JUSTIFICATION_CHARS",
    "PORTAL_REQUEST_TTL_HOURS",
    "submit_request",
]
