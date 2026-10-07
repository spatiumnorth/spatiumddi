"""Operator Copilot tools for the two-person approval queue (issue #62).

Four tools, all carrying ``module="governance.approvals"`` so disabling the
(default-off) feature module strips them from the AI surface (NN #14):

Reads — answer "what's waiting on a second approver?" / "how big is the
backlog?":

* ``find_change_requests`` — list change requests with optional state /
  resource-type / mine filters.
* ``count_change_requests`` — counts grouped by state.

Propose writes — the model surfaces an approve/reject as a propose→Apply
card; the tool itself is read-only (it only persists an
``AIOperationProposal``):

* ``propose_approve_change_request`` — prepare an approval proposal.
* ``propose_reject_change_request`` — prepare a rejection proposal.

The model can NEVER self-approve: the actual decision runs only through
``POST /api/v1/ai/proposals/{id}/apply`` when a *human operator* clicks
Apply, and the backing ``approve_change_request`` / ``reject_change_request``
Operations enforce the full two-person spine server-side (approver !=
requester, approver holds ``{approve, change_request}`` AND the underlying
operation's ``required_permission``, plus a stale-state re-preview). The
human who clicks Apply becomes the approver, so the second-person
constraint the feature exists to enforce is preserved end-to-end.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import (
    RESOURCE_TYPE_CHANGE_REQUEST,
    is_effective_superadmin,
    user_has_permission,
)
from app.models.auth import User
from app.models.change_request import CHANGE_REQUEST_STATES, ChangeRequest
from app.services.ai import operations
from app.services.ai.operations import (
    ApproveChangeRequestArgs,
    RejectChangeRequestArgs,
)
from app.services.ai.tools.base import register_tool

MODULE = "governance.approvals"


def _can_see_all_change_requests(user: User) -> bool:
    """READ RULE (#1), identical to the REST router: a superadmin or a holder
    of ``{approve, change_request}`` may see EVERY change request; everyone
    else is scoped to their own. The MCP read tools have no router gate, so the
    scope is enforced here in-tool — without it the copilot would leak the
    whole platform queue (args / preview / target / requester / approver) to
    any user who can reach the (default-off) governance.approvals module."""
    return is_effective_superadmin(user) or user_has_permission(
        user, "approve", RESOURCE_TYPE_CHANGE_REQUEST
    )


def _cr_to_dict(cr: ChangeRequest) -> dict[str, Any]:
    return {
        "id": str(cr.id),
        "operation": cr.operation,
        "resource_type": cr.resource_type,
        "resource_id": cr.resource_id,
        "resource_display": cr.resource_display,
        "state": cr.state,
        "risk_reason": cr.risk_reason,
        "requested_by": cr.requested_by_display,
        "decided_by": cr.decided_by_display,
        "preview_text": cr.preview_text,
        "expires_at": cr.expires_at.isoformat(),
        "created_at": cr.created_at.isoformat(),
    }


# ── find_change_requests ─────────────────────────────────────────────


class FindChangeRequestsArgs(BaseModel):
    state: str | None = Field(
        default=None,
        description=(
            "Filter to one lifecycle state: pending / approved / rejected / "
            "executed / failed / expired / cancelled. Omit for all states."
        ),
    )
    resource_type: str | None = Field(
        default=None,
        description="Filter to one resource type (subnet / dns_zone / dhcp_scope / …).",
    )
    mine: bool = Field(
        default=False,
        description="When true, only requests the current user submitted.",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_change_requests",
    permission="self",
    description=(
        "List two-person approval change requests — risky operations "
        "(deletes, etc.) a policy queued for a second operator's approval. "
        "Each row carries the operation, frozen target, state, who "
        "requested it, who decided it, the rendered preview, and the TTL. "
        "Use to answer 'what's waiting for approval?' or 'show pending "
        "subnet deletes'. Read-only."
    ),
    args_model=FindChangeRequestsArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def find_change_requests(
    db: AsyncSession, user: User, args: FindChangeRequestsArgs
) -> dict[str, Any]:
    # #696 — this tool is the GATE queue's. Self-service portal rows share the
    # table under origin='portal' and have their own tool; without the pin the
    # two surfaces would bleed into each other.
    stmt = select(ChangeRequest).where(ChangeRequest.origin == "gate")
    if args.state is not None:
        stmt = stmt.where(ChangeRequest.state == args.state)
    if args.resource_type is not None:
        stmt = stmt.where(ChangeRequest.resource_type == args.resource_type)
    # READ RULE (#1): force own-scope for callers who aren't a superadmin /
    # approve-holder, regardless of the ``mine`` arg.
    if args.mine or not _can_see_all_change_requests(user):
        stmt = stmt.where(ChangeRequest.requested_by_user_id == user.id)
    stmt = stmt.order_by(ChangeRequest.created_at.desc()).limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())
    return {
        "change_requests": [_cr_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ── count_change_requests ────────────────────────────────────────────


class CountChangeRequestsArgs(BaseModel):
    mine: bool = Field(
        default=False,
        description="When true, count only requests the current user submitted.",
    )


@register_tool(
    name="count_change_requests",
    permission="self",
    description=(
        "Count two-person approval change requests grouped by lifecycle "
        "state (pending / executed / rejected / …). Use to size the "
        "approval backlog. Read-only."
    ),
    args_model=CountChangeRequestsArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def count_change_requests(
    db: AsyncSession, user: User, args: CountChangeRequestsArgs
) -> dict[str, Any]:
    stmt = (
        select(ChangeRequest.state, func.count(ChangeRequest.id))
        # #696 — gate rows only; portal rows are counted by count_provisioning_requests.
        .where(ChangeRequest.origin == "gate").group_by(ChangeRequest.state)
    )
    # READ RULE (#1): a non-superadmin / non-approve-holder may only count
    # their own requests — counting the whole queue leaks backlog size + (via
    # find) row contents. Force own-scope regardless of the ``mine`` arg.
    if args.mine or not _can_see_all_change_requests(user):
        stmt = stmt.where(ChangeRequest.requested_by_user_id == user.id)
    by_state: dict[str, int] = {s: 0 for s in sorted(CHANGE_REQUEST_STATES)}
    total = 0
    for state, n in (await db.execute(stmt)).all():
        by_state[state] = int(n)
        total += int(n)
    return {"total": total, "by_state": by_state}


# ── propose_approve_change_request / propose_reject_change_request ────
#
# Both reuse the proposals.py propose→Apply contract: build the
# Operation, run preview(), persist an AIOperationProposal on success,
# return the kind="proposal" card the chat drawer renders. The tool is
# read-only (writes=False); the mutation only lands when a human clicks
# Apply. Default-enabled (NN #13): no secrets, no off-prem call — and the
# blast radius is *narrowed* by the two-person spine, since the apply step
# re-enforces approver != requester + the underlying op's permission. The
# module gate (governance.approvals, default-off) keeps them invisible
# until an operator turns the feature on.


async def _propose_decision(
    db: AsyncSession,
    *,
    user: User,
    operation_name: str,
    args: ApproveChangeRequestArgs | RejectChangeRequestArgs,
) -> dict[str, Any]:
    """Run preview + persist a proposal (or surface the rejection). Mirrors
    proposals.py:_propose_via — kept local so changes.py owns its own
    propose surface without importing a sibling's private helper."""
    from app.services.ai.tools.proposals import (  # noqa: PLC0415
        _persist_proposal,
        _proposal_result,
    )

    op = operations.get_operation(operation_name)
    if op is None:
        return {"error": f"Operation {operation_name!r} is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": operation_name,
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation=operation_name,
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


@register_tool(
    name="propose_approve_change_request",
    permission=("approve", "change_request"),
    description=(
        "Prepare an approval proposal for a pending two-person change "
        "request (#62). Pass change_request_id (UUID) and an optional note. "
        "The proposal must be applied by a human operator clicking Apply — "
        "that operator becomes the approver, the underlying operation's "
        "preview re-runs as a stale-state guard, and it executes under the "
        "approver's identity. You can never self-approve. The server "
        "enforces approver != requester and that the approver holds both "
        "{approve, change_request} and the underlying op's permission. "
        "Returns a kind='proposal' card; never call twice for the same id."
    ),
    args_model=ApproveChangeRequestArgs,
    writes=False,  # The propose tool itself is read-only; apply is the write.
    category="ops",
    default_enabled=True,
    module=MODULE,
)
async def propose_approve_change_request(
    db: AsyncSession, user: User, args: ApproveChangeRequestArgs
) -> dict[str, Any]:
    return await _propose_decision(
        db, user=user, operation_name="approve_change_request", args=args
    )


@register_tool(
    name="propose_reject_change_request",
    permission=("approve", "change_request"),
    description=(
        "Prepare a rejection proposal for a pending two-person change "
        "request (#62). Pass change_request_id (UUID) and an optional note. "
        "On Apply the request is rejected and the underlying operation does "
        "NOT run. The rejecter may not be the requester (a self-reject is a "
        "cancel). Returns a kind='proposal' card; never call twice for the "
        "same id."
    ),
    args_model=RejectChangeRequestArgs,
    writes=False,  # The propose tool itself is read-only; apply is the write.
    category="ops",
    default_enabled=True,
    module=MODULE,
)
async def propose_reject_change_request(
    db: AsyncSession, user: User, args: RejectChangeRequestArgs
) -> dict[str, Any]:
    return await _propose_decision(db, user=user, operation_name="reject_change_request", args=args)


__all__ = [
    "count_change_requests",
    "find_change_requests",
    "propose_approve_change_request",
    "propose_reject_change_request",
]
