"""Operator Copilot tools for the self-service request portal (issue #696).

Three tools, all carrying ``module="governance.requests"`` so disabling the
(default-off) feature module strips them from the AI surface (NN #14):

* ``find_provisioning_requests`` — list self-service requests with optional
  state / kind / mine filters. Answers "what is waiting on me?".
* ``count_provisioning_requests`` — counts grouped by state, for backlog size.
* ``list_request_kinds`` — the catalog of what may be requested.

All three are **read-only and default-enabled**. There is deliberately no
``propose_submit_request`` write tool: submitting is already the cheapest,
least privileged action in the system (it provisions nothing and any user with
the Requester role can do it through the form), so a propose→Apply card would
add ceremony without adding safety.

Approving is the action that actually provisions, and it is reachable from the
Copilot through the **existing** ``propose_approve_change_request`` /
``propose_reject_change_request`` tools — portal rows are change requests, so
those work on them unchanged. That is intentional: routing every approval
through one pair of tools means the two-person guarantees are enforced in one
place. As with #62, the model can never self-approve — the decision runs only
when a human clicks Apply, and that human becomes the approver.

Read scoping mirrors the REST router exactly: a caller who cannot approve sees
only their own requests.
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
from app.services.ai.tools.base import register_tool
from app.services.requests.catalog import all_kinds, get_kind

MODULE = "governance.requests"
_ORIGIN = "portal"


def _can_see_all(user: User) -> bool:
    """Identical read rule to the REST router: superadmin or an approve-holder
    sees the whole queue; everyone else sees only what they submitted.

    The MCP tools have no router gate, so the scope is enforced in-tool —
    without it the Copilot would leak every requester's args / preview /
    justification to anyone who can reach the module.
    """
    return is_effective_superadmin(user) or user_has_permission(
        user, "approve", RESOURCE_TYPE_CHANGE_REQUEST
    )


def _to_dict(cr: ChangeRequest) -> dict[str, Any]:
    return {
        "id": str(cr.id),
        "operation": cr.operation,
        "resource_type": cr.resource_type,
        "resource_display": cr.resource_display,
        "state": cr.state,
        "justification": cr.justification,
        "requested_by": cr.requested_by_display,
        "decided_by": cr.decided_by_display,
        "preview_text": cr.preview_text,
        "error": cr.error,
        "expires_at": cr.expires_at.isoformat(),
        "created_at": cr.created_at.isoformat(),
    }


# ── find_provisioning_requests ───────────────────────────────────────


class FindProvisioningRequestsArgs(BaseModel):
    state: str | None = Field(
        default=None,
        description=(
            "Filter by lifecycle state: pending / approved / rejected / "
            "executed / failed / expired / cancelled."
        ),
    )
    kind: str | None = Field(
        default=None,
        description=(
            "Filter by catalog kind: subnet / ip_address / dns_record / " "dhcp_reservation."
        ),
    )
    mine: bool = Field(
        default=False,
        description="When true, only requests the current user submitted.",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_provisioning_requests",
    permission="self",
    description=(
        "List self-service provisioning requests (IP / subnet / DNS / DHCP) "
        "submitted through the request portal, with optional state, kind and "
        "mine filters. Use to answer 'what is waiting for my approval?' or "
        "'what did I ask for?'. Read-only."
    ),
    args_model=FindProvisioningRequestsArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def find_provisioning_requests(
    db: AsyncSession, user: User, args: FindProvisioningRequestsArgs
) -> dict[str, Any]:
    stmt = select(ChangeRequest).where(ChangeRequest.origin == _ORIGIN)
    if args.state is not None:
        stmt = stmt.where(ChangeRequest.state == args.state)
    if args.kind is not None:
        entry = get_kind(args.kind)
        if entry is None:
            return {
                "requests": [],
                "count": 0,
                "error": (
                    f"Unknown request kind {args.kind!r}. Valid kinds: "
                    + ", ".join(k.kind for k in all_kinds())
                ),
            }
        stmt = stmt.where(ChangeRequest.operation == entry.operation)
    # READ RULE: force own-scope for callers who cannot approve, regardless of
    # the ``mine`` arg.
    if args.mine or not _can_see_all(user):
        stmt = stmt.where(ChangeRequest.requested_by_user_id == user.id)
    stmt = stmt.order_by(ChangeRequest.created_at.desc()).limit(args.limit)
    rows = list((await db.execute(stmt)).scalars().all())
    return {"requests": [_to_dict(r) for r in rows], "count": len(rows)}


# ── count_provisioning_requests ──────────────────────────────────────


class CountProvisioningRequestsArgs(BaseModel):
    mine: bool = Field(
        default=False,
        description="When true, count only requests the current user submitted.",
    )


@register_tool(
    name="count_provisioning_requests",
    permission="self",
    description=(
        "Count self-service provisioning requests grouped by lifecycle state. "
        "Use to size the request backlog waiting on approvers. Read-only."
    ),
    args_model=CountProvisioningRequestsArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def count_provisioning_requests(
    db: AsyncSession, user: User, args: CountProvisioningRequestsArgs
) -> dict[str, Any]:
    stmt = (
        select(ChangeRequest.state, func.count(ChangeRequest.id))
        .where(ChangeRequest.origin == _ORIGIN)
        .group_by(ChangeRequest.state)
    )
    if args.mine or not _can_see_all(user):
        stmt = stmt.where(ChangeRequest.requested_by_user_id == user.id)
    by_state: dict[str, int] = {s: 0 for s in sorted(CHANGE_REQUEST_STATES)}
    total = 0
    for state, n in (await db.execute(stmt)).all():
        by_state[state] = int(n)
        total += int(n)
    return {"by_state": by_state, "total": total}


# ── list_request_kinds ───────────────────────────────────────────────


class ListRequestKindsArgs(BaseModel):
    pass


@register_tool(
    name="list_request_kinds",
    permission="authenticated",
    description=(
        "List what can be asked for through the self-service request portal "
        "(subnet / IP address / DNS record / DHCP reservation), with a "
        "description of what approving each one does. Read-only."
    ),
    args_model=ListRequestKindsArgs,
    category="read",
    default_enabled=True,
    module=MODULE,
)
async def list_request_kinds(
    db: AsyncSession, user: User, args: ListRequestKindsArgs
) -> dict[str, Any]:
    return {
        "kinds": [
            {
                "kind": k.kind,
                "label": k.label,
                "description": k.description,
                "category": k.category,
                "operation": k.operation,
            }
            for k in all_kinds()
        ]
    }
