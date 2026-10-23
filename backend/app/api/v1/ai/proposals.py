"""Operator Copilot operation-proposal API (issue #90 Phase 2).

Endpoints to list, get, apply, and discard pending write-operation
proposals. The chat surface fires ``POST /apply`` when the operator
clicks the Apply button on a proposal card (the propose tool ran
earlier and persisted the proposal); ``POST /discard`` is the
explicit reject button.

Permissions:
    * **List / get / apply / discard** are all scoped to the calling
      user — a row created by user A cannot be applied or even
      observed by user B. Superadmin gets the same scoping; if cross-
      user proposal management is needed it'll come in a follow-up.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.core.agent_wake import collecting_wakes
from app.models.ai import AIOperationProposal
from app.services.ai import operations
from app.services.ai.operations_risky import RISKY_OPERATION_NAMES
from app.services.approvals.gate import gate_or_execute

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────


class ProposalResponse(BaseModel):
    id: uuid.UUID
    operation: str
    args: dict[str, Any]
    preview_text: str
    expires_at: datetime
    applied_at: datetime | None
    discarded_at: datetime | None
    result: dict[str, Any] | None
    error: str | None
    created_at: datetime


class ApplyResponse(BaseModel):
    ok: bool
    detail: str
    result: dict[str, Any] | None
    proposal: ProposalResponse


# ── Helpers ──────────────────────────────────────────────────────────────


def _to_response(p: AIOperationProposal) -> ProposalResponse:
    return ProposalResponse(
        id=p.id,
        operation=p.operation,
        args=p.args or {},
        preview_text=p.preview_text or "",
        expires_at=p.expires_at,
        applied_at=p.applied_at,
        discarded_at=p.discarded_at,
        result=p.result,
        error=p.error,
        created_at=p.created_at,
    )


def _terminal_state(p: AIOperationProposal) -> str | None:
    """Return a human-readable terminal state, or None if still pending."""
    if p.applied_at is not None:
        return f"already applied at {p.applied_at.isoformat()}"
    if p.discarded_at is not None:
        return f"already discarded at {p.discarded_at.isoformat()}"
    if p.expires_at < datetime.now(UTC):
        return f"expired at {p.expires_at.isoformat()}"
    return None


# ── Endpoints ────────────────────────────────────────────────────────────


@router.get("/proposals", response_model=list[ProposalResponse])
async def list_proposals(
    current_user: CurrentUser,
    db: DB,
    pending_only: bool = True,
) -> list[ProposalResponse]:
    stmt = select(AIOperationProposal).where(AIOperationProposal.user_id == current_user.id)
    if pending_only:
        stmt = stmt.where(
            AIOperationProposal.applied_at.is_(None),
            AIOperationProposal.discarded_at.is_(None),
            AIOperationProposal.expires_at > datetime.now(UTC),
        )
    stmt = stmt.order_by(AIOperationProposal.created_at.desc()).limit(50)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_response(r) for r in rows]


@router.get("/proposals/{proposal_id}", response_model=ProposalResponse)
async def get_proposal(
    proposal_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ProposalResponse:
    row = await db.get(AIOperationProposal, proposal_id)
    if row is None or row.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _to_response(row)


@router.post("/proposals/{proposal_id}/apply", response_model=ApplyResponse)
async def apply_proposal(
    proposal_id: uuid.UUID, current_user: CurrentUser, db: DB, request: Request
) -> ApplyResponse:
    row = await db.get(AIOperationProposal, proposal_id)
    if row is None or row.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    terminal = _terminal_state(row)
    if terminal is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot apply — proposal {terminal}",
        )
    op = operations.get_operation(row.operation)
    if op is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Operation {row.operation!r} is not registered",
        )

    # SECURITY (#400, C2): authoritative RBAC backstop. The propose→apply
    # flow has NO router-level require_*_permission dependency, so without
    # this gate an authenticated Viewer who owns a proposal row could apply
    # it and write IPAM / DNS / DHCP / multicast / alert rows the equivalent
    # REST route would 403. We enforce the operation's declared
    # (action, resource_type) here, before re-validating args or dispatching
    # — matching the permission the equivalent REST route requires. The
    # per-_apply_ checks in services/ai/operations.py are defense in depth;
    # this endpoint is the primary gate.
    try:
        operations.enforce_operation_permission(current_user, op)
    except operations.OperationPermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    # Re-validate args through the operation's pydantic model — guards
    # against the rare case where the model schema changed between
    # propose and apply (a redeploy mid-flight).
    try:
        args = op.args_model.model_validate(row.args or {})
    except Exception as exc:
        # Surface the validation failure as the proposal's error
        # state so the UI shows the right message.
        row.error = f"args validation failed: {exc}"
        row.discarded_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(row)
        return ApplyResponse(
            ok=False,
            detail=row.error,
            result=None,
            proposal=_to_response(row),
        )

    # Two-person approval (#62): a risky op reached via propose→Apply must
    # route through the SAME gate the equivalent REST route uses — otherwise
    # the AI surface would be a bypass around the approval workflow (#601
    # review). Module-off / no matching policy / superadmin-exempt → the gate
    # returns None and we apply inline exactly as before.
    if op.name in RISKY_OPERATION_NAMES:
        pending = await gate_or_execute(db, current_user, request, operation=op, args=args)
        if pending is not None:
            row.applied_at = datetime.now(UTC)
            row.result = {
                "queued_for_approval": True,
                "change_request_id": str(pending.change_request_id),
                "state": pending.state,
            }
            row.error = None
            await db.commit()
            await db.refresh(row)
            return ApplyResponse(
                ok=True,
                detail="Queued for two-person approval",
                result=row.result,
                proposal=_to_response(row),
            )

    try:
        # #2040 — /ai mounts without ``wake_publishing``, so an op's own
        # ``collect_wake`` (DHCP scope delete, static create, …) was a silent
        # no-op here and its agents converged only on the safety tick. Open the
        # collector around the apply: it publishes after apply() commits and
        # drops the batch if it raises.
        async with collecting_wakes():
            result = await op.apply(db, current_user, args)
    except operations.OperationPermissionError as exc:
        # SECURITY (#400, C2): a permission failure raised by the op's
        # own defense-in-depth check surfaces as a clean 403, not a
        # rolled-back ok=False result. (The authoritative gate above
        # should already have caught the common case.)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # Apply rolled back its own transaction; reload the proposal
        # from a fresh state and stamp the error.
        await db.rollback()
        row = await db.get(AIOperationProposal, proposal_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Proposal vanished mid-apply — investigate",
            ) from exc
        row.error = str(exc)
        row.applied_at = None
        await db.commit()
        await db.refresh(row)
        logger.warning(
            "ai_proposal_apply_failed",
            proposal_id=str(proposal_id),
            operation=row.operation,
            error=str(exc),
        )
        return ApplyResponse(
            ok=False,
            detail=str(exc),
            result=None,
            proposal=_to_response(row),
        )

    # The operation's own apply() already committed the mutation to
    # whatever rows it touches. We follow up with a separate write to
    # stamp the proposal's terminal state — the audit row from the
    # apply path is independent so a partial-stamp doesn't unwind the
    # mutation.
    row = await db.get(AIOperationProposal, proposal_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Proposal vanished mid-apply",
        )
    row.applied_at = datetime.now(UTC)
    row.result = result if isinstance(result, dict) else {"value": result}
    row.error = None
    await db.commit()
    await db.refresh(row)

    logger.info(
        "ai_proposal_applied",
        proposal_id=str(proposal_id),
        operation=row.operation,
        user_id=str(current_user.id),
    )
    return ApplyResponse(
        ok=True,
        detail="applied",
        result=row.result,
        proposal=_to_response(row),
    )


@router.post("/proposals/{proposal_id}/discard", response_model=ProposalResponse)
async def discard_proposal(
    proposal_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> ProposalResponse:
    row = await db.get(AIOperationProposal, proposal_id)
    if row is None or row.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if row.applied_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot discard — already applied",
        )
    if row.discarded_at is None:
        row.discarded_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(row)
    return _to_response(row)
