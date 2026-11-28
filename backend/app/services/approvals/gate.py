"""Approval gate — the single interception point risky handlers call (#62).

A covered delete handler calls :func:`gate_or_execute` at the top. The
return value tells the handler what to do:

* ``None``  → no approval required. The handler executes inline exactly as
  today (delegating to ``operation.apply``). This is the *default* path:
  the ``governance.approvals`` module is off out of the box, and even when
  on, only enabled policies gate. Behaviour is byte-identical to pre-#62.
* :class:`ChangeRequestPending` → a policy matched and the caller can't
  self-approve. A ``change_request`` row is persisted (+ its ``requested``
  audit row, committed) and the handler must return ``202 Accepted`` with
  ``pending.as_dict()`` instead of executing.

Control flow (pinned by the #62 design):

1. Module off → ``None`` (never touches the policy table).
2. Derive ``(action, resource_type)`` for the policy lookup *directly*
   from the operation's ``required_permission`` (e.g. ``("delete",
   "subnet")``) — no hand-maintained name→action map to drift out of
   sync (#2/#3). An import-time assertion proves every registered risky
   op carries a ``required_permission`` so a future op that forgets one
   fails loudly at boot rather than silently never-gating.
3. ``match_policy`` → no enabled match → ``None``.
4. Superadmin caller + ``not policy.applies_to_superadmin`` → ``None``.
5. ``operation.preview`` → if not ok, raise 409 (don't queue a doomed
   request — matches today's inline 409).
6. Persist the ``change_request`` (+ audit), commit, return the pending.

#4 (audit-before-respond): the ``requested`` audit row is committed inside
:func:`create_change_request` before this returns. #2 (async throughout):
everything here is async.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from fastapi import HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.services.ai.operations import Operation, get_operation
from app.services.ai.operations_risky import RISKY_OPERATION_NAMES
from app.services.approvals.policy import (
    GATEABLE_ACTIONS,
    GATEABLE_RESOURCE_TYPES,
    match_policy,
)
from app.services.approvals.service import create_change_request
from app.services.feature_modules import is_module_enabled

logger = structlog.get_logger(__name__)

MODULE_ID = "governance.approvals"


def _assert_risky_ops_have_permission() -> None:
    """Fail loudly at import if any registered risky op can't be gated (#4).

    The gate derives the policy-lookup ``(action, resource_type)`` straight
    from ``operation.required_permission``; an op that forgets to declare one
    would silently never gate (fail-open). Worse: an op that DOES declare a
    permission whose ``(action, resource_type)`` is not in the gateable sets
    passes a "permission exists" check but ``match_policy`` can never select a
    policy for it (the policy CRUD rejects non-gateable pairs), so it would
    still run inline with no approval — a fail-open trap. Require BOTH: the
    permission exists AND its pair is gateable, so a future risky op forces an
    explicit widening of ``GATEABLE_ACTIONS`` / ``GATEABLE_RESOURCE_TYPES``
    instead of silently never gating. Catch the drift at boot.
    """
    missing: list[str] = []
    non_gateable: list[str] = []
    for name in RISKY_OPERATION_NAMES:
        op = get_operation(name)
        if op is None or op.required_permission is None:
            missing.append(name)
            continue
        action, resource_type = op.required_permission
        if action not in GATEABLE_ACTIONS or resource_type not in GATEABLE_RESOURCE_TYPES:
            non_gateable.append(f"{name} ({action}:{resource_type})")
    if missing:  # pragma: no cover — import-time invariant
        raise RuntimeError(
            f"risky operations missing required_permission (cannot derive "
            f"approval policy keys): {sorted(missing)}"
        )
    if non_gateable:  # pragma: no cover — import-time invariant
        raise RuntimeError(
            "risky operations declare a non-gateable (action, resource_type) — "
            "match_policy can never gate them, so they would run inline with no "
            f"approval (fail-open). Widen GATEABLE_ACTIONS / "
            f"GATEABLE_RESOURCE_TYPES: {sorted(non_gateable)}"
        )


_assert_risky_ops_have_permission()


@dataclass(frozen=True)
class ChangeRequestPending:
    """Returned when an operation was queued for approval instead of run."""

    change_request_id: Any
    state: str
    preview_text: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "change_request_id": str(self.change_request_id),
            "state": self.state,
            "preview_text": self.preview_text,
        }


def _resource_id_from_args(args: BaseModel) -> str | None:
    """Best-effort single-target id for the change_request row.

    Covered ops carry a single ``*_id`` (subnet_id / block_id / space_id /
    zone_id / scope_id / group_id). Pick the first such field; ops with no
    single target leave ``resource_id`` NULL.
    """
    data = args.model_dump(mode="json")
    # Prefer the operation's own target id over a secondary (e.g. delete_zone
    # carries both group_id and zone_id — zone_id is the real target).
    for key in ("zone_id", "scope_id", "subnet_id", "block_id", "space_id", "group_id", "row_id"):
        val = data.get(key)
        if val is not None:
            return str(val)
    return None


def _refuse_inline_non_superadmin(user: User, operation: Operation, args: BaseModel) -> None:
    """The route-time 403 for a superadmin step the caller is about to run inline (#4790).

    The apply refuses a non-superadmin with an ``OperationPermissionError`` (so a
    queued request stays pending), but an inline caller has no spine to translate
    that, and it would surface as a 500. Refuse here with the route's own 403.
    """
    if operation.superadmin_when is not None and operation.superadmin_when(args):
        from app.api.deps import ensure_superadmin  # noqa: PLC0415

        ensure_superadmin(user)


async def gate_or_execute(
    db: AsyncSession,
    user: User,
    request: Request,
    *,
    operation: Operation,
    args: BaseModel,
    count: int | None = None,
) -> ChangeRequestPending | None:
    """Decide whether ``operation`` must be queued for second-person approval.

    ``count`` is the number of rows the operation touches. Every covered op
    is a single-target delete, so it defaults to 1 (#4909): a policy with
    ``min_count`` 1 gates every such delete, while a higher threshold needs a
    bulk op that passes a real count.

    Returns ``None`` to tell the caller to execute inline (today's behaviour);
    a :class:`ChangeRequestPending` to tell the caller to return 202.
    """
    # 1. Module off → never gate, never query policies. This is the path
    #    every existing install takes (default-off) → zero behaviour change.
    if not await is_module_enabled(db, MODULE_ID):
        _refuse_inline_non_superadmin(user, operation, args)
        return None

    # 2. Derive the policy lookup keys directly from the operation's
    #    declared permission — no hand-maintained name→action map (#2).
    #    ``required_permission`` is guaranteed present for every risky op by
    #    the import-time assertion above; the guard keeps mypy + a
    #    defensive run-inline fallthrough for any op dispatched here that
    #    didn't declare one.
    if operation.required_permission is None:
        return None
    action, resource_type = operation.required_permission

    # 3. Strongest enabled matching policy, or None.
    policy = await match_policy(db, resource_type, action, 1 if count is None else count)
    if policy is None:
        _refuse_inline_non_superadmin(user, operation, args)
        return None

    # 4. Superadmin bypass — only when the policy explicitly allows it.
    if is_effective_superadmin(user) and not policy.applies_to_superadmin:
        return None

    # 5. Re-run preview now; don't queue a request that can't execute.
    preview = await operation.preview(db, user, args)
    if not preview.ok:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=preview.detail)

    # 6. Persist the pending change request + its audit row, then commit.
    #    #18: args are frozen as JSON via ``model_dump(mode="json")`` here and
    #    rehydrated with ``args_model.model_validate(...)`` at approve time.
    #    That round-trip assumes every arg type is JSON-coercible (UUID→str,
    #    bool, int, str) — true for all six covered delete ops. A future op
    #    carrying a non-JSON-native arg type would need a custom (de)serializer.
    cr = await create_change_request(
        db,
        user=user,
        request=request,
        operation=operation.name,
        resource_type=resource_type,
        resource_id=_resource_id_from_args(args),
        resource_display=preview.preview_text[:500],
        args=args.model_dump(mode="json"),
        preview_text=preview.preview_text,
        risk_reason=policy.name or f"{action}:{resource_type}",
        ttl_hours=policy.ttl_hours,
    )
    await db.commit()
    logger.info(
        "approval_gate.queued",
        change_request_id=str(cr.id),
        operation=operation.name,
        resource_type=resource_type,
        policy_id=str(policy.id),
        requested_by=str(user.id),
    )
    return ChangeRequestPending(
        change_request_id=cr.id, state="pending", preview_text=cr.preview_text
    )


__all__ = ["ChangeRequestPending", "gate_or_execute"]
