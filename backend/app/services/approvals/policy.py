"""Approval policy engine (#62).

Pure async decision layer: given an ``(resource_type, action[, count])``
tuple, return the strongest *enabled* :class:`ApprovalPolicy` that
matches, or ``None`` when no approval is required. Kept side-effect-free
and superadmin-agnostic on purpose — the *gate* (``gate.py``, later
slice) decides the superadmin bypass using the returned row's
``applies_to_superadmin`` flag. Splitting the decision this way keeps the
engine trivially testable and the gate the single place authorization is
applied.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ApprovalPolicy

logger = structlog.get_logger(__name__)

# ── Currently-gateable surface (#4) ────────────────────────────────────────
#
# A policy is only enforceable when there's a registered risky Operation
# whose ``required_permission`` produces the policy's (action, resource_type).
# In P1 the only gated action is ``delete`` and the only gated resource types
# are the six delete-covered families. The policy CRUD validates against these
# sets so an operator can't create an *enabled-but-inert* policy for an action
# that isn't wired yet (the fail-open #2/#4 the seed used to ship). P2 widens
# both sets as bulk_delete / bulk_edit / bulk_allocate / factory_reset /
# import_commit ops land their gate threading.
GATEABLE_ACTIONS: frozenset[str] = frozenset({"delete", "admin"})
GATEABLE_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "subnet",
        "ip_block",
        "ip_space",
        "dns_zone",
        "dhcp_scope",
        "dhcp_server_group",
        # #601 — active block sync: creating/arming a network block pushes a
        # real firewall/gateway block (broad blast radius), so it is a
        # two-person-rule candidate. Gated as ``admin:manage_block_sync``.
        "manage_block_sync",
    }
)


def gateable_pairs() -> frozenset[tuple[str, str]]:
    """The ``(action, resource_type)`` pairs an ENABLED policy can actually
    gate — exactly those declared by a registered risky ``Operation``.

    Validating a policy against these PAIRS (not the two axes independently)
    is what prevents an enabled-but-inert policy: once ``GATEABLE_ACTIONS`` /
    ``GATEABLE_RESOURCE_TYPES`` hold more than one value each, their product
    admits cross pairs like ``(admin, subnet)`` or ``(delete, manage_block_
    sync)`` that no op declares, so ``match_policy`` could never select them
    and the operator would get silent, false protection (#601 review).
    """
    from app.services.ai.operations import get_operation  # noqa: PLC0415
    from app.services.ai.operations_risky import RISKY_OPERATION_NAMES  # noqa: PLC0415

    pairs: set[tuple[str, str]] = set()
    for name in RISKY_OPERATION_NAMES:
        op = get_operation(name)
        if op is not None and op.required_permission is not None:
            pairs.add(op.required_permission)
    return frozenset(pairs)


async def match_policy(
    db: AsyncSession,
    resource_type: str,
    action: str,
    count: int | None = None,
) -> ApprovalPolicy | None:
    """Strongest enabled policy matching ``(resource_type | "*") + action``.

    A row matches when it is ``enabled``, its ``action`` equals ``action``,
    and its ``resource_type`` is either ``resource_type`` or the wildcard
    ``"*"``. A matched row's threshold is satisfied when ``min_count IS
    NULL`` (always require approval) OR ``count`` is provided and
    ``count >= min_count``.

    An exact ``resource_type`` match wins over a ``"*"`` match. Among rows
    of equal specificity, the one with the *lower* ``min_count`` (the
    stricter threshold; ``NULL`` is strictest) wins — so the request is
    gated by the tightest applicable rule.

    Returns ``None`` when nothing matches → no approval required, the
    caller proceeds inline. The superadmin bypass is decided by the CALLER
    via the returned row's ``applies_to_superadmin`` flag, NOT here.
    """
    rows = (
        await db.execute(
            select(ApprovalPolicy).where(
                ApprovalPolicy.enabled.is_(True),
                ApprovalPolicy.action == action,
                ApprovalPolicy.resource_type.in_([resource_type, "*"]),
            )
        )
    ).scalars()

    best: ApprovalPolicy | None = None
    for policy in rows:
        # Threshold gate. ``gate_or_execute`` passes ``count=1`` for the
        # single-target deletes, so ``min_count`` 1 gates them and a higher
        # threshold waits for a bulk op that passes a real row count (#4909).
        if policy.min_count is not None and (count is None or count < policy.min_count):
            continue
        if best is None or _is_stronger(policy, best, resource_type):
            best = policy

    if best is not None:
        logger.debug(
            "approval_policy.matched",
            resource_type=resource_type,
            action=action,
            count=count,
            policy_id=str(best.id),
            policy_name=best.name,
        )
    return best


def _is_stronger(candidate: ApprovalPolicy, current: ApprovalPolicy, resource_type: str) -> bool:
    """True if ``candidate`` should beat the currently-selected ``current``.

    Exact ``resource_type`` beats wildcard ``"*"``. At equal specificity,
    the stricter threshold wins — ``min_count IS NULL`` (always) beats any
    numeric threshold, and a lower numeric threshold beats a higher one.
    """
    cand_exact = candidate.resource_type == resource_type
    curr_exact = current.resource_type == resource_type
    if cand_exact != curr_exact:
        return cand_exact

    # Equal specificity → compare thresholds (None == strictest).
    if candidate.min_count is None:
        return current.min_count is not None
    if current.min_count is None:
        return False
    return candidate.min_count < current.min_count


__all__ = ["GATEABLE_ACTIONS", "GATEABLE_RESOURCE_TYPES", "gateable_pairs", "match_policy"]
