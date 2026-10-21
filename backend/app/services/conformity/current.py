"""The CURRENT conformity state — what the summary, the PDF and the
Copilot rollup report (#2278).

``conformity_result`` is append-only history: every pass of a policy
writes one row per target it resolved, all stamped with the same
``evaluated_at``, and the engine stamps ``policy.last_evaluated_at``
with that same instant once the pass completes. So "the current state
of a policy" is exactly the rows of its most recent pass:

    result.policy_id   = policy.id
    result.evaluated_at = policy.last_evaluated_at

That one join is what retires a stale result. A target that was
deleted, or reclassified out of the policy's scope, is not resolved by
the next pass and so has no row in it — its old ``fail`` stops being
current the moment the pass after its removal lands, without any
cascade (``resource_id`` is a free string, so nothing could cascade)
and without re-deriving the policy's target filter in SQL. That filter
is resolved in exactly one place, the engine's ``_resolve_targets``,
which reads inherited classification; a second copy here would drift
from it, and a drifted copy decides what an auditor is shown.

The rejected alternative, "newest row per (policy, resource) across
all history", is what the readers did before: it can only ever add
targets, never retire one, and it reads the whole history to do it.

Two further properties fall out of the join:

* A pass that dies part-way never becomes current. The engine stamps
  ``last_evaluated_at`` only after its loop, so the rows a broken pass
  flushed carry an ``evaluated_at`` no policy points at, and the
  previous complete pass keeps reporting.
* The read is bounded by policies × current targets, not by history:
  ``ix_conformity_result_policy_evaluated (policy_id, evaluated_at)``
  is an equality lookup on both columns, one probe per enabled policy.

Disabled policies are excluded outright. Their last pass describes a
check nobody is running any more, so reporting it as current state is
the same defect as reporting a deleted target.

The ``DISTINCT ON (policy, resource)`` is defensive: a single pass
resolves each target once, so it only matters if two passes of one
policy ever stamped the same instant.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import Select, and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.conformity import ConformityPolicy, ConformityResult

# Fields that change WHAT a policy checks or which targets it covers.
# Editing one makes the last pass answer a different question, so every
# policy-update path (REST PATCH and the Copilot's update operation)
# goes through :func:`retire_pass_if_rescoped`.
SCOPE_FIELDS = frozenset({"target_kind", "target_filter", "check_kind", "check_args"})


def retire_pass_if_rescoped(policy: ConformityPolicy, changed: Iterable[str]) -> bool:
    """Clear ``policy.last_evaluated_at`` when ``changed`` touches a
    scope field. The summary and PDF then stop reporting that pass as
    current state, and the beat task sees the policy as due on its next
    tick. Returns whether it cleared."""
    if SCOPE_FIELDS.isdisjoint(changed):
        return False
    policy.last_evaluated_at = None
    return True


def _current(stmt: Select, *, framework: str | None) -> Select:
    """Restrict ``stmt`` (which selects from ``conformity_result``) to
    the latest pass of each enabled policy, one row per resource."""
    stmt = (
        stmt.join(
            ConformityPolicy,
            and_(
                ConformityPolicy.id == ConformityResult.policy_id,
                ConformityResult.evaluated_at == ConformityPolicy.last_evaluated_at,
            ),
        )
        .where(ConformityPolicy.enabled.is_(True))
        .distinct(
            ConformityResult.policy_id,
            ConformityResult.resource_kind,
            ConformityResult.resource_id,
        )
        .order_by(
            ConformityResult.policy_id,
            ConformityResult.resource_kind,
            ConformityResult.resource_id,
            ConformityResult.id,
        )
    )
    if framework is not None:
        stmt = stmt.where(ConformityPolicy.framework == framework)
    return stmt


async def current_results(
    db: AsyncSession, *, framework: str | None = None
) -> list[ConformityResult]:
    """Every current result row (see module docstring)."""
    rows = await db.execute(_current(select(ConformityResult), framework=framework))
    return list(rows.scalars().all())


async def current_status_counts(
    db: AsyncSession, *, framework: str | None = None
) -> dict[str, dict[str, int]]:
    """``{framework: {status: count}}`` over the current results,
    aggregated in the database so no result row reaches Python."""
    latest = _current(
        select(ConformityResult.policy_id, ConformityResult.status),
        framework=framework,
    ).subquery()
    stmt = (
        select(
            ConformityPolicy.framework,
            latest.c.status,
            func.count().label("n"),
        )
        .join(ConformityPolicy, ConformityPolicy.id == latest.c.policy_id)
        .group_by(ConformityPolicy.framework, latest.c.status)
    )
    out: dict[str, dict[str, int]] = {}
    for fw, status, n in (await db.execute(stmt)).all():
        out.setdefault(fw, {})[status] = int(n)
    return out


__all__ = [
    "SCOPE_FIELDS",
    "current_results",
    "current_status_counts",
    "retire_pass_if_rescoped",
]
