"""Conformity evaluation engine — target resolver + result writer.

One pass through ``evaluate_policy`` is the per-policy unit. Beat
ticks every minute and calls :func:`evaluate_due_policies`, which
fans out to every enabled policy whose
``last_evaluated_at + eval_interval_hours`` is in the past.
On-demand re-evaluation calls :func:`evaluate_policy` directly.

Target resolution by ``target_kind``:

* ``platform`` — single synthetic ``("platform", "platform")`` row.
* ``subnet`` — every ``Subnet`` row matching the ``target_filter``
  predicate. Supports ``classification: pci_scope|hipaa_scope|internet_facing``
  to scope to subnets with the named flag set.
* ``ip_address`` — every ``IPAddress`` whose subnet matches the
  same ``target_filter`` predicate (the IP itself doesn't carry the
  flag; inheritance is by subnet).
* ``dns_zone`` — every ``DNSZone`` row. ``classification`` here
  means "any subnet pinned to this zone has the flag set" — see
  :func:`_resolve_dns_zones`.
* ``dhcp_scope`` — every ``DHCPScope`` whose linked subnet matches
  the predicate.

Failed → passed and passed → failed transitions can wire into the
alert framework via ``policy.fail_alert_rule_id``: when the latest
result for a (policy, resource) flips from any non-fail status to
``fail``, the engine opens an :class:`AlertEvent` against the named
rule. Operators see the change in the same alerts dashboard they
already monitor.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.conformity import ConformityPolicy, ConformityResult
from app.models.dhcp import DHCPScope
from app.models.dns import DNSZone
from app.models.ipam import IPAddress, Subnet
from app.models.multicast import MulticastGroup
from app.services import audit_forward
from app.services.alerts import _deliver_or_defer, defer_deliveries, deliver_deferred
from app.services.conformity.checks import (
    CHECK_REGISTRY,
    STATUS_FAIL,
    STATUS_NOT_APPLICABLE,
    CheckOutcome,
)

logger = structlog.get_logger(__name__)


_TARGET_KINDS: frozenset[str] = frozenset(
    {"platform", "subnet", "ip_address", "dns_zone", "dhcp_scope", "multicast_group"}
)


# ── Target resolution ───────────────────────────────────────────────


@dataclass(frozen=True)
class _ResolvedTarget:
    kind: str
    row_id: str
    display: str
    row: object | None  # the SQLAlchemy row, or None for ``platform``


async def _resolve_subnets(
    db: AsyncSession,
    target_filter: dict[str, Any],
) -> Sequence[_ResolvedTarget]:
    """Pull subnets matching the ``target_filter`` predicate.

    Recognised filter keys today:
      * ``classification`` — one of the known flag column names
        (``pci_scope`` / ``hipaa_scope`` / ``internet_facing``).
        Filters to subnets with the named flag set.
      * ``subnet_role`` — one of the network-role enum values
        (``data`` / ``voice`` / ``management`` / ``guest``). Filters
        to subnets carrying that role tag.
    """
    q = select(Subnet)
    classification = target_filter.get("classification")
    if classification in ("pci_scope", "hipaa_scope", "internet_facing"):
        col = getattr(Subnet, classification)
        q = q.where(col.is_(True))
    role = target_filter.get("subnet_role")
    if isinstance(role, str) and role:
        q = q.where(Subnet.subnet_role == role)
    rows = (await db.execute(q)).scalars().all()
    return [
        _ResolvedTarget(
            kind="subnet",
            row_id=str(s.id),
            display=f"{s.network} ({s.name or 'unnamed'})",
            row=s,
        )
        for s in rows
    ]


async def _resolve_ip_addresses(
    db: AsyncSession,
    target_filter: dict[str, Any],
) -> Sequence[_ResolvedTarget]:
    """Pull IPs whose subnet matches the predicate."""
    classification = target_filter.get("classification")
    q = select(IPAddress).join(Subnet, Subnet.id == IPAddress.subnet_id)
    if classification in ("pci_scope", "hipaa_scope", "internet_facing"):
        col = getattr(Subnet, classification)
        q = q.where(col.is_(True))
    rows = (await db.execute(q)).scalars().all()
    return [
        _ResolvedTarget(
            kind="ip_address",
            row_id=str(ip.id),
            display=str(ip.address),
            row=ip,
        )
        for ip in rows
    ]


async def _resolve_dns_zones(
    db: AsyncSession,
    target_filter: dict[str, Any],
) -> Sequence[_ResolvedTarget]:
    """Pull DNS zones. ``classification`` filter requires at least one
    subnet pinned to the zone via ``dns_zone_id`` to carry the flag.

    The link is intentionally loose — operators can pin a zone to
    multiple subnets, and a single flagged subnet is enough to bring
    the zone into scope.
    """
    classification = target_filter.get("classification")
    rows = (await db.execute(select(DNSZone))).scalars().all()
    if classification not in ("pci_scope", "hipaa_scope", "internet_facing"):
        return [
            _ResolvedTarget(kind="dns_zone", row_id=str(z.id), display=z.name, row=z) for z in rows
        ]
    col = getattr(Subnet, classification)
    flagged_zone_ids: set[str] = set()
    flagged_subnets = (await db.execute(select(Subnet).where(col.is_(True)))).scalars().all()
    for s in flagged_subnets:
        if s.dns_zone_id:
            flagged_zone_ids.add(str(s.dns_zone_id))
    return [
        _ResolvedTarget(kind="dns_zone", row_id=str(z.id), display=z.name, row=z)
        for z in rows
        if str(z.id) in flagged_zone_ids
    ]


async def _resolve_dhcp_scopes(
    db: AsyncSession,
    target_filter: dict[str, Any],
) -> Sequence[_ResolvedTarget]:
    """Pull DHCP scopes whose linked subnet matches the predicate."""
    classification = target_filter.get("classification")
    q = select(DHCPScope).join(Subnet, Subnet.id == DHCPScope.subnet_id)
    if classification in ("pci_scope", "hipaa_scope", "internet_facing"):
        col = getattr(Subnet, classification)
        q = q.where(col.is_(True))
    rows = (await db.execute(q)).scalars().all()
    return [
        _ResolvedTarget(
            kind="dhcp_scope",
            row_id=str(s.id),
            display=str(s.name or s.id),
            row=s,
        )
        for s in rows
    ]


async def _resolve_multicast_groups(
    db: AsyncSession,
    target_filter: dict[str, Any],
) -> Sequence[_ResolvedTarget]:
    """Pull every multicast group. ``target_filter`` is currently
    unused — the only built-in policy (``no_multicast_collision``)
    runs across all groups in every space, so a per-space filter
    here would only narrow what gets evaluated and that's a
    deferred refinement (issue #126 Phase 2)."""
    rows = (await db.execute(select(MulticastGroup))).scalars().all()
    return [
        _ResolvedTarget(
            kind="multicast_group",
            row_id=str(g.id),
            display=f"{g.address} ({g.name})",
            row=g,
        )
        for g in rows
    ]


async def _resolve_targets(
    db: AsyncSession,
    policy: ConformityPolicy,
) -> Sequence[_ResolvedTarget]:
    if policy.target_kind == "platform":
        return [
            _ResolvedTarget(
                kind="platform",
                row_id="platform",
                display="SpatiumDDI platform",
                row=None,
            )
        ]
    target_filter = policy.target_filter if isinstance(policy.target_filter, dict) else {}
    if policy.target_kind == "subnet":
        return await _resolve_subnets(db, target_filter)
    if policy.target_kind == "ip_address":
        return await _resolve_ip_addresses(db, target_filter)
    if policy.target_kind == "dns_zone":
        return await _resolve_dns_zones(db, target_filter)
    if policy.target_kind == "dhcp_scope":
        return await _resolve_dhcp_scopes(db, target_filter)
    if policy.target_kind == "multicast_group":
        return await _resolve_multicast_groups(db, target_filter)
    return []


# ── Alert hand-off on pass→fail transition ──────────────────────────


async def _previous_status_for(
    db: AsyncSession,
    *,
    policy_id: uuid.UUID,
    resource_kind: str,
    resource_id: str,
) -> str | None:
    """Return the most recent prior result status for this
    (policy, resource), or None if no prior row exists."""
    row = (
        await db.execute(
            select(ConformityResult.status)
            .where(
                ConformityResult.policy_id == policy_id,
                ConformityResult.resource_kind == resource_kind,
                ConformityResult.resource_id == resource_id,
            )
            .order_by(desc(ConformityResult.evaluated_at))
            .limit(1)
        )
    ).scalar_one_or_none()
    return row


async def _maybe_fire_alert(
    db: AsyncSession,
    *,
    policy: ConformityPolicy,
    target: _ResolvedTarget,
    outcome: CheckOutcome,
    previous_status: str | None,
    now: datetime,
) -> None:
    """Open an alert event when this evaluation flipped a previously
    non-fail result (or first observation) to ``fail`` and the policy
    is wired to an alert rule.

    Routes through the same delivery layer as #105's compliance_change
    events so operators see them on the existing alerts dashboard.
    Idempotent: if a matching open event already exists for this
    (rule, policy, resource) trio we skip.
    """
    if outcome.status != STATUS_FAIL:
        return
    if policy.fail_alert_rule_id is None:
        return
    if previous_status == STATUS_FAIL:
        return  # already failing — don't re-page

    rule = await db.get(AlertRule, policy.fail_alert_rule_id)
    if rule is None or not rule.enabled:
        return

    subject_id = f"{policy.id}:{target.kind}:{target.row_id}"
    existing = (
        await db.execute(
            select(AlertEvent).where(
                AlertEvent.rule_id == rule.id,
                AlertEvent.subject_type == "conformity",
                AlertEvent.subject_id == subject_id,
                AlertEvent.resolved_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return

    targets = await audit_forward._load_targets()  # noqa: SLF001
    message = (
        f"Conformity policy {policy.name!r} ({policy.framework}) "
        f"newly failing on {target.kind} {target.display}: {outcome.detail}"
    )
    event = AlertEvent(
        rule_id=rule.id,
        subject_type="conformity",
        subject_id=subject_id,
        subject_display=f"{policy.name} :: {target.display}",
        severity=policy.severity,
        message=message,
        fired_at=now,
        last_observed_value={
            "policy_id": str(policy.id),
            "policy_name": policy.name,
            "framework": policy.framework,
            "reference": policy.reference,
            "target_kind": target.kind,
            "target_id": target.row_id,
            "diagnostic": outcome.diagnostic,
        },
    )
    db.add(event)
    await db.flush()
    # #2261 — queued, not sent, when the caller defers: the event must be
    # committed before it pages anyone.
    ds, dw, dm = await _deliver_or_defer(rule, event, targets)
    event.delivered_syslog = ds
    event.delivered_webhook = dw
    event.delivered_smtp = dm


# ── Core entry points ───────────────────────────────────────────────

# #2261 — advisory-lock key serialising beat passes of
# :func:`evaluate_due_policies`. Transaction-scoped.
_EVALUATE_LOCK_KEY = 0x53504D434F4E  # "SPMCON"


async def evaluate_policy(
    db: AsyncSession,
    policy: ConformityPolicy,
    *,
    now: datetime | None = None,
) -> dict[str, int]:
    """Run one policy against every target it covers.

    Returns a summary dict (``passed`` / ``failed`` / ``warned`` /
    ``not_applicable`` / ``total``). Stamps
    ``policy.last_evaluated_at`` to ``now`` regardless of outcome
    so the beat task's "is this policy due?" check moves forward.

    The caller commits — keeps the engine reusable from both the
    HTTP "evaluate now" path (which wants a single transaction
    around the whole pass) and the beat task (which iterates).
    """
    if now is None:
        now = datetime.now(UTC)

    if policy.target_kind not in _TARGET_KINDS:
        logger.warning(
            "conformity_unknown_target_kind",
            policy=str(policy.id),
            target_kind=policy.target_kind,
        )
        policy.last_evaluated_at = now
        return {"passed": 0, "failed": 0, "warned": 0, "not_applicable": 0, "total": 0}

    check_fn = CHECK_REGISTRY.get(policy.check_kind)
    if check_fn is None:
        # Stale / unknown check_kind. Write a single not_applicable
        # result so the operator can see what's broken in the dashboard.
        policy.last_evaluated_at = now
        db.add(
            ConformityResult(
                policy_id=policy.id,
                resource_kind="platform",
                resource_id="platform",
                resource_display="(missing check)",
                evaluated_at=now,
                status=STATUS_NOT_APPLICABLE,
                detail=f"unknown check_kind {policy.check_kind!r}",
                diagnostic={"check_kind": policy.check_kind},
            )
        )
        return {"passed": 0, "failed": 0, "warned": 0, "not_applicable": 1, "total": 1}

    targets = await _resolve_targets(db, policy)
    summary = {"passed": 0, "failed": 0, "warned": 0, "not_applicable": 0, "total": 0}

    for target in targets:
        try:
            # #2261 — a check that raises a DB error has aborted the
            # transaction; without the savepoint every later statement in
            # the pass (results, alerts, ``last_evaluated_at``) failed too.
            async with db.begin_nested():
                outcome = await check_fn(
                    db,
                    target=target.row,
                    target_kind=policy.target_kind,
                    args=(policy.check_args if isinstance(policy.check_args, dict) else {}),
                    now=now,
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "conformity_check_crashed",
                policy=str(policy.id),
                check_kind=policy.check_kind,
                target_kind=target.kind,
                target_id=target.row_id,
            )
            outcome = CheckOutcome.not_applicable(
                f"check raised {exc.__class__.__name__}: {exc}",
                {"error_type": exc.__class__.__name__},
            )

        previous = await _previous_status_for(
            db,
            policy_id=policy.id,
            resource_kind=target.kind,
            resource_id=target.row_id,
        )
        result = ConformityResult(
            policy_id=policy.id,
            resource_kind=target.kind,
            resource_id=target.row_id,
            resource_display=target.display[:500],
            evaluated_at=now,
            status=outcome.status,
            detail=outcome.detail[:5000] if outcome.detail else "",
            diagnostic=outcome.diagnostic or None,
        )
        db.add(result)

        await _maybe_fire_alert(
            db,
            policy=policy,
            target=target,
            outcome=outcome,
            previous_status=previous,
            now=now,
        )

        summary["total"] += 1
        if outcome.status == "pass":
            summary["passed"] += 1
        elif outcome.status == STATUS_FAIL:
            summary["failed"] += 1
        elif outcome.status == "warn":
            summary["warned"] += 1
        else:
            summary["not_applicable"] += 1

    policy.last_evaluated_at = now
    return summary


async def evaluate_due_policies(db: AsyncSession) -> dict[str, int]:
    """Beat-driven pass: every enabled policy whose
    ``last_evaluated_at`` is older than its
    ``eval_interval_hours`` runs once.

    Per-policy failures are isolated — one broken policy doesn't
    halt the rest of the pass. ``eval_interval_hours == 0`` policies
    are skipped (operator wants on-demand only).

    #2261 — the same three properties as ``alerts.evaluate_all``: each
    policy in its own SAVEPOINT, alerts delivered only after the commit
    that stores them, and passes serialised by an advisory lock.
    """
    totals = {
        "policies_evaluated": 0,
        "passed": 0,
        "failed": 0,
        "warned": 0,
        "not_applicable": 0,
        "total": 0,
    }
    got_lock = (
        await db.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": _EVALUATE_LOCK_KEY})
    ).scalar()
    if not got_lock:
        logger.info("conformity_evaluate_skipped_locked")
        return totals

    now = datetime.now(UTC)
    pol_rows = (
        (await db.execute(select(ConformityPolicy).where(ConformityPolicy.enabled.is_(True))))
        .scalars()
        .all()
    )
    pending: list[tuple[AlertRule, AlertEvent]] = []
    for policy in pol_rows:
        if policy.eval_interval_hours <= 0:
            continue
        if policy.last_evaluated_at is not None:
            cutoff = now - timedelta(hours=policy.eval_interval_hours)
            if policy.last_evaluated_at >= cutoff:
                continue
        # Read before the savepoint: a rollback expires the row, and an
        # expired attribute cannot be lazy-loaded from an async session.
        policy_id, check_kind = str(policy.id), policy.check_kind
        try:
            with defer_deliveries() as policy_queue:
                async with db.begin_nested():
                    summary = await evaluate_policy(db, policy, now=now)
        except Exception:  # noqa: BLE001
            # Rolled back to the savepoint; its queued alerts go with it.
            logger.exception(
                "conformity_policy_eval_failed",
                policy=policy_id,
                check_kind=check_kind,
            )
            continue
        pending.extend(policy_queue)
        totals["policies_evaluated"] += 1
        for k in ("passed", "failed", "warned", "not_applicable", "total"):
            totals[k] += summary[k]
    await db.commit()
    await deliver_deferred(db, pending)
    return totals


__all__ = ["evaluate_policy", "evaluate_due_policies"]
