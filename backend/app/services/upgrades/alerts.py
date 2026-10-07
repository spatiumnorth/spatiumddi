"""Alert wiring for the rolling-upgrade orchestrator (#296 Phase F).

Fires ``AlertEvent`` rows through the existing alerts framework when
the orchestrator hits a terminal failure state. Operators see these
in the same surface as every other AlertRule (UI, webhooks, syslog,
SMTP) without needing a separate subscription for upgrade events.

What's covered today:

* ``cluster_upgrade_failed`` — the orchestrator's ``_drive_loop``
  flipped a SystemUpgradeRun row to ``state='failed'``. One event per
  failed run; auto-resolves when the next successful run completes
  (or 7 days after firing, whichever first). The body carries the
  failed node, the step it failed at, and a structured
  ``failure_category`` so the alert text can hint at the operator's
  next action (drain stuck → check PDBs; auto-revert → check
  ``/health/live`` on the failed node; dead-node → tie into the
  #272 Phase 9 evict-and-replace flow).

What's deferred to Phase F follow-ups (noted with TODO comments):

* Pre-start etcd + pg snapshots — needs supervisor endpoint work for
  etcd-snapshot save and existing-backup-system integration for
  pg_dump. Tracked in the Phase F section of #296.
* Auto-resolve based on a successful follow-up run — the alert stays
  open until the operator clicks resolve in the UI or 7 days elapse,
  same as other transition-once rules.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.system_upgrade import SystemUpgradeRun

logger = structlog.get_logger(__name__)


# Singleton rule name + type discriminator. ``rule_type`` is a
# free-form string column today; the evaluator doesn't need to know
# about this type (events are fired directly from the orchestrator),
# but the string keeps it queryable in the alert-rule list endpoint.
CLUSTER_UPGRADE_FAILED_RULE = "cluster-upgrade-failed"
RULE_TYPE_CLUSTER_UPGRADE_FAILED = "cluster_upgrade_failed"


async def seed_cluster_upgrade_failed_alert_rule() -> None:
    """Seed the singleton ``cluster-upgrade-failed`` AlertRule.

    Idempotent: keyed on ``name`` since there's exactly one rule per
    platform. Enabled by default — a failed rolling upgrade is one
    of the few signals every multi-node operator wants to know about
    immediately. Operators who don't run rolling upgrades (docker-
    compose / single-node) can leave it on; it never fires for them.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == CLUSTER_UPGRADE_FAILED_RULE)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=CLUSTER_UPGRADE_FAILED_RULE,
                description=(
                    "Fires when the multi-node rolling-upgrade orchestrator "
                    "flips a SystemUpgradeRun row to state='failed'. The body "
                    "carries the failed node + step + structured failure "
                    "category so the operator can decide between forward-fix "
                    "(rerun once the underlying issue is resolved) and "
                    "dead-node replacement (#272 Phase 9 evict + re-pair). "
                    "Critical severity — a stalled upgrade leaves the "
                    "cluster in a partially-upgraded mixed-version state "
                    "until the operator acts."
                ),
                rule_type=RULE_TYPE_CLUSTER_UPGRADE_FAILED,
                severity="critical",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=True,
            )
        )
        await session.commit()


# ── Failure categorisation ──────────────────────────────────────────


# Categories the orchestrator stamps into ``run.last_error_category``
# + the AlertEvent's ``last_observed_value`` so the Fleet UI can
# render a category-specific hint (Phase G concern). Keeping the
# strings short + machine-readable lets the AI-tool layer also key
# off them.
CATEGORY_PREFLIGHT = "preflight_fail"
CATEGORY_DRAIN_STUCK = "drain_stuck"
CATEGORY_CORDON_FAIL = "cordon_fail"
CATEGORY_PRIMARY_NOT_MOVED = "cnpg_primary_stuck"
CATEGORY_AUTO_REVERTED = "node_auto_reverted"
CATEGORY_HEALTH_GATE_TIMEOUT = "node_unreachable_after_apply"
CATEGORY_SUPERVISOR_FAILED = "supervisor_reported_failed"
CATEGORY_CONVERGENCE_TIMEOUT = "node_did_not_rejoin"
CATEGORY_CHART_BUMP = "chart_bump_failed"
CATEGORY_UNCORDON_FAIL = "uncordon_fail"
CATEGORY_OTHER = "other"


def classify_per_node_failure(
    *,
    failed_at: str | None,
    error: str | None,
) -> str:
    """Map a Phase C step name + error into a stable category string.

    Used by both the orchestrator (when stamping ``last_error`` on the
    SystemUpgradeRun row) and the alert event body (for UI hinting).
    The mapping is deliberately conservative — when in doubt, return
    ``other`` so the operator looks at the raw message rather than
    trusting a misleading category.
    """
    if failed_at == "preflight":
        return CATEGORY_PREFLIGHT
    if failed_at == "cordon":
        return CATEGORY_CORDON_FAIL
    if failed_at == "verify_primary_moved":
        return CATEGORY_PRIMARY_NOT_MOVED
    if failed_at == "drain":
        return CATEGORY_DRAIN_STUCK
    if failed_at == "reboot":
        # The apply failed on the host before it staged the slot, or never
        # finished staging it. Either way the node was not rebooted.
        if error and "supervisor reported upgrade failed" in error:
            return CATEGORY_SUPERVISOR_FAILED
        return CATEGORY_OTHER
    if failed_at == "health_gate":
        # health_gate has three failure modes — split by the error.
        if error and "supervisor reported upgrade failed" in error:
            return CATEGORY_SUPERVISOR_FAILED
        if error and "timed out" in error:
            # Timeout here is ambiguous — could be supervisor never
            # reporting OR a Phase 8c auto-revert. Treat as "node
            # unreachable" so the operator hint is "check the box
            # came back up cleanly + look at firstboot logs."
            return CATEGORY_HEALTH_GATE_TIMEOUT
        # The version-mismatch branch (last_upgrade_state="done" but
        # installed_version != target) is the explicit auto-revert
        # signal. Per-node primitive doesn't surface that distinction
        # today — added in this Phase F edit (see per_node.py change).
        if error and "auto_reverted" in error:
            return CATEGORY_AUTO_REVERTED
        return CATEGORY_OTHER
    if failed_at == "convergence":
        # Convergence timeout = node Ready but DS pods never came up
        # OR node never came back Ready. Either way the dead-node
        # replacement flow may be the operator's next move.
        return CATEGORY_CONVERGENCE_TIMEOUT
    if failed_at == "uncordon":
        return CATEGORY_UNCORDON_FAIL
    if failed_at == "chart_bump_failed" or failed_at == "chart_bump":
        return CATEGORY_CHART_BUMP
    return CATEGORY_OTHER


def operator_hint(category: str) -> str:
    """One-liner the alert body + Fleet UI surface near the failure.

    Conservative + actionable — these go in front of an operator who
    just got paged at 3 AM. The verbose drilldown lives in the per-
    node step's detail blob.
    """
    if category == CATEGORY_PREFLIGHT:
        return (
            "Pre-flight refused the upgrade. Re-run /api/v1/upgrades/preflight"
            " to see which check failed; resolve before retrying."
        )
    if category == CATEGORY_DRAIN_STUCK:
        return (
            "Drain timed out — a workload pod blocked eviction. Check "
            "PodDisruptionBudgets + per-pod status; once unblocked, abort + "
            "plan a fresh run (drain doesn't auto-retry mid-run)."
        )
    if category == CATEGORY_CORDON_FAIL:
        return (
            "kubectl cordon failed — likely an RBAC issue. Verify the api "
            "ServiceAccount has cluster-scoped patch on nodes "
            "(api.upgradeOrchestratorRBAC.enabled=true in chart values)."
        )
    if category == CATEGORY_PRIMARY_NOT_MOVED:
        return (
            "CNPG primary didn't switch off the cordoned node within the "
            "switchover timeout. Check Cluster.status + replica replay lag; "
            "the cordon-triggered switchover only works with a caught-up "
            "replica."
        )
    if category == CATEGORY_AUTO_REVERTED:
        return (
            "Node reverted to the old slot (Phase 8c health-gate auto-revert). "
            "Check /health/live + firstboot logs on the failed node; the new "
            "slot's app stack didn't come up cleanly."
        )
    if category == CATEGORY_HEALTH_GATE_TIMEOUT:
        return (
            "Node didn't report the new version within the health-gate window. "
            "Check the supervisor's heartbeat + appliance row "
            "last_upgrade_state. If the box is unreachable, consider the "
            "dead-node replacement flow (Fleet → evict + re-pair, #272 Ph9)."
        )
    if category == CATEGORY_SUPERVISOR_FAILED:
        return (
            "Supervisor reported the slot apply failed (dd / firstboot exit "
            "non-zero). Check spatium-upgrade-slot.log on the node; the slot "
            "image may be corrupt or the partition layout incompatible."
        )
    if category == CATEGORY_CONVERGENCE_TIMEOUT:
        return (
            "Node rebooted but didn't fully rejoin (etcd member / DaemonSet "
            "pods didn't come back Ready). Consider dead-node replacement "
            "(Fleet → evict + re-pair, #272 Ph9)."
        )
    if category == CATEGORY_CHART_BUMP:
        return (
            "Every node committed the new slot but the post-loop chart bump "
            "failed (Deployment rollout / migrate Job). Forward-fix: helm "
            "rollback the chart, debug, re-apply the bump."
        )
    if category == CATEGORY_UNCORDON_FAIL:
        return (
            "Node upgraded cleanly but uncordon / maintenance-window clear "
            "failed. The node is still cordoned; ``kubectl uncordon`` it by "
            "hand + patch the CNPG Cluster's nodeMaintenanceWindow.inProgress "
            "to false."
        )
    return (
        "Check progress.per_node[<node>].error in the run detail + decide "
        "between forward-fix (rerun) and dead-node replacement (#272 Ph9)."
    )


# ── Emit helper ─────────────────────────────────────────────────────


async def emit_upgrade_failed_alert(
    db: AsyncSession,
    run: SystemUpgradeRun,
    *,
    failed_node: str | None,
    failed_at_step: str | None,
    category: str,
) -> AlertEvent | None:
    """Open an AlertEvent against the cluster-upgrade-failed rule.

    Returns the new event (or None if the rule isn't seeded yet, e.g.
    a fresh install whose ``main.py`` startup hook hasn't fired before
    this function got called — defensive nullable return). Caller is
    responsible for ``db.commit``; we follow the orchestrator's pattern
    of letting the calling transaction handle persistence.
    """
    rule = await db.scalar(select(AlertRule).where(AlertRule.name == CLUSTER_UPGRADE_FAILED_RULE))
    if rule is None or not rule.enabled:
        logger.warning(
            "upgrade_failed_alert_skipped_no_rule",
            run_id=str(run.id),
            rule_present=rule is not None,
        )
        return None

    hint = operator_hint(category)
    message_parts = [
        f"Cluster rolling upgrade to {run.target_version} failed",
    ]
    if failed_node:
        message_parts.append(f"on node {failed_node!r}")
    if failed_at_step:
        message_parts.append(f"at step {failed_at_step!r}")
    message_parts.append(f"({category}).")
    message_parts.append(hint)
    message = " ".join(message_parts)

    detail: dict[str, Any] = {
        "run_id": str(run.id),
        "target_version": run.target_version,
        "failed_node": failed_node,
        "failed_at_step": failed_at_step,
        "category": category,
        "hint": hint,
        "last_error": run.last_error,
    }

    evt = AlertEvent(
        rule_id=rule.id,
        subject_type="system_upgrade_run",
        subject_id=str(run.id),
        subject_display=f"upgrade → {run.target_version}",
        severity=rule.severity,
        message=message,
        fired_at=datetime.now(UTC),
        last_observed_value=detail,
    )
    db.add(evt)
    # #1576 — deliver to forward targets; the generic evaluator skips
    # externally-driven rule types, so without this the event only
    # ever showed in-app. Caller still owns the commit. Delivery
    # failures must not break the orchestrator's failure transition.
    try:
        await db.flush()
        from app.services import alerts as alert_service  # noqa: PLC0415
        from app.services import audit_forward  # noqa: PLC0415

        targets = await audit_forward._load_targets()  # noqa: SLF001
        ds, dw, dm = await alert_service._deliver(rule, evt, targets)  # noqa: SLF001
        evt.delivered_syslog = ds
        evt.delivered_webhook = dw
        evt.delivered_smtp = dm
    except Exception as exc:  # noqa: BLE001
        logger.warning("upgrade_failed_alert_delivery_failed", run_id=str(run.id), error=str(exc))
    logger.info(
        "upgrade_failed_alert_emitted",
        run_id=str(run.id),
        category=category,
        failed_node=failed_node,
        failed_at_step=failed_at_step,
    )
    return evt
