"""Nightly audit-log chain verifier (issue #73).

Walks the chain in seq order, recomputes each row's hash, and writes
an ``AlertEvent`` against the ``audit-chain-broken`` builtin alert
rule when something doesn't line up. Surfaces through the same
delivery surface (webhooks / email / Slack / Teams / Discord) as
every other AlertRule, so an operator running the platform doesn't
need to subscribe to a separate channel for tampering.

The verifier is read-only — it never tries to "repair" the chain. A
break is by definition evidence of state we can't trust to fix
automatically.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.db import task_session
from app.models.alerts import AlertEvent, AlertRule
from app.services.audit_chain import verify_chain

logger = structlog.get_logger(__name__)


_RULE_NAME = "audit-chain-broken"


async def _async_verify_and_alert() -> dict:
    async with task_session() as db:
        result = await verify_chain(db)
        rule = (
            await db.execute(select(AlertRule).where(AlertRule.name == _RULE_NAME))
        ).scalar_one_or_none()

        if result.ok:
            logger.info("audit_chain_verify_ok", rows_checked=result.rows_checked)
            # Auto-resolve any open break event so the dashboard
            # green-flips after operators investigated and the next
            # nightly walk shows the chain back in sync.
            if rule is not None:
                open_evt = (
                    await db.execute(
                        select(AlertEvent)
                        .where(AlertEvent.rule_id == rule.id)
                        .where(AlertEvent.resolved_at.is_(None))
                        .order_by(AlertEvent.fired_at.desc())
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if open_evt is not None:
                    open_evt.resolved_at = datetime.now(UTC)
                    await db.commit()
            return {"ok": True, "rows_checked": result.rows_checked}

        if rule is None:
            # Seeder ran late or operator deleted the rule. Log loudly
            # but don't crash the verifier — the break itself is the
            # important signal, not the alert plumbing.
            logger.error(
                "audit_chain_broken_no_rule",
                rows_checked=result.rows_checked,
                breaks=len(result.breaks),
            )
            return {"ok": False, "rows_checked": result.rows_checked, "broken": len(result.breaks)}

        # Dedupe: if a still-open break event already exists against
        # the same first-broken seq, skip — the existing event already
        # covers the situation. Subsequent breaks past the first don't
        # generate fresh events; a single tampered range = one alert.
        first = result.breaks[0]
        existing = (
            await db.execute(
                select(AlertEvent)
                .where(AlertEvent.rule_id == rule.id)
                .where(AlertEvent.resolved_at.is_(None))
                .where(AlertEvent.subject_id == first.audit_id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return {
                "ok": False,
                "rows_checked": result.rows_checked,
                "broken": len(result.breaks),
                "deduped": True,
            }

        evt = AlertEvent(
            rule_id=rule.id,
            subject_type="audit_log",
            subject_id=first.audit_id,
            subject_display=f"audit_log.seq={first.seq}",
            severity="critical",
            message=(
                f"Audit-log chain break at seq={first.seq} ({first.reason}: "
                f"{first.action} {first.resource_type} {first.resource_id}). "
                f"Total {len(result.breaks)} broken row(s) across {result.rows_checked} checked."
            ),
            fired_at=datetime.now(UTC),
            last_observed_value={
                "rows_checked": result.rows_checked,
                "break_count": len(result.breaks),
                "first_break": {
                    "seq": first.seq,
                    "audit_id": first.audit_id,
                    "reason": first.reason,
                    "action": first.action,
                    "resource_type": first.resource_type,
                    "resource_id": first.resource_id,
                    "expected_hash": first.expected_hash,
                    "actual_hash": first.actual_hash,
                },
            },
        )
        db.add(evt)
        await db.flush()
        # #1576 — deliver to forward targets like every other alert;
        # the generic evaluator skips externally-driven rule types,
        # so without this the event only ever showed in-app.
        try:
            from app.services import alerts as alert_service  # noqa: PLC0415
            from app.services import audit_forward  # noqa: PLC0415

            targets = await audit_forward._load_targets()  # noqa: SLF001
            ds, dw, dm = await alert_service._deliver(rule, evt, targets)  # noqa: SLF001
            evt.delivered_syslog = ds
            evt.delivered_webhook = dw
            evt.delivered_smtp = dm
        except Exception as exc:  # noqa: BLE001 — delivery must not lose the alert
            logger.warning("audit_chain_broken_delivery_failed", error=str(exc))
        await db.commit()
        logger.error(
            "audit_chain_broken",
            rows_checked=result.rows_checked,
            breaks=len(result.breaks),
            first_break_seq=first.seq,
            first_break_reason=first.reason,
        )
        return {"ok": False, "rows_checked": result.rows_checked, "broken": len(result.breaks)}


@shared_task(
    name="app.tasks.audit_chain_verify.verify_audit_chain",
    bind=True,
    # Issue #222 — autoretry on transient DB / network classes so a
    # nightly verifier hit by a DB blip doesn't have to wait a full
    # 24 h for the next beat firing.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
)
def verify_audit_chain(self: object) -> dict:  # type: ignore[type-arg]
    """Celery entry point. Runs nightly via beat; idempotent on its
    own — re-runs are cheap and self-resolving when the break clears."""
    return asyncio.run(_async_verify_and_alert())
