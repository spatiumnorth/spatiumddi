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
from datetime import UTC, datetime, timedelta

import structlog
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import task_session
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditChainCheckpoint
from app.services.audit_chain import (
    FULL_PASS_INTERVAL,
    ChainVerifyResult,
    checkpoint_still_valid,
    verify_chain,
)

logger = structlog.get_logger(__name__)


_RULE_NAME = "audit-chain-broken"


#: How far in the future ``full_pass_done_at`` may sit before it is treated
#: as forged rather than as clock skew between workers.
_FUTURE_SKEW = timedelta(hours=1)


def _full_pass_reason(done_at: datetime | None, now: datetime) -> str | None:
    """Why the stored checkpoint must not be resumed from, or None.

    The checkpoint lives in the database it vouches for, so anyone able to
    rewrite ``audit_log`` can rewrite it too. A ``full_pass_done_at`` set into
    the future would otherwise never age past ``FULL_PASS_INTERVAL`` and
    would switch the weekly full pass off for good; a date this worker did
    not write is treated as no full pass at all. (``None`` with a nonzero
    ``verified_seq`` is a full pass still in progress, which is resumed.)
    """
    if done_at is None:
        return None
    age = now - done_at
    if age < -_FUTURE_SKEW:
        return "future"
    if age > FULL_PASS_INTERVAL:
        return "stale"
    return None


async def _walk_with_checkpoint(db: AsyncSession) -> ChainVerifyResult:
    """Verify the chain, resuming from the stored checkpoint (#2286).

    Walks only rows added since the last clean run, unless there is no
    usable checkpoint, the last full pass is older than
    ``FULL_PASS_INTERVAL`` or dated in the future, in which case it starts
    from the first row.
    The checkpoint is advanced after every page while the walk is clean, so
    a run cut short keeps its progress and the next one carries on; it is
    never advanced past a break, so a break is found again (and deduped)
    rather than skipped. A failure raises: nothing here turns a walk that
    did not finish into a result.
    """
    now = datetime.now(UTC)
    cp = await db.get(AuditChainCheckpoint, 1)
    start: tuple[int, str] | None = None
    if cp is not None and cp.verified_seq > 0 and cp.verified_hash:
        reason = _full_pass_reason(cp.full_pass_done_at, now)
        if reason is None and not await checkpoint_still_valid(
            db, cp.verified_seq, cp.verified_hash
        ):
            reason = "mismatch"
        if reason is None:
            start = (cp.verified_seq, cp.verified_hash)
        elif reason == "future":
            # This worker never writes a future date: the row was edited,
            # or a clock is badly wrong. Either way it is worth a look.
            logger.warning(
                "audit_chain_verify_full_pass",
                reason=reason,
                full_pass_done_at=str(cp.full_pass_done_at),
            )
        else:
            logger.info("audit_chain_verify_full_pass", reason=reason)
    if cp is None:
        cp = AuditChainCheckpoint(id=1, verified_seq=0)
        db.add(cp)
    if start is None:
        cp.verified_seq = 0
        cp.verified_hash = None
        cp.full_pass_done_at = None
    await db.commit()

    async def _save(last_seq: int, last_hash: str, _rows: int, breaks: int) -> None:
        if breaks:
            return
        cp.verified_seq = last_seq
        cp.verified_hash = last_hash
        cp.updated_at = datetime.now(UTC)
        await db.commit()

    result = await verify_chain(db, start_after=start, on_chunk=_save)
    if result.ok and result.complete and cp.full_pass_done_at is None:
        cp.full_pass_done_at = datetime.now(UTC)
        await db.commit()
    return result


async def _async_verify_and_alert() -> dict:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        try:
            result = await _walk_with_checkpoint(db)
        except Exception:
            # A walk that dies (timeout, lost connection) verified nothing
            # past its checkpoint; say so loudly and fail the task rather
            # than return anything that reads as "verified".
            logger.exception("audit_chain_verify_failed")
            raise
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
            return {
                "ok": True,
                "rows_checked": result.rows_checked,
                "verified_through_seq": result.last_seq,
            }

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

        if not rule.enabled:
            # #1988 — a disabled rule opens nothing and delivers nothing,
            # as the acme / upgrade / conformity rules already behave.
            # Disabling resolves the open events, so without this gate the
            # next pass would re-open one and deliver it for a rule the
            # operator switched off. The break is still logged below.
            logger.error(
                "audit_chain_broken_rule_disabled",
                rows_checked=result.rows_checked,
                breaks=len(result.breaks),
            )
            return {
                "ok": False,
                "rows_checked": result.rows_checked,
                "broken": len(result.breaks),
                "rule_disabled": True,
            }

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
        # #2261 — commit the event BEFORE delivering it. Delivering first
        # meant a failed commit (and this task's autoretry) re-paged for an
        # event that was never stored; now a retry finds it open and dedupes.
        await db.commit()
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
