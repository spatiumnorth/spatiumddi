"""Scheduled DNS record changes (#4830).

A ``DNSScheduledChange`` holds a record create / update / delete until its
``scheduled_at``. This module is the half that is not HTTP: the due sweep, the
single-execution claim, the replay, and the cancel-on-trash hook.

Replay goes through the same record handlers an operator's request does
(``create_record`` / ``update_record`` / ``delete_record`` in
``app.api.v1.dns.router``), as the user who scheduled the change, so every
validation, the record-op queue (RFC 2136 / driver apply, ``enqueue_record_op``)
and the record's own audit row are the ones a live edit gets. The scheduler adds
one ``dns_scheduled_change`` audit row per outcome.

Concurrency (non-negotiable #9): a worker claims a row with one conditional
``UPDATE ... WHERE state = 'pending'``, so with several control-plane nodes (or a
retried task) exactly one runs it. A worker that dies mid-run leaves the row
``running``; :func:`fail_stuck` settles it as failed rather than replaying it,
because whether the write landed is unknown and a replay of a create or delete
would not be safe to guess at.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import HTTPException
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.agent_wake import collecting_wakes
from app.core.permissions import user_has_permission
from app.models.audit import AuditLog
from app.models.auth import Group, User
from app.models.dns import DNSRecord, DNSScheduledChange, DNSZone

logger = structlog.get_logger(__name__)

# A ``running`` claim older than this is a worker that died mid-change.
STUCK_AFTER = timedelta(minutes=15)
# Changes run per sweep; the rest wait for the next tick.
SWEEP_BATCH = 100


def record_fingerprint(record: DNSRecord) -> str:
    """Hash of the fields an update / delete is scheduled against.

    Compared again when the change runs, so a record edited in between is not
    overwritten (or removed) by a change written against the old values.
    """
    body = json.dumps(
        [
            record.name,
            record.record_type,
            record.value,
            record.ttl,
            record.priority,
            record.weight,
            record.port,
            str(record.view_id) if record.view_id else None,
        ],
        sort_keys=True,
    )
    return hashlib.sha256(body.encode()).hexdigest()


def record_label(name: str, record_type: str, zone_name: str) -> str:
    return f"{name}.{zone_name} {record_type}" if name != "@" else f"{zone_name} {record_type}"


def _audit(
    change: DNSScheduledChange,
    *,
    action: str,
    result: str,
    user: User | None = None,
    new_value: dict[str, Any] | None = None,
) -> AuditLog:
    return AuditLog(
        user_id=user.id if user is not None else None,
        user_display_name=user.display_name if user is not None else "system",
        auth_source=user.auth_source if user is not None else "system",
        action=action,
        resource_type="dns_scheduled_change",
        resource_id=str(change.id),
        resource_display=f"{change.action} {change.record_label} at {change.scheduled_at.isoformat()}",
        new_value=new_value,
        result=result,
    )


async def _apply(db: AsyncSession, change: DNSScheduledChange) -> tuple[str, str]:
    """Run the change; returns ``(state, message)``. Raises nothing the caller
    does not handle: an ``HTTPException`` from a handler is a refusal."""
    # Lazy: the router is the heaviest import in the app and this module is
    # also reached from the trash path.
    from app.api.v1.dns import router as dns_api  # noqa: PLC0415

    zone = await db.get(DNSZone, change.zone_id)
    if zone is None:
        return "cancelled", "The zone was deleted or moved to Trash before the change ran."
    record: DNSRecord | None = None
    if change.action != "create":
        record = await db.get(DNSRecord, change.record_id) if change.record_id else None
        if record is None:
            return "cancelled", "The record was deleted or moved to Trash before the change ran."
        if change.base_fingerprint and record_fingerprint(record) != change.base_fingerprint:
            return "failed", "The record changed after this change was scheduled; not applied."

    user = (
        (
            await db.execute(
                select(User)
                .where(User.id == change.created_by_user_id)
                .options(selectinload(User.groups).selectinload(Group.roles))
            )
        ).scalar_one_or_none()
        if change.created_by_user_id
        else None
    )
    if user is None or not user.is_active:
        return "failed", "The user who scheduled this change no longer exists or is inactive."
    needed = "delete" if change.action == "delete" else "write"
    if not user_has_permission(user, needed, "dns_record", change.record_id):
        return "failed", f"The scheduling user no longer has '{needed}' on DNS records."

    group_id = zone.group_id
    async with collecting_wakes():
        if change.action == "create":
            created = await dns_api.create_record(
                group_id, zone.id, dns_api.RecordCreate.model_validate(change.payload), db, user
            )
            change.record_id = created.id
            warning = getattr(created, "provider_warning", None)
        elif change.action == "update":
            assert record is not None
            updated = await dns_api.update_record(
                group_id,
                zone.id,
                record.id,
                dns_api.RecordUpdate.model_validate(change.payload),
                db,
                user,
            )
            warning = getattr(updated, "provider_warning", None)
        else:
            assert record is not None
            await dns_api.delete_record(group_id, zone.id, record.id, db, user)
            warning = None
    return "executed", f"Applied. Provider warning: {warning}" if warning else "Applied."


async def run_change(db: AsyncSession, change_id: uuid.UUID) -> str:
    """Claim and run one due change. Returns the state it ended in, or
    ``"skipped"`` when another worker holds it or it is not due."""
    now = datetime.now(UTC)
    claimed = await db.execute(
        update(DNSScheduledChange)
        .where(
            DNSScheduledChange.id == change_id,
            DNSScheduledChange.state == "pending",
            DNSScheduledChange.scheduled_at <= now,
        )
        .values(state="running", started_at=now)
        .returning(DNSScheduledChange.id)
    )
    if claimed.first() is None:
        await db.rollback()
        return "skipped"
    await db.commit()

    change = await db.get(DNSScheduledChange, change_id)
    if change is None:  # purged with its zone between the claim and now
        return "skipped"
    # Everything below is read again after a rollback, so keep only scalars.
    try:
        state, message = await _apply(db, change)
    except HTTPException as exc:
        await db.rollback()
        state, message = "failed", f"Refused: {exc.detail}"
    except Exception as exc:  # noqa: BLE001 — the row must leave 'running'
        await db.rollback()
        logger.exception("dns_scheduled_change_error", change_id=str(change_id))
        state, message = "failed", f"Unexpected error: {type(exc).__name__}: {exc}"

    change = await db.get(DNSScheduledChange, change_id, populate_existing=True)
    if change is None:
        return state
    change.state = state
    change.result_message = message[:2000]
    change.finished_at = datetime.now(UTC)
    db.add(
        _audit(
            change,
            action="scheduled_execute",
            result="success" if state == "executed" else "error",
            new_value={"state": state, "message": message[:2000]},
        )
    )
    await db.commit()
    return state


async def fail_stuck(db: AsyncSession) -> int:
    """Settle ``running`` rows whose worker died (see the module docstring)."""
    cutoff = datetime.now(UTC) - STUCK_AFTER
    rows = (
        (
            await db.execute(
                select(DNSScheduledChange).where(
                    DNSScheduledChange.state == "running",
                    DNSScheduledChange.started_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    for change in rows:
        change.state = "failed"
        change.finished_at = datetime.now(UTC)
        change.result_message = (
            "The worker stopped before this change finished; check the record before rescheduling."
        )
        db.add(_audit(change, action="scheduled_execute", result="error"))
    if rows:
        await db.commit()
    return len(rows)


async def run_due(db: AsyncSession) -> dict[str, int]:
    """One sweep: run every pending change whose time has come."""
    counts = {"executed": 0, "failed": 0, "cancelled": 0, "skipped": 0, "stuck": 0}
    counts["stuck"] = await fail_stuck(db)
    ids = (
        (
            await db.execute(
                select(DNSScheduledChange.id)
                .where(
                    DNSScheduledChange.state == "pending",
                    DNSScheduledChange.scheduled_at <= datetime.now(UTC),
                )
                .order_by(DNSScheduledChange.scheduled_at)
                .limit(SWEEP_BATCH)
            )
        )
        .scalars()
        .all()
    )
    for change_id in ids:
        outcome = await run_change(db, change_id)
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


async def cancel_for_trash(
    db: AsyncSession,
    *,
    zone_ids: list[uuid.UUID],
    record_ids: list[uuid.UUID],
    user_id: uuid.UUID | None,
) -> int:
    """Cancel the pending changes aimed at zones / records being moved to Trash.

    Called from ``apply_soft_delete``. A restore does not bring them back: the
    operator re-schedules what they still want, having seen it listed as
    cancelled with this reason.
    """
    if not zone_ids and not record_ids:
        return 0
    conds = []
    if zone_ids:
        conds.append(DNSScheduledChange.zone_id.in_(zone_ids))
    if record_ids:
        conds.append(DNSScheduledChange.record_id.in_(record_ids))
    rows = (
        (
            await db.execute(
                select(DNSScheduledChange).where(DNSScheduledChange.state == "pending", or_(*conds))
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for change in rows:
        change.state = "cancelled"
        change.finished_at = now
        change.result_message = (
            "Cancelled: its zone or record was moved to Trash. Restoring it does not re-arm "
            "this change."
        )
        db.add(
            AuditLog(
                user_id=user_id,
                user_display_name="system",
                auth_source="system",
                action="scheduled_cancel",
                resource_type="dns_scheduled_change",
                resource_id=str(change.id),
                resource_display=f"{change.action} {change.record_label}",
                result="success",
            )
        )
    return len(rows)
