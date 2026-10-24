"""Periodic "refresh due domain rows from RDAP" task.

Phase 2 of issue #87. Beat fires :func:`refresh_due_domains` every
hour; per-row gating uses ``Domain.next_check_at`` so a row whose
interval hasn't elapsed is skipped without an RDAP call. The cadence
itself is operator-tunable via
``PlatformSettings.domain_whois_interval_hours`` (default 24 h, min 1
h, max 168 h) — the task reads the setting on every run, so cadence
changes in the UI take effect on the next beat tick without restarting
celery-beat.

Each refresh delegates to
:func:`app.services.domain_refresh.refresh_one_domain` so the
synchronous endpoint and the scheduled task have identical write
semantics. Audit-log behaviour: only rows whose state moved
meaningfully (whois_state / registrar / nameserver_drift /
dnssec_signed) get an audit entry — "still ok" ticks would drown the
log without adding signal.

Idempotent: re-running is a no-op for rows whose
``next_check_at`` is still in the future. RDAP failures isolate to
the row that triggered them; the rest of the sweep proceeds.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import or_, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.models.domain import Domain
from app.models.settings import PlatformSettings
from app.services.dns.tld_registry import effective_registry
from app.services.domain_refresh import (
    build_refresh_audit_payload,
    refresh_one_domain,
)
from app.services.feature_modules import is_module_enabled

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1

# Cadence floor / ceiling. Mirrors the API validator on
# PlatformSettings.domain_whois_interval_hours so a stale DB row that
# predates the validator can't drive a 0-second poll loop.
_MIN_INTERVAL_HOURS = 1
_MAX_INTERVAL_HOURS = 168


def _clamp_interval(hours: int | None) -> int:
    if hours is None or hours < _MIN_INTERVAL_HOURS:
        return _MIN_INTERVAL_HOURS
    if hours > _MAX_INTERVAL_HOURS:
        return _MAX_INTERVAL_HOURS
    return hours


async def _refresh_due_async() -> dict[str, Any]:
    """Sweep every Domain whose ``next_check_at`` has elapsed.

    Returns a small summary dict that surfaces in the celery task
    result + (when there's anything to log about) a single
    platform-level audit row. Per-row audit entries are written by
    ``refresh_one_domain``'s caller below for rows whose state moved.
    """
    async with task_session() as db:
        # #2325 — the module is the operator's off switch for the RDAP
        # egress. Checked before any row is read so an off module makes no
        # lookup at all, not even one whose result would be discarded.
        if not await is_module_enabled(db, "network.domains"):
            return {"status": "skipped", "reason": "module_disabled"}

        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        interval_hours = _clamp_interval(ps.domain_whois_interval_hours if ps is not None else None)

        now = datetime.now(UTC)

        # NULL ``next_check_at`` means "never refreshed yet" — pick
        # those up first; the chronological order handles everything
        # else.
        rows = (
            (
                await db.execute(
                    select(Domain)
                    .where(or_(Domain.next_check_at.is_(None), Domain.next_check_at <= now))
                    .order_by(Domain.next_check_at.asc().nulls_first())
                )
            )
            .scalars()
            .all()
        )

        # #986 — resolved once for the whole sweep, not per row.
        tlds = (await effective_registry(db)).tlds

        scanned = 0
        refreshed = 0
        unreachable = 0
        # #986 — kept apart from ``unreachable`` on purpose. A name with no
        # registry behind it is not a failed lookup, and folding the two
        # together would report every .lan / .internal row as an
        # unreachable registry on every tick — the exact mislabelling this
        # change exists to remove.
        skipped_no_registry = 0
        state_changes = 0
        registrar_changes = 0
        drift_changes = 0
        dnssec_changes = 0
        errors: list[str] = []

        for d in rows:
            scanned += 1
            try:
                result = await refresh_one_domain(
                    d, interval_hours=interval_hours, tlds=tlds, now=now
                )
            except Exception as exc:  # noqa: BLE001 — don't let one row poison the sweep
                errors.append(f"{d.name}: {exc}")
                logger.warning(
                    "domain_whois_refresh_row_failed",
                    domain=d.name,
                    error=str(exc),
                )
                # Mark a check attempt anyway so we don't hot-loop the
                # row on every beat tick.
                d.whois_last_checked_at = now
                continue

            refreshed += 1
            if result.skipped_reason is not None:
                skipped_no_registry += 1
            elif not result.rdap_reachable:
                unreachable += 1
            if result.state_changed:
                state_changes += 1
            if result.registrar_changed:
                registrar_changes += 1
            if result.nameserver_drift_changed:
                drift_changes += 1
            if result.dnssec_signed_changed:
                dnssec_changes += 1

            # Per-row audit only on a meaningful transition. "Still ok"
            # ticks would drown the audit log; the platform-level
            # summary row at the end captures the sweep itself.
            if result.any_meaningful_change:
                db.add(
                    AuditLog(
                        user_display_name="<system>",
                        auth_source="system",
                        action="refresh_whois",
                        resource_type="domain",
                        resource_id=str(d.id),
                        resource_display=d.name,
                        result="success",
                        new_value=build_refresh_audit_payload(d, result),
                    )
                )

        # Sweep summary — only when there was anything to summarise.
        if scanned and (refreshed or errors):
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="domain-whois-refresh",
                    resource_type="platform",
                    resource_id=str(_SINGLETON_ID),
                    resource_display="auto-refresh",
                    result="error" if errors else "success",
                    new_value={
                        "scanned": scanned,
                        "refreshed": refreshed,
                        "unreachable": unreachable,
                        "skipped_no_registry": skipped_no_registry,
                        "state_changes": state_changes,
                        "registrar_changes": registrar_changes,
                        "drift_changes": drift_changes,
                        "dnssec_changes": dnssec_changes,
                        "interval_hours": interval_hours,
                        "errors": errors[:20],
                    },
                )
            )

        await db.commit()

        if scanned:
            logger.info(
                "domain_whois_refresh_completed",
                scanned=scanned,
                refreshed=refreshed,
                unreachable=unreachable,
                skipped_no_registry=skipped_no_registry,
                state_changes=state_changes,
                registrar_changes=registrar_changes,
                drift_changes=drift_changes,
                dnssec_changes=dnssec_changes,
                interval_hours=interval_hours,
                error_count=len(errors),
            )

        return {
            "status": "ran" if scanned else "idle",
            "scanned": scanned,
            "refreshed": refreshed,
            "unreachable": unreachable,
            "skipped_no_registry": skipped_no_registry,
            "state_changes": state_changes,
            "registrar_changes": registrar_changes,
            "drift_changes": drift_changes,
            "dnssec_changes": dnssec_changes,
            "interval_hours": interval_hours,
            "errors": len(errors),
        }


@celery_app.task(name="app.tasks.domain_whois_refresh.refresh_due_domains", bind=True)
def refresh_due_domains(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Beat-fired entrypoint — sweeps every domain whose
    ``next_check_at`` has elapsed.

    Idempotent: re-running it back-to-back is safe; the second pass
    will see the next_check_at values just stamped by the first and
    treat every row as "not due".
    """
    try:
        return asyncio.run(_refresh_due_async())
    except Exception as exc:  # noqa: BLE001
        logger.exception("domain_whois_refresh_failed", error=str(exc))
        raise


async def _refresh_one_by_id_async(domain_id: str) -> dict[str, Any]:
    """RDAP-refresh a single domain by id, in its own session.

    Shares the exact ``refresh_one_domain`` service the beat sweep + the
    manual endpoint use — no duplicated refresh logic. Writes a per-row
    audit entry only on a meaningful change (the same gate the sweep
    uses), so a freshly-created domain that RDAP can't resolve doesn't
    add a noise row on top of the ``create`` audit already written.
    """
    async with task_session() as db:
        # #2325 — a lookup queued just before the module was switched off.
        if not await is_module_enabled(db, "network.domains"):
            return {"status": "skipped", "reason": "module_disabled", "domain_id": domain_id}

        d = await db.get(Domain, uuid.UUID(domain_id))
        if d is None:
            # Created then deleted before the task ran — nothing to do.
            return {"status": "missing", "domain_id": domain_id}

        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        interval_hours = _clamp_interval(ps.domain_whois_interval_hours if ps is not None else None)
        now = datetime.now(UTC)
        tlds = (await effective_registry(db)).tlds

        try:
            result = await refresh_one_domain(d, interval_hours=interval_hours, tlds=tlds, now=now)
        except Exception as exc:  # noqa: BLE001 — one bad lookup shouldn't crash the worker
            logger.warning("domain_whois_refresh_one_failed", domain=d.name, error=str(exc))
            d.whois_last_checked_at = now  # record the attempt so the beat sweep paces itself
            await db.commit()
            return {"status": "error", "domain": d.name, "error": str(exc)}

        if result.any_meaningful_change:
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="refresh_whois",
                    resource_type="domain",
                    resource_id=str(d.id),
                    resource_display=d.name,
                    result="success",
                    new_value=build_refresh_audit_payload(d, result),
                )
            )
        await db.commit()

        logger.info(
            "domain_whois_refresh_one_completed",
            domain=d.name,
            rdap_reachable=result.rdap_reachable,
            skipped_reason=result.skipped_reason,
            state_changed=result.state_changed,
        )
        return {
            # #986 — "skipped" is its own status, not a failed lookup: the
            # name has no registry behind it and never will.
            "status": "skipped" if result.skipped_reason else "ran",
            "domain": d.name,
            "rdap_reachable": result.rdap_reachable,
            "skipped_reason": result.skipped_reason,
            "state_changed": result.state_changed,
        }


@celery_app.task(name="app.tasks.domain_whois_refresh.refresh_one_domain_by_id", bind=True)
def refresh_one_domain_by_id(self: object, domain_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
    """One-shot RDAP refresh for a single domain, dispatched right after
    ``create_domain`` (#278) so the row is populated within seconds
    instead of sitting empty until the next ``refresh_due_domains`` beat
    tick (up to ``domain_whois_interval_hours`` away). Thin wrapper around
    the shared ``refresh_one_domain`` service.
    """
    try:
        return asyncio.run(_refresh_one_by_id_async(domain_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception("domain_whois_refresh_one_failed", domain_id=domain_id, error=str(exc))
        raise


__all__ = ["refresh_due_domains"]
