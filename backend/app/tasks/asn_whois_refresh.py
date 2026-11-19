"""Periodic ASN RDAP refresh task.

Beat fires this every hour; the task itself walks every ``asn`` row
whose ``next_check_at`` has elapsed (or is NULL — newly-created rows
get refreshed on the next tick) and calls
:func:`app.services.rdap_asn.lookup_asn` to pull fresh holder data.

Per-row state machine on the result:

* RDAP returned a payload, ``holder_org`` matches the previous
  non-empty snapshot → ``whois_state="ok"``.
* RDAP returned a payload, ``holder_org`` differs → ``whois_state="drift"``
  (the alert evaluator picks this up via ``asn_holder_drift``).
* RDAP returned ``None`` → ``whois_state="unreachable"`` and we
  bump ``whois_data.consecutive_failures``; the alert evaluator
  fires ``asn_whois_unreachable`` once that hits 3.
* ``kind="private"`` → ``whois_state="n/a"``, refresh skipped (no
  RIR delegates private numbers, so RDAP would only ever 404).

After every touch ``next_check_at`` is bumped by
``PlatformSettings.asn_whois_interval_hours`` (default 24h, min 1h).
The hourly beat tick is just the cadence ceiling; per-row gating is
what actually paces refreshes.

Audit-log every state transition (mirrors the
``dhcp_pull_leases`` pattern) so the operator can see in the audit
trail exactly when a holder change was detected.

Idempotent — re-running before any row is due is a no-op.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import or_, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.asn import ASN
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1


def _datetime_to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


async def _refresh_one_asn(
    db: Any, asn_row: ASN, interval_hours: int, now: datetime
) -> dict[str, Any]:
    """Refresh a single ASN row. Returns a small per-row summary used
    by the caller's audit log + counters.

    Pure RDAP — no legacy WHOIS fallback in Phase 2.
    """
    # Deferred import keeps the celery startup lean.
    from app.services.rdap_asn import lookup_asn  # noqa: PLC0415

    previous_state = asn_row.whois_state
    previous_holder = (asn_row.holder_org or "").strip()
    next_check_at = now + timedelta(hours=interval_hours)

    # Private rows: skip the RDAP call. We still bump ``next_check_at``
    # so the dispatcher doesn't hammer the row every tick.
    if asn_row.kind == "private":
        if asn_row.whois_state != "n/a":
            asn_row.whois_state = "n/a"
        asn_row.whois_last_checked_at = now
        asn_row.next_check_at = next_check_at
        return {
            "asn": asn_row.number,
            "result": "skipped_private",
            "transitioned": previous_state != asn_row.whois_state,
            "old_state": previous_state,
            "new_state": asn_row.whois_state,
        }

    payload = await lookup_asn(int(asn_row.number))

    # Track consecutive failures inside ``whois_data`` so we don't
    # need a schema migration just to count them. Read whatever's
    # already there, never assume the dict shape.
    existing_data = asn_row.whois_data if isinstance(asn_row.whois_data, dict) else {}
    consecutive_failures = int(existing_data.get("consecutive_failures") or 0)

    if payload is None:
        consecutive_failures += 1
        asn_row.whois_state = "unreachable"
        asn_row.whois_last_checked_at = now
        asn_row.next_check_at = next_check_at
        # Keep prior raw payload but stamp the failure counter + last
        # error timestamp so the UI can surface it.
        merged = dict(existing_data)
        merged["consecutive_failures"] = consecutive_failures
        merged["last_error_at"] = _datetime_to_iso(now)
        asn_row.whois_data = merged
        return {
            "asn": asn_row.number,
            "result": "unreachable",
            "transitioned": previous_state != "unreachable",
            "old_state": previous_state,
            "new_state": "unreachable",
            "consecutive_failures": consecutive_failures,
        }

    # Successful RDAP fetch. Reset the failure counter, write the
    # raw payload, derive ``whois_state`` from the holder diff.
    new_holder = (payload.get("holder_org") or "").strip() or None

    if new_holder is not None and previous_holder and previous_holder != new_holder:
        new_state = "drift"
    else:
        new_state = "ok"

    asn_row.holder_org = new_holder
    asn_row.whois_state = new_state
    asn_row.whois_last_checked_at = now
    asn_row.next_check_at = next_check_at

    # Persist a serialisable version of the RDAP response — the raw
    # ``last_modified_at`` field is a ``datetime`` which the JSON
    # serializer in ``app.db`` already coerces via ``default=str``.
    # Persist ``previous_holder`` so the detail-page drift viewer can
    # show the before/after side-by-side without consulting the audit
    # log. Always recorded — even on a non-drift refresh — so the UI
    # can render "no change since last check" when previous == current.
    snapshot = {
        "holder_org": new_holder,
        "previous_holder": previous_holder or None,
        "registry": payload.get("registry"),
        "name": payload.get("name"),
        "last_modified_at": _datetime_to_iso(payload.get("last_modified_at")),
        "raw": payload.get("raw"),
        "consecutive_failures": 0,
    }
    asn_row.whois_data = snapshot

    return {
        "asn": asn_row.number,
        "result": "ok",
        "transitioned": previous_state != new_state,
        "old_state": previous_state,
        "new_state": new_state,
        "old_holder": previous_holder or None,
        "new_holder": new_holder,
    }


async def _run_refresh() -> dict[str, Any]:
    async with task_session() as db:
        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        # Settings row may not exist yet on a brand-new install — fall
        # back to the documented default.
        interval_hours = 24
        if ps is not None:
            interval_hours = max(1, min(168, int(ps.asn_whois_interval_hours or 24)))

        now = datetime.now(UTC)

        # Fetch every row whose ``next_check_at`` is NULL or has elapsed.
        # ``kind="private"`` rows are still picked up so we can stamp
        # ``whois_state="n/a"`` on legacy rows that pre-date Phase 2.
        rows = (
            (
                await db.execute(
                    select(ASN).where(or_(ASN.next_check_at.is_(None), ASN.next_check_at <= now))
                )
            )
            .scalars()
            .all()
        )

        if not rows:
            return {"status": "ran", "refreshed": 0, "transitions": 0, "errors": 0}

        refreshed = 0
        transitions = 0
        errors = 0
        transitions_summary: list[dict[str, Any]] = []

        for asn_row in rows:
            try:
                summary = await _refresh_one_asn(db, asn_row, interval_hours, now)
            except Exception as exc:  # noqa: BLE001 — don't poison the whole sweep
                errors += 1
                logger.warning(
                    "asn_whois_refresh_row_failed",
                    asn=asn_row.number,
                    error=str(exc),
                )
                continue

            refreshed += 1
            if summary.get("transitioned"):
                transitions += 1
                # Audit-log every state transition so an operator can
                # see exactly when holder drift was first detected.
                db.add(
                    AuditLog(
                        user_display_name="<system>",
                        auth_source="system",
                        action="whois_state_transition",
                        resource_type="asn",
                        resource_id=str(asn_row.id),
                        resource_display=f"AS{asn_row.number}",
                        result="success",
                        changed_fields=["whois_state"],
                        old_value={"whois_state": summary.get("old_state")},
                        new_value={
                            "whois_state": summary.get("new_state"),
                            "old_holder": summary.get("old_holder"),
                            "new_holder": summary.get("new_holder"),
                        },
                    )
                )
                transitions_summary.append(
                    {
                        "asn": asn_row.number,
                        "old_state": summary.get("old_state"),
                        "new_state": summary.get("new_state"),
                    }
                )

        await db.commit()

        logger.info(
            "asn_whois_refresh_completed",
            refreshed=refreshed,
            transitions=transitions,
            errors=errors,
        )
        return {
            "status": "ran",
            "refreshed": refreshed,
            "transitions": transitions,
            "errors": errors,
            "transitions_summary": transitions_summary[:20],
        }


@celery_app.task(name="app.tasks.asn_whois_refresh.refresh_due_asns", bind=True)
@module_gated("network.asn")
def refresh_due_asns(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Beat-fired hourly. Per-row ``next_check_at`` gates the actual
    pace; ``PlatformSettings.asn_whois_interval_hours`` controls the
    cadence operator-side without restarting beat."""
    try:
        return asyncio.run(_run_refresh())
    except Exception as exc:  # noqa: BLE001
        logger.exception("asn_whois_refresh_failed", error=str(exc))
        raise


async def _refresh_one_by_id_async(asn_id: str) -> dict[str, Any]:
    """RDAP (+ RPKI for public ASNs) refresh a single ASN by id.

    Reuses the same per-row services the beat sweeps + manual endpoints
    use — the whois state machine here, plus rpki_roa_refresh's per-row
    reconciler for public rows. Private rows skip both RDAP and RPKI
    (RIRs issue neither for private AS numbers); ``_refresh_one_asn``
    still stamps ``whois_last_checked_at`` so the UI poll converges.
    """
    async with task_session() as db:
        row = await db.get(ASN, uuid.UUID(asn_id))
        if row is None:
            return {"status": "missing", "asn_id": asn_id}

        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        whois_interval = 24
        rpki_interval = 4
        rpki_source = "cloudflare"
        if ps is not None:
            whois_interval = max(1, min(168, int(ps.asn_whois_interval_hours or 24)))
            rpki_interval = max(1, min(168, int(ps.rpki_roa_refresh_interval_hours or 4)))
            candidate = (ps.rpki_roa_source or "cloudflare").lower()
            if candidate in {"cloudflare", "ripe"}:
                rpki_source = candidate

        now = datetime.now(UTC)

        try:
            summary = await _refresh_one_asn(db, row, whois_interval, now)
        except Exception as exc:  # noqa: BLE001 — one bad lookup mustn't crash the worker
            logger.warning("asn_whois_refresh_one_failed", asn=row.number, error=str(exc))
            row.whois_last_checked_at = now  # record the attempt so the sweep paces itself
            await db.commit()
            return {"status": "error", "asn": row.number, "error": str(exc)}

        if summary.get("transitioned"):
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="whois_state_transition",
                    resource_type="asn",
                    resource_id=str(row.id),
                    resource_display=f"AS{row.number}",
                    result="success",
                    changed_fields=["whois_state"],
                    old_value={"whois_state": summary.get("old_state")},
                    new_value={
                        "whois_state": summary.get("new_state"),
                        "old_holder": summary.get("old_holder"),
                        "new_holder": summary.get("new_holder"),
                    },
                )
            )

        # RPKI ROAs — public ASNs only (RIRs don't issue ROAs for private
        # AS numbers). Best-effort: an RPKI failure shouldn't undo the
        # whois refresh we just committed conceptually in the same txn.
        rpki_result: str | None = None
        if row.kind == "public":
            from app.tasks.rpki_roa_refresh import _refresh_one_asn as _refresh_one_asn_rpki

            try:
                await _refresh_one_asn_rpki(db, row, rpki_source, rpki_interval, now)
                rpki_result = "ok"
            except Exception as exc:  # noqa: BLE001
                logger.warning("asn_rpki_refresh_one_failed", asn=row.number, error=str(exc))
                rpki_result = "error"

        await db.commit()

        logger.info(
            "asn_whois_refresh_one_completed",
            asn=row.number,
            whois_result=summary.get("result"),
            rpki_result=rpki_result,
        )
        return {
            "status": "ran",
            "asn": row.number,
            "whois_result": summary.get("result"),
            "rpki_result": rpki_result,
        }


@celery_app.task(name="app.tasks.asn_whois_refresh.refresh_one_asn_by_id", bind=True)
@module_gated("network.asn")
def refresh_one_asn_by_id(self: object, asn_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
    """One-shot whois (+ RPKI) refresh for a single ASN, dispatched right
    after create_asn (#278 follow-up) so a public AS is populated within
    seconds instead of sitting at ``n/a`` until the next beat tick."""
    try:
        return asyncio.run(_refresh_one_by_id_async(asn_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception("asn_whois_refresh_one_failed", asn_id=asn_id, error=str(exc))
        raise


__all__ = ["refresh_due_asns", "refresh_one_asn_by_id"]
