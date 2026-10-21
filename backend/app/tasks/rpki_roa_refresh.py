"""Periodic RPKI ROA refresh task.

Beat fires this every hour; the task itself walks every public ASN
that has at least one ROA row OR whose ``next_check_at`` is due, and
syncs the ``asn_rpki_roa`` table against the global ROA dump from
the configured source (Cloudflare or RIPE NCC).

Per-AS reconcile shape:

  1. Pull ROAs originated by this AS from the source service (the sweep
     primes the source layer's cache with the whole due set first, so the
     ~100 MB dump is streamed ONCE per sweep and never held in memory —
     only the due ASNs' slices are kept, for 5 minutes; spatiumddi#1054).
  2. INSERT new ``(prefix, max_length, trust_anchor)`` rows.
  3. UPDATE existing rows in place — bump ``last_checked_at`` and
     recompute ``state``.
  4. DELETE rows that no longer appear in the source. The AS holder
     pulled the ROA, or the trust anchor stopped emitting it.

State derivation lives in :func:`_derive_roa_state` so the alert
evaluator + the manual "Refresh now" path use the same logic:

* ``valid_to is None`` (the public mirrors don't expose validity
  windows) → ``valid``. We don't fire spurious "expired" events on
  unknown windows.
* a source whose validity field is a short-cycle cache expiry rather
  than a per-ROA lifetime → always ``valid``, for the same reason. This
  is the Cloudflare case and it is the common one; see
  ``_LIFETIME_VALIDITY_SOURCES``.
* otherwise: ``valid_to <= now`` → ``expired``; ``valid_to <= now + 30d``
  → ``expiring_soon``; else ``valid``.

Every additive / removed / state-transitioned row gets an audit-log
entry. We deliberately don't audit "still valid, ticked" — that's
noise.

Idempotent: re-running before any AS is due is a no-op.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import or_, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.asn import ASN, ASNRpkiRoa
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1
_VALID_SOURCES = frozenset({"cloudflare", "ripe"})


# Sources whose validity field is a per-ROA LIFETIME, and can therefore
# carry an "expiring soon" signal.
#
# Cloudflare's ``rpki.json`` is deliberately absent (#942). Its
# ``expires`` is the validity of the VRP cache entry — derived from the
# shortest-lived object in the validation chain (EE cert / manifest /
# CRL), all of which RPKI CAs re-sign on a rolling cycle of hours. It is
# not a statement about the ROA's lifetime and does not decay towards a
# renewal deadline. Measured against the live global dump on 2026-08-31:
# of 997,298 ROAs, 100% expired within 7 days and 79% within 2 — so a
# 30-day threshold flags literally every ROA that will ever exist,
# permanently. That is not a noisy signal, it is a constant, and it fed
# the ``rpki_roa_expiring`` alert rule one event PER ROA.
#
# For this source, presence in the dump is the signal: a ROA the AS
# holder actually pulled disappears, and the reconcile below DELETEs it.
# RIPE's ``notAfter`` is a genuine EE-certificate notAfter and keeps the
# ladder. If you add a source, measure its distribution before listing
# it here — the failure mode is silent and total.
_LIFETIME_VALIDITY_SOURCES = frozenset({"ripe"})


def _derive_roa_state(valid_to: datetime | None, now: datetime, source: str) -> str:
    """Map ``valid_to`` → ROA state.

    ``None`` (unknown window) maps to ``valid`` so we don't fire
    spurious alerts on mirrors that don't expose the X.509 notAfter
    field. A source whose validity field is a short-cycle cache expiry
    rather than a lifetime is treated the same way, and for the same
    reason — see :data:`_LIFETIME_VALIDITY_SOURCES`.
    """
    if valid_to is None or source not in _LIFETIME_VALIDITY_SOURCES:
        return "valid"
    if valid_to <= now:
        return "expired"
    if valid_to <= now + timedelta(days=30):
        return "expiring_soon"
    return "valid"


async def _refresh_one_asn(
    db: Any,
    asn_row: ASN,
    source: str,
    interval_hours: int,
    now: datetime,
) -> dict[str, Any]:
    """Reconcile ROAs for one AS. Returns a per-AS summary used by
    the caller's audit log + counters."""
    from app.services.rpki_roa import fetch_roas_for_asn  # noqa: PLC0415

    fetched = await fetch_roas_for_asn(int(asn_row.number), source)
    next_check_at = now + timedelta(hours=interval_hours)

    # Index existing rows by the natural key for diff. Same key the
    # ``uq_asn_rpki_roa`` unique constraint enforces.
    existing_rows = (
        (await db.execute(select(ASNRpkiRoa).where(ASNRpkiRoa.asn_id == asn_row.id)))
        .scalars()
        .all()
    )
    existing_index: dict[tuple[str, int, str | None], ASNRpkiRoa] = {}
    for row in existing_rows:
        key = (str(row.prefix), int(row.max_length), row.trust_anchor or None)
        existing_index[key] = row

    seen_keys: set[tuple[str, int, str | None]] = set()
    added = 0
    updated = 0
    transitions = 0
    transitions_summary: list[dict[str, Any]] = []

    for entry in fetched:
        prefix = entry.get("prefix")
        max_length = entry.get("max_length")
        trust_anchor = entry.get("trust_anchor")
        valid_from = entry.get("valid_from")
        valid_to = entry.get("valid_to")
        if not prefix or max_length is None:
            continue

        key = (str(prefix), int(max_length), trust_anchor or None)
        seen_keys.add(key)
        new_state = _derive_roa_state(valid_to, now, source)

        existing = existing_index.get(key)
        if existing is None:
            # New ROA — INSERT and audit it. We deliberately don't
            # write next_check_at on insert; the per-AS gate is what
            # controls the next refresh.
            db.add(
                ASNRpkiRoa(
                    asn_id=asn_row.id,
                    prefix=prefix,
                    max_length=int(max_length),
                    valid_from=valid_from,
                    valid_to=valid_to,
                    trust_anchor=trust_anchor or "unknown",
                    state=new_state,
                    last_checked_at=now,
                    next_check_at=next_check_at,
                )
            )
            added += 1
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="rpki_roa_added",
                    resource_type="asn",
                    resource_id=str(asn_row.id),
                    resource_display=f"AS{asn_row.number}",
                    result="success",
                    new_value={
                        "prefix": str(prefix),
                        "max_length": int(max_length),
                        "trust_anchor": trust_anchor or "unknown",
                        "state": new_state,
                    },
                )
            )
            continue

        # Existing ROA — UPDATE in place. Track state transitions for
        # audit + counters; ignore mere ``last_checked_at`` bumps.
        old_state = existing.state
        existing.valid_from = valid_from
        existing.valid_to = valid_to
        existing.state = new_state
        existing.last_checked_at = now
        existing.next_check_at = next_check_at
        updated += 1
        if old_state != new_state:
            transitions += 1
            transitions_summary.append(
                {
                    "prefix": str(prefix),
                    "max_length": int(max_length),
                    "trust_anchor": trust_anchor or "unknown",
                    "old_state": old_state,
                    "new_state": new_state,
                }
            )
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="rpki_roa_state_transition",
                    resource_type="asn",
                    resource_id=str(asn_row.id),
                    resource_display=f"AS{asn_row.number}",
                    result="success",
                    changed_fields=["state"],
                    old_value={
                        "prefix": str(prefix),
                        "max_length": int(max_length),
                        "trust_anchor": trust_anchor or "unknown",
                        "state": old_state,
                    },
                    new_value={"state": new_state},
                )
            )

    # DELETE rows that vanished from the source.
    removed = 0
    for key, row in existing_index.items():
        if key in seen_keys:
            continue
        removed += 1
        db.add(
            AuditLog(
                user_display_name="<system>",
                auth_source="system",
                action="rpki_roa_removed",
                resource_type="asn",
                resource_id=str(asn_row.id),
                resource_display=f"AS{asn_row.number}",
                result="success",
                old_value={
                    "prefix": str(row.prefix),
                    "max_length": int(row.max_length),
                    "trust_anchor": row.trust_anchor or "unknown",
                    "state": row.state,
                },
            )
        )
        await db.delete(row)

    return {
        "asn": asn_row.number,
        "fetched": len(fetched),
        "added": added,
        "updated": updated,
        "removed": removed,
        "transitions": transitions,
        "transitions_summary": transitions_summary,
    }


async def _run_refresh() -> dict[str, Any]:
    async with task_session() as db:
        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        interval_hours = 4
        source = "cloudflare"
        if ps is not None:
            interval_hours = max(1, min(168, int(ps.rpki_roa_refresh_interval_hours or 4)))
            candidate = (ps.rpki_roa_source or "cloudflare").lower()
            source = candidate if candidate in _VALID_SOURCES else "cloudflare"

        now = datetime.now(UTC)

        # Pick every public ASN with at least one ROA row OR whose
        # parent gate is due. New rows just need any existing ROA-bearing
        # AS to trigger; the per-row ``next_check_at`` floor on the ROA
        # itself comes from the per-AS reconcile.
        existing_with_roas = (
            (
                await db.execute(
                    select(ASN)
                    .join(ASNRpkiRoa, ASNRpkiRoa.asn_id == ASN.id)
                    .where(
                        ASN.kind == "public",
                        or_(
                            ASNRpkiRoa.next_check_at.is_(None),
                            ASNRpkiRoa.next_check_at <= now,
                        ),
                    )
                    .distinct()
                )
            )
            .scalars()
            .all()
        )

        # Also include any public ASN that has NO ROAs yet — first-time
        # reconcile. ``ASN.next_check_at`` is owned by the WHOIS refresh
        # task (it gets bumped ~24h forward on every successful WHOIS
        # pull), so it would permanently lock out fresh ASNs from their
        # first ROA pull if we gated on it. We don't gate first-time
        # rows at all — the source-side service caches the global ROA
        # dump for 5 min so back-to-back refreshes don't fan out to N
        # network calls. Per-row pacing kicks in once a ROA exists via
        # the ``ASNRpkiRoa.next_check_at`` floor in the existing-ROA
        # branch above.
        first_time = (
            (
                await db.execute(
                    select(ASN)
                    .outerjoin(ASNRpkiRoa, ASNRpkiRoa.asn_id == ASN.id)
                    .where(
                        ASN.kind == "public",
                        ASNRpkiRoa.id.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

        seen_ids: set[str] = set()
        rows: list[ASN] = []
        for r in list(existing_with_roas) + list(first_time):
            key = str(r.id)
            if key in seen_ids:
                continue
            seen_ids.add(key)
            rows.append(r)

        if not rows:
            return {
                "status": "ran",
                "asns_scanned": 0,
                "added": 0,
                "updated": 0,
                "removed": 0,
                "transitions": 0,
                "errors": 0,
            }

        scanned = 0
        added_total = 0
        updated_total = 0
        removed_total = 0
        transitions_total = 0
        errors = 0
        all_transitions: list[dict[str, Any]] = []

        # One streamed fetch for the whole due set (spatiumddi#1054): the
        # source layer indexes only these ASNs' ROAs, so the per-AS calls
        # below are cache hits and the global dump is never held in memory.
        # A failed prime is not an error here — each per-AS call retries it
        # and, failing that, reports "no ROAs this tick" exactly as before.
        from app.services.rpki_roa import prime_roas  # noqa: PLC0415

        await prime_roas({int(r.number) for r in rows}, source)

        for asn_row in rows:
            try:
                summary = await _refresh_one_asn(db, asn_row, source, interval_hours, now)
            except Exception as exc:  # noqa: BLE001 — one bad AS shouldn't poison the whole sweep
                errors += 1
                logger.warning(
                    "rpki_roa_refresh_row_failed",
                    asn=asn_row.number,
                    error=str(exc),
                )
                continue

            scanned += 1
            added_total += summary["added"]
            updated_total += summary["updated"]
            removed_total += summary["removed"]
            transitions_total += summary["transitions"]
            for t in summary.get("transitions_summary", []):
                all_transitions.append({"asn": asn_row.number, **t})

        await db.commit()

        logger.info(
            "rpki_roa_refresh_completed",
            source=source,
            asns_scanned=scanned,
            added=added_total,
            updated=updated_total,
            removed=removed_total,
            transitions=transitions_total,
            errors=errors,
        )
        return {
            "status": "ran",
            "source": source,
            "asns_scanned": scanned,
            "added": added_total,
            "updated": updated_total,
            "removed": removed_total,
            "transitions": transitions_total,
            "errors": errors,
            "transitions_summary": all_transitions[:20],
        }


@celery_app.task(name="app.tasks.rpki_roa_refresh.refresh_due_roas", bind=True)
@module_gated("network.asn")
def refresh_due_roas(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Beat-fired hourly. Per-row ``next_check_at`` gates the actual
    pace; ``PlatformSettings.rpki_roa_refresh_interval_hours`` controls
    the cadence operator-side without restarting beat."""
    try:
        return asyncio.run(_run_refresh())
    except Exception as exc:  # noqa: BLE001
        logger.exception("rpki_roa_refresh_failed", error=str(exc))
        raise


__all__ = ["refresh_due_roas", "_derive_roa_state"]
