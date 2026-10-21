"""Periodic BGP prefix-hijack poll (issue #527).

Beat fires this hourly; the task itself is the RELIABLE source of truth
for prefix-hijack detection (the optional RIS Live WebSocket consumer in
``app.services.bgp.ris_live`` is a real-time upgrade the feature never
depends on). It:

1. Gates on ``PlatformSettings.bgp_monitoring_enabled`` — a no-op when
   the operator hasn't opted in.
2. Refreshes the auto-managed ``bgp_tracked_prefix`` rows for every
   public ASN (from RPKI ROAs + RIPEstat announced-prefixes).
3. Evaluates every enabled tracked prefix whose ``next_check_at`` has
   elapsed: queries RIPEstat for the current announcements, records a
   ``bgp_hijack_detection`` for every unexpected origin (exact-prefix or
   more-specific), and bumps ``next_check_at`` forward by the configured
   interval.
4. Resolves detections whose announcement has been absent past the
   delist window.

The detection table is the latch/dedup state — an ongoing announcement
keeps one open row and fires exactly one ``AlertEvent`` via the standard
alert evaluator. Idempotent: re-running before anything is due is a
no-op; a still-active announcement just bumps ``last_seen_at``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import func, or_, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.asn import ASN
from app.models.bgp_monitor import BGPTrackedPrefix
from app.models.settings import PlatformSettings
from app.services.bgp.hijack_monitor import (
    evaluate_tracked_prefix,
    refresh_tracked_prefixes_for_asn,
    resolve_stale_detections,
)
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_SINGLETON_ID = 1

# Defensive cap on prefixes evaluated per pass — protects a huge fleet
# from fanning out to thousands of external calls in one tick. Leftovers
# get picked up on the next tick (their ``next_check_at`` stays due).
_MAX_PREFIXES_PER_PASS = 500


async def _run_poll() -> dict[str, Any]:
    async with task_session() as db:
        ps = await db.get(PlatformSettings, _SINGLETON_ID)
        if ps is None or not ps.bgp_monitoring_enabled:
            return {"status": "disabled"}

        interval_hours = max(1, min(168, int(ps.bgp_monitoring_interval_hours or 6)))
        now = datetime.now(UTC)
        next_check_at = now + timedelta(hours=interval_hours)

        # (1) refresh auto-managed tracked prefixes for every public AS —
        # but only for ASNs actually due this pass. The RIPEstat
        # announced-prefixes call inside refresh_tracked_prefixes_for_asn
        # is the expensive part; firing it for every AS on every hourly
        # beat ignored the operator's configured cadence. Gate it on the
        # same per-prefix ``next_check_at`` the evaluation step uses: an
        # AS is due when it has NO tracked prefixes yet (newly tracked —
        # refresh promptly to populate its list) or at least one of its
        # prefixes is NULL/elapsed. Because every prefix of one AS shares
        # the same next_check_at (all bumped in lockstep by step 2), this
        # fires the refresh at most once per interval per AS.
        due_gate = (
            await db.execute(
                select(
                    BGPTrackedPrefix.asn_id,
                    func.count()
                    .filter(
                        or_(
                            BGPTrackedPrefix.next_check_at.is_(None),
                            BGPTrackedPrefix.next_check_at <= now,
                        )
                    )
                    .label("due"),
                ).group_by(BGPTrackedPrefix.asn_id)
            )
        ).all()
        # Present-with-zero-due → skip; absent (no prefixes) → default due.
        refresh_due_by_asn: dict[Any, bool] = {asn_id: due > 0 for asn_id, due in due_gate}

        public_asns = (await db.execute(select(ASN).where(ASN.kind == "public"))).scalars().all()
        prefixes_added = 0
        refreshed = 0
        for asn_row in public_asns:
            if not refresh_due_by_asn.get(asn_row.id, True):
                continue
            try:
                prefixes_added += await refresh_tracked_prefixes_for_asn(db, asn_row, now=now)
                refreshed += 1
            except Exception as exc:  # noqa: BLE001 — one bad AS shouldn't poison the sweep
                logger.warning(
                    "bgp_tracked_prefix_refresh_failed",
                    asn=int(asn_row.number),
                    error=str(exc),
                )
        await db.flush()

        # (2) evaluate due, enabled tracked prefixes.
        due_rows = (
            (
                await db.execute(
                    select(BGPTrackedPrefix)
                    .where(
                        BGPTrackedPrefix.enabled.is_(True),
                        or_(
                            BGPTrackedPrefix.next_check_at.is_(None),
                            BGPTrackedPrefix.next_check_at <= now,
                        ),
                    )
                    .order_by(BGPTrackedPrefix.next_check_at.asc().nulls_first())
                    .limit(_MAX_PREFIXES_PER_PASS)
                )
            )
            .scalars()
            .all()
        )

        evaluated = 0
        opened = 0
        errors = 0
        # ASNs that had at least one AVAILABLE evaluation this pass. Only
        # these are eligible for stale-resolution — see the comment on the
        # resolve step below.
        resolvable_asn_ids: set[Any] = set()
        for tracked in due_rows:
            try:
                summary = await evaluate_tracked_prefix(db, tracked, now=now)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                logger.warning(
                    "bgp_prefix_evaluate_failed",
                    prefix=str(tracked.prefix),
                    error=str(exc),
                )
                # Still push next_check_at forward so a persistently
                # failing prefix doesn't monopolise every pass.
                tracked.next_check_at = next_check_at
                continue
            evaluated += 1
            opened += summary["opened"]
            tracked.next_check_at = next_check_at
            # Only count an AS as resolvable when its data actually came
            # back this pass. A soft RIPEstat outage returns
            # ``unavailable=True`` without bumping ``last_seen_at`` on the
            # open detections, so resolving off ``last_seen_at`` during an
            # outage longer than the delist window would auto-clear an
            # ONGOING hijack's alert while the hijack continues. Skipping
            # resolution for unavailable ASNs keeps the detection open
            # until we get a real "announcement is gone" observation.
            if not summary["unavailable"]:
                resolvable_asn_ids.add(tracked.asn_id)

        # (3) resolve detections whose announcement delisted — but only
        # for ASNs whose data was available this pass (see above).
        resolved = 0
        for asn_id in resolvable_asn_ids:
            resolved += await resolve_stale_detections(db, asn_id=asn_id, now=now)

        await db.commit()

        logger.info(
            "bgp_hijack_poll_completed",
            asns_scanned=len(public_asns),
            asns_refreshed=refreshed,
            prefixes_added=prefixes_added,
            prefixes_evaluated=evaluated,
            detections_opened=opened,
            detections_resolved=resolved,
            errors=errors,
        )
        return {
            "status": "ran",
            "asns_scanned": len(public_asns),
            "asns_refreshed": refreshed,
            "prefixes_added": prefixes_added,
            "prefixes_evaluated": evaluated,
            "detections_opened": opened,
            "detections_resolved": resolved,
            "errors": errors,
        }


@celery_app.task(
    name="app.tasks.bgp_hijack_poll.poll_bgp_hijacks",
    bind=True,
    autoretry_for=(ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=600,
    max_retries=3,
)
@module_gated("network.asn")
def poll_bgp_hijacks(self: object) -> dict[str, Any]:  # type: ignore[type-arg]
    """Beat-fired hourly. Per-row ``next_check_at`` gates the actual
    pace; ``PlatformSettings.bgp_monitoring_interval_hours`` controls the
    cadence operator-side without restarting beat. Transient
    connection / OS errors auto-retry with exponential backoff; RIPEstat
    HTTP failures are already swallowed at the client layer into a soft
    ``available: False`` so a flaky upstream just skips this pass."""
    try:
        return asyncio.run(_run_poll())
    except Exception as exc:  # noqa: BLE001
        logger.exception("bgp_hijack_poll_failed", error=str(exc))
        raise


__all__ = ["poll_bgp_hijacks"]
