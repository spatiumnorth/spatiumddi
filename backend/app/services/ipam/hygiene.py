"""On-demand IPAM hygiene report (issue #917, over the #369 detections).

The three hygiene detections have existed since #369 as *alert rules*: a
scheduled evaluator matches them against configured thresholds and fires
events. That answers "tell me when this becomes true", which is the right
shape for monitoring and the wrong one for triage — an operator standing at a
patch panel wants "is anything squatting in my static ranges **right now**",
at a threshold they choose, without having to first configure a rule.

``find_ip_hygiene_findings`` (the copilot tool) already did exactly this by
calling the alert matchers with a transient rule as a threshold carrier. It
was the only surface that could: no REST route existed, so the mobile client
and every other API consumer could see these findings only as fired events, at
whatever thresholds the operator had configured. That asymmetry is what #917
catalogued.

This module is the shared implementation both now call, so the copilot answer
and the REST answer cannot disagree — and both stay pinned to the *alert*
matchers, so a tuning change to a detection reaches all three surfaces at once.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

#: Defaults chosen to match the alert rules' own (``_FREE_RESPONDING_RECENCY_DAYS``
#: / ``_STALE_RESERVATION_DAYS`` in ``services.alerts``) so an unparameterised
#: call reports what the monitoring would.
DEFAULT_FREE_RESPONDING_DAYS = 1
DEFAULT_STALE_RESERVATION_DAYS = 90
DEFAULT_SQUAT_DAYS = 7


async def build_hygiene_report(
    db: AsyncSession,
    *,
    free_responding_days: int = DEFAULT_FREE_RESPONDING_DAYS,
    stale_reservation_days: int = DEFAULT_STALE_RESERVATION_DAYS,
    squat_days: int = DEFAULT_SQUAT_DAYS,
    limit: int = 100,
    subnet_ids: Collection[uuid.UUID] | None = None,
) -> dict[str, Any]:
    """Three buckets of address-space hygiene findings, computed live.

    * ``free_but_responding`` — rows marked ``available`` that answered on the
      wire inside the recency window. Either the row is wrong or something is
      squatting, and both are worth knowing before the address is handed out.
    * ``stale_reservations`` — ``reserved`` / ``static_dhcp`` rows nothing has
      seen in ``stale_reservation_days``. Requires at least one prior sighting,
      so a subnet where discovery was never enabled does not read as dead.
    * ``unknown_mac_in_static_range`` — a reservation whose recently observed
      MAC differs from the recorded one. Operator-set ``mac_address`` is never
      overwritten by discovery, so a differing recent observation is a genuine
      "someone else is answering on this IP".

    ``counts`` are the **full** match counts; the row lists are capped at
    ``limit``. Reporting only the truncated length would understate an estate
    with thousands of findings, which is exactly the estate that needs the
    number.

    ``subnet_ids`` limits every bucket, and its count, to addresses in those
    subnets (a caller bound to specific subnets); ``None`` applies no limit.
    """
    # Imported here rather than at module scope: ``services.alerts`` imports
    # most of the model tree, and a top-level import would drag that into every
    # consumer of this module for no benefit.
    from app.models.alerts import AlertRule  # noqa: PLC0415
    from app.services.alerts import (  # noqa: PLC0415
        RULE_TYPE_IP_FREE_BUT_RESPONDING,
        RULE_TYPE_STALE_RESERVATION,
        RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE,
        _matching_ip_free_but_responding_subjects,
        _matching_stale_reservation_subjects,
        _matching_unknown_mac_in_static_range_subjects,
    )

    def _rule(rule_type: str, days: int) -> AlertRule:
        # A transient (never-added, never-flushed) row used purely as a
        # threshold carrier — the matchers read ``threshold_days`` and nothing
        # else off it.
        return AlertRule(name="adhoc", rule_type=rule_type, severity="info", threshold_days=days)

    free = await _matching_ip_free_but_responding_subjects(
        db, _rule(RULE_TYPE_IP_FREE_BUT_RESPONDING, free_responding_days)
    )
    stale = await _matching_stale_reservation_subjects(
        db, _rule(RULE_TYPE_STALE_RESERVATION, stale_reservation_days)
    )
    squat = await _matching_unknown_mac_in_static_range_subjects(
        db, _rule(RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE, squat_days)
    )

    if subnet_ids is not None:
        from app.models.ipam import IPAddress  # noqa: PLC0415

        found = {sid for rows in (free, stale, squat) for sid, _, _ in rows}
        keep: set[str] = set()
        if found and subnet_ids:
            keep = {
                str(i)
                for i in (
                    await db.execute(
                        select(IPAddress.id).where(
                            IPAddress.id.in_([uuid.UUID(f) for f in found]),
                            IPAddress.subnet_id.in_(list(subnet_ids)),
                        )
                    )
                ).scalars()
            }
        free = [r for r in free if r[0] in keep]
        stale = [r for r in stale if r[0] in keep]
        squat = [r for r in squat if r[0] in keep]

    def _fmt(rows: list[tuple[str, str, str]]) -> list[dict[str, str]]:
        return [{"ip_id": sid, "address": disp, "detail": msg} for sid, disp, msg in rows[:limit]]

    return {
        "free_but_responding": _fmt(free),
        "stale_reservations": _fmt(stale),
        "unknown_mac_in_static_range": _fmt(squat),
        "counts": {
            "free_but_responding": len(free),
            "stale_reservations": len(stale),
            "unknown_mac_in_static_range": len(squat),
        },
        "thresholds": {
            "free_responding_days": free_responding_days,
            "stale_reservation_days": stale_reservation_days,
            "squat_days": squat_days,
        },
        "limit": limit,
        # A caller that got exactly ``limit`` rows cannot tell a full bucket
        # from a truncated one without comparing against ``counts`` — say so
        # rather than making every client rediscover the comparison.
        "truncated": any(len(rows) > limit for rows in (free, stale, squat)),
    }


__all__ = [
    "DEFAULT_FREE_RESPONDING_DAYS",
    "DEFAULT_SQUAT_DAYS",
    "DEFAULT_STALE_RESERVATION_DAYS",
    "build_hygiene_report",
]
