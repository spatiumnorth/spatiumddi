"""Capacity forecasting (#43) — project when a subnet fills up.

Fits a least-squares line through the last ``FORECAST_WINDOW_DAYS`` of the
daily ``subnet_utilization_history`` snapshots (#44) and extrapolates it from
the subnet's current utilisation to 100 %. The regression runs in Postgres
(``regr_slope`` over every subnet in one grouped query), so list views and the
alert evaluator cost one round trip, not one per subnet.

No forecast is produced when:

* fewer than ``MIN_POINTS`` snapshots fall inside the window (a new subnet, or
  a history that has not accumulated yet);
* the slope is zero or negative (flat / shrinking — nothing to project);
* the projected date is more than ``MAX_DAYS_TO_FULL`` away (a vanishing slope
  would otherwise report a date centuries out);
* the subnet is excluded from utilisation (point-to-point / loopback prefixes
  past ``PlatformSettings.utilization_max_prefix_*``), the same rule the
  ``subnet_utilization`` alert applies.

A subnet that is already at 100 % and still trending up reports 0 days.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import Float, and_, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import Subnet, SubnetUtilizationHistory
from app.models.settings import PlatformSettings

FORECAST_WINDOW_DAYS = 30
MIN_POINTS = 14
MAX_DAYS_TO_FULL = 3650


@dataclass(frozen=True)
class CapacityForecast:
    subnet_id: uuid.UUID
    network: str
    name: str
    utilization_percent: float
    slope_percent_per_day: float
    sample_count: int
    days_to_full: int
    forecast_full_date: date


def project_days_to_full(current_percent: float, slope_per_day: float) -> int | None:
    """Days until ``current_percent`` reaches 100 at ``slope_per_day``.

    ``None`` when the slope is not positive or the date is out of range;
    ``0`` when the subnet is already full and still trending up.
    """
    if slope_per_day is None or not math.isfinite(slope_per_day) or slope_per_day <= 0:
        return None
    remaining = 100.0 - current_percent
    if remaining <= 0:
        return 0
    days = math.ceil(remaining / slope_per_day)
    return days if days <= MAX_DAYS_TO_FULL else None


async def compute_capacity_forecasts(
    db: AsyncSession,
    *,
    subnet_ids: list[uuid.UUID] | None = None,
    window_days: int = FORECAST_WINDOW_DAYS,
    min_points: int = MIN_POINTS,
    now: datetime | None = None,
) -> list[CapacityForecast]:
    """Forecast every subnet that has a projectable trend, soonest first."""
    from app.services.alerts import _include_subnet  # lazy: alerts imports this module

    now = now or datetime.now(UTC)
    since = now - timedelta(days=window_days)
    pct = (
        cast(SubnetUtilizationHistory.allocated_ips, Float)
        * 100.0
        / SubnetUtilizationHistory.total_ips
    )
    x_days = func.extract("epoch", SubnetUtilizationHistory.sampled_at) / 86400.0
    stmt = (
        select(
            SubnetUtilizationHistory.subnet_id,
            func.regr_slope(pct, x_days).label("slope"),
            func.count().label("n"),
        )
        .join(Subnet, Subnet.id == SubnetUtilizationHistory.subnet_id)
        .where(
            and_(
                SubnetUtilizationHistory.sampled_at >= since,
                SubnetUtilizationHistory.sampled_at <= now,
                SubnetUtilizationHistory.total_ips > 0,
                Subnet.deleted_at.is_(None),
            )
        )
        .group_by(SubnetUtilizationHistory.subnet_id)
        .having(func.count() >= min_points)
    )
    if subnet_ids is not None:
        stmt = stmt.where(SubnetUtilizationHistory.subnet_id.in_(subnet_ids))
    fits = {r.subnet_id: (r.slope, int(r.n)) for r in (await db.execute(stmt)).all()}
    if not fits:
        return []

    settings = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    subnets = (await db.execute(select(Subnet).where(Subnet.id.in_(list(fits))))).scalars().all()
    out: list[CapacityForecast] = []
    for s in subnets:
        slope, n = fits[s.id]
        if slope is None or not _include_subnet(s, settings):
            continue
        current = (s.allocated_ips or 0) * 100.0 / s.total_ips if s.total_ips else 0.0
        days = project_days_to_full(current, float(slope))
        if days is None:
            continue
        out.append(
            CapacityForecast(
                subnet_id=s.id,
                network=str(s.network),
                name=s.name or "",
                utilization_percent=round(current, 2),
                slope_percent_per_day=round(float(slope), 4),
                sample_count=n,
                days_to_full=days,
                forecast_full_date=(now + timedelta(days=days)).date(),
            )
        )
    out.sort(key=lambda f: (f.days_to_full, f.network))
    return out
