"""One target's end-to-end push (issue #889).

Sequence per target: collect → render → POST → record state. The
watermarks advance **only** on a successful write, so a dead collector
means a delayed export, never a hole in the series (the samples stay in
Postgres until ``prune_metrics`` retires them — a target offline longer
than ``metric_retention_days`` loses whatever aged out, which is the
same bound the built-in charts live under).

The whole push for one target is a single POST. InfluxDB applies a
line-protocol batch atomically per request, so a partial failure can't
leave the watermark describing a half-written batch.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.influxdb import InfluxDBTarget
from app.services.influxdb import collect
from app.services.influxdb.client import config_from_row, write_lines
from app.services.influxdb.line_protocol import Point, render_batch

logger = structlog.get_logger(__name__)


@dataclass
class PushResult:
    target_id: str
    target_name: str
    points: int
    ok: bool
    error: str | None = None


def _prefixed(points: list[Point], prefix: str) -> list[Point]:
    if not prefix:
        return points
    return [
        Point(
            measurement=f"{prefix}{p.measurement}",
            tags=p.tags,
            fields=p.fields,
            timestamp=p.timestamp,
        )
        for p in points
    ]


def is_due(row: InfluxDBTarget, now: datetime) -> bool:
    """Has this target's own interval elapsed since its last push?

    Per-target gating inside a coarse beat tick — the ``ipam_dns_sync``
    pattern — so changing an interval in the UI takes effect without
    restarting beat. A target that has never pushed is always due.
    """
    if row.last_push_at is None:
        return True
    last = row.last_push_at if row.last_push_at.tzinfo else row.last_push_at.replace(tzinfo=UTC)
    return (now - last).total_seconds() >= max(1, int(row.push_interval_seconds or 60))


async def push_target(db: AsyncSession, row: InfluxDBTarget, *, now: datetime) -> PushResult:
    """Collect, write and record one target. Never raises.

    Errors land on ``last_push_error`` and in the log; the caller commits.
    Callers that want the failure to propagate should read the result.
    """
    points: list[Point] = []
    dns_watermark: datetime | None = None
    dhcp_watermark: datetime | None = None

    try:
        if row.push_dns_metrics:
            dns_points, dns_watermark = await collect.collect_dns_points(db, row.last_dns_bucket_at)
            points.extend(dns_points)
        if row.push_dhcp_metrics:
            dhcp_points, dhcp_watermark = await collect.collect_dhcp_points(
                db, row.last_dhcp_bucket_at
            )
            points.extend(dhcp_points)
        if row.push_subnet_utilization:
            points.extend(await collect.collect_subnet_utilization_points(db, now))
        if row.push_dhcp_scope_leases:
            points.extend(await collect.collect_dhcp_scope_lease_points(db, now))

        body = render_batch(_prefixed(points, row.measurement_prefix or ""))
        if not body:
            # Nothing to send, so nobody was contacted: this is not a push
            # the destination accepted (#2749). ``last_push_at`` still moves
            # so interval gating holds; ``last_success_at`` and any recorded
            # failure are left exactly as the last real attempt left them.
            row.last_push_at = now
            row.last_push_points = 0
            logger.info("influxdb_push_empty", target=row.name)
            return PushResult(str(row.id), row.name, 0, ok=True)
        await write_lines(config_from_row(row), body)
    # Broad on purpose: this is the per-target failure-isolation boundary.
    # The caller pushes every due target inside one transaction, so an
    # exception escaping here would abandon the sweep before its commit —
    # discarding the state updates of the targets that *did* succeed, and
    # leaving this one with no ``last_push_error`` to explain itself, so
    # nothing anywhere would say what went wrong.
    except Exception as exc:  # noqa: BLE001
        row.last_push_error = str(exc)[:1000] or type(exc).__name__
        # ``last_push_at`` still advances on failure — otherwise a target
        # that errors fast would be retried on every 30 s beat tick
        # instead of on its own interval.
        row.last_push_at = now
        logger.warning(
            "influxdb_push_failed",
            target=row.name,
            points=len(points),
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return PushResult(str(row.id), row.name, 0, ok=False, error=str(exc))

    if dns_watermark is not None:
        row.last_dns_bucket_at = dns_watermark
    if dhcp_watermark is not None:
        row.last_dhcp_bucket_at = dhcp_watermark
    row.last_push_at = now
    row.last_success_at = now
    row.last_push_points = len(points)
    row.last_push_error = None
    logger.info("influxdb_push_ok", target=row.name, points=len(points))
    return PushResult(str(row.id), row.name, len(points), ok=True)


__all__ = ["PushResult", "is_due", "push_target"]
