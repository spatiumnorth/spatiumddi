"""Turn SpatiumDDI's stored metrics into InfluxDB points (issue #889).

Two shapes of source, which behave differently and are worth telling
apart when reading a dashboard built on this data:

**Counter deltas** (``dns_metric_sample`` / ``dhcp_metric_sample``) —
agent-reported, already bucketed at 60 s, timestamped at the bucket. The
pusher walks these forward from a high-water mark, so a point's
timestamp is when the traffic happened, not when it was exported. Each
push also replays a short window *behind* the mark to catch a bucket an
agent reported late; the two are separate queries with separate row
budgets — see ``_fetch_samples`` for why that matters.

**Point-in-time gauges** (subnet utilization, per-scope active leases) —
sampled here, at push time, from counters the application already
maintains. There is no historical backfill for these: the first point is
the moment the target was enabled. The 60 s agent bucket is the floor for
the deltas; for the gauges the floor is the target's own
``push_interval_seconds``.

Every function returns ``Point`` objects with the measurement name
*unprefixed*; ``push`` applies the target's ``measurement_prefix`` so the
prefix isn't baked into the collectors.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer
from app.models.ipam import IPSpace, Subnet
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.services.influxdb.line_protocol import Point

# Per-source cap on rows drained in a single push. A newly-enabled target
# backfills the whole retention window in ``ceil(rows / MAX_ROWS)`` ticks
# rather than in one oversized POST.
MAX_ROWS_PER_PUSH = 5000

# How far back before the high-water mark to re-send. Agents can report a
# bucket late (a restart, a blocked heartbeat), and the forward drain
# alone would skip it permanently. Re-sending is free: line protocol
# overwrites a point with the same measurement + tags + timestamp.
REPUSH_OVERLAP_SECONDS = 300

MEASUREMENT_DNS = "dns_queries"
MEASUREMENT_DHCP = "dhcp_messages"
MEASUREMENT_SUBNET = "subnet_utilization"
MEASUREMENT_SCOPE_LEASES = "dhcp_scope_leases"


def _epoch(dt: datetime) -> int:
    return int((dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp())


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


async def _fetch_samples(
    db: AsyncSession,
    sample_model: Any,
    server_model: Any,
    watermark: datetime | None,
) -> tuple[list[Any], list[Any]]:
    """Return ``(forward_rows, replay_rows)`` for one metric table.

    Two queries with **separate row budgets**, and that separation is the
    point rather than an optimisation:

    * *forward* is strictly ``bucket_at > watermark``, so the cursor the
      caller derives from it can only move forwards. A single query with
      the overlap folded into its lower bound would, on a fleet dense
      enough to fill ``MAX_ROWS_PER_PUSH`` inside the overlap window,
      return a truncated batch whose maximum is *below* the watermark —
      dragging the cursor backwards a little further every tick until it
      pinned on the oldest retained sample. The export would stop
      advancing while every push still reported success and the UI still
      showed the target green.
    * *replay* is the closed window ``(watermark - overlap, watermark]``,
      re-sent so a bucket an agent reported late is still exported. It
      never contributes to the cursor — these rows are, by definition,
      already behind it.

    ``replay`` is empty on the first push (no watermark yet), when every
    row is ahead of the cursor anyway.
    """
    join_on = server_model.id == sample_model.server_id

    forward_stmt = (
        select(sample_model, server_model.name)
        .join(server_model, join_on)
        .order_by(sample_model.bucket_at.asc())
        .limit(MAX_ROWS_PER_PUSH)
    )
    if watermark is not None:
        forward_stmt = forward_stmt.where(sample_model.bucket_at > _aware(watermark))
    forward = list((await db.execute(forward_stmt)).all())

    if watermark is None:
        return forward, []

    mark = _aware(watermark)
    replay_stmt = (
        select(sample_model, server_model.name)
        .join(server_model, join_on)
        .where(sample_model.bucket_at > mark - timedelta(seconds=REPUSH_OVERLAP_SECONDS))
        .where(sample_model.bucket_at <= mark)
        .order_by(sample_model.bucket_at.asc())
        .limit(MAX_ROWS_PER_PUSH)
    )
    return forward, list((await db.execute(replay_stmt)).all())


async def collect_dns_points(
    db: AsyncSession, watermark: datetime | None
) -> tuple[list[Point], datetime | None]:
    """DNS counter deltas: the forward drain plus the late-arrival replay.

    Returns the points plus the newest ``bucket_at`` **from the forward
    drain only**, which becomes the target's next watermark. ``None``
    when the drain was empty, so the caller leaves the stored cursor
    alone rather than moving it to a replayed row.
    """

    def _point(sample: Any, server_name: str | None) -> Point:
        return Point(
            measurement=MEASUREMENT_DNS,
            tags={"server": server_name or "", "server_id": str(sample.server_id)},
            fields={
                "queries_total": int(sample.queries_total),
                "noerror": int(sample.noerror),
                "nxdomain": int(sample.nxdomain),
                "servfail": int(sample.servfail),
                "recursion": int(sample.recursion),
                "rate_dropped": int(sample.rate_dropped),
                "rate_slipped": int(sample.rate_slipped),
            },
            timestamp=_epoch(sample.bucket_at),
        )

    forward, replay = await _fetch_samples(db, DNSMetricSample, DNSServer, watermark)
    points = [_point(s, n) for s, n in replay] + [_point(s, n) for s, n in forward]
    # Rows come back ascending, so the drain's last row is its maximum.
    newest = _aware(forward[-1][0].bucket_at) if forward else None
    return points, newest


async def collect_dhcp_points(
    db: AsyncSession, watermark: datetime | None
) -> tuple[list[Point], datetime | None]:
    """DHCP message-count deltas — same two-query shape as the DNS side.

    Carries the #980 loss counters too. They are the only reason a field can
    be absent from a point here: everything else is NOT NULL.
    """

    def _point(sample: Any, server_name: str | None) -> Point:
        return Point(
            measurement=MEASUREMENT_DHCP,
            tags={"server": server_name or "", "server_id": str(sample.server_id)},
            fields={
                "discover": int(sample.discover),
                "offer": int(sample.offer),
                "request": int(sample.request),
                "ack": int(sample.ack),
                "nak": int(sample.nak),
                "decline": int(sample.decline),
                "release": int(sample.release),
                "inform": int(sample.inform),
                # #980 — loss, not traffic. Omitted (not zero-filled) when
                # NULL: the agent did not measure it, and line protocol has
                # no null, so writing 0 would assert "no packets were lost"
                # on a server nobody looked at. An absent field leaves a gap
                # in the series, which is the honest rendering.
                **(
                    {"socket_drop": int(sample.socket_drop)}
                    if sample.socket_drop is not None
                    else {}
                ),
                **(
                    {"receive_drop": int(sample.receive_drop)}
                    if sample.receive_drop is not None
                    else {}
                ),
            },
            timestamp=_epoch(sample.bucket_at),
        )

    forward, replay = await _fetch_samples(db, DHCPMetricSample, DHCPServer, watermark)
    points = [_point(s, n) for s, n in replay] + [_point(s, n) for s, n in forward]
    newest = _aware(forward[-1][0].bucket_at) if forward else None
    return points, newest


async def collect_subnet_utilization_points(db: AsyncSession, now: datetime) -> list[Point]:
    """Point-in-time utilization gauge per live subnet.

    Reads the already-maintained ``allocated_ips`` / ``total_ips``
    counters — the same numbers the IPAM grid and the #44 daily history
    show — so this adds a query, not a scan. ``percent`` is recomputed
    here rather than read from ``utilization_percent`` so the three
    fields on a point can never disagree with each other.
    """
    stmt = (
        select(Subnet, IPSpace.name)
        .join(IPSpace, IPSpace.id == Subnet.space_id)
        .where(Subnet.deleted_at.is_(None))
    )
    ts = _epoch(now)
    points: list[Point] = []
    for subnet, space_name in (await db.execute(stmt)).all():
        total = int(subnet.total_ips or 0)
        allocated = int(subnet.allocated_ips or 0)
        percent = (allocated / total * 100.0) if total > 0 else 0.0
        points.append(
            Point(
                measurement=MEASUREMENT_SUBNET,
                tags={
                    "subnet": str(subnet.network),
                    "subnet_id": str(subnet.id),
                    "space": space_name or "",
                },
                fields={
                    "allocated": allocated,
                    "total": total,
                    "percent": round(percent, 4),
                },
                timestamp=ts,
            )
        )
    return points


async def collect_dhcp_scope_lease_points(db: AsyncSession, now: datetime) -> list[Point]:
    """Active-lease count per live DHCP scope.

    Scopes with zero active leases are emitted as ``0`` rather than
    omitted: an absent series and an empty scope look identical on a
    graph, and "the scope went quiet" is exactly what an operator wants
    to see.
    """
    # DISTINCT on the address, not COUNT(*): ``dhcp_lease`` is per-server,
    # and under Kea HA the partners both mirror the same lease — so a bare
    # row count reports 2x the addresses actually in use on a redundant
    # pair, and disagrees with ``services/dhcp/pool_occupancy.py``, which
    # dedupes for exactly this reason.
    counts_stmt = (
        select(DHCPLease.scope_id, func.count(distinct(DHCPLease.ip_address)))
        .where(DHCPLease.scope_id.is_not(None), DHCPLease.state == "active")
        .group_by(DHCPLease.scope_id)
    )
    counts: dict[uuid.UUID, int] = {
        row[0]: int(row[1])
        for row in (await db.execute(counts_stmt)).all()
        if row[0] is not None  # excluded by the WHERE; the filter is for mypy
    }

    scopes_stmt = (
        select(DHCPScope, Subnet.network, DHCPServerGroup.name)
        .join(Subnet, Subnet.id == DHCPScope.subnet_id)
        .join(DHCPServerGroup, DHCPServerGroup.id == DHCPScope.group_id)
        .where(DHCPScope.deleted_at.is_(None))
    )
    ts = _epoch(now)
    points: list[Point] = []
    for scope, network, group_name in (await db.execute(scopes_stmt)).all():
        points.append(
            Point(
                measurement=MEASUREMENT_SCOPE_LEASES,
                tags={
                    "scope": scope.name or str(network),
                    "scope_id": str(scope.id),
                    "group": group_name or "",
                    "subnet": str(network),
                },
                fields={
                    "active_leases": counts.get(scope.id, 0),
                    "is_active": bool(scope.is_active),
                },
                timestamp=ts,
            )
        )
    return points


__all__ = [
    "MAX_ROWS_PER_PUSH",
    "MEASUREMENT_DHCP",
    "MEASUREMENT_DNS",
    "MEASUREMENT_SCOPE_LEASES",
    "MEASUREMENT_SUBNET",
    "REPUSH_OVERLAP_SECONDS",
    "collect_dhcp_points",
    "collect_dhcp_scope_lease_points",
    "collect_dns_points",
    "collect_subnet_utilization_points",
]
