"""Time-series read endpoints for the built-in dashboard.

Two symmetric endpoints — ``/metrics/dns/timeseries`` and
``/metrics/dhcp/timeseries`` — return bucketed per-server counter
deltas over a requested time window. The backing rows are written by
the agents (see `app.api.v1.{dns,dhcp}.agents.agent_metrics`); this
module is read-only.

Window → bucket selection is auto-scaled so charts stay readable:
short windows (< 24 h) return raw 60 s rows, 24 h and longer aggregate
server-side into 5 min buckets. The ceiling is the chart's pixel width,
not a row budget — 24 h of raw 60 s rows is 1,440 points into a
~1,300 px plot, i.e. more points than pixels, which paints a jittery
low-rate series as a solid filled band rather than a line. At 300 s
that window is 288 points and legible; 7 d is 2,016.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_any_resource_permission, require_resource_permission
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.services.feature_modules import require_module

router = APIRouter()


#: The cadence agents report counters at. One ``metric_sample`` row per
#: server per minute, so a point's covered time span is this times the
#: number of distinct buckets folded into it.
_AGENT_BUCKET_SECONDS = 60

WINDOW_SECONDS = {
    "1h": 3600,
    "6h": 6 * 3600,
    "24h": 24 * 3600,
    "7d": 7 * 24 * 3600,
}


def _bucket_seconds_for(window: str) -> int:
    """Pick an aggregation bucket that keeps a window under ~300 plotted points.

    The bound that matters is the chart's pixel width, not a row budget:
    more points than pixels renders a line as a solid band. 24 h is the
    crossover — at raw 60 s it is 1,440 points, at 300 s it is 288.
    """
    if WINDOW_SECONDS[window] >= 24 * 3600:
        return 300  # 5 min
    return 60


def _window_start(window: str) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=WINDOW_SECONDS[window])


class DNSTimePoint(BaseModel):
    t: datetime
    #: Seconds of sampling this point actually covers — ``60 x`` the number
    #: of distinct agent buckets folded into it, NOT ``bucket_seconds``.
    #: Rates must be derived from this or the newest point is systematically
    #: wrong: the current 5-minute bucket has only had one or two 60 s
    #: samples reported into it, and dividing that partial sum by a full 300
    #: renders a 70%+ phantom dip at the right-hand edge of every chart, on
    #: every refresh. The leading bucket is partial for the same reason (the
    #: window start does not align to a bucket boundary), and a bucket
    #: missing a sample because an agent was briefly down is the same
    #: problem in the middle of the series.
    covered_seconds: int
    queries_total: int
    noerror: int
    nxdomain: int
    servfail: int
    recursion: int
    rate_dropped: int = 0
    rate_slipped: int = 0


class DNSTimeseries(BaseModel):
    window: str
    bucket_seconds: int
    points: list[DNSTimePoint]


class DHCPTimePoint(BaseModel):
    t: datetime
    #: Seconds of sampling this point actually covers — ``60 x`` the number
    #: of distinct agent buckets folded into it, NOT ``bucket_seconds``.
    #: Rates must be derived from this or the newest point is systematically
    #: wrong: the current 5-minute bucket has only had one or two 60 s
    #: samples reported into it, and dividing that partial sum by a full 300
    #: renders a 70%+ phantom dip at the right-hand edge of every chart, on
    #: every refresh. The leading bucket is partial for the same reason (the
    #: window start does not align to a bucket boundary), and a bucket
    #: missing a sample because an agent was briefly down is the same
    #: problem in the middle of the series.
    covered_seconds: int
    discover: int
    offer: int
    request: int
    ack: int
    nak: int
    decline: int
    release: int
    inform: int
    #: #980 — packets lost, and where. ``receive_drop`` is Kea's own
    #: ``pkt4/6-receive-drop`` (read, then discarded); ``socket_drop`` is the
    #: kernel dropping datagrams Kea never got to read, which is what a
    #: CPU-starved node does while every Kea counter still reports health.
    #: ``None`` means no sample in this point measured it — an agent older
    #: than #980, or one that cannot read ``/proc/net/udp`` — and must be
    #: rendered as unknown, not as zero.
    receive_drop: int | None = None
    socket_drop: int | None = None


class DHCPTimeseries(BaseModel):
    window: str
    bucket_seconds: int
    points: list[DHCPTimePoint]


def _validate_window(window: str) -> None:
    if window not in WINDOW_SECONDS:
        raise HTTPException(
            status_code=400,
            detail=f"window must be one of {sorted(WINDOW_SECONDS)}",
        )


# Each series reads the same grants as the server it describes: DNS server
# traffic needs what the ``/dns`` router needs, DHCP traffic what the DHCP
# server routes need.
@router.get(
    "/dns/timeseries",
    response_model=DNSTimeseries,
    dependencies=[
        Depends(require_module("core.dns")),
        Depends(require_any_resource_permission("dns_group", "dns_zone", "dns_record")),
    ],
)
async def dns_timeseries(
    db: DB,
    _: CurrentUser,
    server_id: uuid.UUID | None = Query(None),
    window: str = Query("24h"),
) -> DNSTimeseries:
    _validate_window(window)
    bucket_s = _bucket_seconds_for(window)
    since = _window_start(window)

    # Use date_bin(interval, ts, anchor) so aggregated points land on
    # stable bucket boundaries across requests. Sum across all
    # servers when ``server_id`` isn't pinned — gives one aggregate
    # series per metric for the dashboard overview card.
    bucket_col = func.date_bin(
        timedelta(seconds=bucket_s),
        DNSMetricSample.bucket_at,
        datetime(2000, 1, 1, tzinfo=UTC),
    ).label("t")

    stmt = select(
        bucket_col,
        # Distinct agent buckets folded into this point. Counting DISTINCT
        # bucket_at (not rows) is what makes this the covered TIME SPAN
        # rather than a sample count: with several servers reporting, N
        # rows share one minute, and the aggregate rate for that minute is
        # still measured over 60 seconds.
        func.count(func.distinct(DNSMetricSample.bucket_at)).label("sample_buckets"),
        func.sum(DNSMetricSample.queries_total).label("queries_total"),
        func.sum(DNSMetricSample.noerror).label("noerror"),
        func.sum(DNSMetricSample.nxdomain).label("nxdomain"),
        func.sum(DNSMetricSample.servfail).label("servfail"),
        func.sum(DNSMetricSample.recursion).label("recursion"),
        func.sum(DNSMetricSample.rate_dropped).label("rate_dropped"),
        func.sum(DNSMetricSample.rate_slipped).label("rate_slipped"),
    ).where(DNSMetricSample.bucket_at >= since)
    if server_id is not None:
        stmt = stmt.where(DNSMetricSample.server_id == server_id)
    stmt = stmt.group_by(bucket_col).order_by(bucket_col)

    rows = (await db.execute(stmt)).all()
    points = [
        DNSTimePoint(
            t=row._mapping["t"],
            covered_seconds=int(row.sample_buckets or 0) * _AGENT_BUCKET_SECONDS,
            queries_total=int(row.queries_total or 0),
            noerror=int(row.noerror or 0),
            nxdomain=int(row.nxdomain or 0),
            servfail=int(row.servfail or 0),
            recursion=int(row.recursion or 0),
            rate_dropped=int(row.rate_dropped or 0),
            rate_slipped=int(row.rate_slipped or 0),
        )
        for row in rows
    ]
    return DNSTimeseries(window=window, bucket_seconds=bucket_s, points=points)


@router.get(
    "/dhcp/timeseries",
    response_model=DHCPTimeseries,
    dependencies=[
        Depends(require_module("core.dhcp")),
        Depends(require_resource_permission("dhcp_server")),
    ],
)
async def dhcp_timeseries(
    db: DB,
    _: CurrentUser,
    server_id: uuid.UUID | None = Query(None),
    window: str = Query("24h"),
) -> DHCPTimeseries:
    _validate_window(window)
    bucket_s = _bucket_seconds_for(window)
    since = _window_start(window)

    bucket_col = func.date_bin(
        timedelta(seconds=bucket_s),
        DHCPMetricSample.bucket_at,
        datetime(2000, 1, 1, tzinfo=UTC),
    ).label("t")

    stmt = select(
        bucket_col,
        func.count(func.distinct(DHCPMetricSample.bucket_at)).label("sample_buckets"),
        func.sum(DHCPMetricSample.discover).label("discover"),
        func.sum(DHCPMetricSample.offer).label("offer"),
        func.sum(DHCPMetricSample.request).label("request"),
        func.sum(DHCPMetricSample.ack).label("ack"),
        func.sum(DHCPMetricSample.nak).label("nak"),
        func.sum(DHCPMetricSample.decline).label("decline"),
        func.sum(DHCPMetricSample.release).label("release"),
        func.sum(DHCPMetricSample.inform).label("inform"),
        # #980 — SUM over an all-NULL group is NULL, which is the correct
        # answer here (nothing measured) and the reason these are not
        # coalesced like the counters above.
        func.sum(DHCPMetricSample.receive_drop).label("receive_drop"),
        func.sum(DHCPMetricSample.socket_drop).label("socket_drop"),
    ).where(DHCPMetricSample.bucket_at >= since)
    if server_id is not None:
        stmt = stmt.where(DHCPMetricSample.server_id == server_id)
    stmt = stmt.group_by(bucket_col).order_by(bucket_col)

    rows = (await db.execute(stmt)).all()
    points = [
        DHCPTimePoint(
            t=row._mapping["t"],
            covered_seconds=int(row.sample_buckets or 0) * _AGENT_BUCKET_SECONDS,
            discover=int(row.discover or 0),
            offer=int(row.offer or 0),
            request=int(row.request or 0),
            ack=int(row.ack or 0),
            nak=int(row.nak or 0),
            decline=int(row.decline or 0),
            release=int(row.release or 0),
            inform=int(row.inform or 0),
            # ``is None`` rather than ``or``: 0 is measured, and means the
            # opposite of unmeasured.
            receive_drop=None if row.receive_drop is None else int(row.receive_drop),
            socket_drop=None if row.socket_drop is None else int(row.socket_drop),
        )
        for row in rows
    ]
    return DHCPTimeseries(window=window, bucket_seconds=bucket_s, points=points)
