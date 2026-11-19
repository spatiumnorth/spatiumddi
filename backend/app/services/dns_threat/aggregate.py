"""Roll DNS query-log lines up into per-client hourly windows (#699).

The raw ``dns_query_log_entry`` table is operator triage on a 24 h
window. This turns it into something a detection can reason about — one
summary row per client per hour — and, crucially, one that *outlives*
the raw lines. "This host has looked like an exfil tunnel every hour
for three days" has to stay answerable after the evidence rows are
pruned.

Bucketing is fixed hourly, aligned to the hour. The aggregator
recomputes the current bucket and the previous one on every run and
upserts, which makes it idempotent, self-healing against late-arriving
log lines (agents batch and can lag), and safe to run far more often
than the bucket width — the alternative, a trailing rolling window,
would produce overlapping rows that nothing could sensibly key on.

Rows are streamed (server-side cursor, ``yield_per`` batches) ordered by
client so grouping never holds more than one client's queries in
memory: a busy resolver can put six figures of
lines into a single hour, and this runs on the worker alongside
everything else.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns_threat import DNSClientWindow
from app.models.logs import DNSQueryLogEntry
from app.services.dns_threat.beaconing import score_beaconing
from app.services.dns_threat.dga import score_dga
from app.services.dns_threat.scoring import (
    DEFAULT_BENIGN_PARENTS,
    extract_features,
    score_tunneling,
)

logger = structlog.get_logger(__name__)

# Windows outlive the raw log lines (24 h) by a wide margin — the whole
# point is retaining the summary after the evidence is gone — but not
# forever; this is behavioural metadata about clients.
WINDOW_RETENTION_DAYS = 30

# Scored windows below this are kept but are noise for every consumer;
# the Threat tab and the alert matcher both filter above it. Kept low so
# "nothing is scoring at all" stays distinguishable from "the feature
# isn't running".
INTERESTING_SCORE = 20.0

# The score at which a finding is worth waking someone for. Distinct
# from INTERESTING_SCORE on purpose — "worth a look on a dashboard" and
# "page me at 03:00" are different bars — but defined HERE, next to it,
# so the two are visibly a pair rather than drifting apart in separate
# modules. The alert rule imports this; a per-rule threshold_percent
# still overrides it.
ALERTING_SCORE = 60.0

# Beaconing alerts higher than tunneling. Legitimate software polls on
# a timer constantly — monitoring agents, health checks, update
# checkers — and they are indistinguishable from a callback by timing
# alone, so a lower bar would page operators about their own
# infrastructure until they turned the rule off.
BEACON_ALERTING_SCORE = 85.0

# DGA alerts higher than tunneling for the same reason beaconing does,
# plus one specific to this detection: without the NXDOMAIN prior the
# issue originally specified (the query log carries no rcode — see
# ``dga.py``), the score rests on name plausibility alone. That is a
# weaker basis than tunneling's four independent signals, so the bar to
# wake someone is set correspondingly higher.
DGA_ALERTING_SCORE = 80.0

# How far back the raw query log is kept (``prune_log_entries``). The
# backfill sweep can't recover anything older, because the evidence is
# gone.
RAW_LOG_RETENTION_HOURS = 24

# Rows fetched per round trip from the server-side cursor in
# ``aggregate_window``. Memory is one batch plus one client's rows.
STREAM_BATCH_ROWS = 2000

# Set after the first backfill sweep of this process. See run_aggregation.
_backfill_attempted = False


def floor_hour(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


async def aggregate_window(
    db: AsyncSession,
    *,
    window_start: datetime,
    allowlist: frozenset[str] | set[str] = DEFAULT_BENIGN_PARENTS,
) -> int:
    """Compute + upsert every client's row for one hourly bucket.

    Returns the number of client rows written.
    """
    window_end = window_start + timedelta(hours=1)
    stmt = (
        select(
            DNSQueryLogEntry.client_ip,
            DNSQueryLogEntry.qname,
            DNSQueryLogEntry.qtype,
            DNSQueryLogEntry.server_id,
            # Beaconing scores off arrival times, so the rollup needs
            # ts as well as content.
            DNSQueryLogEntry.ts,
        ).where(
            DNSQueryLogEntry.ts >= window_start,
            DNSQueryLogEntry.ts < window_end,
            DNSQueryLogEntry.client_ip.is_not(None),
        )
        # Ordering by client is what lets the grouping below stream:
        # one client's rows arrive together, so only that client's
        # queries are ever held in memory.
        .order_by(DNSQueryLogEntry.client_ip)
        # Without ``yield_per`` an ORM-column select drains the whole
        # cursor into a list (``orm/loading.py`` ``_raw_all_rows``) even
        # under ``db.stream`` — the hour's rows all sat in worker memory
        # and a busy hour OOM-killed it (#4275). ``yield_per`` implies
        # ``stream_results`` and caps the fetch at one batch.
        .execution_options(yield_per=STREAM_BATCH_ROWS)
    )

    written = 0
    current_ip: str | None = None
    batch: list[tuple[str | None, str | None, Any]] = []
    # Arrival times per name, for the beaconing measure. Reset with the
    # batch so only one client's timings are ever held.
    timings: dict[str, list[datetime]] = defaultdict(list)

    async def _flush() -> None:
        nonlocal written, batch, timings
        if current_ip is None or not batch:
            return
        feats = extract_features(batch, allowlist=allowlist)
        verdict = score_tunneling(feats)
        beacon = score_beaconing(timings)
        # Scores off the parent map ``extract_features`` already built,
        # so no second walk over the client's rows.
        dga = score_dga(feats.parent_labels)
        await _upsert(
            db,
            client_ip=current_ip,
            window_start=window_start,
            window_end=window_end,
            feats=feats,
            score=verdict.score,
            signals=verdict.signals_json(),
            beacon=beacon,
            dga=dga,
        )
        written += 1
        batch = []
        timings = defaultdict(list)

    result = await db.stream(stmt)
    async for client_ip, qname, qtype, server_id, ts in result:
        ip = str(client_ip)
        if ip != current_ip:
            await _flush()
            current_ip = ip
        batch.append((qname, qtype, server_id))
        if qname and ts is not None:
            # Allowlisted names are deliberately INCLUDED here, unlike
            # the tunneling ratios: a beacon to a CDN-hosted callback is
            # still a beacon, and the qname in the evidence is what lets
            # an operator judge it.
            timings[qname.lower()].append(ts)
    await _flush()

    await db.commit()
    return written


async def _upsert(
    db: AsyncSession,
    *,
    client_ip: str,
    window_start: datetime,
    window_end: datetime,
    feats: Any,
    score: float,
    signals: list[dict[str, Any]],
    beacon: Any,
    dga: Any,
) -> None:
    """Insert or refresh one client's bucket.

    Upsert rather than insert because the same bucket is recomputed on
    subsequent runs as late log lines land; the unique constraint on
    (client_ip, window_start) is what the conflict target keys on.
    """
    values = {
        "client_ip": client_ip,
        "server_count": feats.server_count,
        "window_start": window_start,
        "window_end": window_end,
        "query_count": feats.query_count,
        "distinct_qnames": feats.distinct_qnames,
        "distinct_parents": feats.distinct_parents,
        "top_parent": feats.top_parent,
        "top_parent_subdomains": feats.top_parent_subdomains,
        "max_label_length": feats.max_label_length,
        "avg_label_length": feats.avg_label_length,
        "mean_label_entropy": feats.mean_label_entropy,
        "payload_qtype_count": feats.payload_qtype_count,
        "tunnel_score": score,
        "tunnel_signals": signals,
        "beacon_score": beacon.score,
        "beacon_candidates": beacon.candidates_json(),
        "beacon_detail": beacon.detail,
        "dga_score": dga.score,
        "dga_candidates": dga.candidates_json(),
        "dga_signals": dga.signals_json(),
        "dga_detail": dga.detail,
        "allowlisted": feats.allowlisted,
    }
    stmt = pg_insert(DNSClientWindow).values(**values)
    await db.execute(
        stmt.on_conflict_do_update(
            constraint="uq_dns_client_window_ip_bucket",
            set_={k: v for k, v in values.items() if k not in ("client_ip", "window_start")},
        )
    )


async def run_aggregation(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    allowlist: frozenset[str] | set[str] = DEFAULT_BENIGN_PARENTS,
) -> dict[str, int]:
    """Recompute the current and previous hourly buckets, then prune.

    Two buckets rather than one because agents batch their log shipping:
    a line generated at 10:59 can arrive at 11:02, after the 10:00
    bucket was first computed. Recomputing the previous hour picks it
    up. Anything later than that is lost to the rollup, which is an
    acceptable trade against unbounded recomputation.
    """
    now = now or datetime.now(UTC)
    current = floor_hour(now)
    previous = current - timedelta(hours=1)

    rows_current = await aggregate_window(db, window_start=current, allowlist=allowlist)
    rows_previous = await aggregate_window(db, window_start=previous, allowlist=allowlist)

    # Backfill. A worker outage longer than two hours (a node drain
    # during a rolling upgrade, an OOM, a Celery/Redis blip) would
    # otherwise leave a permanent hole: the raw rows are still on disk
    # for 24 h but nothing ever looks that far back, and then they are
    # pruned. Bounded by the raw-log retention and skipped where a
    # bucket already has rows, so the steady-state cost is one indexed
    # query per tick.
    backfilled = 0
    # Once per process, not every tick. The gap this recovers from is a
    # worker/beat outage — which means a process restart, so the first
    # tick after coming back is exactly when it matters. Running it on
    # every tick instead re-scanned every legitimately-quiet hour
    # forever, because a bucket with no clients never gets a row and so
    # can never become "covered".
    global _backfill_attempted
    if _backfill_attempted:
        cutoff = now - timedelta(days=WINDOW_RETENTION_DAYS)
        pruned = await db.execute(
            delete(DNSClientWindow).where(DNSClientWindow.window_start < cutoff)
        )
        await db.commit()
        return {
            "windows_current": rows_current,
            "windows_previous": rows_previous,
            "backfilled": 0,
            "pruned": pruned.rowcount or 0,
        }
    _backfill_attempted = True
    covered = set(
        (
            await db.execute(
                select(DNSClientWindow.window_start)
                .where(
                    DNSClientWindow.window_start >= now - timedelta(hours=RAW_LOG_RETENTION_HOURS)
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    for back in range(2, RAW_LOG_RETENTION_HOURS):
        bucket = current - timedelta(hours=back)
        if bucket in covered:
            continue
        written = await aggregate_window(db, window_start=bucket, allowlist=allowlist)
        if written:
            backfilled += written
            logger.info(
                "dns_threat_backfilled_bucket",
                bucket=bucket.isoformat(),
                clients=written,
                note="gap recovered from raw query log — worker was likely down",
            )

    cutoff = now - timedelta(days=WINDOW_RETENTION_DAYS)
    pruned = await db.execute(delete(DNSClientWindow).where(DNSClientWindow.window_start < cutoff))
    await db.commit()

    return {
        "windows_current": rows_current,
        "windows_previous": rows_previous,
        "backfilled": backfilled,
        "pruned": pruned.rowcount or 0,
    }


async def compute_threat_summary(
    db: AsyncSession, *, hours: int = 24, min_score: float = INTERESTING_SCORE
) -> dict[str, Any]:
    """Trailing-window rollup shared by the REST endpoint, the Security
    dashboard card and the Operator Copilot.

    One implementation on purpose: the threshold is expected to be
    retuned once this meets real traffic, and three copies of the query
    would leave the copilot answering against a different definition of
    "suspicious" than the UI shows.
    """
    from sqlalchemy import func, or_

    from app.models.dns_threat_mute import DNSThreatMute

    since = datetime.now(UTC) - timedelta(hours=hours)
    # Muting is a decision that a client has been reviewed and cleared,
    # so it has to clear the client everywhere an operator looks — not
    # just stop the alert. Otherwise the Security dashboard card stays
    # red and the copilot keeps reporting a host someone already
    # triaged, which is exactly what the mute UI promises it won't do.
    muted = select(DNSThreatMute.client_ip).where(
        or_(
            DNSThreatMute.muted_until.is_(None),
            DNSThreatMute.muted_until > datetime.now(UTC),
        )
    )
    totals = (
        await db.execute(
            select(
                func.count().label("windows"),
                func.count(func.distinct(DNSClientWindow.client_ip)).label("clients"),
                func.coalesce(func.max(DNSClientWindow.tunnel_score), 0.0).label("peak"),
            ).where(
                DNSClientWindow.window_start >= since,
                DNSClientWindow.client_ip.not_in(muted),
            )
        )
    ).one()
    suspicious = (
        await db.execute(
            select(func.count(func.distinct(DNSClientWindow.client_ip))).where(
                DNSClientWindow.window_start >= since,
                DNSClientWindow.allowlisted.is_(False),
                DNSClientWindow.tunnel_score >= min_score,
                DNSClientWindow.client_ip.not_in(muted),
            )
        )
    ).scalar_one()
    # Thresholded so a clean install never names an innocent host as
    # "worst" at 0/100.
    worst = (
        await db.execute(
            select(DNSClientWindow)
            .where(
                DNSClientWindow.window_start >= since,
                DNSClientWindow.allowlisted.is_(False),
                DNSClientWindow.tunnel_score >= min_score,
                DNSClientWindow.client_ip.not_in(muted),
            )
            .order_by(DNSClientWindow.tunnel_score.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return {
        "windows_scored": totals.windows or 0,
        "clients_seen": totals.clients or 0,
        "suspicious_clients": suspicious or 0,
        "peak_score": float(totals.peak or 0.0),
        "worst_client_ip": str(worst.client_ip) if worst else None,
        "worst_client_score": worst.tunnel_score if worst else None,
        "worst_client_parent": worst.top_parent if worst else None,
        "since": since,
        # "No data" and "no threats" must stay distinguishable on every
        # surface — an idle feature rendering as an all-clear is the
        # failure this whole feature exists to avoid.
        "has_data": (totals.windows or 0) > 0,
    }
