"""The agent's actual memory use as reported on the heartbeat (#4193).

The DNS and DHCP agents read their container's cgroup (``memory.current`` /
``memory.peak`` / limit) and the resident set of the daemon and of the agent
itself, and send it as the heartbeat's optional ``memory`` block. The latest
report lands on ``{dns,dhcp}_server.memory_status`` and a sample goes into the
server's metric-sample bucket for a short history (same retention as the
counters, ``tasks/prune_metrics``).

Best effort end to end: every field is optional and NULL means UNKNOWN, never
0. A heartbeat without the block (an older agent) leaves the stored report
clears it (the agent that sent figures was replaced by one that does not, so
the old ones are no longer true), and an invalid block is logged and ignored
rather than 422-ing a heartbeat that also carries liveness and op acks. Every
reader goes through :func:`fresh_memory_status`, so a report that stopped being
refreshed (a wedged agent) also reads as not reported.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.metrics import DHCPMetricSample, DNSMetricSample

logger = structlog.get_logger(__name__)

# A byte count no real host reaches; bounds an agent-supplied value to a
# BigInteger with room to spare.
_MAX_BYTES = 1 << 60


class MemoryReport(BaseModel):
    """The ``memory`` heartbeat block. Unknown keys are ignored."""

    model_config = ConfigDict(extra="ignore")

    used_bytes: int | None = Field(default=None, ge=0, le=_MAX_BYTES)
    peak_bytes: int | None = Field(default=None, ge=0, le=_MAX_BYTES)
    limit_bytes: int | None = Field(default=None, ge=0, le=_MAX_BYTES)
    daemon_rss_bytes: int | None = Field(default=None, ge=0, le=_MAX_BYTES)
    agent_rss_bytes: int | None = Field(default=None, ge=0, le=_MAX_BYTES)


class MemoryStatus(MemoryReport):
    """What a server row exposes: the report plus when it arrived."""

    reported_at: datetime | None = None


class _HasMemoryStatus(Protocol):
    id: Any
    memory_status: dict[str, Any] | None


#: Matches ``AGENT_STALE_AFTER`` (120 s) in ``tasks/dns.py`` / ``tasks/dhcp_health.py``
#: (not imported: tasks/ would be an import cycle risk), so the figure goes
#: "not reported" exactly when the server itself reads stale, with no separate
#: threshold that flickers for an agent on a slower HEARTBEAT_INTERVAL.
MEMORY_STALE_AFTER = timedelta(seconds=120)


def fresh_memory_status(
    status: dict[str, Any] | None, now: datetime | None = None
) -> dict[str, Any] | None:
    """The stored report, or None when absent, undated or older than
    :data:`MEMORY_STALE_AFTER`. Use this for every read of ``memory_status``."""
    if not isinstance(status, dict):
        return None
    raw = status.get("reported_at")
    try:
        at = datetime.fromisoformat(raw) if isinstance(raw, str) else None
    except ValueError:
        at = None
    if at is None:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    if (now or datetime.now(UTC)) - at > MEMORY_STALE_AFTER:
        return None
    return status


def _bucket(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(second=0, microsecond=0)


async def apply_reported_memory(
    db: AsyncSession,
    server: _HasMemoryStatus,
    memory: dict[str, Any] | None,
    *,
    sample_model: type[DNSMetricSample] | type[DHCPMetricSample],
    agent_kind: str,
    now: datetime | None = None,
) -> None:
    """Store the report on the server row and fold it into this minute's
    metric-sample bucket (peak is the max seen in the bucket). A heartbeat
    without the block clears the stored report; history samples stay."""
    if memory is None:
        server.memory_status = None
        return
    try:
        report = MemoryReport.model_validate(memory)
    except ValidationError as exc:
        logger.warning(
            "agent_memory_report_invalid",
            agent_kind=agent_kind,
            server_id=str(server.id),
            errors=exc.error_count(),
        )
        return
    now = now or datetime.now(UTC)
    server.memory_status = {**report.model_dump(mode="json"), "reported_at": now.isoformat()}

    if report.used_bytes is None and report.daemon_rss_bytes is None:
        return  # nothing worth a history point
    # An upsert, not get-then-add: the agent's metric push creates the same
    # (server, minute) row and the two requests can race at the minute edge.
    # Only the mem_* columns are touched, so the counters stay the metric
    # push's; a row created here takes their Python-side 0 defaults until it arrives.
    peak = max((p for p in (report.peak_bytes, report.used_bytes) if p is not None), default=None)
    values = {
        "server_id": server.id,
        "bucket_at": _bucket(now),
        "mem_used_bytes": report.used_bytes,
        "mem_peak_bytes": peak,
        "mem_daemon_rss_bytes": report.daemon_rss_bytes,
        "mem_agent_rss_bytes": report.agent_rss_bytes,
    }
    stmt = pg_insert(sample_model).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["server_id", "bucket_at"],
        set_={
            "mem_used_bytes": stmt.excluded.mem_used_bytes,
            "mem_daemon_rss_bytes": stmt.excluded.mem_daemon_rss_bytes,
            "mem_agent_rss_bytes": stmt.excluded.mem_agent_rss_bytes,
            "mem_peak_bytes": func.greatest(
                sample_model.mem_peak_bytes, stmt.excluded.mem_peak_bytes
            ),
        },
    )
    await db.execute(stmt)


class MemoryHistoryPoint(BaseModel):
    ts: datetime
    used_bytes: int | None = None
    peak_bytes: int | None = None
    daemon_rss_bytes: int | None = None
    agent_rss_bytes: int | None = None


class MemoryHistory(BaseModel):
    """Per-minute memory samples for the server modal's sparkline."""

    server_id: Any
    hours: int
    points: list[MemoryHistoryPoint]


#: Longest window the history endpoints serve (``prune_metrics`` keeps the
#: samples 7 days by default, an operator may shorten that).
MAX_HISTORY_HOURS = 24


async def memory_history(
    db: AsyncSession,
    sample_model: type[DNSMetricSample] | type[DHCPMetricSample],
    server_id: Any,
    hours: int,
) -> MemoryHistory:
    """The server's samples that carry memory, oldest first."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = (
        await db.execute(
            select(sample_model)
            .where(sample_model.server_id == server_id)
            .where(sample_model.bucket_at >= since)
            .where(sample_model.mem_used_bytes.is_not(None))
            .order_by(sample_model.bucket_at)
        )
    ).scalars()
    return MemoryHistory(
        server_id=server_id,
        hours=hours,
        points=[
            MemoryHistoryPoint(
                ts=r.bucket_at,
                used_bytes=r.mem_used_bytes,
                peak_bytes=r.mem_peak_bytes,
                daemon_rss_bytes=r.mem_daemon_rss_bytes,
                agent_rss_bytes=r.mem_agent_rss_bytes,
            )
            for r in rows
        ],
    )
