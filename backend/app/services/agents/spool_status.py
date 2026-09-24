"""The agent push spool as reported on the heartbeat (#1077).

The DNS and DHCP agents keep a durable on-disk spool of pushes the control
plane did not acknowledge (``spool.py`` in each agent package), replayed in
order on reconnect. Its state rides every heartbeat as ``spool`` — the shape
of ``SpoolManager.status()`` — and lands on ``{dns,dhcp}_server.spool_status``.

Two heartbeat handlers, one ingest function, for the same reason as
``config_apply.py``: the "only overwrite on a real report" rule has to be
identical on both, or a pre-#1077 agent (which sends no ``spool`` at all)
would silently erase a trim a newer one recorded.

The models tolerate extra keys (``extra="ignore"``): a newer agent may report
fields this control plane predates, and an unknown field must never 422 a
heartbeat. What IS read is bounded and typed, because the column is written
from an agent-supplied payload.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Protocol

import structlog
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

logger = structlog.get_logger(__name__)

#: A trim inside this window is "recent": the alert fires and the chip turns
#: red. A trim is a one-off event with no "recovered" signal from the agent
#: (the counters are cumulative), so the window is what lets the alert
#: auto-resolve — a day is long enough that an overnight trim is still open
#: in the morning.
TRIM_RECENT_WINDOW = timedelta(hours=24)

#: Streams whose loss is a correctness hole rather than a stats gap. Kea lease
#: events are the only way the control plane learns about agent-managed
#: leases, so a trimmed one is a lease with no ``dhcp_lease`` row, no IPAM
#: mirror and no DDNS record until the client renews.
CRITICAL_STREAMS = frozenset({"lease_events"})

# Bounds on what the agent may report — the spool is keyed by a small fixed
# set of stream names, so anything past this is a malformed payload.
_MAX_STREAMS = 32
_MAX_STREAM_NAME = 40
_StreamName = Annotated[str, StringConstraints(min_length=1, max_length=_MAX_STREAM_NAME)]


class SpoolStreamStatus(BaseModel):
    """One stream's spool (``Spool.status()`` on the agent)."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    entries: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)
    cap_bytes: int = Field(default=0, ge=0)
    oldest_at: datetime | None = None
    trimmed_entries_total: int = Field(default=0, ge=0)
    trimmed_bytes_total: int = Field(default=0, ge=0)
    last_trim_at: datetime | None = None
    expired_entries_total: int = Field(default=0, ge=0)
    rejected_entries_total: int = Field(default=0, ge=0)
    write_failures_total: int = Field(default=0, ge=0)


class SpoolStatus(BaseModel):
    """The whole agent spool (``SpoolManager.status()`` on the agent)."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = True
    cap_bytes: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)
    entries: int = Field(default=0, ge=0)
    oldest_at: datetime | None = None
    trimmed_entries_total: int = Field(default=0, ge=0)
    trimmed_bytes_total: int = Field(default=0, ge=0)
    last_trim_at: datetime | None = None
    expired_entries_total: int = Field(default=0, ge=0)
    streams: dict[_StreamName, SpoolStreamStatus] = Field(
        default_factory=dict, max_length=_MAX_STREAMS
    )


class _HasSpoolStatus(Protocol):
    spool_status: dict[str, Any] | None


def apply_reported_spool(
    server: _HasSpoolStatus,
    spool: dict[str, Any] | None,
    *,
    agent_kind: str,
    server_id: str,
) -> None:
    """Persist the heartbeat's spool report onto the server row.

    ``None`` — the agent sent no ``spool`` field — leaves the column exactly as
    it was. NULL in the column means "never reported", which is UNKNOWN, and a
    heartbeat that simply omitted the field must not turn a known trim into
    that.

    The heartbeat declares ``spool`` as a loose dict and validation happens
    HERE, for the same reason ``config`` is handled that way: a malformed spool
    report is a telemetry bug, and 422-ing the whole heartbeat over it would
    take a healthy agent offline (no op ACKs, no token rotation, stale
    last-seen). An invalid report is logged and ignored; the previous value
    stays.
    """
    if spool is None:
        return
    try:
        parsed = SpoolStatus.model_validate(spool)
    except ValidationError as exc:
        logger.warning(
            "agent_spool_status_invalid",
            agent_kind=agent_kind,
            server_id=server_id,
            errors=exc.error_count(),
        )
        return
    server.spool_status = parsed.model_dump(mode="json")


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def recently_trimmed_streams(
    spool_status: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    window: timedelta = TRIM_RECENT_WINDOW,
) -> dict[str, dict[str, Any]]:
    """Streams whose last trim is within ``window``, keyed by stream name.

    Empty when the status is NULL (unknown), when nothing was ever trimmed, or
    when the last trim is older than the window. Falls back to the top-level
    ``last_trim_at`` under the pseudo-stream ``"unknown"`` if a report carries
    a recent aggregate trim but no per-stream breakdown.
    """
    if not isinstance(spool_status, dict):
        return {}
    cutoff = (now or datetime.now(UTC)) - window
    out: dict[str, dict[str, Any]] = {}
    streams = spool_status.get("streams")
    if isinstance(streams, dict):
        for name, s in streams.items():
            if not isinstance(s, dict):
                continue
            ts = _parse_ts(s.get("last_trim_at"))
            if ts is not None and ts >= cutoff:
                out[str(name)] = s
    if not out:
        ts = _parse_ts(spool_status.get("last_trim_at"))
        if ts is not None and ts >= cutoff:
            out["unknown"] = spool_status
    return out
