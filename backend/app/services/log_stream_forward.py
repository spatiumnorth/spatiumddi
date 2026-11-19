"""Forward the DNS query log and DHCP activity log to syslog targets (#4545).

The agents already ship both logs to the control plane
(``dns_query_log_entry`` / ``dhcp_log_entry``). This sends the same entries,
as they are ingested, to every enabled syslog ``AuditForwardTarget`` that
opted into the stream: the targets are the audit-forwarding ones, with two
extra per-target switches (``stream_dns_query_log`` /
``stream_dhcp_activity_log``, both off by default), filters and sampling.

Design, in the order it matters:

* **The ingest request never waits for a collector.** The handler builds one
  event dict per stored row and, after its commit, calls :func:`submit`, a
  synchronous append to a bounded in-process deque. Routing, rendering and
  delivery happen on background tasks of the api's event loop.
* **Bounded memory, counted loss.** Every target has its own queue
  (``TARGET_QUEUE_CAP`` events). A collector that is slow or down
  fills it, and further events displace the oldest, each counted: in
  ``spatiumddi_log_stream_dropped_total`` and, flushed every few seconds,
  in ``audit_forward_target.log_stream_dropped_total`` /
  ``log_stream_last_drop_at``, which the worker-evaluated
  ``log_forward_dropping`` alert reads. A batch that fails
  ``SEND_ATTEMPTS`` times is dropped and counted the same way.
* **One target's trouble stays its own.** Each target has its own queue and
  sender task, so a stuck collector delays only itself.
* **Best effort, per api process.** Each api process forwards the entries it
  ingested; there is no replay across a restart (the entry is still in the
  Logs page for its retention window). Webhook, SMTP and CEF / LEEF targets
  are not eligible: batching a webhook needs a design of its own, and CEF /
  LEEF define no field mapping for these events.

``docs/OBSERVABILITY.md`` has the operator-facing view.
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from collections import deque
from collections.abc import Iterable
from typing import Any

import structlog
from sqlalchemy import func, select, update

from app.metrics import LOG_STREAM_DROPPED, LOG_STREAM_SENT
from app.models.audit_forward import AuditForwardTarget
from app.services import audit_forward, dispatch_db

logger = structlog.get_logger(__name__)

DNS_QUERY_LOG = "dns_query_log"
DHCP_ACTIVITY_LOG = "dhcp_activity_log"
STREAMS = (DNS_QUERY_LOG, DHCP_ACTIVITY_LOG)

#: Formats a log-stream target can use. CEF / LEEF have no field mapping for
#: these events; the other three carry them as JSON.
STREAM_FORMATS = ("rfc5424_json", "rfc3164", "json_lines")

#: Per-stream filter keys, as stored in ``audit_forward_target.log_stream_filters``.
ID_FILTER_KEYS = (
    "dns_server_group_ids",
    "dns_server_ids",
    "dhcp_server_group_ids",
    "dhcp_server_ids",
)
VALUE_FILTER_KEYS = ("dns_rcodes", "dns_qtypes", "dhcp_codes")
FILTER_KEYS = ID_FILTER_KEYS + VALUE_FILTER_KEYS
_MAX_FILTER_VALUES = 100

# ── Limits (module attributes so a test can shrink them) ───────────────────
INGRESS_CAP = 20_000  # events waiting to be routed
TARGET_QUEUE_CAP = 10_000  # events waiting for one target's collector
BATCH_SIZE = 200
SEND_TIMEOUT_S = 10.0
SEND_ATTEMPTS = 3
RETRY_BACKOFF_S = 2.0
TARGET_REFRESH_S = 30.0
DROP_FLUSH_S = 10.0
#: The alert fires while the newest recorded drop is younger than this.
ALERT_WINDOW_S = 15 * 60

_KEA_SEVERITY = {"WARN": "warning", "WARNING": "warning", "ERROR": "error", "FATAL": "critical"}


# ── Filter validation (settings API) ───────────────────────────────────────


def normalize_filters(raw: dict[str, Any] | None) -> dict[str, list[str]] | None:
    """Validate and normalise a ``log_stream_filters`` value; ``None`` when no
    dimension is filtered. Raises ``ValueError`` with the reason."""
    if not raw:
        return None
    out: dict[str, list[str]] = {}
    for key, values in raw.items():
        if key not in FILTER_KEYS:
            raise ValueError(f"unknown log stream filter {key!r}; one of {sorted(FILTER_KEYS)}")
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError(f"{key} must be a list of strings")
        if len(values) > _MAX_FILTER_VALUES:
            raise ValueError(f"{key} may carry at most {_MAX_FILTER_VALUES} values")
        cleaned: list[str] = []
        for v in values:
            v = v.strip()
            if not v:
                continue
            if key in ID_FILTER_KEYS:
                try:
                    v = str(uuid.UUID(v))
                except ValueError as exc:
                    raise ValueError(f"{key} must hold UUIDs: {v!r}") from exc
            else:
                v = v.upper()
            if v not in cleaned:
                cleaned.append(v)
        if cleaned:
            out[key] = cleaned
    return out or None


# ── Event construction (called by the ingest handlers) ─────────────────────


def dns_event(row: Any, group_id: Any) -> dict[str, Any]:
    """One DNS query log row as the wire payload (the Logs page's fields)."""
    return {
        "stream": DNS_QUERY_LOG,
        "timestamp": row.ts.isoformat(),
        "severity": "info",
        "server_id": str(row.server_id) if row.server_id else None,
        "server_name": row.server_name,
        "server_group_id": str(group_id) if group_id else None,
        "client_ip": str(row.client_ip) if row.client_ip else None,
        "client_port": row.client_port,
        "qname": row.qname,
        "qclass": row.qclass,
        "qtype": row.qtype,
        "flags": row.flags,
        "view": row.view,
        "rcode": row.rcode,
        "answer_count": row.answer_count,
        "raw": row.raw,
    }


def dhcp_event(row: Any, group_id: Any) -> dict[str, Any]:
    """One DHCP activity log row as the wire payload."""
    return {
        "stream": DHCP_ACTIVITY_LOG,
        "timestamp": row.ts.isoformat(),
        # Kea's own severity word, folded onto the vocabulary the syslog
        # renderers rank (``info`` / ``warning`` / ``error`` / ``critical``).
        "severity": _KEA_SEVERITY.get((row.severity or "").upper(), "info"),
        "server_id": str(row.server_id) if row.server_id else None,
        "server_name": row.server_name,
        "server_group_id": str(group_id) if group_id else None,
        "code": row.code,
        "mac_address": str(row.mac_address) if row.mac_address else None,
        "ip_address": str(row.ip_address) if row.ip_address else None,
        "transaction_id": row.transaction_id,
        "raw": row.raw,
    }


# ── Per-target filter + sampling ───────────────────────────────────────────


def _rand() -> float:
    return random.random() * 100.0


def _any_of(filters: dict[str, list[str]], key: str, value: Any, *, upper: bool = False) -> bool:
    wanted = filters.get(key)
    if not wanted:
        return True
    if value is None:
        # NULL is "unknown", never a match for a value filter (an rcode that
        # was not recorded must not pass an ``rcode=NXDOMAIN`` filter).
        return False
    return (str(value).upper() if upper else str(value)) in wanted


def accepts(target: dict[str, Any], event: dict[str, Any]) -> bool:
    """Whether ``target`` wants ``event``: stream opt-in, filters, sampling."""
    stream = event["stream"]
    if not target.get(f"stream_{stream}"):
        return False
    filters = target.get("log_stream_filters") or {}
    prefix = "dns" if stream == DNS_QUERY_LOG else "dhcp"
    if not _any_of(filters, f"{prefix}_server_group_ids", event.get("server_group_id")):
        return False
    if not _any_of(filters, f"{prefix}_server_ids", event.get("server_id")):
        return False
    if stream == DNS_QUERY_LOG:
        if not _any_of(filters, "dns_rcodes", event.get("rcode"), upper=True):
            return False
        if not _any_of(filters, "dns_qtypes", event.get("qtype"), upper=True):
            return False
        percent = int(target.get("dns_query_sample_percent") or 100)
        if percent < 100 and _rand() >= percent:
            return False
    elif not _any_of(filters, "dhcp_codes", event.get("code"), upper=True):
        return False
    return True


# ── Process state ──────────────────────────────────────────────────────────


class _TargetQueue:
    def __init__(self, target: dict[str, Any]) -> None:
        self.target = target
        self.events: deque[dict[str, Any]] = deque()
        self.task: asyncio.Task[None] | None = None
        self.unflushed: dict[str, int] = {}  # drops not yet written to the row


class _State:
    def __init__(self) -> None:
        self.targets: dict[str, _TargetQueue] = {}
        self.wanted: set[str] | None = None  # None = not loaded yet
        self.loaded_at = 0.0
        self.ingress: deque[dict[str, Any]] = deque()
        self.pump: asyncio.Task[None] | None = None
        self.refresh: asyncio.Task[None] | None = None
        self.flusher: asyncio.Task[None] | None = None


_state = _State()


def _alive(task: asyncio.Task[Any] | None) -> bool:
    if task is None or task.done():
        return False
    try:
        return task.get_loop() is asyncio.get_running_loop()
    except RuntimeError:
        return False


def reset() -> None:
    """Forget everything (tests; also what a changed event loop needs)."""
    global _state
    for tq in _state.targets.values():
        if tq.task is not None:
            tq.task.cancel()
    for task in (_state.pump, _state.refresh, _state.flusher):
        if task is not None:
            task.cancel()
    _state = _State()


def invalidate() -> None:
    """A target was written: reload on the next ingest (other api processes
    pick it up within ``TARGET_REFRESH_S``)."""
    _state.loaded_at = 0.0


def wants(stream: str) -> bool:
    """Whether any target currently wants ``stream`` (True until the first
    load). The ingest handlers call this before building event dicts so an
    install with no log stream pays nothing but this check."""
    if time.monotonic() - _state.loaded_at > TARGET_REFRESH_S and not _alive(_state.refresh):
        _state.refresh = asyncio.get_running_loop().create_task(_refresh_quietly())
    return _state.wanted is None or stream in _state.wanted


def submit(events: Iterable[dict[str, Any]]) -> None:
    """Hand committed entries to the forwarder. Synchronous, O(n) appends,
    never blocks and never raises: this is called from the ingest request."""
    try:
        batch = list(events)
        if not batch:
            return
        overflow = 0
        for event in batch:
            if len(_state.ingress) >= INGRESS_CAP:
                dropped = _state.ingress.popleft()
                overflow += 1
                _record_unrouted_drop(dropped["stream"])
            _state.ingress.append(event)
        if overflow:
            logger.warning("log_stream_ingress_overflow", dropped=overflow)
        if not _alive(_state.pump):
            _state.pump = asyncio.get_running_loop().create_task(_pump())
    except Exception:  # noqa: BLE001 — forwarding must never fail an ingest
        logger.warning("log_stream_submit_failed", exc_info=True)


# ── Target loading ─────────────────────────────────────────────────────────


async def _load_stream_targets() -> list[dict[str, Any]]:
    async with dispatch_db.session() as session:
        rows = (
            (
                await session.execute(
                    select(AuditForwardTarget)
                    .where(AuditForwardTarget.enabled.is_(True))
                    .where(AuditForwardTarget.kind == "syslog")
                    .where(
                        AuditForwardTarget.stream_dns_query_log.is_(True)
                        | AuditForwardTarget.stream_dhcp_activity_log.is_(True)
                    )
                )
            )
            .scalars()
            .all()
        )
    return [
        {
            "id": str(t.id),
            "name": t.name,
            "format": t.format,
            "host": t.host,
            "port": int(t.port),
            "protocol": t.protocol,
            "facility": int(t.facility),
            "ca_cert_pem": t.ca_cert_pem,
            "stream_dns_query_log": bool(t.stream_dns_query_log),
            "stream_dhcp_activity_log": bool(t.stream_dhcp_activity_log),
            "log_stream_filters": t.log_stream_filters,
            "dns_query_sample_percent": int(t.dns_query_sample_percent or 100),
        }
        for t in rows
        if t.host
    ]


async def refresh_targets() -> None:
    """Reload the opted-in targets, keeping the queue of one that persists."""
    loaded = await _load_stream_targets()
    fresh: dict[str, _TargetQueue] = {}
    for target in loaded:
        tq = _state.targets.get(target["id"])
        if tq is None:
            tq = _TargetQueue(target)
        else:
            tq.target = target
        fresh[target["id"]] = tq
    for tid, tq in _state.targets.items():
        if tid not in fresh and tq.task is not None:
            tq.task.cancel()
    _state.targets = fresh
    _state.wanted = {s for t in loaded for s in STREAMS if t.get(f"stream_{s}")}
    _state.loaded_at = time.monotonic()


async def _refresh_quietly() -> None:
    try:
        await refresh_targets()
    except Exception:  # noqa: BLE001
        # Keep the previous answer and try again after the interval.
        _state.loaded_at = time.monotonic()
        logger.warning("log_stream_target_load_failed", exc_info=True)


# ── Routing ────────────────────────────────────────────────────────────────


async def _pump() -> None:
    while _state.ingress:
        if time.monotonic() - _state.loaded_at > TARGET_REFRESH_S:
            await _refresh_quietly()
        for _ in range(min(BATCH_SIZE, len(_state.ingress))):
            event = _state.ingress.popleft()
            try:
                _route(event)
            except Exception:  # noqa: BLE001 — one bad event must not stop the rest
                logger.warning("log_stream_route_failed", exc_info=True)
        await asyncio.sleep(0)


def _route(event: dict[str, Any]) -> None:
    for tq in _state.targets.values():
        if not accepts(tq.target, event):
            continue
        if len(tq.events) >= TARGET_QUEUE_CAP:
            _record_drop(tq, tq.events.popleft()["stream"], 1)
        tq.events.append(event)
        if not _alive(tq.task):
            tq.task = asyncio.get_running_loop().create_task(_send_loop(tq))


# ── Delivery ───────────────────────────────────────────────────────────────


async def _send_loop(tq: _TargetQueue) -> None:
    while tq.events:
        batch = [tq.events.popleft() for _ in range(min(BATCH_SIZE, len(tq.events)))]
        await _deliver(tq, batch)


async def _deliver(tq: _TargetQueue, batch: list[dict[str, Any]]) -> None:
    t = tq.target
    counts: dict[str, int] = {}
    for event in batch:
        counts[event["stream"]] = counts.get(event["stream"], 0) + 1
    for attempt in range(1, SEND_ATTEMPTS + 1):
        try:
            await asyncio.wait_for(
                audit_forward._deliver_log_stream_batch(t, batch),  # noqa: SLF001
                timeout=SEND_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "log_stream_send_failed",
                target=t.get("name"),
                attempt=attempt,
                error=type(exc).__name__,
            )
            if attempt < SEND_ATTEMPTS:
                await asyncio.sleep(RETRY_BACKOFF_S * attempt)
            continue
        for stream, n in counts.items():
            LOG_STREAM_SENT.labels(stream, t["name"]).inc(n)
        return
    for stream, n in counts.items():
        _record_drop(tq, stream, n)


# ── Drop accounting ────────────────────────────────────────────────────────


def _record_drop(tq: _TargetQueue, stream: str, n: int) -> None:
    LOG_STREAM_DROPPED.labels(stream, tq.target["name"]).inc(n)
    tq.unflushed[stream] = tq.unflushed.get(stream, 0) + n
    try:
        if not _alive(_state.flusher):
            _state.flusher = asyncio.get_running_loop().create_task(_flush_later())
    except RuntimeError:  # no running loop (a sync caller): flushed by the next one
        pass


def _record_unrouted_drop(stream: str) -> None:
    """The ingress cap displaced an event nobody has routed yet: charge it to
    every target that wants the stream."""
    for tq in _state.targets.values():
        if tq.target.get(f"stream_{stream}"):
            _record_drop(tq, stream, 1)


async def _flush_later() -> None:
    await asyncio.sleep(DROP_FLUSH_S)
    await flush_drops()


async def flush_drops() -> None:
    """Write the not-yet-persisted drop counts onto the target rows."""
    pending = {
        tid: (tq, sum(tq.unflushed.values())) for tid, tq in _state.targets.items() if tq.unflushed
    }
    if not pending:
        return
    for tid, (tq, total) in pending.items():
        tq.unflushed = {}
        try:
            async with dispatch_db.session() as session:
                await session.execute(
                    update(AuditForwardTarget)
                    .where(AuditForwardTarget.id == uuid.UUID(tid))
                    .values(
                        log_stream_dropped_total=AuditForwardTarget.log_stream_dropped_total
                        + total,
                        log_stream_last_drop_at=func.now(),
                        # A counter flush is not an operator edit.
                        modified_at=AuditForwardTarget.modified_at,
                    )
                )
                await session.commit()
        except Exception:  # noqa: BLE001
            tq.unflushed["retry"] = tq.unflushed.get("retry", 0) + total
            logger.warning("log_stream_drop_flush_failed", exc_info=True)


async def shutdown() -> None:
    """Api shutdown: persist the pending drop counts, then stop every task
    (queued events are best-effort and are not replayed)."""
    try:
        await asyncio.wait_for(flush_drops(), timeout=5.0)
    except Exception:  # noqa: BLE001
        logger.warning("log_stream_shutdown_flush_failed", exc_info=True)
    tasks = [tq.task for tq in _state.targets.values()]
    tasks += [_state.pump, _state.refresh, _state.flusher]
    live = [t for t in tasks if t is not None and not t.done()]
    for t in live:
        t.cancel()
    await asyncio.gather(*live, return_exceptions=True)
