"""Generalized command channel — control plane → Fleet appliance.

This is a direct generalization of
:mod:`app.services.appliance.k8s_proxy` (#183 Phase 4). Where that
module carries one specific payload (a raw kubeapi HTTP request bound
for ``127.0.0.1:6443``), this one carries an *already-validated* nettool
job — a tool name plus a structured params dict the supervisor maps to
its local nettool runner. We deliberately never ship a raw shell string
or a pre-built argv-with-untrusted-tokens; the supervisor rebuilds the
argv from the structured params with the same allowlist validators the
api container uses, so the channel is shell-injection-safe end-to-end.

Mechanism (identical shape to k8s_proxy):

  * Per-appliance ``asyncio.Queue`` of inbound commands.
  * Per-request ``asyncio.Future`` for the inbound result, keyed by
    ``request_id`` so reply delivery is O(1).
  * The control plane ``enqueue_command(...)`` puts a command on the
    appliance's queue and awaits its future; the supervisor long-polls
    ``pop_command(...)``, runs the tool against its local vantage, and
    POSTs the structured result back through ``deliver_result(...)``.

In-memory, per-replica — same tradeoff k8s_proxy made. Requests are
short-lived request/response pairs that complete within seconds; on
restart every queue clears and the operator just retries. See the
``_Dispatch`` seam below for the multi-replica Redis-HA follow-up.

Readiness check: unlike k8s_proxy (which only blind-enqueues and lets
the operator time out at 30 s when the supervisor is offline), this
module exposes :func:`appliance_ready` so the router can fail FAST with
a 503 instead of hanging the operator for the full timeout when the
appliance hasn't heartbeated recently or isn't approved.

Failure modes:
  * Appliance offline / not approved → ``enqueue_command`` raises
    :class:`ApplianceOffline` *before* the long wait (router → 503).
  * Operator timeout → ``asyncio.TimeoutError`` (router → 504); the
    queue entry is marked cancelled so the supervisor's next poll skips
    it.
  * Supervisor returns a structured tool result → forwarded verbatim to
    the awaiting future.

Scope (this PR): the ``appliance`` vantage only. The DNS / DHCP
service-container vantage and a Redis-backed multi-replica dispatch are
explicit follow-ups; the seams for both are marked below.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.core.shutdown import get_or_shutdown

logger = structlog.get_logger(__name__)


# How recently an appliance must have heartbeated (touched
# ``last_seen_at``) to be considered reachable for a dispatched tool.
# The supervisor heartbeats every ~30 s (and the k8s-proxy / nettool
# long-polls hold open ~30 s), so a 90 s window tolerates one missed
# beat without false-positive "offline". Kept conservative on purpose —
# a too-tight window would 503 a healthy-but-slow appliance.
ONLINE_STALE_SECONDS = 90.0


class ApplianceOffline(RuntimeError):
    """Raised by :func:`enqueue_command` when the target appliance is
    not in a state to run a dispatched tool (not approved, or no recent
    heartbeat). The router maps this to a 503 so the operator gets a
    fast, clear answer instead of a 30 s hang."""


@dataclass
class NetToolCommand:
    """One queued nettool job waiting for the supervisor to pop.

    ``tool`` is the reachability tool name (``ping`` / ``traceroute`` /
    ``dig`` / ``port-test`` / ``tls-cert``). ``params`` is a structured,
    server-validated dict the supervisor maps to its local runner — it
    NEVER contains a raw shell string or a pre-joined argv. The
    supervisor re-validates every field before building the argv.
    """

    request_id: str
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    # Marked True when the operator timed out and we're keeping the
    # entry only to discard the late result. ``pop_command`` skips it.
    cancelled: bool = False


@dataclass
class NetToolResult:
    """Structured tool result the supervisor posts back.

    ``result`` is the JSON-serialised body of the matching nettool
    result model (CommandResult / PortTestResult / TlsCertResult). The
    router re-parses it into the right model + stamps ``ran_from``.
    ``error`` is set instead of ``result`` when the supervisor couldn't
    run the tool at all (unknown tool, local validation failure) so the
    router can surface a clean message rather than a malformed body.
    """

    request_id: str
    result: dict[str, Any] | None = None
    error: str | None = None


class _Dispatch:
    """In-memory, per-replica dispatch backplane.

    SEAM (multi-replica Redis-HA follow-up): this object holds every bit
    of cross-request state — the per-appliance queues + the per-request
    futures. A Redis-backed implementation swaps in here without
    touching any caller: ``enqueue`` would LPUSH onto a per-appliance
    Redis list + BLPOP-await a per-request reply key (or pub/sub), and
    ``pop`` / ``deliver`` would talk to the same keys. The module-level
    ``_dispatch`` singleton below is the single replacement point;
    callers only ever go through the free functions, never the object
    directly. Until then everything stays process-local, so a tool
    dispatched on replica A whose supervisor reply lands on replica B
    won't correlate — acceptable while the control plane is single-
    replica (matches the k8s_proxy tradeoff). The router's readiness
    check + fast 503/504 keep the failure mode survivable in the
    meantime.
    """

    def __init__(self) -> None:
        # defaultdict so the first enqueue for a new appliance auto-
        # creates its queue without an init step.
        self.queues: dict[uuid.UUID, asyncio.Queue[NetToolCommand]] = defaultdict(asyncio.Queue)
        # Keyed by request_id so reply delivery is O(1). Bounded by the
        # operator's in-flight tool count — typically a handful.
        self.futures: dict[str, asyncio.Future[NetToolResult]] = {}


# Module-level singletons, one per CHANNEL — still the single
# replacement point for a future Redis-backed dispatch (see _Dispatch
# docstring), now keyed by channel name.
#
# #999 Part B added the second channel. Storage management shares this
# transport (per-appliance queue + per-request future + the readiness
# fast-fail) and deliberately NOT this queue: a nettool is a read-only
# reachability probe, while ``mdadm --add`` overwrites a disk. Keeping
# them on separate queues means a long-running topology dump cannot sit
# in front of a ping, the two poll endpoints can carry different
# permissions, and neither endpoint's name lies about what it moves.
_dispatches: dict[str, _Dispatch] = defaultdict(_Dispatch)

#: The read-only reachability-tool channel (ping / dig / port-test / …).
CHANNEL_NETTOOL = "nettool"
#: The #999 md / multipath management channel.
CHANNEL_STORAGE = "storage"

#: Every channel that has a supervisor polling it. Validated on the way
#: in rather than left to the ``defaultdict``: an unrecognised name
#: silently creates a queue nothing polls, so a typo would not raise —
#: the command would sit there and the operator would get a 504 blaming
#: the appliance for being offline.
CHANNELS = frozenset({CHANNEL_NETTOOL, CHANNEL_STORAGE})


def _queues(channel: str) -> _Dispatch:
    if channel not in CHANNELS:
        raise ValueError(f"unknown dispatch channel {channel!r}")
    return _dispatches[channel]


def appliance_ready(
    *,
    state: str,
    last_seen_at: datetime | None,
    now: datetime | None = None,
    stale_seconds: float = ONLINE_STALE_SECONDS,
) -> bool:
    """Return True when ``appliance`` looks reachable for a dispatched
    tool: approved AND heartbeated within ``stale_seconds``.

    Pure function of the row's ``state`` + ``last_seen_at`` so the
    router can call it without importing the model and tests can drive
    it directly. ``state`` is compared against the literal
    ``"approved"`` (mirrors ``APPLIANCE_STATE_APPROVED``) — kept as a
    string param so this service has no import dependency on the model.
    """
    if state != "approved":
        return False
    if last_seen_at is None:
        return False
    ref = now or datetime.now(UTC)
    # last_seen_at is stored tz-aware (DateTime(timezone=True)); guard
    # against a naive value defensively so a stray naive datetime in a
    # test doesn't raise on the subtraction.
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=UTC)
    return (ref - last_seen_at) <= timedelta(seconds=stale_seconds)


async def enqueue_command(
    appliance_id: uuid.UUID,
    tool: str,
    params: dict[str, Any],
    *,
    ready: bool = True,
    timeout: float = 30.0,
    channel: str = CHANNEL_NETTOOL,
) -> NetToolResult:
    """Enqueue a nettool job bound for ``appliance_id`` and await the
    supervisor's result.

    Pass ``ready=False`` (the result of :func:`appliance_ready` against
    the resolved row) to fail FAST with :class:`ApplianceOffline`
    instead of hanging for ``timeout`` seconds on an offline appliance.
    The caller computes readiness because it already holds the DB row;
    we keep this function model-free.

    Returns the supervisor's :class:`NetToolResult` on success; raises
    :class:`asyncio.TimeoutError` after ``timeout`` seconds (router →
    504) or :class:`ApplianceOffline` immediately when ``ready`` is
    False (router → 503).
    """
    if not ready:
        logger.info("appliance.nettool.offline_fast_return", appliance_id=str(appliance_id))
        raise ApplianceOffline(f"appliance {appliance_id} is offline or not approved")

    request_id = str(uuid.uuid4())
    command = NetToolCommand(request_id=request_id, tool=tool, params=dict(params))

    future: asyncio.Future[NetToolResult] = asyncio.get_running_loop().create_future()
    _queues(channel).futures[request_id] = future

    await _queues(channel).queues[appliance_id].put(command)
    logger.info(
        "appliance.nettool.enqueued",
        appliance_id=str(appliance_id),
        request_id=request_id,
        tool=tool,
    )
    try:
        return await asyncio.wait_for(future, timeout=timeout)
    except TimeoutError:
        # Mark the queue entry cancelled so the supervisor's next poll
        # skips it (if it hasn't already popped it). Mirrors k8s_proxy.
        command.cancelled = True
        logger.warning(
            "appliance.nettool.timeout",
            appliance_id=str(appliance_id),
            request_id=request_id,
            timeout=timeout,
        )
        raise
    finally:
        # Always evict the future map entry — a late result goes to
        # ``deliver_result`` which logs + discards.
        _queues(channel).futures.pop(request_id, None)


async def pop_command(
    appliance_id: uuid.UUID,
    *,
    timeout: float = 30.0,
    channel: str = CHANNEL_NETTOOL,
) -> NetToolCommand | None:
    """Long-poll for the next nettool job bound for ``appliance_id``.

    Returns the dequeued command, or ``None`` if none arrives within
    ``timeout``. Cancelled entries (the operator already timed out) are
    skipped so the supervisor never runs stale work. Same loop shape as
    ``k8s_proxy.pop_request``.
    """
    queue = _queues(channel).queues[appliance_id]
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return None
        # #3015 — also ended by api shutdown, answering "no command" at once.
        command, _ended = await get_or_shutdown(queue, remaining)
        if command is None:
            return None
        if command.cancelled:
            logger.info(
                "appliance.nettool.skip_cancelled",
                appliance_id=str(appliance_id),
                request_id=command.request_id,
            )
            continue
        return command


def deliver_result(result: NetToolResult, *, channel: str = CHANNEL_NETTOOL) -> bool:
    """Hand a supervisor-returned result to the awaiting future.

    Returns True on a successful match, False when the future has
    already been evicted (operator timed out). The supervisor's reply
    endpoint returns 200 either way — late delivery isn't a
    supervisor-side error. Mirrors ``k8s_proxy.deliver_response``.
    """
    future = _queues(channel).futures.get(result.request_id)
    if future is None or future.done():
        logger.info("appliance.nettool.result_stale", request_id=result.request_id)
        return False
    future.set_result(result)
    return True


def queue_depth(appliance_id: uuid.UUID, *, channel: str = CHANNEL_NETTOOL) -> int:
    """Operator-facing diagnostic: how many nettool jobs are queued for
    this appliance?"""
    queue = _queues(channel).queues.get(appliance_id)
    return queue.qsize() if queue is not None else 0


# The reachability tools that may be dispatched to an appliance vantage.
# whois / mac-vendor / dns-propagation stay server-only (they hit shared
# off-prem infra or a server-side DB and have no per-vantage meaning), so
# they're intentionally absent — the router rejects an appliance target
# for any tool not in this set with a 400.
REACHABILITY_TOOLS: frozenset[str] = frozenset(
    {"ping", "traceroute", "dig", "port-test", "tls-cert"}
)


__all__ = [
    "ONLINE_STALE_SECONDS",
    "REACHABILITY_TOOLS",
    "ApplianceOffline",
    "NetToolCommand",
    "NetToolResult",
    "appliance_ready",
    "deliver_result",
    "enqueue_command",
    "pop_command",
    "queue_depth",
]
