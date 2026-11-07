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

Mechanism (the same shape as k8s_proxy, shared across processes — #3706):

  * Per-appliance, per-channel Redis LIST of inbound commands
    (``spatium:agentcmd:{channel}:q:{appliance_id}``). The enqueue
    ``RPUSH``es (length-capped, TTL'd); the supervisor's long-poll
    ``BLPOP``s, so a command is handed out exactly once (the pop removes
    it) on whichever api replica holds the poll.
  * ``spatium:agentcmd:{channel}:o:{request_id}`` — the appliance the
    command was queued for, held while the waiter waits. Its absence marks
    the command abandoned: a poll skips it, a late reply is discarded, and
    a reply from any other appliance is refused (#3621).
  * ``spatium:agentcmd:{channel}:r:{request_id}`` — LIST the reply is
    pushed to; the waiter ``BLPOP``s it, on whichever process it runs.
  * The control plane ``enqueue_command(...)`` may run in an api replica
    or in the Celery worker (scheduled Wake-on-LAN); either way the
    supervisor's poll, on any replica, receives it and the reply reaches
    the waiter. The worker keeps the same contract as before: it awaits
    the reply for the request's own timeout.

Nothing secret rides these keys: a command is a tool name plus the
validated params the supervisor would otherwise receive over the wire
(hosts, ports, a MAC, an array name), and a reply is the tool's output.

Redis is the transport, not a dependency: if it is unreachable the module
degrades to a per-process ``asyncio.Queue`` + ``Future`` (non-negotiable
#5), correct for a single api replica. An enqueue whose Redis outcome is
ambiguous (sent, then timed out) is treated as queued in Redis ONLY and is
never also queued in process: a storage command (``mdadm``) must never be
delivered twice.

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

Scope: the ``appliance`` vantage only. The DNS / DHCP service-container
vantage is an explicit follow-up.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.config import settings
from app.core import shutdown as _shutdown
from app.core.redis_client import make_async_redis
from app.core.shutdown import get_or_shutdown

# The Redis-wait machinery is k8s_proxy's (#3703); the bounds below are its too.
from app.services.appliance.k8s_proxy import (
    _CLEANUP_TIMEOUT,
    _CONNECT_TIMEOUT,
    _FAILED,
    _OP_TIMEOUT,
    _READ_TIMEOUT,
    _SLICE_SECONDS,
    _blpop_or_shutdown,
    _close,
)

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
    """Per-process FALLBACK state, used only while Redis is unreachable
    (the shared queue, owner and reply keys live in Redis — see the module
    docstring). Correct for a single api replica; on a cluster a command
    queued here simply times out, as it did before #3706."""

    def __init__(self) -> None:
        # defaultdict so the first enqueue for a new appliance auto-
        # creates its queue without an init step.
        self.queues: dict[uuid.UUID, asyncio.Queue[NetToolCommand]] = defaultdict(asyncio.Queue)
        # Keyed by request_id so reply delivery is O(1). Bounded by the
        # operator's in-flight tool count — typically a handful.
        self.futures: dict[str, asyncio.Future[NetToolResult]] = {}
        # request_id -> the appliance the command was queued for (#3621).
        # ``deliver_result`` refuses a result from any other appliance, so
        # one approved cert cannot answer another appliance's command.
        # Set with the future, evicted in the same ``finally``: bounded by
        # the in-flight count exactly like ``futures``.
        self.owners: dict[str, uuid.UUID] = {}


# Module-level fallback state, one per CHANNEL.
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


_Q = "spatium:agentcmd:{channel}:q:"
_OWNER = "spatium:agentcmd:{channel}:o:"
_REPLY = "spatium:agentcmd:{channel}:r:"

# At most this many commands wait for one appliance and channel; the oldest are
# dropped (their waiters time out). Bounds Redis memory for an offline supervisor.
MAX_QUEUED_PER_APPLIANCE = 64
_QUEUE_TTL_SECONDS = 300
_REPLY_TTL_SECONDS = 60
_OWNER_GRACE_SECONDS = 30


def _client() -> Any:
    return make_async_redis(
        settings.redis_url,
        socket_connect_timeout=_CONNECT_TIMEOUT,
        socket_timeout=_READ_TIMEOUT,
    )


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

    Callable from an api replica or the Celery worker: the command and its
    reply travel through Redis, so the supervisor's poll may be on any
    replica (#3706).

    Pass ``ready=False`` (the result of :func:`appliance_ready` against
    the resolved row) to fail FAST with :class:`ApplianceOffline`
    instead of hanging for ``timeout`` seconds on an offline appliance.
    The caller computes readiness because it already holds the DB row;
    we keep this function model-free.

    Returns the supervisor's :class:`NetToolResult` on success; raises
    :class:`asyncio.TimeoutError` after ``timeout`` seconds (router →
    504) or :class:`ApplianceOffline` immediately when ``ready`` is
    False (router → 503). Every Redis wait is bounded by ``timeout``.
    """
    if not ready:
        logger.info("appliance.nettool.offline_fast_return", appliance_id=str(appliance_id))
        raise ApplianceOffline(f"appliance {appliance_id} is offline or not approved")

    dispatch = _queues(channel)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    request_id = str(uuid.uuid4())
    command = NetToolCommand(request_id=request_id, tool=tool, params=dict(params))

    future: asyncio.Future[NetToolResult] = loop.create_future()
    dispatch.futures[request_id] = future
    dispatch.owners[request_id] = appliance_id

    # PING first so a failure is classified by whether the enqueue could have
    # reached Redis. Before the PING succeeds nothing was sent: fall back to the
    # in-process queue. Once the pipeline is sent a failure is ambiguous (Redis
    # may have run it), so the command counts as queued in Redis and is NOT also
    # queued locally — a command in both queues could be handed out twice, and a
    # storage command is an mdadm run.
    client: Any = None
    try:
        client = _client()
        await asyncio.wait_for(client.ping(), timeout=min(timeout, _OP_TIMEOUT))
    except Exception as exc:  # noqa: BLE001 — Redis never got the command
        logger.warning("appliance.nettool.redis_unavailable", op="enqueue", error=str(exc))
        if client is not None:
            await _close(client)
            client = None
        await dispatch.queues[appliance_id].put(command)
    else:
        try:
            pipe = client.pipeline()
            pipe.set(
                _OWNER.format(channel=channel) + request_id,
                str(appliance_id),
                ex=int(timeout) + _OWNER_GRACE_SECONDS,
            )
            qkey = _Q.format(channel=channel) + str(appliance_id)
            pipe.rpush(qkey, json.dumps(dataclasses.asdict(command)))
            pipe.ltrim(qkey, -MAX_QUEUED_PER_APPLIANCE, -1)
            pipe.expire(qkey, _QUEUE_TTL_SECONDS)
            await asyncio.wait_for(pipe.execute(), timeout=min(timeout, _OP_TIMEOUT))
        except Exception as exc:  # noqa: BLE001 — may have run; wait on Redis only
            logger.warning(
                "appliance.nettool.enqueue_ambiguous",
                appliance_id=str(appliance_id),
                request_id=request_id,
                error=str(exc),
            )
    logger.info(
        "appliance.nettool.enqueued",
        appliance_id=str(appliance_id),
        request_id=request_id,
        tool=tool,
    )
    try:
        return await _await_reply(client, channel, request_id, future, deadline)
    except TimeoutError:
        # Mark the local entry cancelled so a same-process poll skips it; the
        # Redis one is skipped via its deleted owner key.
        command.cancelled = True
        logger.warning(
            "appliance.nettool.timeout",
            appliance_id=str(appliance_id),
            request_id=request_id,
            timeout=timeout,
        )
        raise
    finally:
        # Always evict — a late result goes to ``deliver_result`` which logs +
        # discards.
        dispatch.futures.pop(request_id, None)
        dispatch.owners.pop(request_id, None)
        if client is not None:
            try:
                await asyncio.wait_for(
                    client.delete(
                        _OWNER.format(channel=channel) + request_id,
                        _REPLY.format(channel=channel) + request_id,
                    ),
                    timeout=_CLEANUP_TIMEOUT,
                )
            except Exception:  # noqa: BLE001 — both keys carry a TTL
                pass
            await _close(client)


async def _await_reply(
    client: Any,
    channel: str,
    request_id: str,
    future: asyncio.Future[NetToolResult],
    deadline: float,
) -> NetToolResult:
    """Wait for the reply: the Redis reply list (any replica may have received
    it) or the local future (the Redis-down fallback), until the loop time
    ``deadline`` — never past it, however Redis behaves."""
    loop = asyncio.get_running_loop()
    while True:
        if future.done():
            return future.result()
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError
        if client is None:
            await asyncio.wait({future}, timeout=remaining)
            continue
        read = asyncio.ensure_future(
            client.blpop(
                _REPLY.format(channel=channel) + request_id,
                timeout=min(_SLICE_SECONDS, remaining),
            )
        )
        try:
            await asyncio.wait(
                {read, future}, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            unfinished = not read.done()
            if unfinished:
                read.cancel()
        if future.done():
            return future.result()
        if unfinished:
            continue  # the deadline passed mid-read; the loop raises TimeoutError
        try:
            item = read.result()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — Redis died mid-wait; local future only
            logger.warning("appliance.nettool.redis_unavailable", op="reply", error=str(exc))
            await _close(client)
            client = None
            continue
        if item is not None:
            return NetToolResult(**json.loads(item[1]))


async def pop_command(
    appliance_id: uuid.UUID,
    *,
    timeout: float = 30.0,
    channel: str = CHANNEL_NETTOOL,
) -> NetToolCommand | None:
    """Long-poll for the next nettool job bound for ``appliance_id``.

    Returns the dequeued command, or ``None`` if none arrives within
    ``timeout``. Abandoned entries (the waiter already timed out) are
    skipped so the supervisor never runs stale work. A command queued by any
    api replica or the worker is seen (#3706); the ``BLPOP`` removes it, so it
    is handed out at most once.
    """
    dispatch = _queues(channel)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    local = dispatch.queues[appliance_id]
    qkey = _Q.format(channel=channel) + str(appliance_id)
    okey = _OWNER.format(channel=channel)
    client: Any = None
    try:
        client = _client()
    except Exception as exc:  # noqa: BLE001 — degrade to the in-process queue
        logger.warning("appliance.nettool.redis_unavailable", op="pop", error=str(exc))
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0 or _shutdown.shutdown_requested():
                return None
            # The in-process queue is only fed while Redis is down.
            while not local.empty():
                queued = local.get_nowait()
                if not queued.cancelled:
                    return queued
            if client is None:
                # #3015 — also ended by api shutdown, answering "no command" at once.
                queued, _ended = await get_or_shutdown(local, min(remaining, _SLICE_SECONDS))
                if queued is not None and not queued.cancelled:
                    return queued
                continue
            raw = await _blpop_or_shutdown(client, qkey, min(remaining, _SLICE_SECONDS))
            if raw is _FAILED:
                await _close(client)
                client = None
                continue
            if raw is None:
                continue
            data = json.loads(raw)
            try:
                alive = await client.exists(okey + data["request_id"])
            except Exception:  # noqa: BLE001 — deliver rather than drop on a blip
                alive = True
            if not alive:
                logger.info(
                    "appliance.nettool.skip_cancelled",
                    appliance_id=str(appliance_id),
                    request_id=data["request_id"],
                )
                continue
            return NetToolCommand(**data)
    finally:
        if client is not None:
            await _close(client)


async def deliver_result(
    result: NetToolResult, *, appliance_id: uuid.UUID, channel: str = CHANNEL_NETTOOL
) -> bool:
    """Hand a supervisor-returned result to the awaiting enqueue, which may be
    on a different api replica or in the worker (#3706).

    Returns True on a successful match, False when nobody is waiting any more
    (the waiter timed out) or when ``appliance_id`` — the appliance whose cert
    posted the result — is not the one the command was queued for (#3621). The
    supervisor's reply endpoint returns 200 either way — late delivery isn't a
    supervisor-side error.
    """
    client: Any = None
    try:
        client = _client()
        owner = await asyncio.wait_for(
            client.get(_OWNER.format(channel=channel) + result.request_id), timeout=_OP_TIMEOUT
        )
        if owner is not None:
            owner_s = owner.decode() if isinstance(owner, bytes) else str(owner)
            if owner_s != str(appliance_id):
                logger.warning(
                    "appliance.nettool.result_wrong_appliance",
                    request_id=result.request_id,
                    appliance_id=str(appliance_id),
                )
                return False
            rkey = _REPLY.format(channel=channel) + result.request_id
            pipe = client.pipeline()
            pipe.rpush(rkey, json.dumps(dataclasses.asdict(result)))
            pipe.expire(rkey, _REPLY_TTL_SECONDS)
            await asyncio.wait_for(pipe.execute(), timeout=_OP_TIMEOUT)
            return True
        # No owner key: nobody waits via Redis. A same-process waiter that
        # enqueued while Redis was down is handled below.
    except Exception as exc:  # noqa: BLE001 — degrade to the in-process path
        logger.warning("appliance.nettool.redis_unavailable", op="reply", error=str(exc))
    finally:
        if client is not None:
            await _close(client)
    return _deliver_local(result, appliance_id, channel)


def _deliver_local(result: NetToolResult, appliance_id: uuid.UUID, channel: str) -> bool:
    dispatch = _queues(channel)
    owner = dispatch.owners.get(result.request_id)
    if owner is not None and owner != appliance_id:
        logger.warning(
            "appliance.nettool.result_wrong_appliance",
            request_id=result.request_id,
            appliance_id=str(appliance_id),
        )
        return False
    future = dispatch.futures.get(result.request_id)
    if future is None or future.done():
        logger.info("appliance.nettool.result_stale", request_id=result.request_id)
        return False
    future.set_result(result)
    return True


def queue_depth(appliance_id: uuid.UUID, *, channel: str = CHANNEL_NETTOOL) -> int:
    """How many jobs wait in THIS process's fallback queue (only non-zero
    while Redis is down; the shared queue lives in Redis)."""
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
