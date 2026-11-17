"""Backend half of the kubeapi proxy (#183 Phase 4).

The supervisor maintains an outbound mTLS connection to the control
plane. Operator actions that need to hit an appliance's local kubeapi
enqueue a request here; the supervisor long-polls for it via
``POST /supervisor/k8s-proxy/poll``, executes against the local
``127.0.0.1:6443``, and POSTs the response back via
``/supervisor/k8s-proxy/reply/{request_id}``. NAT-friendly, no
inbound firewall holes on the appliance side.

Shared across api replicas (#3703): the operator's request lands on
one api pod while the supervisor's long-poll is parked on another, so
neither the request queue nor the reply may live in one process. Both
ride Redis (``settings.redis_url``, the same bus as
``app.core.agent_wake``):

  * ``spatium:k8sproxy:q:{appliance_id}`` — LIST of request JSON. The
    enqueue ``RPUSH``es (length-capped, TTL'd) and the supervisor's poll
    ``BLPOP``s, so a request is delivered the instant it is pushed, on
    whichever replica holds the poll.
  * ``spatium:k8sproxy:o:{request_id}`` — the appliance the request was
    queued for (#3618 reply-owner check), held for as long as the
    operator is waiting. Its absence marks the request abandoned: a poll
    skips it and a late reply is discarded.
  * ``spatium:k8sproxy:r:{request_id}`` — LIST the reply is pushed to;
    the waiting request ``BLPOP``s it, on whichever replica it runs.

If Redis is unreachable the module degrades to the old per-process
``asyncio.Queue`` + ``Future`` path (non-negotiable #5: degrade, never
wedge) — correct for a single api replica, and the cluster case simply
times out as it did before.

Failure modes:
  * Operator request timeout → future cancelled, response (if it
    eventually arrives) discarded.
  * Supervisor disconnect mid-request → operator times out, retries.
  * Supervisor returns 5xx-bodies from the local kubeapi → forwarded
    verbatim; the operator sees the kubeapi error as if direct.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.config import settings
from app.core import shutdown as _shutdown
from app.core.redis_client import make_async_redis
from app.core.shutdown import get_or_shutdown, wait_or_shutdown

# The Redis-wait bounds and blocking read are shared with agent_cmd (#3706).
from app.services.appliance.redis_channel import CLEANUP_TIMEOUT as _CLEANUP_TIMEOUT
from app.services.appliance.redis_channel import CONNECT_TIMEOUT as _CONNECT_TIMEOUT
from app.services.appliance.redis_channel import FAILED as _FAILED
from app.services.appliance.redis_channel import OP_TIMEOUT as _OP_TIMEOUT
from app.services.appliance.redis_channel import READ_TIMEOUT as _READ_TIMEOUT
from app.services.appliance.redis_channel import SLICE_SECONDS as _SLICE_SECONDS
from app.services.appliance.redis_channel import blpop_or_shutdown
from app.services.appliance.redis_channel import close_client as _close

logger = structlog.get_logger(__name__)


@dataclass
class K8sProxyRequest:
    """One queued kubeapi request waiting for the supervisor to pop.

    ``body_b64`` is base64 to keep the JSON wire format clean for
    arbitrary content types (HelmChart YAML, protobuf, etc) — the
    supervisor decodes before dispatching to the local kubeapi.
    """

    request_id: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body_b64: str = ""
    # When the operator timed out and we're just keeping the entry
    # around to discard the late response. The poll endpoint skips
    # cancelled entries.
    cancelled: bool = False


@dataclass
class K8sProxyResponse:
    """Response the supervisor posts back after executing the
    request against the local kubeapi."""

    request_id: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body_b64: str = ""


_Q_PREFIX = "spatium:k8sproxy:q:"
_OWNER_PREFIX = "spatium:k8sproxy:o:"
_REPLY_PREFIX = "spatium:k8sproxy:r:"

# At most this many requests wait for one appliance; the oldest are dropped
# (their operators time out). Bounds Redis memory if a supervisor is offline.
MAX_QUEUED_PER_APPLIANCE = 64
# Every key expires on its own, so an abandoned entry cannot accumulate.
_QUEUE_TTL_SECONDS = 300
_REPLY_TTL_SECONDS = 60
_OWNER_GRACE_SECONDS = 30


def _client() -> Any:
    return make_async_redis(
        settings.redis_url,
        socket_connect_timeout=_CONNECT_TIMEOUT,
        socket_timeout=_READ_TIMEOUT,
    )


# Per-process fallback, used only while Redis is unreachable. defaultdict so the first enqueue for a new
# appliance auto-creates the queue without an init step.
_request_queues: dict[uuid.UUID, asyncio.Queue[K8sProxyRequest]] = defaultdict(asyncio.Queue)

# Per-request response futures. Keyed by request_id so reply
# dispatching is O(1). Memory cost is bounded by the operator's
# in-flight request count — typically <10 across the whole fleet.
_response_futures: dict[str, asyncio.Future[K8sProxyResponse]] = {}

# #3618 — which appliance each in-flight request was queued for. A reply
# is accepted only from that appliance's cert, so one approved appliance
# cannot answer for another (feed the operator a forged pod list or log).
_request_owner: dict[str, uuid.UUID] = {}


async def enqueue_request(
    appliance_id: uuid.UUID,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> K8sProxyResponse:
    """Enqueue a kubeapi request bound for ``appliance_id`` and await
    the supervisor's response.

    Returns the response when the supervisor posts it back; raises
    :class:`asyncio.TimeoutError` after ``timeout`` seconds if no
    response arrives (operator-facing action surfaces this as a 504).

    The supervisor must be actively polling — if it's offline or
    misbehaving, the request just times out. Phase 5+ adds a
    pre-flight readiness check that returns a clearer error before
    the long wait.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    request_id = str(uuid.uuid4())
    body_b64 = base64.b64encode(body).decode("ascii") if body else ""

    request = K8sProxyRequest(
        request_id=request_id,
        method=method.upper(),
        path=path,
        headers=dict(headers or {}),
        body_b64=body_b64,
    )

    future: asyncio.Future[K8sProxyResponse] = loop.create_future()
    _response_futures[request_id] = future
    _request_owner[request_id] = appliance_id

    # Connect (PING) first, so a failure is classified by whether the enqueue
    # could have reached Redis. Before the PING succeeds nothing about this
    # request was sent: fall back to the in-process queue. Once the pipeline
    # is sent, a failure is ambiguous (a timeout after Redis may have run it),
    # so the request is treated as queued in Redis and NOT also queued
    # locally — a request in both queues could be executed twice.
    client: Any = None
    try:
        client = _client()
        await asyncio.wait_for(client.ping(), timeout=min(timeout, _OP_TIMEOUT))
    except Exception as exc:  # noqa: BLE001 — Redis never got the command
        logger.warning("appliance.k8s_proxy.redis_unavailable", op="enqueue", error=str(exc))
        if client is not None:
            await _close(client)
            client = None
        await _request_queues[appliance_id].put(request)
    else:
        try:
            pipe = client.pipeline()
            pipe.set(
                _OWNER_PREFIX + request_id,
                str(appliance_id),
                ex=int(timeout) + _OWNER_GRACE_SECONDS,
            )
            qkey = _Q_PREFIX + str(appliance_id)
            pipe.rpush(qkey, json.dumps(dataclasses.asdict(request)))
            pipe.ltrim(qkey, -MAX_QUEUED_PER_APPLIANCE, -1)
            pipe.expire(qkey, _QUEUE_TTL_SECONDS)
            await asyncio.wait_for(pipe.execute(), timeout=min(timeout, _OP_TIMEOUT))
        except Exception as exc:  # noqa: BLE001 — may have run; wait on Redis only
            logger.warning(
                "appliance.k8s_proxy.enqueue_ambiguous",
                appliance_id=str(appliance_id),
                request_id=request_id,
                error=str(exc),
            )
    logger.info(
        "appliance.k8s_proxy.enqueued",
        appliance_id=str(appliance_id),
        request_id=request_id,
        method=request.method,
        path=path,
    )
    try:
        return await _await_reply(client, request_id, future, deadline)
    except TimeoutError:
        # Mark the local queue entry cancelled so a same-process poll
        # skips it; the Redis one is skipped via its deleted owner key.
        request.cancelled = True
        logger.warning(
            "appliance.k8s_proxy.timeout",
            appliance_id=str(appliance_id),
            request_id=request_id,
            timeout=timeout,
        )
        raise
    finally:
        # Always evict the owner / future entries — late responses go to
        # ``deliver_response`` which logs + discards.
        _response_futures.pop(request_id, None)
        _request_owner.pop(request_id, None)
        if client is not None:
            try:
                await asyncio.wait_for(
                    client.delete(_OWNER_PREFIX + request_id, _REPLY_PREFIX + request_id),
                    timeout=_CLEANUP_TIMEOUT,
                )
            except Exception:  # noqa: BLE001 — both keys carry a TTL
                pass
            await _close(client)


async def _await_reply(
    client: Any,
    request_id: str,
    future: asyncio.Future[K8sProxyResponse],
    deadline: float,
) -> K8sProxyResponse:
    """Wait for the reply: the Redis reply list (any replica may have
    received it) or the local future (the Redis-down fallback), until the
    loop time ``deadline`` — never past it, however Redis behaves."""
    loop = asyncio.get_running_loop()
    while True:
        if future.done():
            return future.result()
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError
        if client is None:
            if await wait_or_shutdown({future}, remaining) and not future.done():
                raise TimeoutError  # the api is shutting down; answer now (#3015)
            continue
        read = asyncio.ensure_future(
            client.blpop(_REPLY_PREFIX + request_id, timeout=min(_SLICE_SECONDS, remaining))
        )
        try:
            stopping = await wait_or_shutdown({read, future}, remaining)
        finally:
            unfinished = not read.done()
            if unfinished:
                read.cancel()
        if future.done():
            return future.result()
        if stopping and unfinished:
            raise TimeoutError  # the api is shutting down; answer now (#3015)
        if unfinished:
            continue  # the deadline passed mid-read; the loop raises TimeoutError
        try:
            item = read.result()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — Redis died mid-wait; local future only
            logger.warning("appliance.k8s_proxy.redis_unavailable", op="reply", error=str(exc))
            await _close(client)
            client = None
            continue
        if item is not None:
            return K8sProxyResponse(**json.loads(item[1]))


async def pop_request(appliance_id: uuid.UUID, *, timeout: float = 30.0) -> K8sProxyRequest | None:
    """Long-poll for the next request bound for ``appliance_id``.

    Returns the dequeued request, or ``None`` if no request arrives
    within ``timeout``. Abandoned entries (operator timed out
    upstream) are skipped — the supervisor never sees stale work.
    Requests queued by any api replica are seen (#3703).
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    local = _request_queues[appliance_id]
    client: Any = None
    try:
        client = _client()
    except Exception as exc:  # noqa: BLE001 — degrade to the in-process queue
        logger.warning("appliance.k8s_proxy.redis_unavailable", op="pop", error=str(exc))
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
                # #3015 — also ended by api shutdown, answering "no request" at once.
                queued, _ended = await get_or_shutdown(local, min(remaining, _SLICE_SECONDS))
                if queued is not None and not queued.cancelled:
                    return queued
                continue
            raw = await _blpop_or_shutdown(
                client, _Q_PREFIX + str(appliance_id), min(remaining, _SLICE_SECONDS)
            )
            if raw is _FAILED:
                await _close(client)
                client = None
                continue
            if raw is None:
                continue
            data = json.loads(raw)
            try:
                alive = await client.exists(_OWNER_PREFIX + data["request_id"])
            except Exception:  # noqa: BLE001 — deliver rather than drop on a blip
                alive = True
            if not alive:
                logger.info(
                    "appliance.k8s_proxy.skip_cancelled",
                    appliance_id=str(appliance_id),
                    request_id=data["request_id"],
                )
                continue
            return K8sProxyRequest(**data)
    finally:
        if client is not None:
            await _close(client)


async def _blpop_or_shutdown(client: Any, key: str, timeout: float) -> Any:
    """One ``BLPOP`` slice raced against api shutdown (#3015); see
    :func:`app.services.appliance.redis_channel.blpop_or_shutdown`."""
    return await blpop_or_shutdown(
        client, key, timeout, log_event="appliance.k8s_proxy.redis_unavailable"
    )


async def deliver_response(response: K8sProxyResponse, *, appliance_id: uuid.UUID) -> bool:
    """Hand a supervisor-returned response to the awaiting request, which
    may be waiting on a different api replica (#3703).

    Returns True on successful match, False when nobody is waiting any
    more (operator timed out) or when ``appliance_id`` — the appliance
    whose cert posted the reply — is not the one the request was queued
    for. The supervisor's POST returns 200 either way — late delivery
    isn't a supervisor-side error.
    """
    client: Any = None
    try:
        client = _client()
        owner = await client.get(_OWNER_PREFIX + response.request_id)
        if owner is not None:
            owner_s = owner.decode() if isinstance(owner, bytes) else str(owner)
            if owner_s != str(appliance_id):
                logger.warning(
                    "appliance.k8s_proxy.reply_wrong_appliance",
                    request_id=response.request_id,
                    appliance_id=str(appliance_id),
                )
                return False
            rkey = _REPLY_PREFIX + response.request_id
            pipe = client.pipeline()
            pipe.rpush(rkey, json.dumps(dataclasses.asdict(response)))
            pipe.expire(rkey, _REPLY_TTL_SECONDS)
            await pipe.execute()
            return True
        # No owner key: nobody waits via Redis. A same-process waiter that
        # enqueued while Redis was down is handled below.
    except Exception as exc:  # noqa: BLE001 — degrade to the in-process path
        logger.warning("appliance.k8s_proxy.redis_unavailable", op="reply", error=str(exc))
    finally:
        if client is not None:
            await _close(client)
    return _deliver_local(response, appliance_id)


def _deliver_local(response: K8sProxyResponse, appliance_id: uuid.UUID) -> bool:
    owner = _request_owner.get(response.request_id)
    if owner is not None and owner != appliance_id:
        logger.warning(
            "appliance.k8s_proxy.reply_wrong_appliance",
            request_id=response.request_id,
            appliance_id=str(appliance_id),
        )
        return False
    future = _response_futures.get(response.request_id)
    if future is None or future.done():
        logger.info(
            "appliance.k8s_proxy.response_stale",
            request_id=response.request_id,
            status=response.status,
        )
        return False
    future.set_result(response)
    return True


def queue_depth(appliance_id: uuid.UUID) -> int:
    """How many requests wait in THIS process's fallback queue (only
    non-zero while Redis is down; the shared queue lives in Redis)."""
    queue = _request_queues.get(appliance_id)
    if queue is None:
        return 0
    return queue.qsize()


def _decode_body(body_b64: str) -> bytes:
    """Decode a base64-encoded request/response body."""
    return base64.b64decode(body_b64) if body_b64 else b""


__all__ = [
    "K8sProxyRequest",
    "K8sProxyResponse",
    "_decode_body",
    "deliver_response",
    "enqueue_request",
    "pop_request",
    "queue_depth",
]


# Convenience helpers used by operator-action endpoints.


async def k8s_call(
    appliance_id: uuid.UUID,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | bytes | None = None,
    content_type: str | None = None,
    accept: str = "application/json",
    timeout: float = 30.0,
) -> tuple[int, bytes]:
    """High-level wrapper: shape a kubeapi call, enqueue, await,
    return ``(status, body_bytes)``.

    ``body`` may be a dict (auto-serialised JSON), raw bytes, or
    None. Operator-facing endpoints call this for one-shot actions
    (restart pod, get deployment, list nodes) and let the result
    bubble up to the HTTP response.
    """
    import json  # noqa: PLC0415 — lazy; only on the action path.

    raw: bytes
    headers: dict[str, str] = {"Accept": accept}
    if body is None:
        raw = b""
    elif isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
        if content_type:
            headers["Content-Type"] = content_type
    else:
        raw = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = content_type or "application/json"

    response = await enqueue_request(
        appliance_id,
        method,
        path,
        body=raw,
        headers=headers,
        timeout=timeout,
    )
    return response.status, _decode_body(response.body_b64)
