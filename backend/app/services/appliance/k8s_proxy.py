"""Backend half of the kubeapi proxy (#183 Phase 4).

The supervisor maintains an outbound mTLS connection to the control
plane. Operator actions that need to hit an appliance's local kubeapi
enqueue a request here; the supervisor long-polls for it via
``POST /supervisor/k8s-proxy/poll``, executes against the local
``127.0.0.1:6443``, and POSTs the response back via
``/supervisor/k8s-proxy/reply/{request_id}``. NAT-friendly, no
inbound firewall holes on the appliance side.

In-memory only — per-appliance ``asyncio.Queue`` for inbound
requests + per-request ``Future`` for inbound responses. Restart of
the api container clears every queue; operators just retry. We
considered Redis-backed durability but the use case is request/
response pairs that complete within seconds; on-disk persistence
buys nothing.

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
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from app.core.shutdown import get_or_shutdown

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


# Per-appliance queues. defaultdict so the first enqueue for a new
# appliance auto-creates the queue without an init step.
_request_queues: dict[uuid.UUID, asyncio.Queue[K8sProxyRequest]] = defaultdict(asyncio.Queue)

# Per-request response futures. Keyed by request_id so reply
# dispatching is O(1). Memory cost is bounded by the operator's
# in-flight request count — typically <10 across the whole fleet.
_response_futures: dict[str, asyncio.Future[K8sProxyResponse]] = {}


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
    request_id = str(uuid.uuid4())
    body_b64 = base64.b64encode(body).decode("ascii") if body else ""

    request = K8sProxyRequest(
        request_id=request_id,
        method=method.upper(),
        path=path,
        headers=dict(headers or {}),
        body_b64=body_b64,
    )

    future: asyncio.Future[K8sProxyResponse] = asyncio.get_running_loop().create_future()
    _response_futures[request_id] = future

    await _request_queues[appliance_id].put(request)
    logger.info(
        "appliance.k8s_proxy.enqueued",
        appliance_id=str(appliance_id),
        request_id=request_id,
        method=request.method,
        path=path,
    )
    try:
        return await asyncio.wait_for(future, timeout=timeout)
    except TimeoutError:
        # Mark the queue entry cancelled so the supervisor's next
        # poll skips it (if it hasn't already popped it).
        request.cancelled = True
        logger.warning(
            "appliance.k8s_proxy.timeout",
            appliance_id=str(appliance_id),
            request_id=request_id,
            timeout=timeout,
        )
        raise
    finally:
        # Always evict the future map entry — late responses go to
        # ``deliver_response`` which logs + discards.
        _response_futures.pop(request_id, None)


async def pop_request(appliance_id: uuid.UUID, *, timeout: float = 30.0) -> K8sProxyRequest | None:
    """Long-poll for the next request bound for ``appliance_id``.

    Returns the dequeued request, or ``None`` if no request arrives
    within ``timeout``. Cancelled entries (operator timed out
    upstream) are skipped — the supervisor never sees stale work.
    """
    queue = _request_queues[appliance_id]
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return None
        # #3015 — also ended by api shutdown, answering "no request" at once.
        request, _ended = await get_or_shutdown(queue, remaining)
        if request is None:
            return None
        if request.cancelled:
            # Skip stale entries and keep waiting on the same queue.
            logger.info(
                "appliance.k8s_proxy.skip_cancelled",
                appliance_id=str(appliance_id),
                request_id=request.request_id,
            )
            continue
        return request


def deliver_response(response: K8sProxyResponse) -> bool:
    """Hand a supervisor-returned response to the awaiting future.

    Returns True on successful match, False when the future has
    already been GC'd (operator timed out, future evicted from the
    map). The supervisor's POST returns 204 either way — late
    delivery isn't a supervisor-side error.
    """
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
    """Operator-facing diagnostic: how many requests are queued for
    this appliance? Surfaced on heartbeat for monitoring."""
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
