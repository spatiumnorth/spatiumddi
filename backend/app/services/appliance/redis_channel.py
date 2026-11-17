"""Redis-wait primitives shared by the supervisor command channels.

:mod:`app.services.appliance.k8s_proxy` (#3703) and
:mod:`app.services.appliance.agent_cmd` (#3706) both move a request to a
supervisor whose long-poll may be parked on another api replica, over a
per-appliance Redis list, and wait for its reply on a per-request list. The
bounds and the one blocking-read helper they need live here, so the two
channels cannot drift apart on how long a Redis call may take.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.core import shutdown as _shutdown

logger = structlog.get_logger(__name__)

# One Redis blocking read is at most this long, so shutdown / a local
# fallback entry is noticed within a second.
SLICE_SECONDS = 1.0
CONNECT_TIMEOUT = 2.0
# A socket READ bound, longer than any BLPOP slice (which is the longest a
# healthy server takes to answer), so a master that accepts the connection and
# then stops answering fails the call instead of parking it. core.redis_client
# leaves this unset on purpose (#925: the wake bus parks pub/sub reads); every
# read here is at most one slice, so it is safe to set.
READ_TIMEOUT = SLICE_SECONDS + 4.0
# Upper bound on one Redis round trip from the caller's side: a sentinel walk
# past dead per-pod names costs ~13 s even with the connect bounded (#925), and
# a caller's wait must not stretch past its own timeout because of it.
OP_TIMEOUT = SLICE_SECONDS + 5.0
# Best-effort key cleanup after a request ends; every key also carries a TTL.
CLEANUP_TIMEOUT = 2.0

#: Returned by :func:`blpop_or_shutdown` when Redis failed (as opposed to a
#: timeout or shutdown, which return ``None``).
FAILED: Any = object()


async def close_client(client: Any) -> None:
    try:
        await client.aclose()
    except Exception:  # noqa: BLE001 — closing a dead connection; nothing to do
        pass


async def blpop_or_shutdown(client: Any, key: str, timeout: float, *, log_event: str) -> Any:
    """One ``BLPOP`` slice raced against api shutdown (#3015). Returns the
    popped value, ``None`` on timeout / shutdown, :data:`FAILED` on a Redis
    error (logged as ``log_event``, the calling channel's own event name)."""
    read = asyncio.ensure_future(client.blpop(key, timeout=timeout))
    stop = _shutdown.shutdown_future()
    try:
        await asyncio.wait(
            {read, stop}, timeout=timeout + OP_TIMEOUT, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        _shutdown.discard(stop)
        unfinished = not read.done()
        if unfinished:
            read.cancel()
    if unfinished:
        # Shutdown, or Redis stalled well past the slice: end this read.
        return None if _shutdown.shutdown_requested() else FAILED
    try:
        item = read.result()
    except Exception as exc:  # noqa: BLE001 — caller degrades to the local queue
        logger.warning(log_event, op="pop", error=str(exc))
        return FAILED
    return None if item is None else item[1]
