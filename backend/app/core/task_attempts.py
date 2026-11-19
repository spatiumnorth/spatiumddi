"""Bound how often one Celery message may be delivered (#2271).

The global ``task_acks_late`` + ``task_reject_on_worker_lost`` pair means a
task whose worker is killed mid-run (the OOM killer, a node drain) is
requeued for the next worker. For an idempotent task that is the contract
(non-negotiable #9), but for a task that is *itself* what kills the worker
it is a poison message: it is handed from worker to worker for ever, and
because the kill skips the task's own failure handling nothing is ever
recorded.

Kombu's ``delivery_info["redelivered"]`` is a boolean (kombu 5.6
``transport/redis.py`` sets it True on any restore), so it cannot tell one
legitimate redelivery after a deploy from the tenth. A Redis counter keyed on
the message's task id can: a redelivery keeps the id, while a re-enqueue
(the sweep, a deferral) is a new message with a new id and starts at one.

Advisory by design: with Redis unreachable the count is unknown and the task
runs, because refusing to run on a broker blip would turn a hiccup into lost
work.
"""

from __future__ import annotations

import structlog

from app.config import settings
from app.core.redis_client import make_async_redis

logger = structlog.get_logger(__name__)

DELIVERY_KEY_PREFIX = "spatium:task-delivery:"
# Longer than any redelivery cycle (visibility timeout is an hour by default).
DELIVERY_TTL_SECONDS = 6 * 3600


async def count_delivery(task_name: str, task_id: str | None) -> int | None:
    """Record one delivery of this message; return how many there have been
    (1 on the first), or None when it cannot be counted."""
    if not task_id:
        return None
    client = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=2.0)
        key = f"{DELIVERY_KEY_PREFIX}{task_name}:{task_id}"
        # One MULTI/EXEC so a worker killed between the two cannot leave the
        # key without a TTL (the #2294 shape).
        async with client.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, DELIVERY_TTL_SECONDS)
            n, _ = await pipe.execute()
        return int(n)
    except Exception as exc:  # noqa: BLE001 — advisory: unknown count, run anyway
        logger.warning("task_delivery_count_unavailable", task=task_name, error=str(exc))
        return None
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001  # nosec B110 — best-effort close
                pass


__all__ = ["DELIVERY_KEY_PREFIX", "count_delivery"]
