"""Single-flight guard for long-running late-ack tasks (#4163).

``task_acks_late`` means a message stays un-acked until its task finishes.
When the Redis master moves while a task is running, kombu restores the
unacked message and a second worker is handed it: the same task, same id,
running twice at once (14 of 15 nmap scans did). Turning on
``worker_cancel_long_running_tasks_on_connection_loss`` would kill the run
instead; this guards the *second* delivery.

``single_flight`` takes a Redis lock keyed on the task name plus a natural
key (the scan id, defaulting to the Celery task id), holds it with a short TTL
that a heartbeat thread keeps extending while the task runs, and releases it
on the way out. A successful run also leaves a done marker for its message id.

A delivery is never dropped unless its message is known to have finished:
  * done marker present: a true duplicate, acked as a no-op;
  * lock held, no marker: a live run, or one killed without releasing (its
    lock lapses within ``LOCK_TTL_SECONDS``). The copy ``retry``s after the TTL
    and then either skips (the first run finished) or runs (it died).

Advisory by design, like :mod:`app.core.task_attempts`: with Redis unreachable
the task runs unguarded rather than blocking work on a broker blip.
"""

from __future__ import annotations

import functools
import threading
import uuid
from collections.abc import Callable
from typing import Any

import structlog

from app.config import settings
from app.core.redis_client import make_sync_redis

logger = structlog.get_logger(__name__)

LOCK_KEY_PREFIX = "spatium:task-lock:"
# Keyed on the message (Celery task id), not the natural key: a redelivery keeps
# its id, while the next scheduled run of the same subnet is a new message.
DONE_KEY_PREFIX = "spatium:task-done:"
DONE_TTL_SECONDS = 24 * 3600
# Deferrals while another delivery holds the lock: ~70 s each, ~2.3 h in all.
MAX_DEFER_RETRIES = 120
# Short on purpose: it only has to outlast a missed heartbeat. A dead run's
# lock lapses this soon after its last extension.
LOCK_TTL_SECONDS = 60
HEARTBEAT_SECONDS = 15

_EXTEND_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('expire', KEYS[1], ARGV[2]) else return 0 end"
)
_RELEASE_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


class _Heartbeat(threading.Thread):
    def __init__(self, client: Any, key: str, token: str, ttl: int, interval: float) -> None:
        super().__init__(name="task-lock-heartbeat", daemon=True)
        self._client = client
        self._key = key
        self._token = token
        self._ttl = ttl
        self._interval = interval
        self._stop_evt = threading.Event()

    def run(self) -> None:
        while not self._stop_evt.wait(self._interval):
            try:
                self._client.eval(_EXTEND_LUA, 1, self._key, self._token, self._ttl)
            except Exception as exc:  # noqa: BLE001 — advisory; retry next beat
                logger.warning("task_lock_extend_failed", key=self._key, error=str(exc))

    def stop(self) -> None:
        self._stop_evt.set()


def single_flight(
    key: Callable[..., str | None] | None = None,
    *,
    ttl: int | None = None,
    heartbeat: float | None = None,
    skipped: Callable[..., Any] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a ``bind=True`` task body so only one delivery runs at a time.

    ``key(*args, **kwargs)`` returns the natural key (without ``self``);
    ``None`` falls back to the Celery task id. ``skipped(*args, **kwargs)``
    builds the return value of a suppressed duplicate.
    """

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            name = getattr(self, "name", fn.__name__)
            natural = key(*args, **kwargs) if key is not None else None
            if natural is None:
                natural = getattr(getattr(self, "request", None), "id", None)
            if not natural:
                return fn(self, *args, **kwargs)
            lock_key = f"{LOCK_KEY_PREFIX}{name}:{natural}"
            task_id = getattr(getattr(self, "request", None), "id", None)
            done_key = f"{DONE_KEY_PREFIX}{name}:{task_id}" if task_id else None
            lock_ttl = ttl if ttl is not None else LOCK_TTL_SECONDS
            token = uuid.uuid4().hex
            client: Any = None
            beat: _Heartbeat | None = None
            try:
                client = make_sync_redis(settings.redis_url, socket_connect_timeout=2.0)
                if done_key is not None and client.exists(done_key):
                    got, finished = False, True
                else:
                    got = client.set(lock_key, token, nx=True, ex=lock_ttl)
                    finished = False
            except Exception as exc:  # noqa: BLE001 — fail open: run unguarded
                logger.warning("task_lock_unavailable", task=name, error=str(exc))
                got, finished, client = True, False, None
            if not got:
                _close(client)
                if finished:
                    # This very message already ran to completion: a true
                    # duplicate. Ack it.
                    logger.warning(
                        "task_duplicate_delivery_skipped",
                        task=name,
                        key=str(natural),
                        task_id=task_id,
                    )
                    return skipped(*args, **kwargs) if skipped else {"status": "duplicate_skipped"}
                # Lock held, message not finished: a live run, or one that died
                # without releasing. Never drop the message; wait out the lock
                # and look again (a dead run's lock lapses on its own).
                logger.warning(
                    "task_duplicate_delivery_deferred", task=name, key=str(natural), task_id=task_id
                )
                try:
                    raise self.retry(countdown=lock_ttl + 10, max_retries=MAX_DEFER_RETRIES)
                except self.MaxRetriesExceededError:
                    logger.error("task_duplicate_delivery_gave_up", task=name, key=str(natural))
                    return fn(self, *args, **kwargs)
            if client is not None:
                beat = _Heartbeat(
                    client,
                    lock_key,
                    token,
                    lock_ttl,
                    heartbeat if heartbeat is not None else HEARTBEAT_SECONDS,
                )
                beat.start()
            try:
                result = fn(self, *args, **kwargs)
                if client is not None and done_key is not None:
                    try:
                        client.set(done_key, "1", ex=DONE_TTL_SECONDS)
                    except Exception as exc:  # noqa: BLE001 — advisory
                        logger.warning("task_done_mark_failed", task=name, error=str(exc))
                return result
            finally:
                if beat is not None:
                    beat.stop()
                    beat.join(timeout=5)
                try:
                    if client is not None:
                        client.eval(_RELEASE_LUA, 1, lock_key, token)
                except Exception as exc:  # noqa: BLE001 — lapses on its own TTL
                    logger.warning("task_lock_release_failed", task=name, error=str(exc))
                _close(client)

        return wrapper

    return deco


def _close(client: Any) -> None:
    if client is None:
        return
    try:
        client.close()
    except Exception:  # noqa: BLE001  # nosec B110 — best-effort close
        pass


__all__ = ["DONE_KEY_PREFIX", "LOCK_KEY_PREFIX", "LOCK_TTL_SECONDS", "single_flight"]
