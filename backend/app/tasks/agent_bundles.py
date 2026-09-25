"""Render DNS agent config bundles in the worker (#1111).

``render_dns_bundle(server_id)`` renders one server's bundle at its
current dirty sequence and stores it (``services.dns.agent_bundle_render``)
so the agent long-poll serves bytes instead of assembling the group's
whole record set on the api's request loop, once per agent per change.
The worker has no HTTP liveness probe to kill a long build and its
per-task engine carries no ``command_timeout`` (``app.db.task_session``),
so the 1.09 M-row records query that could not fit the api's 30 s
ceiling simply runs.

Two Redis keys shape the load, both advisory (Redis down degrades to
"render anyway"; the store's unique (server, watermark) keeps duplicates
out):

* a per-server lock — never two renders in flight for one server. A
  request that finds the lock held sets a DIRTY flag and returns; the
  holder re-checks the flag before releasing and renders once more. That,
  not a debounce, is what turns a 1,000-batch seed into a handful of
  renders: every commit still enqueues, but only one render runs and one
  more follows it.
* a global slot — one render at a time fleet-wide, because the render's
  peak memory is proportional to the group's record count and the BYO
  chart ships the worker at 1Gi. A task that finds the slot taken
  re-enqueues itself a couple of seconds later.

Both are a short lease (``dns_agent_bundle_render_lease_seconds``) that a
thread of the render's own renews while it runs, and each holds the
render's token, so a render killed mid-flight frees them within one lease
and no render ever releases a key it no longer owns.

``render_missing_sweep`` (beat, 30 s) enqueues every enabled agent-based
server whose newest stored bundle is behind its dirty sequence — the
belt and braces for a lost broker message.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, or_, select

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_server_channel, publish_wake
from app.core.redis_client import make_async_redis, make_sync_redis
from app.db import task_session
from app.drivers.dns import AGENTLESS_DRIVERS
from app.models.dns import DNSServer
from app.services.dns.agent_bundle_render import render_and_store
from app.services.dns.agent_bundle_store import (
    RENDER_STATUS_FAILED,
    RENDERED_BY_WORKER,
    is_current,
    record_failure,
)

logger = structlog.get_logger(__name__)

RENDER_LOCK_PREFIX = "spatium:bundle:render:"
RENDER_DIRTY_PREFIX = "spatium:bundle:dirty:"
RENDER_SLOT_KEY = "spatium:bundle:render-slot"
# A task that found the fleet-wide slot taken comes back this much later.
SLOT_RETRY_SECONDS = 2
# A server whose last render failed this recently is left to the explicit
# enqueue (a change bumps it immediately); the sweep does not spin on it.
SWEEP_FAILED_BACKOFF = timedelta(minutes=5)
SWEEP_MAX_PER_TICK = 500
_CONNECT_TIMEOUT = 2.0

# Release a key only while it still holds this holder's token. A lease can
# run out under a slow or stalled holder and another render take the key;
# an unconditional DELETE from the first holder would then free it under
# the second and let a third start beside it.
_RELEASE_IF_OWNER = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


# Extend a key's lease only while it still holds this holder's token.
_RENEW_IF_OWNER = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0
"""
# The dirty flag outlives any render that could consume it: the task's own
# hard time limit.
DIRTY_FLAG_SECONDS = 960


async def _release(client: Any, key: str, value: str) -> None:
    await client.eval(_RELEASE_IF_OWNER, 1, key, value)


def _lease_ms() -> int:
    return max(1, int(settings.dns_agent_bundle_render_lease_seconds)) * 1000


class _LeaseKeeper:
    """Renews a render's keys every third of the lease until stopped.

    A thread with its own (sync) client, not a task on the render's event
    loop: serialising and gzipping a million-row bundle blocks that loop
    for seconds at a time, and a lease renewed from it would lapse under a
    render that is alive. A process killed mid-render takes the thread with
    it, so the lease then runs out on its own.
    """

    def __init__(self, keys: list[tuple[str, str]], lease_ms: int) -> None:
        self._keys = list(keys)
        self._lease_ms = lease_ms
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="bundle-lease", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _loop(self) -> None:
        client = None
        while not self._stop.wait(self._lease_ms / 3000):
            try:
                if client is None:
                    client = make_sync_redis(
                        settings.redis_url,
                        socket_connect_timeout=_CONNECT_TIMEOUT,
                        socket_timeout=_CONNECT_TIMEOUT,
                    )
                for key, value in list(self._keys):
                    if not client.eval(_RENEW_IF_OWNER, 1, key, value, str(self._lease_ms)):
                        # Lapsed and taken (or gone): not ours to extend.
                        self._keys.remove((key, value))
                        logger.warning("dns_agent_bundle_lease_lost", key=key)
            except Exception as exc:  # noqa: BLE001 — keep trying until stopped
                logger.warning("dns_agent_bundle_lease_renew_failed", error=str(exc))
                client = None
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


TASK_RENDER = "app.tasks.agent_bundles.render_dns_bundle"
TASK_SWEEP = "app.tasks.agent_bundles.render_missing_sweep"


def enqueue_render(server_id: str) -> bool:
    """Publish one render request. Returns False (and logs) on a broker
    failure — the caller must treat that as "the sweep will get it"."""
    try:
        render_dns_bundle.apply_async(
            args=[str(server_id)],
            retry=False,
            queue="bundles",
        )
        return True
    except Exception as exc:  # noqa: BLE001 — the 30 s sweep is the backstop
        logger.warning("dns_agent_bundle_enqueue_failed", server_id=str(server_id), error=str(exc))
        return False


async def _server_exists(db: Any, server_id: uuid.UUID) -> bool:
    return (
        await db.execute(select(DNSServer.id).where(DNSServer.id == server_id))
    ).scalar_one_or_none() is not None


async def _render_once(server_id: uuid.UUID) -> dict[str, Any]:
    async with task_session() as db:
        server = await db.get(DNSServer, server_id)
        if server is None:
            return {"status": "gone"}
        if server.driver in AGENTLESS_DRIVERS or not server.is_enabled:
            return {"status": "skipped"}
        if is_current(server):
            return {"status": "current", "watermark": server.bundle_watermark}
        try:
            outcome = await render_and_store(db, server, rendered_by=RENDERED_BY_WORKER)
            await db.commit()
        except Exception as exc:
            await db.rollback()
            if not await _server_exists(db, server_id):
                # Deleted while it rendered (the store's FK is what noticed):
                # nothing is left to render for, and nothing failed.
                return {"status": "gone"}
            try:
                await record_failure(db, server_id, f"{type(exc).__name__}: {exc}")
                await db.commit()
            except Exception:  # noqa: BLE001
                logger.exception("dns_agent_bundle_record_failure_failed", server_id=str(server_id))
            raise
    # Parked long-polls for this server wake and serve the new bundle now
    # instead of at their next tick.
    await publish_wake(dns_server_channel(server_id))
    return {
        "status": "stored" if outcome.stored else "already_stored",
        "watermark": outcome.watermark,
        "etag": outcome.etag,
        "structural_etag": outcome.structural_etag,
        "records": outcome.records,
        "render_ms": outcome.render_ms,
        "body_bytes": outcome.body_bytes,
    }


async def _close(client: Any) -> None:
    if client is None:
        return
    try:
        await client.aclose()
    except Exception:  # noqa: BLE001
        pass


async def _acquire(
    client: Any,
    *,
    lock_key: str,
    dirty_key: str,
    token: str,
    slot_value: str,
    lease_ms: int,
    resumed: bool,
) -> str:
    """Take this render's keys: ``held`` (the server's lock and the fleet
    slot are both this render's), ``coalesced`` or ``deferred``."""
    owned = False
    if resumed:
        # A render deferred for the slot, back with the token its lock still
        # holds. Only a retry stuck far past its countdown finds the lease
        # gone; then it takes the lock afresh if nobody else did.
        owned = bool(await client.eval(_RENEW_IF_OWNER, 1, lock_key, token, str(lease_ms)))
    if not owned:
        owned = bool(await client.set(lock_key, token, nx=True, px=lease_ms))
    if not owned:
        # Someone renders this server, or waits to: flag the change so the
        # holder renders once more before it lets go.
        await client.set(dirty_key, "1", ex=DIRTY_FLAG_SECONDS)
        return "coalesced"
    if not await client.set(RENDER_SLOT_KEY, slot_value, nx=True, px=lease_ms):
        # Keep the server's lock while waiting for the slot: the duplicates
        # the sweep and every further mark enqueue meanwhile then coalesce
        # into this one render instead of each starting a retry chain of
        # its own (they used to multiply for as long as one render held the
        # slot). The lease was just taken or renewed, so it outlives the
        # countdown by far.
        return "deferred"
    return "held"


async def _run(server_id_text: str, lock_token: str | None = None) -> dict[str, Any]:
    server_id = uuid.UUID(server_id_text)
    lock_key = RENDER_LOCK_PREFIX + server_id_text
    dirty_key = RENDER_DIRTY_PREFIX + server_id_text
    lease_ms = _lease_ms()
    # This render's own token: the lock holds it, the slot holds it with the
    # server id (so the slot still says whose render holds it). A deferred
    # render comes back with the token its lock already holds.
    token = lock_token or uuid.uuid4().hex
    slot_value = f"{server_id_text}:{token}"
    client = None
    held = False
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        status = await _acquire(
            client,
            lock_key=lock_key,
            dirty_key=dirty_key,
            token=token,
            slot_value=slot_value,
            lease_ms=lease_ms,
            resumed=lock_token is not None,
        )
        if status == "coalesced":
            await _close(client)
            return {"status": "coalesced"}
        if status == "deferred":
            await _close(client)
            return {"status": "deferred", "lock_token": token}
        held = True
    except Exception as exc:  # noqa: BLE001 — Redis is advisory here: render anyway
        logger.warning(
            "dns_agent_bundle_lock_unavailable", server_id=server_id_text, error=str(exc)
        )
        await _close(client)
        client = None

    keeper: _LeaseKeeper | None = None
    if held:
        keeper = _LeaseKeeper([(RENDER_SLOT_KEY, slot_value), (lock_key, token)], lease_ms)
        keeper.start()
    renders = 0
    result: dict[str, Any] = {}
    try:
        while True:
            if client is not None:
                await client.delete(dirty_key)
            result = await _render_once(server_id)
            renders += 1
            if client is None or result.get("status") in ("gone", "skipped"):
                break
            if not await client.get(dirty_key):
                break
            if renders >= 50:  # pragma: no cover — a write storm that never pauses
                logger.warning("dns_agent_bundle_render_loop_capped", server_id=server_id_text)
                break
    finally:
        if keeper is not None:
            keeper.stop()
        if client is not None:
            try:
                await _release(client, RENDER_SLOT_KEY, slot_value)
                await _release(client, lock_key, token)
            except Exception:  # noqa: BLE001
                pass
            await _close(client)
    result["renders"] = renders
    return result


@celery_app.task(
    name=TASK_RENDER,
    bind=True,
    acks_late=True,
    soft_time_limit=900,
    time_limit=960,
)
def render_dns_bundle(  # type: ignore[type-arg]
    self: object, server_id: str, lock_token: str | None = None
) -> dict[str, Any]:
    """Render and store one server's bundle at its current dirty sequence.

    ``lock_token``: set only on the retry of a render that was deferred for
    the fleet slot — the server's lock still holds it.
    """
    result = asyncio.run(_run(server_id, lock_token=lock_token))
    token = result.pop("lock_token", None)
    if result.get("status") == "deferred":
        render_dns_bundle.apply_async(
            args=[server_id],
            kwargs={"lock_token": token},
            countdown=SLOT_RETRY_SECONDS,
            retry=False,
            queue="bundles",
        )
    logger.info("dns_agent_bundle_render_task", server_id=server_id, **result)
    return result


async def _sweep() -> dict[str, int]:
    cutoff = datetime.now(UTC) - SWEEP_FAILED_BACKOFF
    async with task_session() as db:
        ids = (
            (
                await db.execute(
                    select(DNSServer.id)
                    .where(
                        DNSServer.is_enabled.is_(True),
                        DNSServer.pending_approval.is_(False),
                        DNSServer.driver.not_in(list(AGENTLESS_DRIVERS)),
                        or_(
                            DNSServer.bundle_watermark.is_(None),
                            DNSServer.bundle_watermark < DNSServer.bundle_dirty_seq,
                            # Rendered by another release: the upgrade's
                            # one re-render per server (``is_current``).
                            DNSServer.bundle_app_version.is_distinct_from(settings.version),
                        ),
                        or_(
                            DNSServer.bundle_render_status.is_distinct_from(RENDER_STATUS_FAILED),
                            DNSServer.bundle_render_at.is_(None),
                            and_(
                                DNSServer.bundle_render_status == RENDER_STATUS_FAILED,
                                DNSServer.bundle_render_at < cutoff,
                            ),
                        ),
                    )
                    .order_by(DNSServer.bundle_render_at.asc().nulls_first())
                    .limit(SWEEP_MAX_PER_TICK)
                )
            )
            .scalars()
            .all()
        )
    enqueued = 0
    for sid in ids:
        if not enqueue_render(str(sid)):
            break
        enqueued += 1
    if ids:
        logger.info("dns_agent_bundle_sweep", stale=len(ids), enqueued=enqueued)
    return {"stale": len(ids), "enqueued": enqueued}


@celery_app.task(name=TASK_SWEEP)
def render_missing_sweep() -> dict[str, int]:
    """Every 30 s: enqueue a render for any enabled agent-based server whose
    newest stored bundle is behind its dirty sequence, was rendered by
    another release, or is absent."""
    return asyncio.run(_sweep())


__all__ = ["enqueue_render", "render_dns_bundle", "render_missing_sweep"]
