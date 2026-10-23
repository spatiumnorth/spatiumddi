"""Render DNS agent config bundles in the worker (#1111).

``render_dns_bundle(server_id)`` renders one server's bundle at its
current dirty sequence and stores it (``services.dns.agent_bundle_render``)
so the agent long-poll serves bytes instead of assembling the group's
whole record set on the api's request loop, once per agent per change.
The worker has no HTTP liveness probe to kill a long build, so the
1.09 M-row records query that could not fit the api's 30 s ceiling runs
here. Its per-task engine is still bounded (#1719): the render opens its
session with ``settings.task_db_long_command_timeout`` (900 s per
statement), not the 120 s ``task_db_command_timeout`` every other task
gets, because the records query on a large group legitimately runs past
120 s. The bound exists so a black-holed CNPG primary fails the render
in minutes rather than the kernel's ~15 min TCP retransmit timeout; the
cheap sweep query keeps the default bound.

Two Redis keys shape the load, both advisory (Redis down degrades to
"render anyway"; the store's unique (server, watermark) keeps duplicates
out):

* a per-server lock — never two renders in flight for one server. A
  request that finds the lock held sets a DIRTY flag and returns; the
  holder re-checks the flag before releasing and renders once more. That,
  not a debounce, is what turns a 1,000-batch seed into a handful of
  renders: every commit still enqueues, but only one render runs and one
  more follows it.
* fleet-wide slots — ``dns_agent_bundle_render_slots`` renders at once
  (#2227; it was one). The render's peak memory was proportional to the
  group's record count and the BYO chart ships the worker at 1Gi; since
  #2227 it is bounded (a batch of records, the zones, the compressed body),
  so the limit now keeps the load off the database, which each render reads
  the whole group from. A task that finds every slot taken re-enqueues
  itself a couple of seconds later and says that it waits; a holder whose
  server changed again while it rendered then hands its slot on (re-enqueues
  itself just after a waiter's next try, keeping its server's lock) instead
  of rendering again, so one
  server under a write storm no longer keeps every other server waiting.

Both are a short lease (``dns_agent_bundle_render_lease_seconds``) that a
thread of the render's own renews while it runs, and each holds the
render's token, so a render killed mid-flight frees them within one lease
and no render ever releases a key it no longer owns.

A render that never finishes — its process killed mid-render, which runs no
``finally`` and records nothing — is counted (#2227): a per-server counter is
raised before each render and cleared when it returns or raises. A broker
redelivers a task whose worker died (``task_reject_on_worker_lost``) and the
sweep re-enqueues anything behind, so without the count a render the worker
cannot survive would kill one worker process after another indefinitely,
with nothing on the server row to say why. After ``ABANDONED_RENDER_LIMIT``
unfinished renders the next one records the reason as a render failure (the
``agent_bundle_render_failed`` alert) and holds the server for
``ABANDONED_HOLD``; then one more render is let through, so a kill that was
not the render's fault (a neighbour's memory) recovers on its own.

``render_missing_sweep`` (beat, 30 s) enqueues every enabled agent-based
server whose newest stored bundle is behind its dirty sequence — the
belt and braces for a lost broker message.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, or_, select

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_server_channel, publish_wake
from app.core.redis_client import make_async_redis, make_sync_redis
from app.core.task_attempts import count_delivery
from app.db import task_session
from app.drivers.dns import AGENTLESS_DRIVERS
from app.models.dns import DNSServer
from app.services.dns import agent_bundle_store as bundle_store
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
# Set (briefly) by a render waiting for a slot, so a holder with more to
# render hands its slot on rather than rendering again (#2227).
RENDER_WAITING_KEY = "spatium:bundle:render-waiting"
WAITING_FLAG_SECONDS = 10
# A holder starts no further render of its server once it has held the slot
# this long; it re-enqueues itself instead. Well inside the task's 900 s soft
# time limit, which otherwise a write storm reached mid-render (#2227).
RENDER_LOOP_BUDGET_SECONDS = 300
# #2227 — renders of a server that started and have not finished, and a hold
# on a server whose renders keep dying (see ``_abandoned_verdict``).
RENDER_ATTEMPTS_PREFIX = "spatium:bundle:attempts:"
RENDER_HOLD_PREFIX = "spatium:bundle:hold:"
# This many renders of one server started and never finished (each killed
# with its process — the OOM killer, the task's hard time limit) and the next
# one does not start: it records why and holds the server for
# ``ABANDONED_HOLD``, after which ONE more render is let through.
ABANDONED_RENDER_LIMIT = 2
# Long enough that a render the worker cannot survive costs one worker
# process per hold, not one per change; the same as the sweep's backoff after
# a recorded failure, which the failure this records also triggers.
ABANDONED_HOLD = timedelta(minutes=5)
# An unfinished start older than this no longer counts.
ATTEMPTS_TTL_SECONDS = 3600
# A task that found the fleet-wide slot taken comes back this much later.
SLOT_RETRY_SECONDS = 2
# A holder that handed its slot on comes back this much later: after every
# waiter's next try, so a waiter takes the freed slot first (#2227).
HANDED_ON_RETRY_SECONDS = SLOT_RETRY_SECONDS + 1
# A server whose last render failed this recently is left to the explicit
# enqueue (a change bumps it immediately); the sweep does not spin on it.
SWEEP_FAILED_BACKOFF = timedelta(minutes=5)
SWEEP_MAX_PER_TICK = 500
# How many times one render message may be delivered (#2271). A render whose
# worker is killed (OOM) is requeued by ``reject_on_worker_lost``; past this
# the render is recorded as failed instead, and ``SWEEP_FAILED_BACKOFF``
# paces the next attempt rather than the workers taking turns to die on it.
MAX_RENDER_DELIVERIES = 3
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


def _slot_keys() -> list[str]:
    """The fleet's render slots (#2227): ``RENDER_SLOT_KEY`` and, past one,
    ``RENDER_SLOT_KEY:1`` and on — ``dns_agent_bundle_render_slots`` of them."""
    n = max(1, int(settings.dns_agent_bundle_render_slots))
    return [RENDER_SLOT_KEY, *(f"{RENDER_SLOT_KEY}:{i}" for i in range(1, n))]


def _abandoned_reason(unfinished: int) -> str:
    return (
        f"{unfinished} renders of this server's bundle started and never finished. The "
        "worker process running each was killed mid-render, either out of memory (the "
        "worker's memory limit; see 'Control-plane memory for large groups' in "
        "docs/features/DNS.md) or past the render task's hard time limit. Rendering is "
        f"held for {int(ABANDONED_HOLD.total_seconds() // 60)} minutes, then tried once more."
    )


async def _abandoned_verdict(client: Any, server_id_text: str) -> str | None:
    """``on_hold`` while the server is held after its renders kept dying,
    ``abandoned`` when the renders that started and never finished have just
    reached ``ABANDONED_RENDER_LIMIT`` (the hold is placed, and the counter set
    to let one render through once it lapses), else ``None``: render."""
    if await client.exists(RENDER_HOLD_PREFIX + server_id_text):
        return "on_hold"
    unfinished = int(await client.get(RENDER_ATTEMPTS_PREFIX + server_id_text) or 0)
    if unfinished < ABANDONED_RENDER_LIMIT:
        return None
    await client.set(
        RENDER_HOLD_PREFIX + server_id_text, "1", ex=int(ABANDONED_HOLD.total_seconds())
    )
    await client.set(
        RENDER_ATTEMPTS_PREFIX + server_id_text,
        str(ABANDONED_RENDER_LIMIT - 1),
        ex=ATTEMPTS_TTL_SECONDS,
    )
    return "abandoned"


async def _record_abandoned(server_id: uuid.UUID, unfinished: int) -> None:
    reason = _abandoned_reason(unfinished)
    logger.error(
        "dns_agent_bundle_render_abandoned", server_id=str(server_id), unfinished=unfinished
    )
    async with task_session() as db:
        await record_failure(db, server_id, reason)
        await db.commit()


async def _render_counted(client: Any, server_id: uuid.UUID, server_id_text: str) -> dict[str, Any]:
    """``_render_once`` between raising this server's unfinished-render count
    and clearing it. A render that returns or raises has finished (a raise is
    recorded as a failure by ``_render_once``); only a process killed in the
    middle leaves the count raised."""
    key = RENDER_ATTEMPTS_PREFIX + server_id_text
    if client is not None:
        try:
            await client.incr(key)
            await client.expire(key, ATTEMPTS_TTL_SECONDS)
        except Exception as exc:  # noqa: BLE001 — advisory, like the lock
            logger.warning("dns_agent_bundle_attempt_count_failed", error=str(exc))
    try:
        return await _render_once(server_id)
    finally:
        if client is not None:
            try:
                await client.delete(key)
            except Exception as exc:  # noqa: BLE001 — the TTL retires it
                logger.warning("dns_agent_bundle_attempt_clear_failed", error=str(exc))


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
    # Long bound: the group's records query is one statement that can run
    # past the 120 s default on a large group (see module docstring, #1719).
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
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
) -> tuple[str, str | None]:
    """Take this render's keys: ``held`` (the server's lock and a fleet slot
    are both this render's; the slot key comes with it), ``coalesced`` or
    ``deferred``."""
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
        return "coalesced", None
    for slot_key in _slot_keys():
        if await client.set(slot_key, slot_value, nx=True, px=lease_ms):
            return "held", slot_key
    # Every slot is taken. Keep the server's lock while waiting: the
    # duplicates the sweep and every further mark enqueue meanwhile then
    # coalesce into this one render instead of each starting a retry chain of
    # its own (they used to multiply for as long as one render held the
    # slot). The lease was just taken or renewed, so it outlives the
    # countdown by far. Say that a render waits, so a holder with more of its
    # own to render hands its slot on (``_run``).
    await client.set(RENDER_WAITING_KEY, "1", ex=WAITING_FLAG_SECONDS)
    return "deferred", None


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
    slot_key = RENDER_SLOT_KEY
    started = time.monotonic()
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        status, taken = await _acquire(
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
        slot_key = taken or RENDER_SLOT_KEY
    except Exception as exc:  # noqa: BLE001 — Redis is advisory here: render anyway
        logger.warning(
            "dns_agent_bundle_lock_unavailable", server_id=server_id_text, error=str(exc)
        )
        await _close(client)
        client = None

    keeper: _LeaseKeeper | None = None
    if held:
        keeper = _LeaseKeeper([(slot_key, slot_value), (lock_key, token)], lease_ms)
        keeper.start()
    renders = 0
    result: dict[str, Any] = {}
    # Set when this render hands its slot on with its server still dirty: the
    # server's lock stays with the re-enqueued task, as a deferred one's does.
    handed_on = False
    try:
        if client is not None:
            verdict: str | None = None
            try:
                verdict = await _abandoned_verdict(client, server_id_text)
            except Exception as exc:  # noqa: BLE001 — advisory: render anyway
                logger.warning("dns_agent_bundle_attempt_check_failed", error=str(exc))
            if verdict == "on_hold":
                return {"status": "on_hold", "renders": 0}
            if verdict == "abandoned":
                await _record_abandoned(server_id, ABANDONED_RENDER_LIMIT)
                return {"status": "abandoned", "renders": 0}
        while True:
            if client is not None:
                await client.delete(dirty_key)
            result = await _render_counted(client, server_id, server_id_text)
            renders += 1
            if client is None or result.get("status") in ("gone", "skipped"):
                break
            if not await client.get(dirty_key):
                break
            # More changed while it rendered. Render again here only while no
            # other server waits for a slot and the task is inside its budget:
            # a write storm used to keep one server rendering for up to 50
            # renders while every other server's agents waited, and ran the
            # task into its soft time limit mid-render (#2227). Otherwise the
            # task comes back through the queue, keeping its server's lock.
            if (
                renders >= 50
                or time.monotonic() - started > RENDER_LOOP_BUDGET_SECONDS
                or await client.exists(RENDER_WAITING_KEY)
            ):
                handed_on = True
                break
    finally:
        if keeper is not None:
            keeper.stop()
        if client is not None:
            try:
                await _release(client, slot_key, slot_value)
                if not handed_on:
                    await _release(client, lock_key, token)
            except Exception:  # noqa: BLE001
                pass
            await _close(client)
    result["renders"] = renders
    if handed_on:
        result["status"] = "handed_on"
        result["lock_token"] = token
    return result


async def _run_bounded(
    server_id_text: str, lock_token: str | None, task_id: str | None
) -> dict[str, Any]:
    """``_run`` behind the delivery bound (#2271).

    A redelivery of this message means the worker holding it died without
    acking — for a render, most likely the OOM killer. Past
    ``MAX_RENDER_DELIVERIES`` stop rendering and record the failure, which
    is what the graceful path would have done had the process survived.
    """
    deliveries = await count_delivery(TASK_RENDER, task_id)
    if deliveries is not None and deliveries > MAX_RENDER_DELIVERIES:
        try:
            server_id = uuid.UUID(server_id_text)
            async with task_session() as db:
                await record_failure(
                    db,
                    server_id,
                    f"render abandoned: message delivered {deliveries} times — the worker "
                    "was lost mid-render each time (out of memory?)",
                )
                await db.commit()
        except Exception:  # noqa: BLE001
            logger.exception("dns_agent_bundle_record_failure_failed", server_id=server_id_text)
        logger.error(
            "dns_agent_bundle_render_abandoned",
            server_id=server_id_text,
            task_id=task_id,
            deliveries=deliveries,
            limit=MAX_RENDER_DELIVERIES,
        )
        return {"status": "abandoned", "deliveries": deliveries}
    return await _run(server_id_text, lock_token=lock_token)


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
    result = asyncio.run(
        _run_bounded(
            server_id,
            lock_token,
            getattr(getattr(self, "request", None), "id", None),
        )
    )
    token = result.pop("lock_token", None)
    if result.get("status") in ("deferred", "handed_on"):
        render_dns_bundle.apply_async(
            args=[server_id],
            kwargs={"lock_token": token},
            # A deferred render tries again in SLOT_RETRY_SECONDS. One that
            # handed its slot on comes back a second LATER than that: back at
            # once, it found the slot it had just freed before the waiter's
            # next try came round, and took it again — so the hand-on handed
            # nothing to anyone under exactly the storm it exists for.
            countdown=(
                SLOT_RETRY_SECONDS if result["status"] == "deferred" else HANDED_ON_RETRY_SECONDS
            ),
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
                            # Rendered by an older renderer revision: the
                            # upgrade's one re-render per server
                            # (``is_current``). A newer one is left alone.
                            DNSServer.bundle_renderer_revision.is_(None),
                            DNSServer.bundle_renderer_revision < bundle_store.RENDERER_REVISION,
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
    newest stored bundle is behind its dirty sequence, came from an older
    renderer revision, or is absent."""
    return asyncio.run(_sweep())


__all__ = ["enqueue_render", "render_dns_bundle", "render_missing_sweep"]
