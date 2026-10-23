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
cheap sweep query keeps the default bound. A render whose time limit is
scaled past 900 s (below) gets its soft limit as the statement bound
instead: the records query is one statement that grows with the group,
and a fixed bound would fail every render of a big enough group at that
same statement. No statement outlives the task's own limit either way.

Time limits scale with the data (#2240). Celery's limits travel in each
task message — a runtime ``celery control time_limit`` reaches only the
workers up at that moment, and a retry published afterwards carries the
old limits again — so they are set where the render is published:
``render_time_limits`` gives soft = max(900 s, 120 s + 1.5 s per 1,000
records), hard = soft + 60 s, capped at 6 h. ``render_missing_sweep``
sizes each request from the group's largest stored bundle
(``known_records``); the api's after-commit enqueue publishes at the
900 s floor, so no api commit pays a query for it. Once a render holds
its keys it counts the group's records as they are now, and a message
whose limit is too short for that count republishes itself sized for the
count plus 25 % — keeping its server's lock, as a deferral does — instead
of starting a render the worker would kill. A deferred retry keeps the
limits of the message it came from.

Two kinds of Redis key shape the load, both advisory (Redis down
degrades to "render anyway"; the store's unique (server, watermark) keeps
duplicates out):

* a per-server lock — never two renders in flight for one server. A
  request that finds the lock held sets a DIRTY flag and returns; the
  holder re-checks the flag before releasing and renders once more. That,
  not a debounce, is what turns a 1,000-batch seed into a handful of
  renders: every commit still enqueues, but only one render runs and one
  more follows it.
* fleet slots — at most ``dns_agent_bundle_render_slots`` renders at once
  fleet-wide (default 1), because the render's peak memory is
  proportional to the group's record count and the BYO chart ships the
  worker at 1Gi. Slot 0 is ``spatium:bundle:render-slot``, the one key a
  single slot always was; slot i > 0 is ``spatium:bundle:render-slot:<i>``.
  A task that finds every slot taken re-enqueues itself a couple of
  seconds later. With more than one slot a render also takes one of its
  worker's ``dns_agent_bundle_renders_per_worker`` host slots, so two
  renders never stack inside one worker's memory limit because two of its
  processes happened to pick them up.

Each is a short lease (``dns_agent_bundle_render_lease_seconds``) that a
thread of the render's own renews while it runs, however long that is,
and each holds the render's token, so a render killed mid-flight frees
them within one lease and no render ever releases a key it no longer owns
— the slot it releases is exactly the one it took.

``render_missing_sweep`` (beat, 30 s) enqueues every enabled agent-based
server whose newest stored bundle is behind its dirty sequence — the
belt and braces for a lost broker message.
"""

from __future__ import annotations

import asyncio
import math
import socket
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_server_channel, publish_wake
from app.core.redis_client import make_async_redis, make_sync_redis
from app.core.task_attempts import count_delivery
from app.db import task_session
from app.drivers.dns import AGENTLESS_DRIVERS
from app.models.dns import DNSAgentBundle, DNSRecord, DNSServer, DNSZone
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
# Fleet slot 0; slot i > 0 is ``f"{RENDER_SLOT_KEY}:{i}"`` (``_slot_keys``).
RENDER_SLOT_KEY = "spatium:bundle:render-slot"
# Per-worker slots: ``f"{RENDER_HOST_PREFIX}{hostname}:{j}"`` (``_host_keys``).
RENDER_HOST_PREFIX = "spatium:bundle:render-host:"
# A task that found the fleet-wide slot taken comes back this much later.
SLOT_RETRY_SECONDS = 2
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

# ── Render time limits, scaled to the data (#2240) ─────────────────────────
#
# soft = max(FLOOR, BASE + PER_1000 x records / 1000), at most CEILING;
# hard = soft + MARGIN. The floor is the fixed 900 s / 960 s every render had
# before, so a group up to ~520k records renders under exactly those limits.
# 2M records (the 1M-device scale lab) -> 3120 s / 3180 s.
RENDER_SOFT_LIMIT_FLOOR = 900
RENDER_LIMIT_BASE_SECONDS = 120
RENDER_SECONDS_PER_1000_RECORDS = 1.5
RENDER_HARD_LIMIT_MARGIN = 60
# 6 h (~14M records): a ceiling on what a bad count can ask for.
RENDER_SOFT_LIMIT_CEILING = 6 * 3600
# A render that republishes itself for a larger group sizes the new message
# for this much more than it counted, so records landing before the retry
# runs do not send it round again.
RENDER_RESIZE_HEADROOM = 1.25

# The dirty flag outlives any render that could consume it: the longest hard
# time limit a render can be given.
DIRTY_FLAG_SECONDS = RENDER_SOFT_LIMIT_CEILING + RENDER_HARD_LIMIT_MARGIN


def render_time_limits(records: int | None) -> tuple[int, int]:
    """``(soft_time_limit, hard_time_limit)`` in seconds for a render of a
    group holding ``records`` records; the 900 s / 960 s floor when the
    count is unknown."""
    soft = RENDER_SOFT_LIMIT_FLOOR
    if records is not None and records > 0:
        scaled = math.ceil(
            RENDER_LIMIT_BASE_SECONDS + RENDER_SECONDS_PER_1000_RECORDS * records / 1000
        )
        soft = min(max(soft, scaled), RENDER_SOFT_LIMIT_CEILING)
    return soft, soft + RENDER_HARD_LIMIT_MARGIN


def _render_command_timeout(soft_limit: int) -> float:
    """The render session's per-statement bound (#1719): the long bound, or
    the render's own soft limit once that is longer (module docstring)."""
    return max(float(settings.task_db_long_command_timeout), float(soft_limit))


def _message_limits(task: object) -> tuple[int, int]:
    """The ``(soft, hard)`` limits the running message carries: Celery puts
    ``[hard, soft]`` in each message's ``timelimit`` header. A message that
    set none (one published by a release before #2240, or a direct call)
    runs under the decorator's floor."""
    request = getattr(task, "request", None)
    hard, soft = getattr(request, "timelimit", None) or (None, None)
    if not soft:
        return render_time_limits(None)
    return int(soft), int(hard) if hard else int(soft) + RENDER_HARD_LIMIT_MARGIN


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


def _publish(
    server_id: str,
    limits: tuple[int, int],
    *,
    lock_token: str | None = None,
    countdown: float | None = None,
) -> None:
    """Publish one render message carrying ``limits`` (``(soft, hard)``).
    The limits have to travel in the message (module docstring)."""
    soft, hard = limits
    options: dict[str, Any] = {
        "args": [str(server_id)],
        "retry": False,
        "queue": "bundles",
        "soft_time_limit": soft,
        "time_limit": hard,
    }
    if lock_token is not None:
        options["kwargs"] = {"lock_token": lock_token}
    if countdown is not None:
        options["countdown"] = countdown
    render_dns_bundle.apply_async(**options)


def enqueue_render(server_id: str, records: int | None = None) -> bool:
    """Publish one render request, its time limits sized for ``records``
    (the group's last known record count; ``None`` = the 900 s floor, which
    the render corrects itself from once it runs). Returns False (and logs)
    on a broker failure — the caller must treat that as "the sweep will get
    it"."""
    try:
        _publish(str(server_id), render_time_limits(records))
        return True
    except Exception as exc:  # noqa: BLE001 — the 30 s sweep is the backstop
        logger.warning("dns_agent_bundle_enqueue_failed", server_id=str(server_id), error=str(exc))
        return False


async def _server_exists(db: Any, server_id: uuid.UUID) -> bool:
    return (
        await db.execute(select(DNSServer.id).where(DNSServer.id == server_id))
    ).scalar_one_or_none() is not None


async def known_records(db: AsyncSession, server_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, int]:
    """The last known record count of each server's group: the largest
    ``records`` among the bundles stored for any server of that group (the
    table keeps ``dns_agent_bundle_keep_versions`` rows per server, so this
    reads a handful of rows). A server whose group has no stored bundle is
    left out. The group's, not the server's own: a server added to a big
    group has no bundle yet, and its first render is as big as its peers'."""
    ids = sorted(set(server_ids))
    if not ids:
        return {}
    peer = aliased(DNSServer)
    rows = await db.execute(
        select(DNSServer.id, func.max(DNSAgentBundle.records))
        .join(peer, peer.group_id == DNSServer.group_id)
        .join(DNSAgentBundle, DNSAgentBundle.server_id == peer.id)
        .where(DNSServer.id.in_(ids))
        .group_by(DNSServer.id)
    )
    return {sid: int(count) for sid, count in rows.tuples() if count is not None}


async def _estimate_records(db: AsyncSession, server: DNSServer) -> int:
    """What the render about to start will carry, for its time limit: the
    group's records as they are now (one COUNT on the ``dns_record`` zone
    index, once per render), or the last stored bundle's count when that is
    larger (a split-horizon bundle ships a shared record once per view)."""
    live = (
        await db.execute(
            select(func.count(DNSRecord.id))
            .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
            .where(DNSZone.group_id == server.group_id)
        )
    ).scalar_one()
    stored = (await known_records(db, [server.id])).get(server.id, 0)
    return max(int(live or 0), stored)


async def _render_once(server_id: uuid.UUID, soft_limit: int | None = None) -> dict[str, Any]:
    """Render ``server_id`` once, inside a message whose soft time limit is
    ``soft_limit`` (``None``: the floor). Returns ``status: "resize"`` and
    the count, rendering nothing, when that limit is too short for the
    group as it is now."""
    budget = soft_limit or RENDER_SOFT_LIMIT_FLOOR
    # Long bound: the group's records query is one statement that can run
    # past the 120 s default on a large group (see module docstring, #1719).
    async with task_session(command_timeout=_render_command_timeout(budget)) as db:
        server = await db.get(DNSServer, server_id)
        if server is None:
            return {"status": "gone"}
        if server.driver in AGENTLESS_DRIVERS or not server.is_enabled:
            return {"status": "skipped"}
        if is_current(server):
            return {"status": "current", "watermark": server.bundle_watermark}
        try:
            records = await _estimate_records(db, server)
            if render_time_limits(records)[0] > budget:
                return {"status": "resize", "records": records, "soft_time_limit": budget}
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


def _slot_keys() -> list[str]:
    """The fleet slots, slot 0 first: ``RENDER_SLOT_KEY`` itself, then
    ``RENDER_SLOT_KEY:<i>`` up to ``dns_agent_bundle_render_slots``."""
    slots = max(1, int(settings.dns_agent_bundle_render_slots))
    return [RENDER_SLOT_KEY] + [f"{RENDER_SLOT_KEY}:{i}" for i in range(1, slots)]


def _host_keys() -> list[str]:
    """This worker's own slots (its hostname is its pod or container), or
    none: with one fleet slot, or no per-worker cap, nothing is taken."""
    per_worker = int(settings.dns_agent_bundle_renders_per_worker)
    if int(settings.dns_agent_bundle_render_slots) <= 1 or per_worker <= 0:
        return []
    host = socket.gethostname()
    return [f"{RENDER_HOST_PREFIX}{host}:{j}" for j in range(per_worker)]


async def _take_one(client: Any, keys: list[str], value: str, lease_ms: int) -> str | None:
    """Take the first free key of ``keys`` for ``value``; the key, or None
    when every one is held."""
    for key in keys:
        if await client.set(key, value, nx=True, px=lease_ms):
            return key
    return None


async def _acquire(
    client: Any,
    *,
    lock_key: str,
    dirty_key: str,
    token: str,
    slot_value: str,
    lease_ms: int,
    resumed: bool,
) -> tuple[str, list[str]]:
    """Take this render's keys: ``held`` (the server's lock and a fleet slot
    — and, with several fleet slots, a slot of this worker's — are this
    render's), ``coalesced`` or ``deferred``. With ``held``, the slot keys
    this render took (each holds ``slot_value``); none otherwise."""
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
        return "coalesced", []
    slot_key = await _take_one(client, _slot_keys(), slot_value, lease_ms)
    if slot_key is None:
        # Keep the server's lock while waiting for a slot: the duplicates
        # the sweep and every further mark enqueue meanwhile then coalesce
        # into this one render instead of each starting a retry chain of
        # its own (they used to multiply for as long as one render held the
        # slot). The lease was just taken or renewed, so it outlives the
        # countdown by far.
        return "deferred", []
    held = [slot_key]
    host_keys = _host_keys()
    if host_keys:
        host_key = await _take_one(client, host_keys, slot_value, lease_ms)
        if host_key is None:
            # This worker already renders as much as it may: give the fleet
            # slot back for a render on another worker and wait like any
            # other deferral (the retry may land on any worker).
            await _release(client, slot_key, slot_value)
            return "deferred", []
        held.append(host_key)
    return "held", held


async def _run(
    server_id_text: str, lock_token: str | None = None, soft_limit: int | None = None
) -> dict[str, Any]:
    """``soft_limit``: the running message's soft time limit (``None``: the
    floor). ``status: "resize"`` returns the lock token like a deferral."""
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
    slot_keys: list[str] = []
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        status, slot_keys = await _acquire(
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
        keeper = _LeaseKeeper(
            [(key, slot_value) for key in slot_keys] + [(lock_key, token)], lease_ms
        )
        keeper.start()
    renders = 0
    resize = False
    result: dict[str, Any] = {}
    try:
        while True:
            if client is not None:
                await client.delete(dirty_key)
            result = await _render_once(server_id, soft_limit)
            if result.get("status") == "resize":
                # Too big for this message's limits: the task republishes it
                # sized for the count. The server's lock waits with it.
                resize = True
                break
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
                for key in slot_keys:
                    await _release(client, key, slot_value)
                if not resize:
                    await _release(client, lock_key, token)
            except Exception:  # noqa: BLE001
                pass
            await _close(client)
    if resize and held:
        result["lock_token"] = token
    result["renders"] = renders
    return result


async def _run_bounded(
    server_id_text: str,
    lock_token: str | None,
    task_id: str | None,
    soft_limit: int | None = None,
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
    return await _run(server_id_text, lock_token=lock_token, soft_limit=soft_limit)


@celery_app.task(
    name=TASK_RENDER,
    bind=True,
    acks_late=True,
    # The floor. Every publish sets its own limits (``render_time_limits``);
    # these apply only to a message that carries none.
    soft_time_limit=RENDER_SOFT_LIMIT_FLOOR,
    time_limit=RENDER_SOFT_LIMIT_FLOOR + RENDER_HARD_LIMIT_MARGIN,
)
def render_dns_bundle(  # type: ignore[type-arg]
    self: object, server_id: str, lock_token: str | None = None
) -> dict[str, Any]:
    """Render and store one server's bundle at its current dirty sequence.

    ``lock_token``: set only on the retry of a render that was deferred for
    a fleet slot, or republished with longer limits — the server's lock
    still holds it.
    """
    limits = _message_limits(self)
    result = asyncio.run(
        _run_bounded(
            server_id,
            lock_token,
            getattr(getattr(self, "request", None), "id", None),
            soft_limit=limits[0],
        )
    )
    token = result.pop("lock_token", None)
    status = result.get("status")
    if status == "deferred":
        # The retry keeps this message's limits: they were sized for it.
        _publish(server_id, limits, lock_token=token, countdown=SLOT_RETRY_SECONDS)
    elif status == "resize":
        resized = render_time_limits(math.ceil(int(result["records"]) * RENDER_RESIZE_HEADROOM))
        result["resized_to"] = resized[0]
        _publish(server_id, resized, lock_token=token)
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
        # Each request sized for its group's last stored bundle (#2240).
        records = await known_records(db, ids)
    enqueued = 0
    for sid in ids:
        if not enqueue_render(str(sid), records=records.get(sid)):
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


__all__ = [
    "enqueue_render",
    "known_records",
    "render_dns_bundle",
    "render_missing_sweep",
    "render_time_limits",
]
