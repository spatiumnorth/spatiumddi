"""Redis pub/sub "wake" for the agent ``/config`` long-polls (#358).

The DNS and DHCP agents hold an HTTP long-poll open on ``/config``; the
api handler re-builds the ConfigBundle from the DB on a fixed tick and
returns the moment the ETag shifts. Historically that tick was a blind
``asyncio.sleep(2)`` re-poll, so every parked agent forced ~15 bundle
rebuilds per 30 s window even when nothing changed, and a real change
took up to one tick to surface.

This module lets a mutating request *wake* the parked long-poll the
instant its change commits, collapsing both the latency and the idle
re-poll cost — **without** Redis ever becoming the sole delivery path
(non-negotiable #5):

* ``publish_wake`` is fire-and-forget. Any Redis error is swallowed +
  logged; it never propagates into the mutating request (a Redis
  outage must not 500 a CRUD write).
* ``wake_subscription`` / ``WakeSubscription.wait`` degrade to a plain
  ``asyncio.sleep`` on **any** Redis error, so a Redis-down deployment
  behaves byte-for-byte like the old fixed-tick poll.
* The ETag / pending-ops compare in the long-poll stays the sole
  source of truth. A wake is purely advisory ("re-check now"): a
  spurious wake costs one no-op rebuild, a missed wake is caught by
  the ``WAKE_TICK_SECONDS`` belt-and-braces tick or the next deadline.

Cross-process safe: every api replica subscribes to the channels for
the agents whose long-polls it is holding; a mutation committed on any
replica (or a Celery worker — those publish over ``settings.redis_url``
explicitly) fans out to all subscribers via the Redis master, so the
woken poll re-reads committed state regardless of which replica holds
it. Reuses the Sentinel-aware ``make_async_redis`` so it follows
failover in an HA deployment.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from enum import StrEnum
from typing import Any

import structlog

from app.config import settings
from app.core import shutdown as _shutdown
from app.core.redis_client import make_async_redis

logger = structlog.get_logger(__name__)

# Belt-and-braces re-poll tick when Redis is healthy: even if some
# mutation site is not instrumented to publish a wake, the parked
# long-poll still re-checks the ETag at least this often.
#
# Now that the config-affecting mutation sites publish wakes (#358
# Phase 0a record chokepoint + 0b DHCP / DNS-structural / host-config /
# worker / import / resize publishers), the common case converges via
# the wake in well under a second, so the idle re-poll can relax from
# the historical 2 s to 12 s — banking ~6x fewer idle ConfigBundle
# rebuilds per parked agent. A genuinely missed publisher degrades to
# <=12 s convergence, never staleness (the ETag compare is the source
# of truth). Redis-down falls back to LONGPOLL_POLL_INTERVAL_FALLBACK
# (2 s) — exactly the pre-#358 cadence.
WAKE_TICK_SECONDS = 12.0

# Cadence the long-poll falls back to when Redis is unavailable — equal
# to the historical fixed tick so a Redis-down deployment behaves
# exactly like the pre-#358 poll.
LONGPOLL_POLL_INTERVAL_FALLBACK = 2.0

# Short connect timeout so a wedged Redis can't stall a request thread —
# the publish swallows the failure and the subscribe degrades to poll.
_CONNECT_TIMEOUT = 2.0

_PREFIX = "spatium:wake:"
_METRIC_PREFIX = "spatium:wake:metrics:published:"


def _ch(*parts: str) -> str:
    return _PREFIX + ":".join(parts)


# ── Channel builders (single source of truth so publish/subscribe can't drift) ──


def dns_group_channel(group_id: uuid.UUID | str) -> str:
    return _ch("dns", "group", str(group_id))


def dns_server_channel(server_id: uuid.UUID | str) -> str:
    return _ch("dns", "server", str(server_id))


def dhcp_group_channel(group_id: uuid.UUID | str) -> str:
    return _ch("dhcp", "group", str(group_id))


def dhcp_server_channel(server_id: uuid.UUID | str) -> str:
    return _ch("dhcp", "server", str(server_id))


def looking_glass_collector_channel(collector_id: uuid.UUID | str) -> str:
    return _ch("looking_glass", "collector", str(collector_id))


def appliance_channel(appliance_id: uuid.UUID | str) -> str:
    """Per-appliance channel for the heartbeat-gated supervisor signals
    (#358 Phase 1): fleet OS/slot upgrade, reboot, role assignment, and
    host-config (SNMP/NTP/LLDP/firewall/timezone). Published when those
    desired-state columns are stamped; the supervisor's heartbeat
    long-poll subscribes so commands start in ~0 s instead of waiting up
    to one heartbeat interval. Keyed off the existing ``appliance.id``.
    """
    return _ch("appliance", str(appliance_id))


# Broadcast channel for host-config (SNMP / NTP / LLDP) changes. Only
# the DHCP agent long-poll folds those into its ETag today, so only it
# subscribes here.
HOSTCONFIG_ALL = _ch("hostconfig", "all")


# Web UI certificate changed in the DB (#1895). Published by the Celery
# worker after an ACME issue / renewal commits; the api (the only process
# whose ServiceAccount may patch the ``spatium-appliance-tls`` Secret)
# subscribes in its lifespan and deploys the active cert.
APPLIANCE_CERT_DEPLOY = _ch("appliance", "cert-deploy")


def dns_wake_channels(server: Any) -> list[str]:
    """Channels a DNS agent long-poll subscribes to: its group (config
    fan-out) + its own server row (per-server ops / resume / settings).
    """
    return [dns_group_channel(server.group_id), dns_server_channel(server.id)]


def dhcp_wake_channels(server: Any) -> list[str]:
    """Channels a DHCP agent long-poll subscribes to: its own server row,
    its group (when it belongs to one — ``server_group_id`` is nullable),
    and the host-config broadcast (the DHCP bundle folds SNMP/NTP/LLDP).
    """
    channels = [dhcp_server_channel(server.id)]
    if server.server_group_id is not None:
        channels.append(dhcp_group_channel(server.server_group_id))
    channels.append(HOSTCONFIG_ALL)
    return channels


def looking_glass_wake_channels(collector: Any) -> list[str]:
    """Channel a Looking Glass collector's config long-poll subscribes to:
    just its own collector row. A wake here means a peer was created /
    edited / deleted and the collector should re-fetch its peer set. LG
    has no group fan-out (peers hang directly off the collector).
    """
    return [looking_glass_collector_channel(collector.id)]


def appliance_wake_channels(appliance: Any) -> list[str]:
    """Channel the supervisor heartbeat long-poll subscribes to (#358
    Phase 1): just its own appliance row. A wake here means a
    desired-state column changed and the heartbeat should return now.
    """
    return [appliance_channel(appliance.id)]


def _metric_class(channel: str) -> str:
    """Coarse class for the published-count metric (``dns`` / ``dhcp`` /
    ``hostconfig`` / ``appliance``), derived from the channel."""
    rest = channel[len(_PREFIX) :] if channel.startswith(_PREFIX) else channel
    return rest.split(":", 1)[0] or "other"


# ── Publish ──────────────────────────────────────────────────────────────────


async def publish_wake(*channels: str) -> None:
    """Fire-and-forget wake on ``channels``. Swallows all errors — a
    Redis outage must never break the mutating request that triggered
    it (the parked poll falls back to its ``WAKE_TICK_SECONDS`` tick).

    MUST be called **after** ``db.commit()`` so the woken poll re-reads
    committed state. MUST NOT be called from the long-poll's own
    ``last_config_etag`` bookkeeping commit (that would self-wake-storm).
    """
    deduped = list(dict.fromkeys(c for c in channels if c))
    if not deduped:
        return
    client = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        for ch in deduped:
            await client.publish(ch, "1")
            try:
                await client.incr(_METRIC_PREFIX + _metric_class(ch))
            except Exception:  # noqa: BLE001 — metric is best-effort
                pass
    except Exception as exc:  # noqa: BLE001 — wake is advisory; never raise
        logger.warning("agent_wake_publish_failed", channels=deduped, error=str(exc))
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass


# ── Request-scoped collector (DNS record chokepoint) ───────────────────────────
#
# ``enqueue_record_op`` / ``enqueue_record_ops_batch`` fan a record change
# out to one DNSRecordOp per agent server but do NOT commit. They stash
# the affected channels here; the mutating handler reads-and-clears +
# publishes once, AFTER its own commit (mirrors the ``_dns_op_collector``
# pattern in ipam/router.py).

_wake_collector: ContextVar[set[str] | None] = ContextVar("agent_wake_collector", default=None)


def collect_wake(*channels: str) -> None:
    """Stash channels to be published by the enclosing handler's flush.

    No-op when no collector is active (single-op callers publish
    inline instead), so this is always safe to call from shared
    enqueue helpers.
    """
    bucket = _wake_collector.get()
    if bucket is None:
        return
    for ch in channels:
        if ch:
            bucket.add(ch)


async def wake_publishing() -> AsyncIterator[None]:
    """FastAPI dependency: open a request-scoped wake collector so any
    ``collect_wake`` calls made while handling the request publish once,
    after the handler's ``db.commit()``. Attach to mutation routers
    (never the agent long-poll routers). On a read request the collector
    just stays empty, so it's always safe to attach broadly."""
    async with collecting_wakes():
        yield


@asynccontextmanager
async def collecting_wakes() -> AsyncIterator[None]:
    """Open a request-scoped wake collector. On clean exit, publishes
    every channel stashed via ``collect_wake`` once. Drops the batch on
    exception (the mutation rolled back, so there's nothing to wake)."""
    token = _wake_collector.set(set())
    try:
        yield
        channels = _wake_collector.get() or set()
        if channels:
            await publish_wake(*channels)
    finally:
        _wake_collector.reset(token)


# ── Subscribe / wait ───────────────────────────────────────────────────────────


class WakeResult(StrEnum):
    WAKE = "wake"  # a real wake message arrived → re-check now
    TIMEOUT = "timeout"  # tick elapsed with no wake → re-check anyway
    UNAVAILABLE = "unavailable"  # Redis error → degraded to poll fallback
    SHUTDOWN = "shutdown"  # this api process is stopping (#3015) → answer now


class WakeSubscription:
    """A live pub/sub subscription bound to one parked long-poll. Created
    via ``wake_subscription`` so the subscribe happens BEFORE the first
    bundle build (closing the mutation-lands-in-the-gap race). Degrades
    to a sleep on any Redis error and stays degraded for the rest of the
    request (the next ``/config`` reconnects fresh — requests are <=30 s).
    """

    def __init__(self, pubsub: Any, client: Any, degraded: bool) -> None:
        self._pubsub = pubsub
        self._client = client
        self.degraded = degraded

    async def wait(self, timeout: float) -> WakeResult:
        """Block up to ``timeout`` for a wake. Returns WAKE on a real
        message, TIMEOUT when the tick elapses, UNAVAILABLE (after a
        fallback sleep) on any Redis error so the caller keeps looping
        at the old cadence."""
        if _shutdown.shutdown_requested():
            return WakeResult.SHUTDOWN
        if self.degraded or self._pubsub is None:
            if await _shutdown.sleep_or_shutdown(min(timeout, LONGPOLL_POLL_INTERVAL_FALLBACK)):
                return WakeResult.SHUTDOWN
            return WakeResult.UNAVAILABLE
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return WakeResult.TIMEOUT
                msg, ended = await self._read_or_shutdown(remaining)
                if ended:
                    return WakeResult.SHUTDOWN
                if msg is not None and msg.get("type") == "message":
                    return WakeResult.WAKE
        except Exception as exc:  # noqa: BLE001 — degrade to poll, never fail the poll
            logger.warning("agent_wake_wait_failed", error=str(exc))
            self.degraded = True
            if await _shutdown.sleep_or_shutdown(LONGPOLL_POLL_INTERVAL_FALLBACK):
                return WakeResult.SHUTDOWN
            return WakeResult.UNAVAILABLE

    async def _read_or_shutdown(self, timeout: float) -> tuple[Any, bool]:
        """One pub/sub read of up to ``timeout``, raced against api shutdown
        (#3015). Returns ``(message_or_None, shutdown_won)``.

        A race rather than a short read in a loop: a parked poll then costs
        one timer per wake tick instead of several wakeups a second, which
        matters with a whole fleet parked on one pod. When shutdown wins the
        read is cancelled, possibly mid-frame, so the subscription is marked
        degraded and never read again — it is torn down with the request
        anyway (``wake_subscription`` owns a dedicated connection).
        """
        read = asyncio.ensure_future(
            self._pubsub.get_message(ignore_subscribe_messages=True, timeout=timeout)
        )
        stop = _shutdown.shutdown_future()
        try:
            await asyncio.wait({read, stop}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            _shutdown.discard(stop)
            if not read.done():
                read.cancel()
                self.degraded = True
                try:
                    await read
                except (asyncio.CancelledError, Exception):  # noqa: BLE001 — abandoned read
                    pass
        if read.cancelled():
            return None, True
        return read.result(), False


@asynccontextmanager
async def wake_subscription(channels: Iterable[str]) -> AsyncIterator[WakeSubscription]:
    """Subscribe to ``channels`` for the lifetime of a long-poll.

    If Redis is unreachable the context still yields a (degraded)
    subscription whose ``wait`` sleeps — so the long-poll loop is
    identical to write either way. Always tears the pub/sub connection
    down in ``finally``: a poll that ends early (an exception, a
    cancellation) must not leave it open, or a flapping fleet would exhaust
    Redis connections. An agent disconnecting mid-poll does NOT cancel the
    handler, which runs on to its deadline (#2042); that is why the DNS
    long-poll checks ``request.is_disconnected()`` before committing a page
    of ops.
    """
    chans = [c for c in channels if c]
    client = None
    pubsub = None
    degraded = False
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        pubsub = client.pubsub()
        await pubsub.subscribe(*chans)
    except Exception as exc:  # noqa: BLE001 — degrade to poll
        logger.warning("agent_wake_subscribe_failed", channels=chans, error=str(exc))
        degraded = True
    sub = WakeSubscription(pubsub if not degraded else None, client, degraded)
    try:
        yield sub
    finally:
        if pubsub is not None:
            try:
                await pubsub.unsubscribe()
            except Exception:  # noqa: BLE001
                pass
            try:
                await pubsub.aclose()
            except Exception:  # noqa: BLE001
                pass
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass


# ── Metrics (for the Platform Insights Redis tab, #358 dashboard phase) ────────


async def get_wake_metrics() -> dict[str, Any]:
    """Live wake-bus stats: published counters by class + active wake
    channels with subscriber counts. Degrade-friendly (``available=False``
    + hint on any error) so the dashboard never 500s."""
    client = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        published: dict[str, int] = {}
        async for key in client.scan_iter(match=_METRIC_PREFIX + "*"):
            key_s = key.decode() if isinstance(key, bytes) else str(key)
            val = await client.get(key_s)
            published[key_s[len(_METRIC_PREFIX) :]] = int(val) if val is not None else 0
        raw_channels = await client.pubsub_channels(_PREFIX + "*")
        channels = [c.decode() if isinstance(c, bytes) else str(c) for c in raw_channels]
        active: list[dict[str, Any]] = []
        total_subs = 0
        if channels:
            numsub = await client.pubsub_numsub(*channels)
            for ch, count in numsub:
                ch_s = ch.decode() if isinstance(ch, bytes) else str(ch)
                active.append({"channel": ch_s, "subscribers": int(count)})
                total_subs += int(count)
        return {
            "available": True,
            "published_by_class": published,
            "active_channels": active,
            "total_subscribers": total_subs,
        }
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "hint": str(exc)}
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass
