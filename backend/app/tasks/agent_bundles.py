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

``render_missing_sweep`` (beat, 30 s) enqueues every enabled agent-based
server whose newest stored bundle is behind its dirty sequence — the
belt and braces for a lost broker message.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, or_, select

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_server_channel, publish_wake
from app.core.redis_client import make_async_redis
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


async def _run(server_id_text: str) -> dict[str, Any]:
    server_id = uuid.UUID(server_id_text)
    lock_key = RENDER_LOCK_PREFIX + server_id_text
    dirty_key = RENDER_DIRTY_PREFIX + server_id_text
    ttl = max(60, int(settings.dns_agent_bundle_render_lock_seconds))
    client = None
    have_lock = False
    have_slot = False
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=_CONNECT_TIMEOUT)
        if not await client.set(lock_key, "1", nx=True, ex=ttl):
            await client.set(dirty_key, "1", ex=ttl)
            return {"status": "coalesced"}
        have_lock = True
        if not await client.set(RENDER_SLOT_KEY, server_id_text, nx=True, ex=ttl):
            await client.delete(lock_key)
            return {"status": "deferred"}
        have_slot = True
    except Exception as exc:  # noqa: BLE001 — Redis is advisory here: render anyway
        logger.warning(
            "dns_agent_bundle_lock_unavailable", server_id=server_id_text, error=str(exc)
        )
        client = None

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
        if client is not None:
            try:
                if have_slot:
                    await client.delete(RENDER_SLOT_KEY)
                if have_lock:
                    await client.delete(lock_key)
            except Exception:  # noqa: BLE001
                pass
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass
    result["renders"] = renders
    return result


@celery_app.task(
    name=TASK_RENDER,
    bind=True,
    acks_late=True,
    soft_time_limit=900,
    time_limit=960,
)
def render_dns_bundle(self: object, server_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
    """Render and store one server's bundle at its current dirty sequence."""
    result = asyncio.run(_run(server_id))
    if result.get("status") == "deferred":
        render_dns_bundle.apply_async(
            args=[server_id], countdown=SLOT_RETRY_SECONDS, retry=False, queue="bundles"
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
