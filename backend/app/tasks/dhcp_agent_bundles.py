"""Render DHCP agent config bundles in the worker (#1111).

``render_dhcp_bundle(server_id)`` builds one agent server's bundle
(``services.dhcp.agent_bundle``) and stores it, so the agent long-poll serves
a stored row instead of rebuilding the group's configuration on the api's
request loop once per agent per wake. The mutating transaction enqueues the
render after commit; ``render_stale_sweep`` (beat) is the backstop for a lost
broker message and the periodic refresh of the inputs a write cannot mark (see
``agent_bundle``'s module docstring).

Idempotent (non-negotiable #9): a render is a pure function of the database,
stored with ``ON CONFLICT DO UPDATE`` and never moved backwards, so a retried
or duplicated message changes nothing.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dhcp_server_channel, publish_wake
from app.db import task_session
from app.drivers.dhcp import is_agentless
from app.models.dhcp import DHCPAgentBundle, DHCPServer
from app.services.dhcp import agent_bundle as store
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

TASK_RENDER = "app.tasks.dhcp_agent_bundles.render_dhcp_bundle"
TASK_SWEEP = "app.tasks.dhcp_agent_bundles.render_stale_sweep"


def enqueue_render(server_id: str) -> bool:
    """Publish one render request. False (and logged) on a broker failure: the
    sweep gets it within one tick."""
    try:
        render_dhcp_bundle.apply_async(args=[str(server_id)], queue="bundles", retry=False)
        return True
    except Exception as exc:  # noqa: BLE001 — the sweep is the backstop
        logger.warning("dhcp_agent_bundle_enqueue_failed", server_id=str(server_id), error=str(exc))
        return False


def _fresh(server: DHCPServer, stored: DHCPAgentBundle | None) -> bool:
    if not store.is_current(server, stored):
        return False
    assert stored is not None  # noqa: S101 — is_current
    age = datetime.now(UTC) - stored.built_at
    return age < timedelta(seconds=settings.dhcp_agent_bundle_refresh_seconds)


async def _render_once(server_id: Any, *, force: bool = False) -> dict[str, Any]:
    async with task_session() as db:
        server = await db.get(DHCPServer, server_id)
        if server is None:
            return {"status": "gone"}
        if is_agentless(server.driver):
            return {"status": "skipped"}
        before = await store.load_stored(db, server.id)
        if not force and _fresh(server, before):
            return {"status": "current"}
        was_current = store.is_current(server, before)
        await db.refresh(server)
        try:
            outcome = await store.render_and_store(db, server, rendered_by=store.RENDERED_BY_WORKER)
            await db.commit()
        except Exception:
            await db.rollback()
            if await db.get(DHCPServer, server_id) is None:
                return {"status": "gone"}  # deleted mid-render: nothing failed
            raise
    changed = before is None or before.bundle_etag != outcome.etag
    # A poll parked on a stale bundle needs the wake; a refresh that changed
    # nothing does not.
    if changed or not was_current:
        await publish_wake(dhcp_server_channel(server_id))
    return {
        "status": "stored",
        "watermark": outcome.watermark,
        "etag": outcome.etag,
        "changed": changed,
        "render_ms": outcome.render_ms,
    }


@celery_app.task(name=TASK_RENDER, bind=True, acks_late=True, soft_time_limit=120, time_limit=180)
def render_dhcp_bundle(self: object, server_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
    """Render and store one agent server's bundle at its current sequence."""
    import uuid  # noqa: PLC0415

    result = asyncio.run(_render_once(uuid.UUID(server_id)))
    logger.info("dhcp_agent_bundle_render_task", server_id=server_id, **result)
    return result


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        servers = list((await db.execute(select(DHCPServer))).scalars().all())
        stored = {
            b.server_id: b for b in (await db.execute(select(DHCPAgentBundle))).scalars().all()
        }
    stale = [s for s in servers if not is_agentless(s.driver) and not _fresh(s, stored.get(s.id))]
    enqueued = 0
    for s in stale:
        if not enqueue_render(str(s.id)):
            break
        enqueued += 1
    return {"stale": len(stale), "enqueued": enqueued}


@celery_app.task(name=TASK_SWEEP)
@module_gated("core.dhcp")
def render_stale_sweep() -> dict[str, int]:
    """Every beat tick: enqueue a render for any agent DHCP server whose
    stored bundle is missing, behind its dirty sequence, from an older
    renderer, or older than ``dhcp_agent_bundle_refresh_seconds``."""
    return asyncio.run(_sweep())


__all__ = ["enqueue_render", "render_dhcp_bundle", "render_stale_sweep"]
