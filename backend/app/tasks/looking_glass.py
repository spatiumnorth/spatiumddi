"""BGP Looking Glass collector housekeeping tasks (issue #566).

``collector_stale_sweep`` mirrors ``app.tasks.dns.agent_stale_sweep``:
a beat task that flips a ``LookingGlassCollector`` to ``unreachable`` once
its heartbeat has been silent past the staleness window, so a dead collector
doesn't sit frozen at ``active`` forever in the Sessions / Fleet UI.

``reresolve_route_links`` (Phase 3) is the periodic correctness backstop for
the IPAM/ASN/VRF linkage resolved at ingest time — it re-runs the same
matcher over every active route so an IPAM edit made *between* RIB pushes
(no new wire snapshot to trigger a fresh resolve) still converges. Issue
#566 Phase 6 extends it to also re-run the VRF Route-Target cross-check
(``app.services.looking_glass.vrf_match``) so a VRF's import/export target
list edited after a route's last ingest still converges here too — same
precedence rule as ``routes_ingest.py``: an RT hit wins over the plain
IPAM-effective VRF.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.models.bgp_looking_glass import BGPLGRoute, LookingGlassCollector
from app.services.looking_glass.ipam_link import (
    build_resolution_cache,
    resolve_route_links,
)
from app.services.looking_glass.vrf_match import build_vrf_rt_index, match_vrf_for_route
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

# Generous multiple of the collector heartbeat interval so a single missed
# beat doesn't flap the row to unreachable.
COLLECTOR_STALE_AFTER_SECONDS = 180


async def _collector_stale_sweep_async() -> dict[str, int]:
    """Flip collectors to ``unreachable`` when no heartbeat seen past the window.

    Idempotent — only touches rows currently ``active`` whose ``last_seen_at``
    is beyond the cutoff.
    """
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            cutoff = datetime.now(UTC) - timedelta(seconds=COLLECTOR_STALE_AFTER_SECONDS)
            res = await db.execute(
                update(LookingGlassCollector)
                .where(
                    LookingGlassCollector.status == "active",
                    LookingGlassCollector.last_seen_at.isnot(None),
                    LookingGlassCollector.last_seen_at < cutoff,
                )
                .values(status="unreachable")
                .returning(LookingGlassCollector.id)
            )
            changed = len(res.all())
            await db.commit()
            if changed:
                logger.info("lg_collector_stale_sweep", marked_unreachable=changed)
            return {"marked_unreachable": changed}
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.looking_glass.collector_stale_sweep")
@module_gated("network.looking_glass")
def collector_stale_sweep() -> dict[str, int]:
    """Celery beat task — flips stale Looking Glass collectors to 'unreachable'."""
    return asyncio.run(_collector_stale_sweep_async())


async def _reresolve_route_links_async() -> dict[str, int]:
    """Re-run the IPAM/ASN/VRF matcher over every still-active route.

    Catches the case an ingest-time resolve can't: an IPAM edit made
    *after* a route was last pushed (new subnet carved under an
    already-advertised block, a block's vrf_id/asn_id reassigned, a new
    ASN row created for a previously-untracked origin) with no new RIB
    push to trigger a fresh resolve. Idempotent — a no-op recompute
    changes nothing.
    """
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            active = (
                (await db.execute(select(BGPLGRoute).where(BGPLGRoute.withdrawn_at.is_(None))))
                .scalars()
                .all()
            )
            if not active:
                return {"checked": 0, "changed": 0}

            cache = await build_resolution_cache(db)  # always fresh, bypass TTL
            vrf_rt_index = await build_vrf_rt_index(db)  # also always fresh
            changed = 0
            for route in active:
                links = resolve_route_links(cache, str(route.prefix), route.origin_asn)
                # Route-Target cross-check takes precedence over the plain
                # IPAM-effective VRF (issue #566 Phase 6 — mirrors
                # routes_ingest.py's ingest-time precedence rule).
                vpn_matched_vrf_id = match_vrf_for_route(
                    list(route.ext_communities or []), vrf_rt_index
                )
                vrf_id = vpn_matched_vrf_id if vpn_matched_vrf_id is not None else links.vrf_id
                before = (
                    route.matched_block_id,
                    route.matched_subnet_id,
                    route.matched_space_id,
                    route.matched_asn_id,
                    route.matched_vrf_id,
                )
                after = (
                    links.block_id,
                    links.subnet_id,
                    links.space_id,
                    links.asn_id,
                    vrf_id,
                )
                if before != after:
                    route.matched_block_id = links.block_id
                    route.matched_subnet_id = links.subnet_id
                    route.matched_space_id = links.space_id
                    route.matched_asn_id = links.asn_id
                    route.matched_vrf_id = vrf_id
                    changed += 1
            await db.commit()
            if changed:
                logger.info("lg_route_links_reresolved", checked=len(active), changed=changed)
            return {"checked": len(active), "changed": changed}
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.looking_glass.reresolve_route_links")
@module_gated("network.looking_glass")
def reresolve_route_links() -> dict[str, int]:
    """Celery beat task — re-resolves matched_*_id for every active route."""
    return asyncio.run(_reresolve_route_links_async())
