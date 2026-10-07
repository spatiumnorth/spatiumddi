"""Periodic OPNsense firewall reconcile.

Mirrors ``proxmox_sync`` — 30 s beat tick, per-firewall interval
gating, platform-wide kill switch via
``PlatformSettings.integration_opnsense_enabled``. Plus a
``sync_router_now`` task for the UI's "Sync Now" button.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.models.opnsense import OPNsenseRouter
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    from app.services.opnsense.reconcile import reconcile_router  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_opnsense_enabled:
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(OPNsenseRouter).where(OPNsenseRouter.enabled.is_(True))))
                .scalars()
                .all()
            )
            # Snapshot the row ids and re-fetch each inside the loop. A
            # per-router rollback expires every ORM object on the shared
            # session, so reading off ``rows`` on a later iteration would
            # trigger a sync lazy-load and blow up with MissingGreenlet
            # (mirrors the Proxmox #333 fix).
            router_ids = [r.id for r in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for router_id in router_ids:
                router = await db.get(OPNsenseRouter, router_id)
                if router is None:
                    continue
                if router.last_synced_at is not None:
                    elapsed = now - router.last_synced_at
                    if elapsed < timedelta(seconds=router.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                router_name = router.name  # a failed flush expires router
                try:
                    summary = await reconcile_router(db, router)
                except Exception as exc:  # noqa: BLE001 — one router shouldn't poison the sweep
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next router still syncs.
                    await db.rollback()
                    errors.append(f"{router_name}: {exc}")
                    logger.warning(
                        "opnsense_reconcile_crash",
                        router=str(router_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{router.name}: {summary.error}")

            return {
                "status": "ok",
                "ran": ran,
                "skipped_interval": skipped_interval,
                "ok": ok_count,
                "errors": err_count,
                "error_messages": errors[:20],
            }
    finally:
        await engine.dispose()


async def _run_one(router_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.opnsense.reconcile import reconcile_router  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            router = await db.get(OPNsenseRouter, _uuid.UUID(router_id))
            if router is None:
                return {"status": "not_found"}
            summary = await reconcile_router(db, router)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "firmware_version": summary.firmware_version,
                "interface_count": summary.interface_count,
                "lease_count": summary.lease_count,
                "reservation_count": summary.reservation_count,
                "arp_count": summary.arp_count,
                "blocks_created": summary.blocks_created,
                "blocks_deleted": summary.blocks_deleted,
                "subnets_created": summary.subnets_created,
                "subnets_updated": summary.subnets_updated,
                "subnets_deleted": summary.subnets_deleted,
                "subnets_matched": summary.subnets_matched,
                "addresses_created": summary.addresses_created,
                "addresses_updated": summary.addresses_updated,
                "addresses_deleted": summary.addresses_deleted,
                "skipped_no_subnet": summary.skipped_no_subnet,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.opnsense_sync.sweep_opnsense_routers",
    bind=True,
)
def sweep_opnsense_routers(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.opnsense_sync.sync_router_now",
    bind=True,
)
def sync_router_now(self: Any, router_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(router_id))


__all__ = ["sweep_opnsense_routers", "sync_router_now"]
