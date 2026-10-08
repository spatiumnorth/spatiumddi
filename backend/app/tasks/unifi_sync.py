"""Periodic UniFi controller reconcile.

Mirrors ``proxmox_sync`` — 30 s beat tick, per-controller interval
gating, platform-wide kill switch via
``PlatformSettings.integration_unifi_enabled``. Plus a
``sync_controller_now`` task for the UI's "Sync Now" button.

Cloud-mode controllers have a 60 s floor regardless of the
configured ``sync_interval_seconds`` because ``api.ui.com``
rate-limits and the cloud connector adds ~200 ms per call —
hammering it makes everyone's reconcile slower without giving
the operator fresher data.
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
from app.models.settings import PlatformSettings
from app.models.unifi import UnifiController

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1
_CLOUD_INTERVAL_FLOOR_S = 60


def _effective_interval(controller: UnifiController) -> int:
    if controller.mode == "cloud":
        return max(controller.sync_interval_seconds, _CLOUD_INTERVAL_FLOOR_S)
    return controller.sync_interval_seconds


async def _run_sweep() -> dict[str, Any]:
    from app.services.unifi.reconcile import reconcile_controller  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_unifi_enabled:
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(UnifiController).where(UnifiController.enabled.is_(True))))
                .scalars()
                .all()
            )
            # A per-controller rollback (below) expires every ORM object on the
            # shared session, so walk ids and re-fetch each controller (#333).
            controller_ids = [controller.id for controller in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for controller_id in controller_ids:
                controller = await db.get(UnifiController, controller_id)
                if controller is None:
                    continue
                interval = _effective_interval(controller)
                if controller.last_synced_at is not None:
                    elapsed = now - controller.last_synced_at
                    if elapsed < timedelta(seconds=interval):
                        skipped_interval += 1
                        continue
                controller_name = controller.name  # a failed flush expires controller
                try:
                    summary = await reconcile_controller(db, controller)
                except Exception as exc:  # noqa: BLE001
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next controller still syncs.
                    await db.rollback()
                    errors.append(f"{controller_name}: {exc}")
                    logger.warning(
                        "unifi_reconcile_crash",
                        controller=str(controller_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{controller.name}: {summary.error}")

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


async def _run_one(controller_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.unifi.reconcile import reconcile_controller  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            controller = await db.get(UnifiController, _uuid.UUID(controller_id))
            if controller is None:
                return {"status": "not_found"}
            summary = await reconcile_controller(db, controller)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "controller_version": summary.controller_version,
                "site_count": summary.site_count,
                "network_count": summary.network_count,
                "client_count": summary.client_count,
                "blocks_created": summary.blocks_created,
                "blocks_deleted": summary.blocks_deleted,
                "subnets_created": summary.subnets_created,
                "subnets_updated": summary.subnets_updated,
                "subnets_deleted": summary.subnets_deleted,
                "addresses_created": summary.addresses_created,
                "addresses_updated": summary.addresses_updated,
                "addresses_deleted": summary.addresses_deleted,
                "skipped_no_subnet": summary.skipped_no_subnet,
                "sites_skipped": summary.sites_skipped,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.unifi_sync.sweep_unifi_controllers",
    bind=True,
)
def sweep_unifi_controllers(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.unifi_sync.sync_controller_now",
    bind=True,
)
def sync_controller_now(self: Any, controller_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(controller_id))


__all__ = ["sweep_unifi_controllers", "sync_controller_now"]
