"""Periodic Cloud endpoint reconcile (issue #37, Part A).

Mirrors ``proxmox_sync`` — 30 s beat tick, per-endpoint interval gating,
platform-wide kill switch via ``PlatformSettings.integration_cloud_enabled``.
Plus a ``sync_endpoint_now`` task for the UI's "Sync now" button.
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
from app.models.cloud import CloudEndpoint
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    from app.services.cloud.reconcile import reconcile_endpoint  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_cloud_enabled:
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(CloudEndpoint).where(CloudEndpoint.enabled.is_(True))))
                .scalars()
                .all()
            )
            # Snapshot the gate fields into plain values before the loop. A
            # per-endpoint rollback (below) expires every ORM object on the
            # shared session, so reading ``endpoint.last_synced_at`` straight
            # off ``rows`` on a later iteration would trigger a sync lazy-load
            # and blow up with MissingGreenlet. We re-fetch each endpoint
            # inside the loop instead (issue #333).
            endpoint_ids = [endpoint.id for endpoint in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for endpoint_id in endpoint_ids:
                endpoint = await db.get(CloudEndpoint, endpoint_id)
                if endpoint is None:
                    continue
                if endpoint.last_synced_at is not None:
                    elapsed = now - endpoint.last_synced_at
                    if elapsed < timedelta(seconds=endpoint.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                endpoint_name = endpoint.name  # a failed flush expires endpoint
                try:
                    summary = await reconcile_endpoint(db, endpoint)
                except Exception as exc:  # noqa: BLE001 — one endpoint shouldn't poison the sweep
                    err_count += 1
                    # A crash inside reconcile_endpoint leaves the shared
                    # session in a failed-transaction state; without this
                    # rollback the next endpoint's first query raises
                    # PendingRollbackError, turning one bad endpoint into a
                    # sweep-wide failure (issue #333).
                    await db.rollback()
                    errors.append(f"{endpoint_name}: {exc}")
                    logger.warning(
                        "cloud_reconcile_crash",
                        endpoint=str(endpoint_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{endpoint.name}: {summary.error}")

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


async def _run_one(endpoint_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.cloud.reconcile import reconcile_endpoint  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            endpoint = await db.get(CloudEndpoint, _uuid.UUID(endpoint_id))
            if endpoint is None:
                return {"status": "not_found"}
            summary = await reconcile_endpoint(db, endpoint)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "provider_account_id": summary.provider_account_id,
                "network_count": summary.network_count,
                "instance_count": summary.instance_count,
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
    name="app.tasks.cloud_sync.sweep_cloud_endpoints",
    bind=True,
)
def sweep_cloud_endpoints(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.cloud_sync.sync_endpoint_now",
    bind=True,
)
def sync_endpoint_now(self: Any, endpoint_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(endpoint_id))


__all__ = ["sweep_cloud_endpoints", "sync_endpoint_now"]
