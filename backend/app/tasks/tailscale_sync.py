"""Periodic Tailscale tenant reconcile.

Mirrors ``proxmox_sync`` — 30 s beat tick, per-tenant interval
gating, platform-wide kill switch via
``PlatformSettings.integration_tailscale_enabled``. Plus a
``sync_tenant_now`` task for the UI's "Sync Now" button.
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
from app.models.tailscale import TailscaleTenant

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    from app.services.tailscale.reconcile import reconcile_tenant  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_tailscale_enabled:
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(TailscaleTenant).where(TailscaleTenant.enabled.is_(True))))
                .scalars()
                .all()
            )
            # A per-tenant rollback (below) expires every ORM object on the
            # shared session, so walk ids and re-fetch each tenant (#333).
            tenant_ids = [tenant.id for tenant in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for tenant_id in tenant_ids:
                tenant = await db.get(TailscaleTenant, tenant_id)
                if tenant is None:
                    continue
                if tenant.last_synced_at is not None:
                    elapsed = now - tenant.last_synced_at
                    if elapsed < timedelta(seconds=tenant.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                tenant_name = tenant.name  # a failed flush expires tenant
                try:
                    summary = await reconcile_tenant(db, tenant)
                except Exception as exc:  # noqa: BLE001
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next tenant still syncs.
                    await db.rollback()
                    errors.append(f"{tenant_name}: {exc}")
                    logger.warning(
                        "tailscale_reconcile_crash",
                        tenant=str(tenant_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{tenant.name}: {summary.error}")

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


async def _run_one(tenant_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.tailscale.reconcile import reconcile_tenant  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            tenant = await db.get(TailscaleTenant, _uuid.UUID(tenant_id))
            if tenant is None:
                return {"status": "not_found"}
            summary = await reconcile_tenant(db, tenant)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "tailnet_domain": summary.tailnet_domain,
                "device_count": summary.device_count,
                "blocks_created": summary.blocks_created,
                "subnets_created": summary.subnets_created,
                "addresses_created": summary.addresses_created,
                "addresses_updated": summary.addresses_updated,
                "addresses_deleted": summary.addresses_deleted,
                "skipped_expired": summary.skipped_expired,
                "skipped_no_subnet": summary.skipped_no_subnet,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.tailscale_sync.sweep_tailscale_tenants",
    bind=True,
)
def sweep_tailscale_tenants(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.tailscale_sync.sync_tenant_now",
    bind=True,
)
def sync_tenant_now(self: Any, tenant_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(tenant_id))


__all__ = ["sweep_tailscale_tenants", "sync_tenant_now"]
