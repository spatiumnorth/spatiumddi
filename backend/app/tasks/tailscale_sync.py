"""Periodic Tailscale tenant reconcile.

Mirrors ``proxmox_sync`` — 30 s beat tick, per-tenant interval
gating, platform-wide kill switch via
``PlatformSettings.integration_tailscale_enabled``. Plus a
``sync_tenant_now`` task for the UI's "Sync Now" button, and a daily
``refresh_tailscale_token_expiry`` that re-reads each tenant's API token
expiry (#2138).
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
from app.db import task_connect_args
from app.models.settings import PlatformSettings
from app.models.tailscale import TailscaleTenant
from app.services.integration_sync_failure import record_sync_crash
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    from app.services.tailscale.reconcile import reconcile_tenant  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
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
                    crash = await record_sync_crash(
                        db,
                        TailscaleTenant,
                        tenant_id,
                        resource_type="tailscale_tenant",
                        action="tailscale.reconcile",
                        exc=exc,
                    )
                    errors.append(f"{tenant_name}: {crash}")
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

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            tenant = await db.get(TailscaleTenant, _uuid.UUID(tenant_id))
            if tenant is None:
                return {"status": "not_found"}
            row_id = tenant.id
            try:
                summary = await reconcile_tenant(db, tenant)
            except Exception as exc:  # noqa: BLE001 — record it, don't lose it (#2141)
                await db.rollback()
                crash = await record_sync_crash(
                    db,
                    TailscaleTenant,
                    row_id,
                    resource_type="tailscale_tenant",
                    action="tailscale.reconcile",
                    exc=exc,
                )
                logger.warning("tailscale_sync_now_crash", target=str(row_id), error=crash)
                return {"status": "error", "error": crash}
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


async def refresh_token_expiry(db: Any) -> dict[str, Any]:
    """Re-read every enabled tenant's API token expiry from Tailscale (#2138).

    Idempotent (non-negotiable #9): a read that returns the stored value
    writes nothing, and a failed read leaves the stored value — Tailscale's
    earlier answer or the operator's date — exactly as it was. Disabled
    tenants are skipped; nothing syncs with their token, so nothing breaks
    when it lapses.
    """
    from app.core.crypto import decrypt_str  # noqa: PLC0415
    from app.services.tailscale.token_expiry import (  # noqa: PLC0415
        apply_read,
        fetch_token_expiry,
    )

    ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
    if ps is None or not ps.integration_tailscale_enabled:
        return {"status": "disabled"}

    rows = (
        (await db.execute(select(TailscaleTenant).where(TailscaleTenant.enabled.is_(True))))
        .scalars()
        .all()
    )
    read_ok = 0
    changed = 0
    unread = 0
    for tenant in rows:
        if not tenant.api_key_encrypted:
            continue
        try:
            api_key = decrypt_str(tenant.api_key_encrypted)
        except ValueError:
            unread += 1
            continue
        read = await fetch_token_expiry(api_key=api_key, tailnet=tenant.tailnet)
        if not read.ok:
            unread += 1
            logger.info("tailscale_token_expiry_unread", tenant=str(tenant.id), reason=read.note)
            continue
        read_ok += 1
        if apply_read(tenant, read):
            changed += 1
    if changed:
        await db.commit()
    return {"status": "ok", "read": read_ok, "changed": changed, "unread": unread}


async def _run_token_expiry_refresh() -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            return await refresh_token_expiry(db)
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.tailscale_sync.refresh_tailscale_token_expiry",
    bind=True,
)
@module_gated("integrations.tailscale")
def refresh_tailscale_token_expiry(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_token_expiry_refresh())


@celery_app.task(
    name="app.tasks.tailscale_sync.sweep_tailscale_tenants",
    bind=True,
)
@module_gated("integrations.tailscale")
def sweep_tailscale_tenants(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.tailscale_sync.sync_tenant_now",
    bind=True,
)
def sync_tenant_now(self: Any, tenant_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(tenant_id))


__all__ = [
    "refresh_tailscale_token_expiry",
    "refresh_token_expiry",
    "sweep_tailscale_tenants",
    "sync_tenant_now",
]
