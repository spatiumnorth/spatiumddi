"""Periodic NetBird instance reconcile.

Mirrors ``tailscale_sync`` — 30 s beat tick, per-instance interval
gating, platform-wide kill switch via
the ``integrations.netbird`` feature module (#2196). Plus a
``sync_instance_now`` task for the UI's "Sync Now" button.
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
from app.models.netbird import NetbirdInstance
from app.services.feature_modules import is_module_enabled
from app.services.integration_sync_failure import record_sync_crash

logger = structlog.get_logger(__name__)


async def _run_sweep() -> dict[str, Any]:
    from app.services.netbird.reconcile import reconcile_instance  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if not await is_module_enabled(db, "integrations.netbird"):
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(NetbirdInstance).where(NetbirdInstance.enabled.is_(True))))
                .scalars()
                .all()
            )
            # A per-instance rollback (below) expires every ORM object on the
            # shared session, so walk ids and re-fetch each instance (#333).
            instance_ids = [instance.id for instance in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for instance_id in instance_ids:
                instance = await db.get(NetbirdInstance, instance_id)
                if instance is None:
                    continue
                if instance.last_synced_at is not None:
                    elapsed = now - instance.last_synced_at
                    if elapsed < timedelta(seconds=instance.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                instance_name = instance.name  # a failed flush expires instance
                try:
                    summary = await reconcile_instance(db, instance)
                except Exception as exc:  # noqa: BLE001
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next instance still syncs.
                    await db.rollback()
                    crash = await record_sync_crash(
                        db,
                        NetbirdInstance,
                        instance_id,
                        resource_type="netbird_instance",
                        action="netbird.reconcile",
                        exc=exc,
                    )
                    errors.append(f"{instance_name}: {crash}")
                    logger.warning(
                        "netbird_reconcile_crash",
                        instance=str(instance_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{instance.name}: {summary.error}")

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


async def _run_one(instance_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.netbird.reconcile import reconcile_instance  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            instance = await db.get(NetbirdInstance, _uuid.UUID(instance_id))
            if instance is None:
                return {"status": "not_found"}
            row_id = instance.id
            try:
                summary = await reconcile_instance(db, instance)
            except Exception as exc:  # noqa: BLE001 — record it, don't lose it (#2141)
                await db.rollback()
                crash = await record_sync_crash(
                    db,
                    NetbirdInstance,
                    row_id,
                    resource_type="netbird_instance",
                    action="netbird.reconcile",
                    exc=exc,
                )
                logger.warning("netbird_sync_now_crash", target=str(row_id), error=crash)
                return {"status": "error", "error": crash}
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "dns_domain": summary.dns_domain,
                "peer_count": summary.peer_count,
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
    name="app.tasks.netbird_sync.sweep_netbird_instances",
    bind=True,
)
def sweep_netbird_instances(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.netbird_sync.sync_instance_now",
    bind=True,
)
def sync_instance_now(self: Any, instance_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(instance_id))


__all__ = ["sweep_netbird_instances", "sync_instance_now"]
