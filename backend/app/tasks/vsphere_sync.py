"""Periodic vSphere target reconcile.

Mirrors ``vsphere_sync`` — 30 s beat tick, per-target interval
gating, platform-wide kill switch via
the ``integrations.vsphere`` feature module (#2196). Plus a
``sync_target_now`` task for the UI's "Sync Now" button.
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
from app.models.vsphere import VSphereTarget
from app.services.feature_modules import is_module_enabled
from app.services.integration_sync_failure import record_sync_crash
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)


async def _run_sweep() -> dict[str, Any]:
    from app.services.vsphere.reconcile import reconcile_target  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if not await is_module_enabled(db, "integrations.vsphere"):
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(VSphereTarget).where(VSphereTarget.enabled.is_(True))))
                .scalars()
                .all()
            )
            # Snapshot the gate fields into plain values before the loop. A
            # per-target rollback (below) expires every ORM object on the shared
            # session, so reading ``target.last_synced_at`` straight off ``rows``
            # on a later iteration would trigger a sync lazy-load and blow up
            # with MissingGreenlet. We re-fetch each target inside the loop
            # instead (issue #333).
            target_ids = [target.id for target in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for target_id in target_ids:
                target = await db.get(VSphereTarget, target_id)
                if target is None:
                    continue
                if target.last_synced_at is not None:
                    elapsed = now - target.last_synced_at
                    if elapsed < timedelta(seconds=target.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                target_name = target.name  # a failed flush expires target
                try:
                    summary = await reconcile_target(db, target)
                except Exception as exc:  # noqa: BLE001 — one target shouldn't poison the sweep
                    err_count += 1
                    # A crash inside reconcile_target leaves the shared session
                    # in a failed-transaction state; without this rollback the
                    # next target's first query raises PendingRollbackError,
                    # turning one bad target into a sweep-wide failure (#333).
                    await db.rollback()
                    crash = await record_sync_crash(
                        db,
                        VSphereTarget,
                        target_id,
                        resource_type="vsphere_target",
                        action="vsphere.reconcile",
                        exc=exc,
                    )
                    errors.append(f"{target_name}: {crash}")
                    logger.warning(
                        "vsphere_reconcile_crash",
                        target=str(target_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{target.name}: {summary.error}")

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


async def _run_one(target_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.vsphere.reconcile import reconcile_target  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            target = await db.get(VSphereTarget, _uuid.UUID(target_id))
            if target is None:
                return {"status": "not_found"}
            row_id = target.id
            try:
                summary = await reconcile_target(db, target)
            except Exception as exc:  # noqa: BLE001 — record it, don't lose it (#2141)
                await db.rollback()
                crash = await record_sync_crash(
                    db,
                    VSphereTarget,
                    row_id,
                    resource_type="vsphere_target",
                    action="vsphere.reconcile",
                    exc=exc,
                )
                logger.warning("vsphere_sync_now_crash", target=str(row_id), error=crash)
                return {"status": "error", "error": crash}
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                # #2577 — what the sync released outside the target's IP space.
                "released": summary.released.as_dict(),
                "vcenter_version": summary.vcenter_version,
                "host_count": summary.host_count,
                "vm_count": summary.vm_count,
                "addresses_created": summary.addresses_created,
                "addresses_updated": summary.addresses_updated,
                "addresses_deleted": summary.addresses_deleted,
                "skipped_no_subnet": summary.skipped_no_subnet,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.vsphere_sync.sweep_vsphere_targets",
    bind=True,
)
@module_gated("integrations.vsphere")
def sweep_vsphere_targets(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.vsphere_sync.sync_target_now",
    bind=True,
)
def sync_target_now(self: Any, target_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(target_id))


__all__ = ["sweep_vsphere_targets", "sync_target_now"]
