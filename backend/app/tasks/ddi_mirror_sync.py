"""Periodic commercial-DDI mirror reconcile (#4729).

Same shape as ``opnsense_sync`` — 30 s beat tick, per-target interval gating,
platform-wide kill switch via the ``migration.ddi_mirror`` feature module.
Plus a ``sync_target_now`` task for the UI's "Sync Now" button.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.db import task_connect_args
from app.models.ddi_mirror import DDIMirrorTarget
from app.services.feature_modules import is_module_enabled
from app.services.integration_sync_failure import record_sync_crash
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

_RESOURCE = "ddi_mirror_target"
_ACTION = "ddi_mirror.reconcile"


async def _run_sweep() -> dict[str, Any]:
    from app.services.ddi_mirror.reconcile import reconcile_target  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if not await is_module_enabled(db, "migration.ddi_mirror"):
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(DDIMirrorTarget).where(DDIMirrorTarget.enabled.is_(True))))
                .scalars()
                .all()
            )
            # Snapshot ids and re-fetch inside the loop: a per-target rollback
            # expires shared-session ORM objects.
            target_ids = [r.id for r in rows]

            now = datetime.now(UTC)
            ran = skipped_interval = ok_count = err_count = 0
            errors: list[str] = []

            for target_id in target_ids:
                t = await db.get(DDIMirrorTarget, target_id)
                if t is None:
                    continue
                if t.last_synced_at is not None and now - t.last_synced_at < timedelta(
                    seconds=t.sync_interval_seconds
                ):
                    skipped_interval += 1
                    continue
                target_name = t.name  # a failed flush expires t
                try:
                    summary = await reconcile_target(db, t)
                except Exception as exc:  # noqa: BLE001 — one target must not poison the sweep
                    err_count += 1
                    await db.rollback()
                    crash = await record_sync_crash(
                        db,
                        DDIMirrorTarget,
                        target_id,
                        resource_type=_RESOURCE,
                        action=_ACTION,
                        exc=exc,
                    )
                    errors.append(f"{target_name}: {crash}")
                    logger.warning("ddi_mirror_reconcile_crash", target=str(target_id), error=crash)
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{target_name}: {summary.error}")

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
    from app.services.ddi_mirror.reconcile import reconcile_target  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            t = await db.get(DDIMirrorTarget, uuid.UUID(target_id))
            if t is None:
                return {"status": "not_found"}
            row_id = t.id
            try:
                summary = await reconcile_target(db, t)
            except Exception as exc:  # noqa: BLE001 — record it, don't lose it (#2141)
                await db.rollback()
                crash = await record_sync_crash(
                    db,
                    DDIMirrorTarget,
                    row_id,
                    resource_type=_RESOURCE,
                    action=_ACTION,
                    exc=exc,
                )
                logger.warning("ddi_mirror_sync_now_crash", target=str(row_id), error=crash)
                return {"status": "error", "error": crash}
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "warning": summary.warning,
                "version": summary.version,
                "object_count": summary.object_count,
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.ddi_mirror_sync.sweep_ddi_mirror_targets", bind=True)
@module_gated("migration.ddi_mirror")
def sweep_ddi_mirror_targets(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(name="app.tasks.ddi_mirror_sync.sync_target_now", bind=True)
def sync_target_now(self: Any, target_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(target_id))


__all__ = ["sweep_ddi_mirror_targets", "sync_target_now"]
