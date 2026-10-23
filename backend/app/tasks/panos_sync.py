"""Periodic Palo Alto PAN-OS / Panorama firewall reconcile.

Mirrors ``opnsense_sync`` — 30 s beat tick, per-firewall interval gating,
platform-wide kill switch via the ``integrations.paloalto`` feature module (#2196).
Plus a ``sync_firewall_now`` task for the UI's "Sync Now" button.
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
from app.models.panos import PANOSFirewall
from app.services.feature_modules import is_module_enabled
from app.services.integration_sync_failure import record_sync_crash
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)


async def _run_sweep() -> dict[str, Any]:
    from app.services.panos.reconcile import reconcile_firewall  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            if not await is_module_enabled(db, "integrations.paloalto"):
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(PANOSFirewall).where(PANOSFirewall.enabled.is_(True))))
                .scalars()
                .all()
            )
            # Snapshot ids and re-fetch inside the loop — a per-firewall
            # rollback expires shared-session ORM objects (Proxmox #333 fix).
            firewall_ids = [r.id for r in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for firewall_id in firewall_ids:
                fw = await db.get(PANOSFirewall, firewall_id)
                if fw is None:
                    continue
                if fw.last_synced_at is not None:
                    elapsed = now - fw.last_synced_at
                    if elapsed < timedelta(seconds=fw.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                fw_name = fw.name  # a failed flush expires fw
                try:
                    summary = await reconcile_firewall(db, fw)
                except Exception as exc:  # noqa: BLE001 — one firewall shouldn't poison the sweep
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next firewall still syncs.
                    await db.rollback()
                    crash = await record_sync_crash(
                        db,
                        PANOSFirewall,
                        firewall_id,
                        resource_type="panos_firewall",
                        action="panos.reconcile",
                        exc=exc,
                    )
                    errors.append(f"{fw_name}: {crash}")
                    logger.warning(
                        "panos_reconcile_crash", firewall=str(firewall_id), error=str(exc)
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{fw.name}: {summary.error}")

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


async def _run_one(firewall_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.panos.reconcile import reconcile_firewall  # noqa: PLC0415

    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            fw = await db.get(PANOSFirewall, _uuid.UUID(firewall_id))
            if fw is None:
                return {"status": "not_found"}
            row_id = fw.id
            try:
                summary = await reconcile_firewall(db, fw)
            except Exception as exc:  # noqa: BLE001 — record it, don't lose it (#2141)
                await db.rollback()
                crash = await record_sync_crash(
                    db,
                    PANOSFirewall,
                    row_id,
                    resource_type="panos_firewall",
                    action="panos.reconcile",
                    exc=exc,
                )
                logger.warning("panos_sync_now_crash", target=str(row_id), error=crash)
                return {"status": "error", "error": crash}
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "sw_version": summary.sw_version,
                "model": summary.model,
                "object_count": summary.object_count,
                "nat_rule_count": summary.nat_rule_count,
                "interface_count": summary.interface_count,
                "lease_count": summary.lease_count,
                "objects_created": summary.objects_created,
                "objects_updated": summary.objects_updated,
                "objects_deleted": summary.objects_deleted,
                "nat_created": summary.nat_created,
                "nat_updated": summary.nat_updated,
                "nat_deleted": summary.nat_deleted,
                "subnets_created": summary.subnets_created,
                "addresses_created": summary.addresses_created,
                "warnings": summary.warnings[:20],
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.panos_sync.sweep_panos_firewalls", bind=True)
@module_gated("integrations.paloalto")
def sweep_panos_firewalls(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(name="app.tasks.panos_sync.sync_firewall_now", bind=True)
def sync_firewall_now(self: Any, firewall_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(firewall_id))


__all__ = ["sweep_panos_firewalls", "sync_firewall_now"]
