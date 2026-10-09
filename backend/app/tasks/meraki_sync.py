"""Periodic Cisco Meraki read-only reconcile (#606).

Mirrors ``panos_sync`` — 30 s beat tick, per-org interval gating, platform-wide
kill switch via ``PlatformSettings.integration_meraki_enabled``. Plus a
``sync_org_now`` task for the UI's "Sync Now" button.
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
from app.models.meraki import MerakiOrg
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    from app.services.meraki.reconcile import reconcile_org  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_meraki_enabled:
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(MerakiOrg).where(MerakiOrg.enabled.is_(True))))
                .scalars()
                .all()
            )
            # Snapshot ids and re-fetch inside the loop — a per-org rollback
            # expires shared-session ORM objects (Proxmox #333 fix).
            org_ids = [r.id for r in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for org_id in org_ids:
                org = await db.get(MerakiOrg, org_id)
                if org is None:
                    continue
                if org.last_synced_at is not None:
                    elapsed = now - org.last_synced_at
                    if elapsed < timedelta(seconds=org.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                org_name = org.name  # a failed flush expires org
                try:
                    summary = await reconcile_org(db, org)
                except Exception as exc:  # noqa: BLE001 — one org shouldn't poison the sweep
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next org still syncs.
                    await db.rollback()
                    errors.append(f"{org_name}: {exc}")
                    logger.warning("meraki_reconcile_crash", org=str(org_id), error=str(exc))
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{org.name}: {summary.error}")

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


async def _run_one(org_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.meraki.reconcile import reconcile_org  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            org = await db.get(MerakiOrg, _uuid.UUID(org_id))
            if org is None:
                return {"status": "not_found"}
            summary = await reconcile_org(db, org)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "network_count": summary.network_count,
                "object_count": summary.object_count,
                "nat_rule_count": summary.nat_rule_count,
                "objects_created": summary.objects_created,
                "objects_updated": summary.objects_updated,
                "objects_deleted": summary.objects_deleted,
                "nat_created": summary.nat_created,
                "subnets_created": summary.subnets_created,
                "addresses_created": summary.addresses_created,
                "warnings": summary.warnings[:20],
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.meraki_sync.sweep_meraki_orgs", bind=True)
def sweep_meraki_orgs(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(name="app.tasks.meraki_sync.sync_org_now", bind=True)
def sync_org_now(self: Any, org_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(org_id))


__all__ = ["sweep_meraki_orgs", "sync_org_now"]
