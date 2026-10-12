"""Periodic Docker host reconcile.

Mirrors ``kubernetes_sync`` — 30 s beat tick, per-host interval
gating, platform-wide kill switch via
``PlatformSettings.integration_docker_enabled``. Plus a
``sync_host_now`` task for the UI's "Sync Now" button.
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
from app.models.docker import DockerHost
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    from app.services.docker.reconcile import reconcile_host  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_docker_enabled:
                return {"status": "disabled"}

            rows = (
                (await db.execute(select(DockerHost).where(DockerHost.enabled.is_(True))))
                .scalars()
                .all()
            )
            # A per-host rollback (below) expires every ORM object on the
            # shared session, so walk ids and re-fetch each host (#333).
            host_ids = [host.id for host in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for host_id in host_ids:
                host = await db.get(DockerHost, host_id)
                if host is None:
                    continue
                if host.last_synced_at is not None:
                    elapsed = now - host.last_synced_at
                    if elapsed < timedelta(seconds=host.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                host_name = host.name  # a failed flush expires host
                try:
                    summary = await reconcile_host(db, host)
                except Exception as exc:  # noqa: BLE001 — one host shouldn't poison the sweep
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next host still syncs.
                    await db.rollback()
                    errors.append(f"{host_name}: {exc}")
                    logger.warning(
                        "docker_reconcile_crash",
                        host=str(host_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{host.name}: {summary.error}")

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


async def _run_one(host_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.docker.reconcile import reconcile_host  # noqa: PLC0415

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            host = await db.get(DockerHost, _uuid.UUID(host_id))
            if host is None:
                return {"status": "not_found"}
            summary = await reconcile_host(db, host)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "container_count": summary.container_count,
                "blocks_created": summary.blocks_created,
                "blocks_deleted": summary.blocks_deleted,
                "subnets_created": summary.subnets_created,
                "subnets_updated": summary.subnets_updated,
                "subnets_deleted": summary.subnets_deleted,
                "addresses_created": summary.addresses_created,
                "addresses_updated": summary.addresses_updated,
                "addresses_deleted": summary.addresses_deleted,
                "skipped_no_subnet": summary.skipped_no_subnet,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.docker_sync.sweep_docker_hosts",
    bind=True,
)
def sweep_docker_hosts(self: Any) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.docker_sync.sync_host_now",
    bind=True,
)
def sync_host_now(self: Any, host_id: str) -> dict[str, Any]:  # noqa: ARG001
    return asyncio.run(_run_one(host_id))


__all__ = ["sweep_docker_hosts", "sync_host_now"]
