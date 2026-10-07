"""Periodic Kubernetes cluster reconcile — Phase 1b.

Fires every 30 s from Celery Beat — the cluster-level minimum interval.
Iterates every enabled ``KubernetesCluster`` and runs the per-cluster
reconciler when its individual ``sync_interval_seconds`` has elapsed.
Gated overall by ``PlatformSettings.integration_kubernetes_enabled`` so
flipping the global toggle off pauses all clusters without touching
their rows.

Also exposes a ``sync_cluster_now`` task for the admin UI's "Sync Now"
button — skips the interval check so operators can force a pass.
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
from app.models.kubernetes import KubernetesCluster
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _run_sweep() -> dict[str, Any]:
    # Deferred import — matches the pattern in dhcp_pull_leases etc.
    # Keeps celery worker startup time down and avoids pulling the
    # whole router graph into the beat process.
    from app.services.kubernetes.reconcile import (  # noqa: PLC0415
        reconcile_cluster,
    )

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
            if ps is None or not ps.integration_kubernetes_enabled:
                return {"status": "disabled"}

            rows = (
                (
                    await db.execute(
                        select(KubernetesCluster).where(KubernetesCluster.enabled.is_(True))
                    )
                )
                .scalars()
                .all()
            )
            # A per-cluster rollback (below) expires every ORM object on the
            # shared session, so walk ids and re-fetch each cluster (#333).
            cluster_ids = [cluster.id for cluster in rows]

            now = datetime.now(UTC)
            ran = 0
            skipped_interval = 0
            ok_count = 0
            err_count = 0
            errors: list[str] = []

            for cluster_id in cluster_ids:
                cluster = await db.get(KubernetesCluster, cluster_id)
                if cluster is None:
                    continue
                if cluster.last_synced_at is not None:
                    elapsed = now - cluster.last_synced_at
                    if elapsed < timedelta(seconds=cluster.sync_interval_seconds):
                        skipped_interval += 1
                        continue
                cluster_name = cluster.name  # a failed flush expires cluster
                try:
                    summary = await reconcile_cluster(db, cluster)
                except Exception as exc:  # noqa: BLE001 — one cluster shouldn't poison the sweep
                    err_count += 1
                    # A crash leaves the shared session in a failed
                    # transaction; roll back so the next cluster still syncs.
                    await db.rollback()
                    errors.append(f"{cluster_name}: {exc}")
                    logger.warning(
                        "k8s_reconcile_crash",
                        cluster=str(cluster_id),
                        error=str(exc),
                    )
                    continue
                ran += 1
                if summary.ok:
                    ok_count += 1
                else:
                    err_count += 1
                    if summary.error:
                        errors.append(f"{cluster.name}: {summary.error}")

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


async def _run_one(cluster_id: str) -> dict[str, Any]:
    import uuid as _uuid  # noqa: PLC0415

    from app.services.kubernetes.reconcile import (  # noqa: PLC0415
        reconcile_cluster,
    )

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            cluster = await db.get(KubernetesCluster, _uuid.UUID(cluster_id))
            if cluster is None:
                return {"status": "not_found"}
            summary = await reconcile_cluster(db, cluster)
            return {
                "status": "ok" if summary.ok else "error",
                "error": summary.error,
                "node_count": summary.node_count,
                "blocks_created": summary.blocks_created,
                "blocks_deleted": summary.blocks_deleted,
                "addresses_created": summary.addresses_created,
                "addresses_updated": summary.addresses_updated,
                "addresses_deleted": summary.addresses_deleted,
                "records_created": summary.records_created,
                "records_updated": summary.records_updated,
                "records_deleted": summary.records_deleted,
                "skipped_no_subnet": summary.skipped_no_subnet,
                "skipped_no_zone": summary.skipped_no_zone,
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.kubernetes_sync.sweep_kubernetes_clusters",
    bind=True,
)
def sweep_kubernetes_clusters(self: Any) -> dict[str, Any]:  # noqa: ARG001
    """Beat-fired sweep — runs the reconciler against every enabled
    cluster whose interval has elapsed."""
    return asyncio.run(_run_sweep())


@celery_app.task(
    name="app.tasks.kubernetes_sync.sync_cluster_now",
    bind=True,
)
def sync_cluster_now(self: Any, cluster_id: str) -> dict[str, Any]:  # noqa: ARG001
    """Force a reconcile for one cluster. Fired by the "Sync Now"
    button in the admin UI; no interval gating."""
    return asyncio.run(_run_one(cluster_id))


__all__ = ["sweep_kubernetes_clusters", "sync_cluster_now"]
