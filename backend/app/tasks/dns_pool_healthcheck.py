"""DNS pool health-check task.

Same shape as ``snmp_poll`` — a beat-fired dispatcher that finds due
pools (``next_check_at <= now``) and queues a ``run_pool_check``
Celery task per pool. The per-pool task acquires a per-row
``SELECT … FOR UPDATE SKIP LOCKED`` so a manual "Check Now" running in
parallel with the dispatcher won't double-poll.

Each member is checked concurrently inside the task with
``asyncio.gather`` (per-check timeout from the pool config). State
transitions go through ``apply_check_to_member`` (consecutive-success /
-failure thresholds gate flips), then ``apply_pool_state`` reconciles
the rendered ``DNSRecord`` rows.

ICMP is deliberately deferred — see ``services/dns/pool_healthcheck``
docstring.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_group_channel, publish_wake
from app.db import task_connect_args
from app.models.dns import DNSPool
from app.services.dns.pool_apply import apply_pool_state
from app.services.dns.pool_healthcheck import apply_check_to_member, run_check
from app.services.feature_modules import is_module_enabled
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)


async def _run_pool_check_async(pool_id_str: str) -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return {"status": "disabled"}
            row = await db.execute(
                select(DNSPool)
                .where(DNSPool.id == UUID(pool_id_str))
                .with_for_update(skip_locked=True)
            )
            pool = row.scalar_one_or_none()
            if pool is None:
                # Locked or deleted — give up; the next beat tick will retry.
                return {"status": "skipped", "reason": "locked_or_deleted"}

            if not pool.enabled:
                pool.last_checked_at = datetime.now(UTC)
                pool.next_check_at = datetime.now(UTC) + timedelta(
                    seconds=max(30, int(pool.hc_interval_seconds or 30))
                )
                await db.commit()
                return {"status": "skipped", "reason": "pool_disabled"}

            # Run all member checks concurrently.
            check_tasks = [run_check(pool, m) for m in pool.members]
            results = await asyncio.gather(*check_tasks, return_exceptions=False)

            transitions = 0
            for member, result in zip(pool.members, results, strict=True):
                change = apply_check_to_member(
                    member,
                    result,
                    unhealthy_threshold=pool.hc_unhealthy_threshold,
                    healthy_threshold=pool.hc_healthy_threshold,
                )
                member.last_check_at = datetime.now(UTC)
                if change.transitioned:
                    transitions += 1

            apply_summary = await apply_pool_state(db, pool)

            pool.last_checked_at = datetime.now(UTC)
            pool.next_check_at = datetime.now(UTC) + timedelta(
                seconds=max(30, int(pool.hc_interval_seconds or 30))
            )

            records_changed = bool(apply_summary.get("created") or apply_summary.get("deleted"))
            group_id = pool.group_id

            await db.commit()

            # Worker process — no request-scoped wake collector, so publish
            # directly AFTER commit. Only when reconcile actually rendered a
            # record change (otherwise the bundle ETag is unchanged and a wake
            # is a wasted no-op rebuild).
            if records_changed:
                await publish_wake(dns_group_channel(group_id))

            return {
                "status": "ok",
                "pool": pool.name,
                "members_checked": len(results),
                "transitions": transitions,
                "rendered": apply_summary,
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.dns_pool_healthcheck.run_pool_check", bind=True)
def run_pool_check(self: Any, pool_id_str: str) -> dict[str, Any]:  # noqa: ARG001
    """Check one pool's members + reconcile rendered records.

    Idempotent — safe to retry. Acquires a per-pool row lock so
    concurrent runs don't double-poll.
    """
    return asyncio.run(_run_pool_check_async(pool_id_str))


# ── Beat-fired dispatcher ───────────────────────────────────────────


async def _dispatch_due_async() -> int:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    queued = 0
    try:
        async with factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return 0
            now = datetime.now(UTC)
            rows = (
                (
                    await db.execute(
                        select(DNSPool).where(
                            DNSPool.enabled.is_(True),
                            (DNSPool.next_check_at.is_(None)) | (DNSPool.next_check_at <= now),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for r in rows:
                try:
                    run_pool_check.delay(str(r.id))
                    queued += 1
                except Exception as exc:  # noqa: BLE001 — broker down? give up quietly
                    logger.warning("dns_pool_dispatch_enqueue_failed", error=str(exc))
                    break
        return queued
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.dns_pool_healthcheck.dispatch_due_pools", bind=True)
@module_gated("core.dns")
def dispatch_due_pools(self: Any) -> int:  # noqa: ARG001
    """Beat-fired sweep — queues ``run_pool_check`` per due pool."""
    return asyncio.run(_dispatch_due_async())


__all__ = ["run_pool_check", "dispatch_due_pools"]
