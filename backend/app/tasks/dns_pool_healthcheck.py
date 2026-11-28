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
from sqlalchemy import select, text
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


# Postgres advisory-lock namespace for the per-pool single-flight lock (#4808).
# The second key is hashtext(pool_id); this int separates the keyspace from the
# other two-int advisory locks in the app.
_POOL_CHECK_LOCK_NS = 0x504F4F4C  # "POOL"


def _hc_signature(pool: DNSPool) -> tuple[Any, ...]:
    """The pool fields a probe's outcome depends on. A result is dropped when
    any of them changed while the probes ran."""
    return (
        pool.hc_type,
        pool.hc_target_port,
        pool.hc_path,
        pool.hc_method,
        pool.hc_verify_tls,
        tuple(pool.hc_expected_status_codes or ()),
        pool.hc_timeout_seconds,
    )


async def _run_pool_check_async(pool_id_str: str) -> dict[str, Any]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    pool_id = UUID(pool_id_str)
    try:
        # #4808 — read, commit, probe with no session open, write in a fresh
        # one. The probes used to run under ``SELECT ... FOR UPDATE SKIP
        # LOCKED``, so a member that answered slowly held a pooled connection
        # ``idle in transaction`` and blocked every write to the pool row for
        # up to the per-check timeout.
        async with factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return {"status": "disabled"}
            # Single-flight, so a manual "Check Now" racing the dispatcher does
            # not double-poll. A SESSION-level advisory lock rather than the
            # row lock: it holds no transaction and blocks no writer, it
            # outlives the commits below, and Postgres drops it when the
            # connection closes (``engine.dispose()`` in the ``finally``, or a
            # worker killed mid-check), so it cannot wedge the pool. The
            # discovery sweep (#515) takes its lock the same way.
            locked = await db.scalar(
                text("SELECT pg_try_advisory_lock(:ns, hashtext(:pid))"),
                {"ns": _POOL_CHECK_LOCK_NS, "pid": pool_id_str},
            )
            if not locked:
                # Another run is checking it — the next beat tick will retry.
                return {"status": "skipped", "reason": "locked_or_deleted"}
            pool = await db.get(DNSPool, pool_id)
            if pool is None:
                return {"status": "skipped", "reason": "locked_or_deleted"}

            if not pool.enabled:
                pool.last_checked_at = datetime.now(UTC)
                pool.next_check_at = datetime.now(UTC) + timedelta(
                    seconds=max(30, int(pool.hc_interval_seconds or 30))
                )
                await db.commit()
                return {"status": "skipped", "reason": "pool_disabled"}

            signature = _hc_signature(pool)
            probed = [(m.id, m.address, m) for m in pool.members]
            await db.commit()  # end the read transaction before any probe

        # Run all member checks concurrently, with no session open. They read
        # only the plain attributes loaded above (``expire_on_commit=False``).
        results = await asyncio.gather(*(run_check(pool, m) for _id, _addr, m in probed))

        async with factory() as db:
            row = await db.execute(select(DNSPool).where(DNSPool.id == pool_id).with_for_update())
            fresh = row.scalar_one_or_none()
            # Deleted, disabled or re-tuned while the probes ran: the results
            # describe a pool that no longer exists as probed.
            if fresh is None or not fresh.enabled or _hc_signature(fresh) != signature:
                return {"status": "skipped", "reason": "changed_during_check"}
            by_id = {m.id: m for m in fresh.members}

            transitions = 0
            checked = 0
            for (member_id, address, _m), result in zip(probed, results, strict=True):
                member = by_id.get(member_id)
                if member is None or member.address != address:
                    continue  # removed or re-addressed meanwhile
                change = apply_check_to_member(
                    member,
                    result,
                    unhealthy_threshold=fresh.hc_unhealthy_threshold,
                    healthy_threshold=fresh.hc_healthy_threshold,
                )
                member.last_check_at = datetime.now(UTC)
                checked += 1
                if change.transitioned:
                    transitions += 1

            apply_summary = await apply_pool_state(db, fresh)

            fresh.last_checked_at = datetime.now(UTC)
            fresh.next_check_at = datetime.now(UTC) + timedelta(
                seconds=max(30, int(fresh.hc_interval_seconds or 30))
            )

            records_changed = bool(apply_summary.get("created") or apply_summary.get("deleted"))
            group_id = fresh.group_id
            pool_name = fresh.name

            await db.commit()

            # Worker process — no request-scoped wake collector, so publish
            # directly AFTER commit. Only when reconcile actually rendered a
            # record change (otherwise the bundle ETag is unchanged and a wake
            # is a wasted no-op rebuild).
            if records_changed:
                await publish_wake(dns_group_channel(group_id))

            return {
                "status": "ok",
                "pool": pool_name,
                "members_checked": checked,
                "transitions": transitions,
                "rendered": apply_summary,
            }
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.dns_pool_healthcheck.run_pool_check", bind=True)
def run_pool_check(self: Any, pool_id_str: str) -> dict[str, Any]:  # noqa: ARG001
    """Check one pool's members + reconcile rendered records.

    Idempotent — safe to retry. Takes a per-pool advisory lock so
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
