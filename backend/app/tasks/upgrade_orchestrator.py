"""Celery task wrapper for the rolling-upgrade orchestrator (#296 Phase D).

The orchestrator's async ``drive_upgrade`` runs inside ``asyncio.run``
via a ``@shared_task`` so the long-running per-node loop (potentially
30+ min per node) lives outside the api request lifecycle. Standard
codebase pattern — see ``app.tasks.audit_chain_verify`` for the
async-in-sync shape.

The api endpoint enqueues this task with the run_id. The task:

* Opens its own AsyncSession via ``task_session`` (api request
  sessions get torn down at request end; we need our own).
* Re-acquires / takes over the upgrade Lease (the api endpoint
  doesn't hold one — Phase D's design keeps lease ownership inside
  the orchestrator process).
* Drives the per-node loop to terminal state.

Resume semantics: re-enqueuing the same run_id is safe — the
orchestrator reads the row's ``progress.per_node`` map + skips
completed nodes. A worker that dies mid-upgrade can be recovered by
the operator clicking Resume (api re-enqueues) or by a future stuck-
runs beat task (Phase D follow-up — not in this commit).

Failure isolation: an uncaught exception inside ``drive_upgrade``
gets caught here + the run row flips to ``state='failed'`` with the
exception in ``last_error``. Otherwise a worker-side crash would
strand the row in ``running`` forever. The exception is a database that
was unreachable (#2177): that is an outage, not a failed upgrade, so the
drive releases its Lease, leaves the row ``running`` and is retried.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

import structlog
from celery import shared_task
from redis.exceptions import RedisError
from sqlalchemy import select

from app.config import settings
from app.core.db_transient import is_transient_db_error
from app.db import task_session
from app.services.upgrades.orchestrator import OrchestratorError, drive_upgrade

logger = structlog.get_logger(__name__)

# A handed-off drive that lands back on the node it is leaving is passed on
# again, up to this many times, this many seconds apart (#1449).
_MAX_HANDOFF_HOPS = 30
_HANDOFF_HOP_DELAY_S = 5
# The rest of a run after its shared-tag flip waits for a worker on the new
# tag, passed on this many times (10 min at 5 s) before it runs anyway
# (#1710): the flip rolls the workers one at a time, a minute or two each.
_MAX_VERSION_HOPS = 120

# #2177 — a drive that lost the database outside a step (the run row's own
# writes between steps and nodes) is retried after these delays, its Lease
# released first so the retry takes it over at once. ~90 s in all, plus each
# attempt's own connect timeout: a CloudNativePG failover, with room. Celery's
# exponential backoff from 1 s with full jitter put both of the old two
# retries inside about a second.
_DB_RETRY_COUNTDOWNS_S = (5, 10, 15, 30, 30)


class DriveDatabaseUnavailable(RuntimeError):
    """The drive stopped because the database was unreachable (#2177).

    Raised once the drive has released its own Lease, so whatever carries the
    run on next (this task's retry, else the orphan sweep) takes it over
    without waiting out ``LEASE_DURATION_S``. The run row is left ``running``:
    an outage is not the upgrade failing."""


async def _async_drive(run_id: str, *, avoid_version: str | None = None) -> dict[str, str]:
    """Open a fresh async session + drive the run to terminal state.

    ``avoid_version`` is the task's own, passed on so that the drive knows
    whether it is a version hand-off's continuation (#2869)."""
    try:
        rid = uuid.UUID(run_id)
    except ValueError as exc:
        raise OrchestratorError(f"invalid run_id {run_id!r}") from exc

    # This drive's lease identity, chosen here so the crash handler below can
    # release the lease this drive took and never another drive's (#1512).
    from app.services.upgrades import mutex  # noqa: PLC0415

    me = mutex.drive_identity()
    try:
        return await _drive_in_session(rid, run_id, me, avoid_version=avoid_version)
    except OrchestratorError:
        raise
    except Exception as exc:
        if not is_transient_db_error(exc):
            raise
        # #2177 — the database went away under the drive (a CNPG failover),
        # or came back only to go again while the crash handler below wrote
        # the row. Nothing about the run is known to be wrong, so the row is
        # left ``running``; the Lease is released (only this drive's, a
        # compare-and-swap; it is a kubeapi call, unaffected by the outage) so
        # the retry, or else the orphan sweep, takes the run over at once
        # instead of after the Lease's 600 s.
        mutex.release_if_held(holder=me, attempts=3)
        logger.warning(
            "upgrade_drive_database_unavailable",
            run_id=run_id,
            exc_type=type(exc).__name__,
            error=str(exc),
        )
        raise DriveDatabaseUnavailable(f"{type(exc).__name__}: {exc}") from exc


async def _drive_in_session(
    rid: uuid.UUID, run_id: str, me: str, *, avoid_version: str | None = None
) -> dict[str, str]:
    from app.services.upgrades import mutex  # noqa: PLC0415

    async with task_session() as db:
        try:
            run = await drive_upgrade(db, rid, holder=me, avoid_version=avoid_version)
        except OrchestratorError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface ANY error to the row
            if is_transient_db_error(exc):
                raise  # #2177 — an outage, not a crash: ``_async_drive`` handles it
            # Logged before the row is written: when the database is lost
            # during that write (#2177), the crash would otherwise go unlogged.
            logger.exception("upgrade_orchestrator_crashed", run_id=run_id)
            # Mark the row as failed so the UI doesn't show "running"
            # forever after the worker crashed. The orchestrator's own
            # halt-on-failure handles step-level failures; this catches
            # the rarer "the loop itself crashed" case.
            from app.models.system_upgrade import SystemUpgradeRun  # noqa: PLC0415

            # The failure may have left the session in a failed transaction
            # (a flush that raised); without this every statement below
            # raises PendingRollbackError, the row is never marked failed,
            # and the run sits in ``planned`` / ``running`` with no error
            # (#1449).
            try:
                await db.rollback()
                # Row-locked and holder-checked (#1704): the run is marked only
                # while it is still this drive's. After a takeover it is the new
                # drive's, and after a Halt or Abort the state is the operator's.
                row = (
                    await db.execute(
                        select(SystemUpgradeRun)
                        .where(SystemUpgradeRun.id == rid)
                        .with_for_update()
                        .execution_options(populate_existing=True)
                    )
                ).scalar_one_or_none()
                if (
                    row is not None
                    and row.state in ("planned", "running")
                    and row.lease_holder in (None, me)
                ):
                    in_flight_node, in_flight_step, held = _in_flight_hold(
                        getattr(row, "progress", None)
                    )
                    row.state = "failed"
                    last_error = f"orchestrator crashed: {exc}"
                    if held:
                        last_error += (
                            f"; node {in_flight_node} was at step {in_flight_step} and may "
                            f"still hold: {', '.join(held)}"
                        )
                    row.last_error = last_error
                    from datetime import UTC, datetime  # noqa: PLC0415

                    row.finished_at = datetime.now(UTC)
                    await db.commit()
                    # #2809 — a crash is a failed run like any other, and the
                    # operator hears of it the same way: the walk's two crashed
                    # runs ended ``failed`` with the cluster-upgrade-failed
                    # rule on and raised nothing, because only the drive's own
                    # failure paths called the alert. Best-effort: the row is
                    # already marked, and a delivery error must not undo that.
                    await _alert_crashed_run(db, row, in_flight_node, in_flight_step)
                else:
                    await db.commit()  # ends the row lock; nothing to write
            finally:
                # A failed run holds the lease for nothing; left held, the next
                # Start is refused until it expires. Only this drive's, never
                # another drive's that took it over. Released even when the
                # row could not be written (#2177): the run is then left
                # ``running``, and the orphan sweep re-drives it.
                mutex.release_if_held(holder=me)
            return {"run_id": run_id, "state": "failed", "error": str(exc)}

    return {"run_id": str(run.id), "state": run.state}


def _in_flight_hold(progress: dict[str, Any] | None) -> tuple[str | None, str | None, list[str]]:
    """The node a crashed drive was in the middle of, the step it was at,
    and what that node may still hold (#2809), from ``progress.in_flight``.

    Read, not released: the crash handler cannot tell what the dead chain
    finished, and an operator resuming the node from where it was (a new run,
    or a re-drive) needs the node exactly as it was left."""
    from app.services.upgrades import per_node  # noqa: PLC0415
    from app.services.upgrades.orchestrator import IN_FLIGHT_KEY  # noqa: PLC0415

    entry = progress.get(IN_FLIGHT_KEY) if isinstance(progress, dict) else None
    if not isinstance(entry, dict):
        return None, None, []
    node = entry.get("node") if isinstance(entry.get("node"), str) else None
    step = entry.get("step") if entry.get("step") in per_node.CHAIN else None
    if node is None or step is None:
        return node, step, []
    chain = list(per_node.CHAIN)
    at = chain.index(step)
    held: list[str] = []
    # The step being run counts: it may have landed before the drive died,
    # as ``single_node_upgrade`` assumes on a resume.
    if chain.index("cordon") <= at < chain.index("cluster_verify"):
        held.append("cordon")
    if chain.index("cnpg_maintenance_on") <= at < chain.index("cluster_verify"):
        held.append("maintenance_window")
    return node, step, held


async def _alert_crashed_run(
    db: Any, row: Any, failed_node: str | None, failed_at_step: str | None
) -> None:
    """Raise the cluster-upgrade-failed alert for a run the crash handler
    marked failed (#2809). Never raises."""
    from app.services.upgrades import alerts as upgrade_alerts  # noqa: PLC0415

    # Read before anything can roll the session back and expire the row.
    run_id = str(getattr(row, "id", None))
    try:
        await upgrade_alerts.emit_upgrade_failed_alert(
            db,
            row,
            failed_node=failed_node,
            failed_at_step=failed_at_step or "orchestrator",
            category=upgrade_alerts.CATEGORY_OTHER,
        )
        await db.commit()
    except Exception:  # noqa: BLE001 — the row is marked; the alert is extra
        logger.exception("upgrade_crash_alert_failed", run_id=run_id)
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001 — the connection is gone; nothing to keep
            logger.debug("upgrade_crash_alert_rollback_failed", exc_info=True)


@shared_task(
    name="app.tasks.upgrade_orchestrator.drive_upgrade_run",
    bind=True,
    # #2177 — retried only when the database was unreachable, after the
    # explicit ``_DB_RETRY_COUNTDOWNS_S`` (not Celery's 1 s jittered backoff,
    # which spent both retries inside a second of a CNPG failover). Any other
    # error is the crash handler's: the run is marked failed, not retried.
    # Re-running is safe (non-negotiable #9): the drive resumes from
    # ``progress.per_node`` and every per-node step is idempotent.
    max_retries=len(_DB_RETRY_COUNTDOWNS_S),
)
def drive_upgrade_run(  # type: ignore[type-arg]
    self: Any,
    run_id: str,
    avoid_node: str | None = None,
    hops: int = 0,
    avoid_version: str | None = None,
) -> dict[str, str]:
    """Celery entrypoint. ``run_id`` is the SystemUpgradeRun UUID as a
    str (Celery's JSON serializer can't carry UUIDs directly).

    ``avoid_node`` is set by a drive handing itself off before the node its
    worker runs on is drained (#1449). A worker on that node passes the task
    on rather than running it, so a worker elsewhere takes it. After
    ``_MAX_HANDOFF_HOPS`` passes (no other worker took it, say every other
    worker is down) it runs here anyway: a drive evicted mid-chain is
    redelivered later, which beats one that never runs.

    ``avoid_version`` is set by the drive that flipped the shared charts'
    image tag (#1710): the flip rolls every worker off that version, this
    one's too, so a worker still running it passes the task on, up to
    ``_MAX_VERSION_HOPS`` times, and a worker on the new version finishes
    the run."""
    own = os.environ.get("NODE_NAME") or None
    if avoid_node and own == avoid_node and hops < _MAX_HANDOFF_HOPS:
        drive_upgrade_run.apply_async(  # type: ignore[attr-defined]
            args=[run_id],
            kwargs={"avoid_node": avoid_node, "hops": hops + 1},
            countdown=_HANDOFF_HOP_DELAY_S,
        )
        logger.info("upgrade_drive_passed_on", run_id=run_id, node=own, hops=hops + 1)
        return {"run_id": run_id, "state": "passed_on"}
    if avoid_version and settings.version == avoid_version and hops < _MAX_VERSION_HOPS:
        drive_upgrade_run.apply_async(  # type: ignore[attr-defined]
            args=[run_id],
            kwargs={"avoid_version": avoid_version, "hops": hops + 1},
            countdown=_HANDOFF_HOP_DELAY_S,
        )
        logger.info(
            "upgrade_drive_passed_on_by_version",
            run_id=run_id,
            version=avoid_version,
            hops=hops + 1,
        )
        return {"run_id": run_id, "state": "passed_on"}
    try:
        return asyncio.run(_async_drive(run_id, avoid_version=avoid_version))
    except DriveDatabaseUnavailable as exc:
        retries = int(getattr(self.request, "retries", 0) or 0)
        if retries >= len(_DB_RETRY_COUNTDOWNS_S):
            # The Lease is already released and the row left ``running``: the
            # orphan sweep re-drives the run once the database is back.
            logger.warning("upgrade_drive_database_retries_exhausted", run_id=run_id)
            raise
        raise self.retry(
            exc=exc,
            countdown=_DB_RETRY_COUNTDOWNS_S[retries],
            max_retries=len(_DB_RETRY_COUNTDOWNS_S),
        ) from exc


async def _async_release_lingering_hold() -> dict[str, str] | None:
    from app.services.upgrades import shared_tags  # noqa: PLC0415

    async with task_session() as db:
        return await shared_tags.release_lingering_hold(db)


@shared_task(name="app.tasks.upgrade_orchestrator.release_lingering_shared_tag_hold")
def release_lingering_shared_tag_hold() -> dict[str, str] | None:
    """Beat, every minute (#1710): end the shared-tag hold of a rolling run
    that failed or was aborted, once every cluster member reports one
    installed version (the operator finished, or took back, the roll node
    by node). Without it the control plane would stay on the old tag until
    a rolling run succeeded."""
    return asyncio.run(_async_release_lingering_hold())


# A `running` rolling run whose Lease is free is re-driven only after it has
# been seen free on two consecutive sweeps this far apart or more, and at most
# once per ``_REDRIVE_COOLDOWN_S`` (#1713). A Lease seen held resets the count.
_ORPHAN_SEEN_TTL_S = 600
_REDRIVE_COOLDOWN_S = 600
_ORPHAN_MIN_AGE_S = 45
# A drive that handed itself on released the Lease for the hand-off; the task
# carrying the run on hops between workers meanwhile (#1449, #1710). Within
# these windows of the hand-off the run is in transit, not orphaned.
_HANDOFF_GRACE_S = _MAX_HANDOFF_HOPS * _HANDOFF_HOP_DELAY_S + 150
_VERSION_HANDOFF_GRACE_S = _MAX_VERSION_HOPS * _HANDOFF_HOP_DELAY_S + 300


def _redrive_kwargs(progress: dict[str, Any], now: float) -> dict[str, Any] | None:
    """The ``drive_upgrade_run`` kwargs that carry a run on as its last drive
    meant to, or None while a hand-off it made is still in transit.

    A re-drive keeps the hand-off's request: a drive that handed off before
    draining its own node asked not to run there (#1449), and one that moved
    the shared tags asked for a worker off the old tag (#1710). Dropping
    either would land the re-driven drive exactly where it must not be."""
    from datetime import datetime  # noqa: PLC0415

    from app.services.upgrades import shared_tags  # noqa: PLC0415

    def _ts(value: Any) -> float:
        try:
            return datetime.fromisoformat(str(value)).timestamp()
        except ValueError:
            return 0.0

    kwargs: dict[str, Any] = {}
    events = list((progress or {}).get("events") or [])
    # The last takeover: a hand-off before it has already been picked up.
    taken_over_at = max(
        (_ts(e.get("at")) for e in events if e.get("event") == "lease_takeover"), default=0.0
    )
    handoff = next((e for e in reversed(events) if e.get("event") == "drive_handoff"), None)
    if handoff is not None:
        at = _ts(handoff.get("at"))
        if at >= taken_over_at and now - at < _HANDOFF_GRACE_S:
            return None
        if handoff.get("node"):
            # Still the node a drive must not run on while it drains it.
            kwargs["avoid_node"] = str(handoff["node"])
    record = dict((progress or {}).get(shared_tags.PROGRESS_KEY) or {})
    flip = dict(record.get("flip") or {})
    if flip.get("handed_off_at") and record.get("from_tag"):
        at = _ts(flip["handed_off_at"])
        if at >= taken_over_at and now - at < _VERSION_HANDOFF_GRACE_S:
            return None
        kwargs["avoid_version"] = str(record["from_tag"])
    return kwargs


def _sweep_redis() -> Any:
    from app.core.redis_client import make_sync_redis  # noqa: PLC0415

    return make_sync_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)


async def _running_runs() -> list[tuple[uuid.UUID, dict[str, Any]]]:
    from app.models.system_upgrade import SystemUpgradeRun  # noqa: PLC0415

    async with task_session() as db:
        rows = await db.execute(
            select(SystemUpgradeRun.id, SystemUpgradeRun.progress).where(
                SystemUpgradeRun.state == "running", SystemUpgradeRun.kind == "cluster_rolling"
            )
        )
        return [(rid, dict(progress or {})) for rid, progress in rows.all()]


def resume_orphaned_runs_sync(
    runs: list[tuple[uuid.UUID, dict[str, Any]]], redis_client: Any, *, now: float | None = None
) -> list[str]:
    """For each ``running`` run, re-enqueue its drive when none is driving it.

    A drive that exits while its run is still ``running`` (its Lease lost, its
    worker killed, a task acked after a clean return) leaves nothing to carry
    the run on (#1713). "No drive" is read off the Lease, the mutex: free
    (never held, released, or expired) on two consecutive sweeps. An
    unanswered Lease read is skipped, never taken for "free", and resets
    nothing. The re-driven task still has to ``acquire`` the Lease, so a drive
    that came back in the meantime wins and this one is refused: the sweep
    never assumes it.
    """
    from app.services.appliance import k8s  # noqa: PLC0415
    from app.services.upgrades import mutex  # noqa: PLC0415

    if not runs or k8s.get_config() is None:
        return []  # nothing running, or a deployment with no Lease
    try:
        state = mutex.read_state_strict()
    except mutex.LeaseUnknownError as exc:
        logger.warning("upgrade_orphan_sweep_lease_unknown", error=str(exc))
        return []
    now = time.time() if now is None else now
    redriven: list[str] = []
    for rid, progress in runs:
        seen_key = f"spatium:upgrade:orphan-seen:{rid}"
        if state.held:
            # A live drive renews it. The next free sighting starts over.
            redis_client.delete(seen_key)
            continue
        kwargs = _redrive_kwargs(progress, now)
        if kwargs is None:
            redis_client.delete(seen_key)
            continue  # a hand-off is still carrying the run on
        first = redis_client.get(seen_key)
        if first is None:
            redis_client.set(seen_key, str(now), ex=_ORPHAN_SEEN_TTL_S)
            continue
        if now - float(first) < _ORPHAN_MIN_AGE_S:
            continue
        # SET NX: of two sweeps (a second beat, a slow first), one re-drives.
        if not redis_client.set(
            f"spatium:upgrade:redrive:{rid}", str(now), nx=True, ex=_REDRIVE_COOLDOWN_S
        ):
            continue
        redis_client.delete(seen_key)
        drive_upgrade_run.apply_async(args=[str(rid)], kwargs=kwargs)  # type: ignore[attr-defined]
        logger.warning("upgrade_orphaned_run_redriven", run_id=str(rid), **kwargs)
        redriven.append(str(rid))
    return redriven


@shared_task(name="app.tasks.upgrade_orchestrator.resume_orphaned_runs")
def resume_orphaned_runs() -> list[str]:
    """Beat, every minute (#1713): re-drive a ``running`` rolling run whose
    drive is gone. Nothing else does: ``drive_upgrade_run`` is enqueued by
    Start, Resume and the drive's own hand-offs only, and a task is acked when
    it returns, so a drive that exited cleanly is never redelivered.

    No-op without a kubeapi (docker-compose has no Lease and no rolling run).
    Redis unreachable: nothing is re-driven this tick, since the two-sighting
    count and the cooldown live there and re-driving without them could
    enqueue a drive every minute."""
    from app.services.appliance import k8s  # noqa: PLC0415

    if k8s.get_config() is None:
        return []
    runs = asyncio.run(_running_runs())
    if not runs:
        return []
    try:
        r = _sweep_redis()
    except Exception as exc:  # noqa: BLE001 — a sentinel lookup that failed
        logger.warning("upgrade_orphan_sweep_redis_unavailable", error=str(exc))
        return []
    try:
        return resume_orphaned_runs_sync(runs, r)
    except RedisError as exc:  # Redis down mid-sweep
        logger.warning("upgrade_orphan_sweep_failed", error=str(exc))
        return []
    finally:
        try:
            r.close()
        except Exception:  # noqa: BLE001 — closing a broken client
            pass
