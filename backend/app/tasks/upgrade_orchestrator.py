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
strand the row in ``running`` forever.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

import structlog
from celery import shared_task
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
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


async def _async_drive(run_id: str) -> dict[str, str]:
    """Open a fresh async session + drive the run to terminal state."""
    try:
        rid = uuid.UUID(run_id)
    except ValueError as exc:
        raise OrchestratorError(f"invalid run_id {run_id!r}") from exc

    # This drive's lease identity, chosen here so the crash handler below can
    # release the lease this drive took and never another drive's (#1512).
    from app.services.upgrades import mutex  # noqa: PLC0415

    me = mutex.drive_identity()
    async with task_session() as db:
        try:
            run = await drive_upgrade(db, rid, holder=me)
        except OrchestratorError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface ANY error to the row
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
                row.state = "failed"
                row.last_error = f"orchestrator crashed: {exc}"
                from datetime import UTC, datetime  # noqa: PLC0415

                row.finished_at = datetime.now(UTC)
                await db.commit()
            else:
                await db.commit()  # ends the row lock; nothing to write
            # A failed run holds the lease for nothing; left held, the next
            # Start is refused until it expires. Only this drive's, never
            # another drive's that took it over.
            mutex.release_if_held(holder=me)
            logger.exception("upgrade_orchestrator_crashed", run_id=run_id)
            return {"run_id": run_id, "state": "failed", "error": str(exc)}

    return {"run_id": str(run.id), "state": run.state}


@shared_task(
    name="app.tasks.upgrade_orchestrator.drive_upgrade_run",
    bind=True,
    # Autoretry on transient classes. SQLAlchemyError catches connection
    # blips against the upgrade row's session; ConnectionError / OSError
    # catch kubeapi transients before the orchestrator's own
    # KubeapiUnavailableError handling kicks in.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    # NB: max_retries is kept LOW here — autoretrying a 30-min upgrade
    # is rarely the right move. Operator can re-enqueue via the api's
    # /resume endpoint with full agency.
    max_retries=2,
)
def drive_upgrade_run(  # type: ignore[type-arg]
    self: object,
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
    return asyncio.run(_async_drive(run_id))


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
# been seen free on two sweeps this far apart or more, and at most once per
# ``_REDRIVE_COOLDOWN_S`` (#1713): a drive handing itself to another node
# releases the Lease for the moment before the next drive takes it.
_ORPHAN_SEEN_TTL_S = 600
_REDRIVE_COOLDOWN_S = 600
_ORPHAN_MIN_AGE_S = 45


def _sweep_redis() -> Any:
    from app.core.redis_client import make_sync_redis  # noqa: PLC0415

    return make_sync_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)


async def _running_run_ids() -> list[uuid.UUID]:
    from app.models.system_upgrade import SystemUpgradeRun  # noqa: PLC0415

    async with task_session() as db:
        rows = await db.execute(
            select(SystemUpgradeRun.id).where(
                SystemUpgradeRun.state == "running", SystemUpgradeRun.kind == "cluster_rolling"
            )
        )
        return list(rows.scalars().all())


def resume_orphaned_runs_sync(
    run_ids: list[uuid.UUID], redis_client: Any, *, now: float | None = None
) -> list[str]:
    """For each ``running`` run, re-enqueue its drive when none is driving it.

    A drive that exits while its run is still ``running`` (its Lease lost, its
    worker killed, a task acked after a clean return) leaves nothing to carry
    the run on (#1713). "No drive" is read off the Lease, the mutex: free
    (never held, released, or expired) and still free on a second sweep. An
    unanswered Lease read is skipped, never taken for "free". The re-driven
    task still has to ``acquire`` the Lease, so a drive that came back in the
    meantime wins and this one is refused: the sweep never assumes it.
    """
    from app.services.appliance import k8s  # noqa: PLC0415
    from app.services.upgrades import mutex  # noqa: PLC0415

    if not run_ids or k8s.get_config() is None:
        return []  # nothing running, or a deployment with no Lease
    try:
        state = mutex.read_state_strict()
    except mutex.LeaseUnknownError as exc:
        logger.warning("upgrade_orphan_sweep_lease_unknown", error=str(exc))
        return []
    if state.held:
        return []  # a live drive renews it
    now = time.time() if now is None else now
    redriven: list[str] = []
    for rid in run_ids:
        seen_key = f"spatium:upgrade:orphan-seen:{rid}"
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
        drive_upgrade_run.apply_async(args=[str(rid)])  # type: ignore[attr-defined]
        logger.warning("upgrade_orphaned_run_redriven", run_id=str(rid))
        redriven.append(str(rid))
    return redriven


@shared_task(name="app.tasks.upgrade_orchestrator.resume_orphaned_runs")
def resume_orphaned_runs() -> list[str]:
    """Beat, every minute (#1713): re-drive a ``running`` rolling run whose
    drive is gone. Nothing else does: ``drive_upgrade_run`` is enqueued by
    Start, Resume and the drive's own hand-offs only, and a task is acked when
    it returns, so a drive that exited cleanly is never redelivered."""
    run_ids = asyncio.run(_running_run_ids())
    if not run_ids:
        return []
    r = _sweep_redis()
    try:
        return resume_orphaned_runs_sync(run_ids, r)
    finally:
        try:
            r.close()
        except Exception:  # noqa: BLE001 — closing a broken client
            pass
