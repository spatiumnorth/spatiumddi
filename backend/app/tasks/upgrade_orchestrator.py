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
import uuid

import structlog
from celery import shared_task
from sqlalchemy.exc import SQLAlchemyError

from app.db import task_session
from app.services.upgrades.orchestrator import OrchestratorError, drive_upgrade

logger = structlog.get_logger(__name__)

# A handed-off drive that lands back on the node it is leaving is passed on
# again, up to this many times, this many seconds apart (#1449).
_MAX_HANDOFF_HOPS = 30
_HANDOFF_HOP_DELAY_S = 5


async def _async_drive(run_id: str) -> dict[str, str]:
    """Open a fresh async session + drive the run to terminal state."""
    try:
        rid = uuid.UUID(run_id)
    except ValueError as exc:
        raise OrchestratorError(f"invalid run_id {run_id!r}") from exc

    async with task_session() as db:
        try:
            run = await drive_upgrade(db, rid)
        except OrchestratorError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface ANY error to the row
            # Mark the row as failed so the UI doesn't show "running"
            # forever after the worker crashed. The orchestrator's own
            # halt-on-failure handles step-level failures; this catches
            # the rarer "the loop itself crashed" case.
            from app.models.system_upgrade import SystemUpgradeRun  # noqa: PLC0415
            from app.services.upgrades import mutex  # noqa: PLC0415

            # The failure may have left the session in a failed transaction
            # (a flush that raised); without this every statement below
            # raises PendingRollbackError, the row is never marked failed,
            # and the run sits in ``planned`` / ``running`` with no error
            # (#1449).
            await db.rollback()
            row = await db.get(SystemUpgradeRun, rid)
            if row is not None and row.state in ("planned", "running"):
                row.state = "failed"
                row.last_error = f"orchestrator crashed: {exc}"
                from datetime import UTC, datetime  # noqa: PLC0415

                row.finished_at = datetime.now(UTC)
                await db.commit()
            # A failed run holds the lease for nothing; left held, the next
            # Start is refused until it expires. Only ours, never another
            # worker's that took it over.
            mutex.release_if_held()
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
) -> dict[str, str]:
    """Celery entrypoint. ``run_id`` is the SystemUpgradeRun UUID as a
    str (Celery's JSON serializer can't carry UUIDs directly).

    ``avoid_node`` is set by a drive handing itself off before the node its
    worker runs on is drained (#1449). A worker on that node passes the task
    on rather than running it, so a worker elsewhere takes it. After
    ``_MAX_HANDOFF_HOPS`` passes (no other worker took it, say every other
    worker is down) it runs here anyway: a drive evicted mid-chain is
    redelivered later, which beats one that never runs."""
    own = os.environ.get("NODE_NAME") or None
    if avoid_node and own == avoid_node and hops < _MAX_HANDOFF_HOPS:
        drive_upgrade_run.apply_async(  # type: ignore[attr-defined]
            args=[run_id],
            kwargs={"avoid_node": avoid_node, "hops": hops + 1},
            countdown=_HANDOFF_HOP_DELAY_S,
        )
        logger.info("upgrade_drive_passed_on", run_id=run_id, node=own, hops=hops + 1)
        return {"run_id": run_id, "state": "passed_on"}
    return asyncio.run(_async_drive(run_id))
