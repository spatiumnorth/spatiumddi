"""Recurring repair for stranded DHCP-reservation IPAM mirrors (#620).

A reservation owns an ``ip_address`` row (``status="static_dhcp"``, back-linked
by ``static_assignment_id``). Every path that destroys a reservation is supposed
to release that mirror first — #618 wired up the ones that didn't, and #620
fixed the Windows scope reconciler, which used to Core-DELETE every reservation
under a scope and re-insert it under a fresh id on every poll, orphaning the
mirror of anything an operator had created in the UI.

So why sweep at all, if the paths are fixed? Because of how this fails. A
stranded mirror is silent and unrecoverable from the UI: the address sits at
``static_dhcp`` pointing at a reservation Postgres has dropped, so it is neither
allocated nor free, nothing hands it out, and no amount of clicking frees it —
every release path looks the mirror up by the reservation's *current* id and
matches nothing. The last one took a one-shot repair migration
(``d7b3f2a9c15e``) to clean up. This is that migration's step 1 made recurring,
so the next one — from a path nobody has thought of yet — costs an operator
nothing and heals within the hour.

Cheap by construction: the predicate matches only provable residue, so on a
healthy install it finds nothing and writes nothing (not even an audit row).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.services.dhcp.lease_cleanup import sweep_orphaned_lease_mirrors
from app.services.dhcp.static_ipam import sweep_orphaned_static_mirrors
from app.services.feature_modules import is_module_enabled
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

# Cap per run so a pathological install (a repair migration that never ran, say)
# can't turn one tick into an hour-long transaction holding locks on ip_address.
# Whatever is left over is picked up on the next tick — the sweep is idempotent.
_MAX_PER_RUN = 500
_LEASE_SWEEP_BUDGET_S = 240.0


async def _sweep() -> int:
    async with task_session() as db:
        # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
        # do no work (and open no driver connections) when it is.
        if not await is_module_enabled(db, "core.dhcp"):
            return 0
        freed = await sweep_orphaned_static_mirrors(db, limit=_MAX_PER_RUN)
        # #2290 — dynamic-lease mirrors whose lease rows are gone (server delete).
        # Loop in committed batches under a time budget: a deleted server can
        # strand 100k mirrors and one batch per hour would take a week.
        deadline = time.monotonic() + _LEASE_SWEEP_BUDGET_S
        capped = False
        while True:
            n = await sweep_orphaned_lease_mirrors(db, limit=_MAX_PER_RUN)
            freed += n
            if n < _MAX_PER_RUN:
                break
            if time.monotonic() > deadline:
                # A full batch and out of budget: mirrors may remain.
                capped = True
                break
            await db.commit()
        if freed:
            # Only audit when we actually changed something — a row per hour
            # saying "found nothing" would bury the one that matters. Freeing an
            # address IS a mutation, and mutations are audited (non-negotiable
            # #4); it is also a signal worth reading, because a non-zero count
            # here means some path is still stranding mirrors.
            db.add(
                AuditLog(
                    user_display_name="<system>",
                    auth_source="system",
                    action="dhcp-mirror-sweep",
                    resource_type="platform",
                    resource_id="dhcp-mirror-sweep",
                    resource_display="orphaned DHCP mirrors (reservation + lease)",
                    result="success",
                    new_value={"mirrors_freed": freed, "capped": capped},
                )
            )
        await db.commit()
        return freed


@celery_app.task(
    bind=True,
    name="app.tasks.dhcp_mirror_sweep.sweep_orphaned_mirrors",
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_kwargs={"max_retries": 3},
)
@module_gated("core.dhcp")
def sweep_orphaned_mirrors(self: Any) -> dict[str, int]:  # noqa: ARG001
    freed = asyncio.run(_sweep())
    if freed:
        # Warning, not info: a healthy install frees nothing, so a hit means a
        # reservation-destroying path skipped its mirror release and wants
        # finding — the sweep is the backstop, not the fix.
        logger.warning("dhcp_mirror_sweep_freed_orphans", mirrors_freed=freed)
    return {"mirrors_freed": freed}
