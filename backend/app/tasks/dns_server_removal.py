"""Remove a DNS server in the worker, not in the DELETE request (#4173).

``DELETE /dns/groups/{g}/servers/{s}`` used to run one ``DELETE FROM
dns_server`` and let Postgres cascade through every table that points at it.
On an install with a large query log that was over a minute inside the HTTP
request, holding locks on the busiest tables while the agents kept inserting.

Now the handler stamps ``removing_at`` (the UI reads it as "Removing…", the
server's agent is refused), audits, and enqueues this task. The task works in
bounded batches, each its own transaction:

1. **History** (``dns_query_log_entry``, ``dns_rpz_hit``) is detached, not
   deleted: ``server_id`` goes NULL and ``server_name`` is stamped on rows
   that predate the column. Those rows record what clients asked, so they
   outlive the server and the retention prune ages them out. Doing the
   UPDATE here, in batches, is what keeps the final ``DELETE`` from running
   the ``ON DELETE SET NULL`` over the whole table at once.
2. **Operational rows** (bundles, record ops, zone and runtime state, ingest
   snapshots, metric samples) are deleted in batches.
3. The server row goes last, in one small transaction.

Idempotent (non-negotiable #9): every step selects what is *left* for the
server, so a retry resumes where the last run stopped, and a server that is
already gone is a no-op.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.config import settings
from app.db import task_session
from app.models.dns import DNSServer

logger = structlog.get_logger(__name__)

BATCH_SIZE = 5000

# Tables whose rows are detached from the server and kept.
HISTORY_TABLES = ("dns_query_log_entry", "dns_rpz_hit")

# Tables whose rows go with the server. Fixed names, never user input.
OPERATIONAL_TABLES = (
    "dns_agent_bundle",
    "dns_record_op",
    "dns_server_zone_state",
    "dns_server_runtime_state",
    "dns_ingest_snapshot",
    "dns_metric_sample",
)


async def _detach_history(
    db: AsyncSession, table: str, server_id: uuid.UUID, name: str, batch: int
) -> int:
    total = 0
    while True:
        res = await db.execute(
            text(
                f"UPDATE {table} SET server_id = NULL, "  # noqa: S608 - fixed table names
                "server_name = COALESCE(server_name, :name) "
                # ``id``, not ``ctid``: these tables are partitioned (#2185) and a
                # ctid is only unique within one partition.
                f"WHERE id IN (SELECT id FROM {table} "
                "WHERE server_id = :sid LIMIT :n)"
            ),
            {"sid": server_id, "name": name, "n": batch},
        )
        await db.commit()
        n = int(res.rowcount or 0)
        total += n
        if n < batch:
            return total


async def _delete_operational(
    db: AsyncSession, table: str, server_id: uuid.UUID, batch: int
) -> int:
    total = 0
    while True:
        res = await db.execute(
            text(
                f"DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} "  # noqa: S608
                "WHERE server_id = :sid LIMIT :n)"
            ),
            {"sid": server_id, "n": batch},
        )
        await db.commit()
        n = int(res.rowcount or 0)
        total += n
        if n < batch:
            return total


async def remove_server_with_session(
    db: AsyncSession, server_id: uuid.UUID, *, batch_size: int = BATCH_SIZE
) -> dict[str, Any]:
    """Finish a requested server removal against an explicit session."""
    server = await db.get(DNSServer, server_id)
    if server is None:
        return {"status": "gone"}
    if server.removing_at is None:
        # Only the delete handler marks a server; never remove an unmarked one.
        return {"status": "not_removing"}
    name = server.name
    counts: dict[str, int] = {}
    for table in HISTORY_TABLES:
        counts[table] = await _detach_history(db, table, server_id, name, batch_size)
    for table in OPERATIONAL_TABLES:
        counts[table] = await _delete_operational(db, table, server_id, batch_size)
    # The history tables have no foreign key (#2185), so the detach above is the
    # whole job; this delete only cascades the operational rows that arrived since.
    await db.execute(delete(DNSServer).where(DNSServer.id == server_id))
    await db.commit()
    return {"status": "removed", "rows": counts}


async def _run(server_id: uuid.UUID) -> dict[str, Any]:
    async with task_session(command_timeout=settings.task_db_long_command_timeout) as db:
        return await remove_server_with_session(db, server_id)


@celery_app.task(name="app.tasks.dns_server_removal.remove_dns_server")
def remove_dns_server(server_id: str) -> dict[str, Any]:
    result = asyncio.run(_run(uuid.UUID(server_id)))
    logger.info("dns_server_removed", server_id=server_id, **result)
    return result
