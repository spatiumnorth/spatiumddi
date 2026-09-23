"""Replay dedupe for spooled agent pushes (#1077).

Agents append a push the control plane did not acknowledge to a durable
on-disk spool and replay it, in order, on reconnect. That makes the batch in
flight at the moment of an outage a problem: a POST whose RESPONSE was lost is
indistinguishable, on the agent's side, from one that never arrived, so it is
replayed even though its rows are already committed. Only the server can tell
the two apart.

Every spooled payload carries a ``batch_id`` (32 lowercase hex — a uuid4
``.hex``). Each batch-ingest handler calls :func:`claim_batch` BEFORE it
writes anything. The claim is an ``INSERT … ON CONFLICT DO NOTHING
RETURNING`` into ``agent_ingest_receipt`` inside the handler's own
transaction, so the receipt commits exactly when the ingested rows do:

* first delivery — the claim inserts, the handler writes, one commit covers
  both;
* replay of a committed batch — the claim conflicts, the handler returns
  :func:`duplicate_response` and inserts nothing;
* replay of a batch whose first attempt ROLLED BACK — the receipt rolled back
  with it, so the replay is processed as new, which is correct;
* two deliveries racing — the second INSERT blocks on the primary key until
  the first transaction ends, then either no-ops (first committed) or
  proceeds (first rolled back). Postgres serialises this for us; there is no
  window in which both write.

A body with no ``batch_id`` (an agent older than #1077, or a caller that
never spools) skips the claim entirely — exactly the pre-#1077 behaviour.

One helper for every endpoint so the check cannot be present in nine
handlers and forgotten in the tenth. Ingest handlers write no audit rows
(agent telemetry is too high-volume for the audit log, and none of them did
before this), so neither does the claim.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_ingest import AgentIngestReceipt

#: The only accepted shape. The value is written to the database, so it is
#: validated at the API edge (422) rather than trusted.
BATCH_ID_PATTERN = r"^[0-9a-f]{32}$"

#: Pydantic field type every batch-ingest request model declares as
#: ``batch_id: BatchId = None``.
BatchId = Annotated[
    Annotated[str, StringConstraints(min_length=32, max_length=32, pattern=BATCH_ID_PATTERN)]
    | None,
    Field(
        description=(
            "Replay-dedupe key minted by the agent's spool (#1077): 32 lowercase "
            "hex characters. A batch already ingested under this id for this "
            "server is acknowledged as a duplicate and inserts nothing. Omit to "
            "skip dedupe (pre-#1077 behaviour)."
        ),
    ),
]

#: How long a receipt is kept. It only has to outlive the gap between a lost
#: response and the agent's retry of that batch — i.e. the outage — but that
#: gap is unbounded for metrics and lease events (their spool has no age
#: limit, only a byte cap), so the window is deliberately generous. A replay
#: arriving after its receipt was pruned is processed again, which for the
#: accumulating DHCP / DNS metrics would double-count that one bucket.
RECEIPT_RETENTION_DAYS = 35


async def claim_batch(
    db: AsyncSession,
    *,
    server_id: uuid.UUID,
    batch_id: str | None,
    stream: str,
) -> bool:
    """Claim ``batch_id`` for ``server_id``. True = new, go ahead and ingest.

    False means this exact batch was already committed: the caller must
    return :func:`duplicate_response` without writing anything. Always True
    when ``batch_id`` is None (no dedupe requested).

    Does NOT commit — the receipt must land in the same transaction as the
    rows it vouches for, or a crash between the two would either lose the
    batch (receipt without rows) or double it (rows without receipt).
    """
    if batch_id is None:
        return True
    stmt = (
        pg_insert(AgentIngestReceipt)
        .values(server_id=server_id, batch_id=batch_id, stream=stream)
        .on_conflict_do_nothing(index_elements=["server_id", "batch_id"])
        .returning(AgentIngestReceipt.batch_id)
    )
    claimed = (await db.execute(stmt)).scalar_one_or_none()
    return claimed is not None


class IngestAck(BaseModel):
    """Common response body for every agent batch-ingest endpoint.

    ``duplicate`` is true when the batch was recognised by its ``batch_id`` as
    one already ingested — nothing was written. Endpoint-specific counters are
    declared on subclasses; ``extra="allow"`` keeps any counter a service
    function returns that is not (yet) declared, so typing the response can
    never silently drop a field an agent logs.
    """

    model_config = ConfigDict(extra="allow")

    status: str = "ok"
    duplicate: bool = False


def duplicate_response(**extra: Any) -> dict[str, Any]:
    """The 200 body for a replayed batch. ``status`` stays ``ok`` so an agent
    that only checks the HTTP status treats it as delivered — which it was."""
    return {"status": "ok", "duplicate": True, **extra}


async def prune_receipts(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Delete receipts older than :data:`RECEIPT_RETENTION_DAYS`. Idempotent.

    Does not commit; the nightly log sweep commits it with the rest.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(days=RECEIPT_RETENTION_DAYS)
    result = await db.execute(
        delete(AgentIngestReceipt).where(AgentIngestReceipt.received_at < cutoff)
    )
    return int(result.rowcount or 0)
