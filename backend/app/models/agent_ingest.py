"""Agent ingest receipts — replay dedupe for spooled agent pushes (#1077).

Agents spool a batch the control plane did not acknowledge and replay it on
reconnect. A POST whose *response* was lost is indistinguishable, from the
agent's side, from one that never arrived, so the batch in flight at the
moment of an outage is replayed even though its rows are already committed.
The server has to be the one to say "already have it".

Each spooled batch carries a ``batch_id``. The ingest handler claims
``(server_id, batch_id)`` here in the SAME transaction as the rows it
inserts, so a receipt exists exactly when the rows do: a rolled-back ingest
leaves no receipt and the replay is processed normally; a committed one makes
the replay a no-op. See ``app.services.agents.ingest_receipt``.

``server_id`` carries no foreign key because it names a row in either
``dns_server`` or ``dhcp_server``. Both are UUID4, so the two id spaces do not
collide in practice, and a receipt that outlives its server is harmless — it
is pruned with the rest after ``RECEIPT_RETENTION_DAYS``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, PrimaryKeyConstraint, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AgentIngestReceipt(Base):
    __tablename__ = "agent_ingest_receipt"
    __table_args__ = (
        PrimaryKeyConstraint("server_id", "batch_id", name="pk_agent_ingest_receipt"),
        # The nightly prune deletes by age.
        Index("ix_agent_ingest_receipt_received_at", "received_at"),
    )

    server_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # 32 lowercase hex characters (a uuid4 ``.hex``), validated at the API edge.
    batch_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # Which endpoint claimed it (``dns.metrics``, ``dhcp.lease_events`` …).
    # Diagnostic only — the PK does not include it, because a batch id is
    # minted per batch and never legitimately reused across streams.
    stream: Mapped[str] = mapped_column(String(40), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
