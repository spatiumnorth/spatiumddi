"""Agent ingest receipts + heartbeat-reported spool status (#1077).

Agents now spool a push the control plane did not acknowledge and replay it
on reconnect. Two pieces of storage make that safe and visible:

* ``agent_ingest_receipt`` — one row per ``(server_id, batch_id)`` an ingest
  endpoint has committed. Claimed in the same transaction as the rows the
  batch inserts, so a replay of a batch whose response was lost is answered
  "duplicate" and inserts nothing. Pruned after 35 days by the nightly log
  sweep. ``server_id`` has no foreign key because it names either a
  ``dns_server`` or a ``dhcp_server`` row.
* ``dns_server.spool_status`` / ``dhcp_server.spool_status`` — the agent's
  spool as last reported on its heartbeat. Nullable and not backfilled: NULL
  means the agent has never reported one (pre-#1077, or agentless), which is
  UNKNOWN rather than "nothing queued".

Revision ID: c5e8a1f3d027
Revises: 8e317fdd5b12
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "c5e8a1f3d027"
down_revision = "8e317fdd5b12"
branch_labels = None
depends_on = None

_SERVER_TABLES = ("dns_server", "dhcp_server")


def upgrade() -> None:
    op.create_table(
        "agent_ingest_receipt",
        sa.Column("server_id", UUID(as_uuid=True), nullable=False),
        sa.Column("batch_id", sa.String(32), nullable=False),
        sa.Column("stream", sa.String(40), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("server_id", "batch_id", name="pk_agent_ingest_receipt"),
    )
    op.create_index(
        "ix_agent_ingest_receipt_received_at",
        "agent_ingest_receipt",
        ["received_at"],
        unique=False,
    )
    for table in _SERVER_TABLES:
        op.add_column(table, sa.Column("spool_status", JSONB(), nullable=True))


def downgrade() -> None:
    for table in _SERVER_TABLES:
        op.drop_column(table, "spool_status")
    op.drop_index("ix_agent_ingest_receipt_received_at", table_name="agent_ingest_receipt")
    op.drop_table("agent_ingest_receipt")
