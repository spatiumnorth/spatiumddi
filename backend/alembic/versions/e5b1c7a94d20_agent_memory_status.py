"""Agent memory telemetry (#4193).

Adds ``memory_status`` (JSONB, the latest heartbeat ``memory`` block) to
``dns_server`` and ``dhcp_server``, and four nullable ``mem_*`` columns to
``dns_metric_sample`` / ``dhcp_metric_sample`` for a short history. All
nullable, no backfill: NULL means the agent never reported, which is unknown.

Revision ID: e5b1c7a94d20
Revises: a3c9e5d1b7f2
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "e5b1c7a94d20"
down_revision: str | None = "a3c9e5d1b7f2"
branch_labels: str | None = None
depends_on: str | None = None

_SAMPLES = ("dns_metric_sample", "dhcp_metric_sample")
_COLS = ("mem_used_bytes", "mem_peak_bytes", "mem_daemon_rss_bytes", "mem_agent_rss_bytes")


def upgrade() -> None:
    for table in ("dns_server", "dhcp_server"):
        op.add_column(table, sa.Column("memory_status", postgresql.JSONB(), nullable=True))
    for table in _SAMPLES:
        for col in _COLS:
            op.add_column(table, sa.Column(col, sa.BigInteger(), nullable=True))


def downgrade() -> None:
    for table in _SAMPLES:
        for col in _COLS:
            op.drop_column(table, col)
    for table in ("dns_server", "dhcp_server"):
        op.drop_column(table, "memory_status")
