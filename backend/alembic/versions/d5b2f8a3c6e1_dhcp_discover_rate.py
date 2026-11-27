"""DHCP DISCOVER-rate readings per client MAC and per relay (#4737).

Revision ID: d5b2f8a3c6e1
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 09:00:00

The DHCP agent's opt-in DISCOVER watch ships the client MACs and relays whose
DISCOVER rate is above a floor. One row per ``(server, kind, subject)`` holds
the latest window; the ``dhcp_discover_flood`` alert rule reads them. Purely
additive: an agent that does not ship the stream simply leaves the table
empty, and the rule has no data to fire on.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d5b2f8a3c6e1"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dhcp_discover_rate",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dhcp_server.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("subject", sa.String(length=64), nullable=False),
        sa.Column("giaddr", postgresql.INET(), nullable=True),
        sa.Column("discovers", sa.Integer(), nullable=False),
        sa.Column("distinct_macs", sa.Integer(), nullable=True),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "modified_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("server_id", "kind", "subject", name="uq_dhcp_discover_rate_subject"),
    )
    op.create_index("ix_dhcp_discover_rate_window_end", "dhcp_discover_rate", ["window_end"])


def downgrade() -> None:
    op.drop_index("ix_dhcp_discover_rate_window_end", table_name="dhcp_discover_rate")
    op.drop_table("dhcp_discover_rate")
