"""Per-secondary zone refresh / expiry state (#4732).

Revision ID: d7b3a9f15c42
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00

Adds ``dns_secondary_zone_state``: one row per (server, zone) holding what a
secondary's own daemon reports about a zone it receives by transfer -- the
serial it holds, when the zone expires and is next due a refresh, and the SOA
timers it runs on. Every report column is nullable (NULL means the agent has
not reported it, never "healthy"); the rows cascade with the server and the
zone. The two ``dns_secondary_*`` alert rule types read it; their rules are
seeded at startup, disabled, not here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d7b3a9f15c42"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_secondary_zone_state",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("zone_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("serial", sa.BigInteger(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_refresh_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_loaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("soa_refresh", sa.Integer(), nullable=True),
        sa.Column("soa_retry", sa.Integer(), nullable=True),
        sa.Column("soa_expire", sa.Integer(), nullable=True),
        sa.Column(
            "reported_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
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
        sa.ForeignKeyConstraint(["server_id"], ["dns_server.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["zone_id"], ["dns_zone.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("server_id", "zone_id", name="uq_dns_secondary_zone_state"),
    )
    op.create_index(
        "ix_dns_secondary_zone_state_server_id", "dns_secondary_zone_state", ["server_id"]
    )
    op.create_index("ix_dns_secondary_zone_state_zone", "dns_secondary_zone_state", ["zone_id"])


def downgrade() -> None:
    op.drop_index("ix_dns_secondary_zone_state_zone", table_name="dns_secondary_zone_state")
    op.drop_index("ix_dns_secondary_zone_state_server_id", table_name="dns_secondary_zone_state")
    op.drop_table("dns_secondary_zone_state")
