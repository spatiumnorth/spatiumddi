"""Windows DHCP failover + per-server scope observation (#1110).

Two new tables and three nullable columns on ``dhcp_server``. Nothing is
backfilled: every row here is written by the topology poll from what a
Windows DHCP server reports, and an install upgrades into this with no
observations, which is exactly what it has.

* ``dhcp_failover_relationship`` — an observed mirror of
  ``Get-DhcpServerv4Failover``, one row per (observing server,
  relationship name). Both partners report the same relationship from
  their own side, and a relationship with an unregistered partner is only
  ever seen from one, so the rows are observations rather than a merged
  object. The shared secret is never read.
* ``dhcp_server_scope_state`` — which scopes each server actually holds,
  keyed by CIDR (a Windows scope whose subnet is not in IPAM has no
  ``dhcp_scope`` row and still counts). The group model assumes every
  member serves every scope; for Windows that is only safe under a
  failover relationship, so it has to be observed rather than assumed.
* ``dhcp_server.scopes_observed_at`` / ``failover_observed_at`` /
  ``failover_error`` — freshness per server instead of per row, so a poll
  that finds nothing changed writes one timestamp rather than every row.
  NULL means never observed — UNKNOWN, not "none".

Revision ID: 8e317fdd5b12
Revises: e3b9d7412c5a
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID

revision = "8e317fdd5b12"
down_revision = "e3b9d7412c5a"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    # TimestampMixin's func.now() only materialises through create_all; a
    # real install builds this table from the migration, so the default has
    # to be here or the first INSERT fails NOT NULL.
    return [
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
    ]


def upgrade() -> None:
    op.add_column(
        "dhcp_server",
        sa.Column("scopes_observed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "dhcp_server",
        sa.Column("failover_observed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("dhcp_server", sa.Column("failover_error", sa.Text(), nullable=True))

    op.create_table(
        "dhcp_failover_relationship",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "server_id",
            UUID(as_uuid=True),
            sa.ForeignKey("dhcp_server.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("partner_server", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("mode", sa.String(length=32), nullable=True),
        sa.Column("server_role", sa.String(length=32), nullable=True),
        sa.Column("state", sa.String(length=64), nullable=True),
        sa.Column("load_balance_percent", sa.Integer(), nullable=True),
        sa.Column("reserve_percent", sa.Integer(), nullable=True),
        sa.Column("max_client_lead_time_seconds", sa.Integer(), nullable=True),
        sa.Column("state_switch_interval_seconds", sa.Integer(), nullable=True),
        sa.Column("auto_state_transition", sa.Boolean(), nullable=True),
        sa.Column("enable_auth", sa.Boolean(), nullable=True),
        sa.Column(
            "scope_ids",
            JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        *_timestamps(),
        sa.UniqueConstraint(
            "server_id", "name", name="uq_dhcp_failover_relationship_server_name"
        ),
    )
    op.create_index(
        "ix_dhcp_failover_relationship_server_id",
        "dhcp_failover_relationship",
        ["server_id"],
    )

    op.create_table(
        "dhcp_server_scope_state",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "server_id",
            UUID(as_uuid=True),
            sa.ForeignKey("dhcp_server.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scope_cidr", CIDR(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("start_ip", INET(), nullable=True),
        sa.Column("end_ip", INET(), nullable=True),
        sa.Column(
            "exclusions",
            JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("config_hash", sa.String(length=64), nullable=False, server_default=""),
        *_timestamps(),
        sa.UniqueConstraint("server_id", "scope_cidr", name="uq_dhcp_server_scope_state"),
    )
    op.create_index(
        "ix_dhcp_server_scope_state_server_id",
        "dhcp_server_scope_state",
        ["server_id"],
    )
    op.create_index(
        "ix_dhcp_server_scope_state_cidr",
        "dhcp_server_scope_state",
        ["scope_cidr"],
    )


def downgrade() -> None:
    op.drop_index("ix_dhcp_server_scope_state_cidr", table_name="dhcp_server_scope_state")
    op.drop_index("ix_dhcp_server_scope_state_server_id", table_name="dhcp_server_scope_state")
    op.drop_table("dhcp_server_scope_state")
    op.drop_index(
        "ix_dhcp_failover_relationship_server_id",
        table_name="dhcp_failover_relationship",
    )
    op.drop_table("dhcp_failover_relationship")
    op.drop_column("dhcp_server", "failover_error")
    op.drop_column("dhcp_server", "failover_observed_at")
    op.drop_column("dhcp_server", "scopes_observed_at")
