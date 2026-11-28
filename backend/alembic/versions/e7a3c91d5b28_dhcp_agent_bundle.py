"""Stored DHCP agent config bundles (#1111).

One table and one column, both additive; no backfill. An install upgrades into
this with no bundle stored for any server, which is also what every existing
row means: the long-poll then holds briefly for the worker's render and builds
inline once if none arrives, so an agent is never left without config.

``dhcp_agent_bundle`` holds one row per agent-based DHCP server: the agent's
wire ``bundle`` object as compact JSON text plus the driver bundle's ETag.
``dhcp_server.bundle_dirty_seq`` is bumped in the transaction of every change
that feeds a bundle; the stored row records the value it was rendered at, so
"current" is one integer comparison (the DNS design, ``c4d1e7f90a2b``).

Revision ID: e7a3c91d5b28
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "e7a3c91d5b28"
down_revision = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dhcp_agent_bundle",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "server_id",
            UUID(as_uuid=True),
            sa.ForeignKey("dhcp_server.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("dirty_watermark", sa.BigInteger(), nullable=False),
        sa.Column("renderer_revision", sa.Integer(), nullable=False),
        sa.Column("bundle_etag", sa.String(128), nullable=False),
        sa.Column("has_failover", sa.Boolean(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("rendered_by", sa.String(16), nullable=False),
        sa.Column("render_ms", sa.Integer(), nullable=False),
        sa.Column(
            "built_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("server_id", name="uq_dhcp_agent_bundle_server"),
    )
    op.add_column(
        "dhcp_server",
        sa.Column("bundle_dirty_seq", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("dhcp_server", "bundle_dirty_seq")
    op.drop_table("dhcp_agent_bundle")
