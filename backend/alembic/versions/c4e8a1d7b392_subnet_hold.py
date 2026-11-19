"""subnet_hold table (#4492)

A CIDR set aside for a future project, with a reason, owner and expiry. No
subnet, placeholder addresses, reverse zone or DHCP scope is created; subnet
creation refuses overlapping space while the hold is active.

Revision ID: c4e8a1d7b392
Revises: b6d2e9f41a07
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c4e8a1d7b392"
down_revision: str | None = "b6d2e9f41a07"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "subnet_hold",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.Column("space_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("block_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("network", postgresql.CIDR(), nullable=False),
        sa.Column("reason", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("owner_group_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("customer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("converted_subnet_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["space_id"], ["ip_space.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["block_id"], ["ip_block.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["owner_group_id"], ["group.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["customer_id"], ["customer.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_subnet_hold_space_active",
        "subnet_hold",
        ["space_id"],
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index("ix_subnet_hold_expires_at", "subnet_hold", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_subnet_hold_expires_at", table_name="subnet_hold")
    op.drop_index("ix_subnet_hold_space_active", table_name="subnet_hold")
    op.drop_table("subnet_hold")
