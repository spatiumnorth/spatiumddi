"""dhcp_server.last_sync_error — why the last scheduled lease pull failed (#2306)

Revision ID: e2b6f81d4a37
Revises: d3a7f19c52e8
Create Date: 2026-10-21 12:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "e2b6f81d4a37"
down_revision = "d3a7f19c52e8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dhcp_server", sa.Column("last_sync_error", sa.Text(), nullable=True))
    op.add_column(
        "dhcp_server",
        sa.Column("last_sync_error_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dhcp_server", "last_sync_error_at")
    op.drop_column("dhcp_server", "last_sync_error")
