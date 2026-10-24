"""platform_settings: metric and query-log retention become settings (#2273)

``prune_metrics`` already read ``metric_retention_days`` through ``getattr``
and always got ``None``, because the column never existed: metric samples were
kept for a hard-coded 7 days whatever the docs said. ``prune_logs`` kept DNS
query and DHCP activity logs for a hard-coded 24 hours. Both are now columns,
with server defaults equal to today's hard-coded values, so nothing changes
on upgrade until an operator edits them.

Revision ID: a3c7e91f2d58
Revises: e7b3d19a4c26
Create Date: 2026-10-23 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "a3c7e91f2d58"
down_revision = "e7b3d19a4c26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "platform_settings",
        sa.Column("metric_retention_days", sa.Integer(), nullable=False, server_default="7"),
    )
    op.add_column(
        "platform_settings",
        sa.Column("log_retention_hours", sa.Integer(), nullable=False, server_default="24"),
    )


def downgrade() -> None:
    op.drop_column("platform_settings", "log_retention_hours")
    op.drop_column("platform_settings", "metric_retention_days")
