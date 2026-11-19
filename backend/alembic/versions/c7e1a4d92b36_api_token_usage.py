"""api_token: per-day call counts and the last client address (#4491)

Adds ``api_token.last_client_ip`` and ``api_token_usage_daily`` (one row per
token per UTC day, kept 90 days) so operators can find tokens that are idle
or never used. Both are additive; a not-yet-upgraded api pod ignores them.

Revision ID: c7e1a4d92b36
Revises: b6d2e9f41a07
Create Date: 2026-11-19 10:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c7e1a4d92b36"
down_revision = "b6d2e9f41a07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("api_token", sa.Column("last_client_ip", sa.String(45), nullable=True))
    op.create_table(
        "api_token_usage_daily",
        sa.Column(
            "token_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("api_token.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("day", sa.Date(), primary_key=True),
        sa.Column("calls", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_api_token_usage_daily_day", "api_token_usage_daily", ["day"])


def downgrade() -> None:
    op.drop_index("ix_api_token_usage_daily_day", table_name="api_token_usage_daily")
    op.drop_table("api_token_usage_daily")
    op.drop_column("api_token", "last_client_ip")
