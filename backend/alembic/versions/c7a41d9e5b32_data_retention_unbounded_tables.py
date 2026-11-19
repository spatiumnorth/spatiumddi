"""Retention windows for the tables that grew forever (#2274).

Nine columns on ``platform_settings``, one per window the new
``prune_unbounded_tables`` sweep reads. Each carries the default the issue
names as a server default, so an existing install starts pruning on the
next nightly run with those windows; 0 turns a window off (keep forever).

Revision ID: c7a41d9e5b32
Revises: b6d2e9f41a07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "c7a41d9e5b32"
down_revision: str | None = "b6d2e9f41a07"
branch_labels: str | None = None
depends_on: str | None = None

_COLUMNS: tuple[tuple[str, int], ...] = (
    ("alert_event_retention_days", 180),
    ("ip_mac_history_retention_days", 365),
    ("nmap_scan_retention_days", 90),
    ("conformity_result_retention_days", 365),
    ("event_outbox_retention_days", 7),
    ("user_session_retention_days", 30),
    ("ai_chat_retention_days", 90),
    ("change_request_retention_days", 365),
    ("run_log_retention_days", 90),
)


def upgrade() -> None:
    for name, default in _COLUMNS:
        op.add_column(
            "platform_settings",
            sa.Column(name, sa.Integer(), nullable=False, server_default=sa.text(str(default))),
        )


def downgrade() -> None:
    for name, _ in reversed(_COLUMNS):
        op.drop_column("platform_settings", name)
