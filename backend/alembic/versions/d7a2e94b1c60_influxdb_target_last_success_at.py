"""influxdb_target.last_success_at (#1990)

``last_push_at`` is the last ATTEMPT: a failed push moves it on purpose, so a
target that errors fast keeps to its own interval instead of being retried on
every 30 s beat tick. The Settings table presented it as the last push, so a
target that had never delivered a point read "31m ago (0 pts)".

``last_success_at`` records the last push that was accepted. NULL means never.
``last_push_points`` is only written on success, so it is already the count for
that push.

Backfill: a row with a push time and no recorded error last succeeded at that
time. A row whose last attempt failed is left NULL, since an earlier success is
not recoverable and "never" would be less honest than unknown, but the old
column never said otherwise either.

Revision ID: d7a2e94b1c60
Revises: a9c3e5f71b28
Create Date: 2026-10-16

"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d7a2e94b1c60"
down_revision = "a9c3e5f71b28"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "influxdb_target",
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE influxdb_target SET last_success_at = last_push_at "
        "WHERE last_push_at IS NOT NULL AND last_push_error IS NULL"
    )


def downgrade() -> None:
    op.drop_column("influxdb_target", "last_success_at")
