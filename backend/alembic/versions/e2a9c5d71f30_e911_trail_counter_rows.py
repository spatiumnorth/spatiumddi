"""E911 lookup trail: per-caller per-minute counter rows (#3514).

Past the per-caller logging budget a HELD lookup is counted rather than
logged on its own row. The counter lives in ``e911_resolution_log`` itself,
so one query over the table still shows every lookup (individually, or as
"N lookups not individually logged"). Adds three nullable columns
(``caller_key``, ``window_start``, ``suppressed_count``), all NULL on the
existing rows, which are individual lookups; a CHECK that the three are
set together; and the partial unique index the upsert conflicts on.

Revision ID: e2a9c5d71f30
Revises: d8f3b6a41e52
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "e2a9c5d71f30"
down_revision: str | None = "d8f3b6a41e52"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("e911_resolution_log", sa.Column("caller_key", sa.String(64), nullable=True))
    op.add_column(
        "e911_resolution_log",
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("e911_resolution_log", sa.Column("suppressed_count", sa.Integer(), nullable=True))
    op.create_check_constraint(
        "ck_e911_res_log_suppressed_shape",
        "e911_resolution_log",
        "(caller_key IS NULL AND window_start IS NULL AND suppressed_count IS NULL)"
        " OR (caller_key IS NOT NULL AND window_start IS NOT NULL"
        " AND suppressed_count >= 1)",
    )
    op.create_index(
        "uq_e911_res_log_suppressed_window",
        "e911_resolution_log",
        ["caller_key", "window_start"],
        unique=True,
        postgresql_where=sa.text("caller_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_e911_res_log_suppressed_window", table_name="e911_resolution_log")
    op.drop_constraint("ck_e911_res_log_suppressed_shape", "e911_resolution_log", type_="check")
    op.drop_column("e911_resolution_log", "suppressed_count")
    op.drop_column("e911_resolution_log", "window_start")
    op.drop_column("e911_resolution_log", "caller_key")
