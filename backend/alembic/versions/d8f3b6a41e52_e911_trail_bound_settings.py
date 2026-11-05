"""E911 lookup-trail bounds as platform settings (#3514).

Two columns on ``platform_settings``: the per-caller budget of logged
``POST /held`` lookups per minute (default 120) and how many days the
``prune_e911_resolution_log`` sweep keeps ``e911_resolution_log`` rows
(default 90). Both carry server defaults, so an existing install gets the
values the constants used to have.

Revision ID: d8f3b6a41e52
Revises: c4e8a2d6b917
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "d8f3b6a41e52"
down_revision: str | None = "c4e8a2d6b917"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "platform_settings",
        sa.Column(
            "e911_lookup_log_budget_per_minute",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("120"),
        ),
    )
    op.add_column(
        "platform_settings",
        sa.Column(
            "e911_resolution_log_retention_days",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("90"),
        ),
    )


def downgrade() -> None:
    op.drop_column("platform_settings", "e911_resolution_log_retention_days")
    op.drop_column("platform_settings", "e911_lookup_log_budget_per_minute")
