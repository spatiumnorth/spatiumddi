"""Issue #1261 — postgres_synchronous on platform_settings.

The operator's opt-in synchronous-replication setting for the appliance's
CloudNativePG cluster: ``{enabled, method, number, data_durability}``. The
seed supervisor renders it into ``postgresql.cnpg.synchronous`` of the
spatium-control HelmChartConfig. ``{}`` (the default) means unset, which is
asynchronous replication exactly as before, so this is purely additive.

Revision ID: d4a8c27e91f3
Revises: d8b3f6a1c274
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "d4a8c27e91f3"
down_revision: str | None = "d8b3f6a1c274"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "platform_settings",
        sa.Column(
            "postgres_synchronous",
            JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("platform_settings", "postgres_synchronous")
