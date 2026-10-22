"""subnet.show_free_ranges — per-subnet toggle for the free-range rows (#2137).

Revision ID: c4a8e1f26d93
Revises: e3b7c19f5a42
Create Date: 2026-10-18 00:00:00

Nullable on purpose: NULL means "use the default" (off for an
integration-owned subnet or one larger than a /16, on otherwise), so
existing rows need no backfill and the default rule can change later.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c4a8e1f26d93"
down_revision: str | None = "e3b7c19f5a42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("subnet", sa.Column("show_free_ranges", sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column("subnet", "show_free_ranges")
