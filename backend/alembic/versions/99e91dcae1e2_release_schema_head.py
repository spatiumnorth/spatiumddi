"""release_schema_head: the schema head each release ran at (#1227).

One new table, no seed. Each release inserts its own row on startup once the
schema is at its head, so a slot rollback or a per-box downgrade can tell
whether the release it is going back to can run on this database. Releases
older than this table are answered from ``app/data/release_schema_heads.json``.

Revision ID: 99e91dcae1e2
Revises: d8e1b5a26c47
Create Date: 2026-09-29
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "99e91dcae1e2"
down_revision = "d8e1b5a26c47"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "release_schema_head",
        sa.Column("version", sa.String(length=64), primary_key=True),
        sa.Column("alembic_head", sa.String(length=64), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("release_schema_head")
