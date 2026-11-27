"""Scheduled DNS record changes (#4830).

Revision ID: d5b2f8a1c3e7
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00

Adds ``dns_scheduled_change``: a record create / update / delete held until a
set time. The beat sweep claims due rows and replays each through the normal
record write path. Rows cascade with their zone; ``record_id`` is set NULL when
the record is purged.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d5b2f8a1c3e7"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_scheduled_change",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "modified_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "zone_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dns_zone.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "record_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dns_record.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(10), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("record_label", sa.String(600), nullable=False),
        sa.Column("base_fingerprint", sa.String(64), nullable=True),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(10), server_default="pending", nullable=False),
        sa.Column("result_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_display", sa.String(255), nullable=False),
    )
    op.create_index("ix_dns_scheduled_change_zone_id", "dns_scheduled_change", ["zone_id"])
    op.create_index("ix_dns_scheduled_change_record_id", "dns_scheduled_change", ["record_id"])
    op.create_index(
        "ix_dns_scheduled_change_state_due", "dns_scheduled_change", ["state", "scheduled_at"]
    )


def downgrade() -> None:
    op.drop_table("dns_scheduled_change")
