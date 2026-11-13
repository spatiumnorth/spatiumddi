"""Add ``pairing_attempt``: refused supervisor registrations (#2225).

The register endpoint answers every refusal with one generic 403, so Fleet
could not say that a second appliance was turned away by a single-use code.
This table keeps one grouped row per (code, hostname, reason) for the
superadmin pairing tab. ``pairing_code_id`` is NULL when the submitted code
matched nothing; it cascades with the code.

Revision ID: f4c1a7d92e68
Revises: ede3bcd2aff4
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "f4c1a7d92e68"
down_revision: str | None = "ede3bcd2aff4"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "pairing_attempt",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")
        ),
        sa.Column(
            "pairing_code_id",
            UUID(as_uuid=True),
            sa.ForeignKey("pairing_code.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("reason", sa.String(32), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "first_attempted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "last_attempted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_pairing_attempt_pairing_code_id", "pairing_attempt", ["pairing_code_id"])
    op.create_index("ix_pairing_attempt_last_attempted_at", "pairing_attempt", ["last_attempted_at"])


def downgrade() -> None:
    op.drop_index("ix_pairing_attempt_last_attempted_at", table_name="pairing_attempt")
    op.drop_index("ix_pairing_attempt_pairing_code_id", table_name="pairing_attempt")
    op.drop_table("pairing_attempt")
