"""#2941 — ``user_session.rotated_at`` + ``rotated_to_id``: refresh-rotation grace.

Two nullable columns, written only by ``/auth/refresh`` when it rotates a
session away. They record that the row was revoked BY A ROTATION, and into
which successor, which is what lets the short grace window in
``app.core.session_rotation`` apply to rotations and to nothing else: a
logout, a force-logout or a password change revokes a row without them and
is refused at once.

No backfill: rows rotated before this migration carry no successor and so
get no grace, which is exactly the behaviour they had. No foreign key on
``rotated_to_id`` (a successor that is gone is simply not found) and so no
index: the column is only ever read by primary key from the row holding it.

Revision ID: c4f81e2a9d37
Revises: b7d2e4f91a08
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c4f81e2a9d37"
down_revision: str | None = "b7d2e4f91a08"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "user_session",
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "user_session",
        sa.Column("rotated_to_id", postgresql.UUID(as_uuid=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_session", "rotated_to_id")
    op.drop_column("user_session", "rotated_at")
