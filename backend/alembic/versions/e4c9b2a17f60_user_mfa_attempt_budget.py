"""user: per-account wrong-code budget for the MFA sign-in step

Adds two columns to ``user`` that count wrong second-factor answers at
``/auth/login/mfa``, independent of the account-lockout setting:

* ``mfa_failed_count`` — wrong codes inside the current window, reset on
  a successful sign-in or an admin unlock.
* ``mfa_last_failed_at`` — the newest counted failure; the window is
  measured from it.

Kept on the row rather than in Redis so the budget still holds when
Redis is unavailable.

Revision ID: e4c9b2a17f60
Revises: f4c2a8e61b93
Create Date: 2026-10-21 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "e4c9b2a17f60"
down_revision = "f4c2a8e61b93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column(
            "mfa_failed_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "user",
        sa.Column("mfa_last_failed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user", "mfa_last_failed_at")
    op.drop_column("user", "mfa_failed_count")
