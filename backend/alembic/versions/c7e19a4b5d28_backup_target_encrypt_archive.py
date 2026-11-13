"""backup_target.encrypt_archive — whole-archive encryption (#1362)

Until now only ``secrets.enc`` was encrypted; the database dump next to it
was stored as is. This adds a per-target switch that encrypts the dump too
(AES-256-GCM, chunked, key derived from the target's own passphrase).

Defaults FALSE, so no existing target changes under a running schedule. The
API defaults it to TRUE for a target created after this lands.

Revision ID: c7e19a4b5d28
Revises: ede3bcd2aff4
Create Date: 2026-11-13
"""

from alembic import op
import sqlalchemy as sa

revision = "c7e19a4b5d28"
down_revision = "ede3bcd2aff4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "backup_target",
        sa.Column(
            "encrypt_archive",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("backup_target", "encrypt_archive")
