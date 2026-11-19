"""dns_server: add ``zone_resync_seq`` (#2281)

Bumped when an agent-based DNS server is re-enabled, and folded into that
server's structural etag when non-zero, so its agent re-renders every zone
and picks up the record changes made while the server was disabled. Zero
for every existing row, which adds nothing to the fingerprint, so no
installed agent re-renders because of this migration.

Revision ID: e4b8c27d91f3
Revises: e7b3d19a4c26
Create Date: 2026-10-21 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "e4b8c27d91f3"
down_revision = "e7b3d19a4c26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column("zone_resync_seq", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    op.drop_column("dns_server", "zone_resync_seq")
