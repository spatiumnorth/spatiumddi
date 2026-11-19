"""subnet: store the skip_reverse_zone opt-out (#2735)

``POST /ipam/subnets`` accepted ``skip_reverse_zone`` and consumed it on the
spot, so the opt-out lasted until the first named address, whose record sync
runs the reverse-zone catch-up and created the zone anyway. The flag is now a
column the catch-up, a resize and the bulk backfills read.

No backfill: nothing records which existing subnets opted out, and false is
today's behaviour for all of them.

Revision ID: c6d2e84f1a97
Revises: c3a8f5e12d94
Create Date: 2026-10-24 12:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c6d2e84f1a97"
down_revision = "c3a8f5e12d94"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "subnet",
        sa.Column(
            "skip_reverse_zone",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("subnet", "skip_reverse_zone")
