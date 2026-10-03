"""appliance.reboot_requested_boot_id — retire a reboot request on proof (#1446)

The control plane cleared ``reboot_requested`` 15 s after the stamp, which
could happen before the supervisor's next heartbeat ever delivered it. The
request is now retired when a heartbeat arrives from a different boot than
the one recorded here. Nullable, no backfill: NULL means "not recorded yet",
which the heartbeat handler fills from the next heartbeat.

Revision ID: 199eb1562927
Revises: 5e6d56b39ab7
Create Date: 2026-10-03
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "199eb1562927"
down_revision = "5e6d56b39ab7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "appliance",
        sa.Column("reboot_requested_boot_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("appliance", "reboot_requested_boot_id")
