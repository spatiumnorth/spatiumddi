"""dhcp_server: ``applied_subnet_ids`` (#3790)

A Kea HA member applies a subnet-only change in memory, one subnet at a time,
and must never carry a subnet its partner lacks. Each agent reports the Kea
subnet ids it has applied on its heartbeat; the control plane stores them here
and hands each member its partner's set in the bundle.

NULL means the agent has not reported one (an older agent, or no apply yet).
It is UNKNOWN, never "no subnets".

Revision ID: d4a7c2e9f1b3
Revises: d8b3f6a1c274
Create Date: 2026-11-19 12:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d4a7c2e9f1b3"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dhcp_server",
        sa.Column("applied_subnet_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dhcp_server", "applied_subnet_ids")
