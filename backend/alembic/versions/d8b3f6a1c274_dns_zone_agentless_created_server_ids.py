"""dns_zone.agentless_created_server_ids (#1771)

Retiring an auto-generated reverse zone used to push ``delete`` to every
agentless server of the group, including one that already held a same-named
zone the operator made. This records, per zone, the servers where SpatiumDDI's
own create reported a change; the retire deletes only there. Existing zones
get NULL, which reads as "not created by SpatiumDDI": nothing is deleted at a
provider for them on a retire, and nothing is lost by that (a zone left behind
is visible, a zone deleted wrongly is not).

Revision ID: d8b3f6a1c274
Revises: c4e7a1d93b52
Create Date: 2026-11-18 10:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d8b3f6a1c274"
down_revision = "c4e7a1d93b52"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_zone",
        sa.Column("agentless_created_server_ids", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_zone", "agentless_created_server_ids")
