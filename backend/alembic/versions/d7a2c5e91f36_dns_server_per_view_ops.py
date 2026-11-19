"""Record which DNS agents apply a record op into the view it names (#2242).

A group with views could not ship record ops: an RFC 2136 update to loopback
lands in whichever view matches ``127.0.0.1``. An agent that signs each op with
the key of the view the op names (``per-view-ops`` in
``X-Spatium-Agent-Features``) can take them, and only for such an agent does the
control plane stop folding records into the structural payload and ship the ops.
``agent_per_view_ops`` is what the last register, heartbeat or poll said. False
for an agent of an older release, which keeps today's re-render path.

Revision ID: d7a2c5e91f36
Revises: c4e8a1d7f253
Create Date: 2026-11-19 12:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "d7a2c5e91f36"
down_revision = "c4e8a1d7f253"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column(
            "agent_per_view_ops",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("dns_server", "agent_per_view_ops")
