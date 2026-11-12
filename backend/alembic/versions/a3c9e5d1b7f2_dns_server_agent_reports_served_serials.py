"""dns_server: add ``agent_reports_served_serials`` (#3940)

Set from ``X-Spatium-Agent-Features`` on an agent's register and heartbeat:
the BIND9 agent reads a secondary / stub zone's serial back from named
instead of reporting the bundle's 0. False for every existing row, so the
control plane keeps comparing an older agent's report with the target until
that agent says otherwise.

Revision ID: a3c9e5d1b7f2
Revises: ede3bcd2aff4
Create Date: 2026-11-12 15:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "a3c9e5d1b7f2"
down_revision = "ede3bcd2aff4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column(
            "agent_reports_served_serials",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("dns_server", "agent_reports_served_serials")
