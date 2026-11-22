"""dhcp_client_class.match_spec (#54)

A client class built from the structured relay-agent (option 82) match keeps
the operator's spec here, and ``match_expression`` keeps the Kea test compiled
from it, so the bundle, the agent and the ETag see no new field. Every existing
class gets NULL, which reads as "hand-written expression": nothing is rewritten.

Revision ID: e5a1c8d27f43
Revises: d8b3f6a1c274
Create Date: 2026-11-21 10:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e5a1c8d27f43"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dhcp_client_class",
        sa.Column("match_spec", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dhcp_client_class", "match_spec")
