"""appliance.roles_awaiting_key — surface a role held back for a missing agent key (#4646)

An appliance assigned a DNS / DHCP role whose agent key the control plane does
not have starts nothing: the supervisor does not render the role's DaemonSet
(it could only crash) and, until now, said so only in an info log, so the Fleet
row looked healthy.

This column carries the held-back role names from the supervisor heartbeat to
the Fleet UI. ``[]`` means nothing is waiting.

Revision ID: e4a91c7d52b3
Revises: e5a2c8d4f7b1
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "e4a91c7d52b3"
down_revision = "e5a2c8d4f7b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "appliance",
        sa.Column(
            "roles_awaiting_key",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("appliance", "roles_awaiting_key")
