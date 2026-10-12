"""Mark an appliance eviction that follows a graceful demote (#1541).

New column ``appliance.evict_after_demote`` (boolean, NOT NULL, default
false). A demoted member's ``left`` report hands its row to the seed's
eviction, which deletes the stale k8s Node and confirms etcd no longer lists
the member. That eviction used to be indistinguishable from a dead-node
Replace, so the seed armed #1059's CloudNativePG size hold on it and held
the control plane at its old size for good. The flag tells the seed which
evictions are a demote's cleanup.

No backfill: every eviction a pre-#1541 build stamped was a Replace, which
is what ``false`` means.

Revision ID: e3a81c5d07f2
Revises: a3d9e5c17b42
Create Date: 2026-10-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e3a81c5d07f2"
down_revision = "a3d9e5c17b42"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "appliance",
        sa.Column(
            "evict_after_demote",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("appliance", "evict_after_demote")
