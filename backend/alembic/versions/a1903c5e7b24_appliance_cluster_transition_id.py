"""appliance.cluster_transition_id — which promote a join report belongs to (#1903)

A node evicted by Replace whose box is still running keeps ``ready <seed>`` in
its cluster-join sidecar. Re-promoted against the same seed, it reported that
stale ``ready`` and the heartbeat settled it as a member with no join having
happened. The promote now stamps a fresh id; the supervisor echoes the id of the
join it actually fired, and the heartbeat accepts a terminal join verdict only
when the ids match.

Pure-additive nullable column. NULL means no promote has stamped one (every row
written before this migration), which the heartbeat treats as "nothing to match".

Revision ID: a1903c5e7b24
Revises: d9d0f6ddc446
Create Date: 2026-10-15

"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a1903c5e7b24"
down_revision = "d9d0f6ddc446"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "appliance",
        sa.Column("cluster_transition_id", sa.String(36), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("appliance", "cluster_transition_id")
