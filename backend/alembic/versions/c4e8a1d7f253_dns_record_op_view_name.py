"""dns_record_op: ``view_name`` names the view an op is queued for (#2242)

A group with views renders one copy of a zone per view that serves it, but an
op carried no view, so the queued-op sweep had to be name-scoped and a view's
op could not be told from its sibling's. The new nullable column holds the
view whose copy the op is for: the enqueue path writes one op per view that
renders the zone, and ``NULL`` in a flat group.

Nullable with no default and no backfill: ``NULL`` on every existing row means
"queued before views were recorded", which the sweep reads as the old
name-scoped match. Nothing reads the column for dispatch yet; ops queued under
views are still retired by the bundle build exactly as before.

Revision ID: c4e8a1d7f253
Revises: b6d2e9f41a07
Create Date: 2026-11-19 09:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c4e8a1d7f253"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dns_record_op", sa.Column("view_name", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_record_op", "view_name")
