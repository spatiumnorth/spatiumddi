"""dns_blocklist: last_success_at, the last refresh that actually succeeded (#2313)

``last_synced_at`` is stamped on a failed fetch too (so a broken feed is
retried on its own interval, not on every sweep), which means it cannot say
how long a feed has been failing. ``last_success_at`` moves only on success.
Backfilled from the rows whose last attempt succeeded; a row whose last
attempt failed stays NULL, because nothing recorded when it last worked.

Revision ID: c4a8e2f7b913
Revises: e7b3d19a4c26
Create Date: 2026-10-23 09:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c4a8e2f7b913"
down_revision = "e7b3d19a4c26"
branch_labels = None
depends_on = None


BACKFILL_SQL = (
    "UPDATE dns_blocklist SET last_success_at = last_synced_at "
    "WHERE last_sync_status = 'success'"
)


def upgrade() -> None:
    op.add_column(
        "dns_blocklist",
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(sa.text(BACKFILL_SQL))


def downgrade() -> None:
    op.drop_column("dns_blocklist", "last_success_at")
