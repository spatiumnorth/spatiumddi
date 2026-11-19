"""dhcp_scope: hostname_to_ipam_sync now takes effect; keep today's behaviour (#2269)

``hostname_to_ipam_sync`` was stored and never read: every lease's hostname
reached IPAM whatever the scope said. It is honoured now, and its default
``on_static_only`` would silently strip lease hostnames from IPAM on every
existing scope. The setting never did anything, so ``on_static_only`` on a
stored row means "never chosen" as often as "chosen": rewrite it to
``on_lease`` (what those scopes have always done) and move the column's
server default with it. ``disabled`` is left alone — that one was a
deliberate choice, and is now honoured. The downgrade restores the old
column default only; rewritten rows cannot be told apart afterwards.

Revision ID: e7b3d19a4c26
Revises: e2b6f81d4a37
Create Date: 2026-10-21 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "e7b3d19a4c26"
down_revision = "e2b6f81d4a37"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE dhcp_scope SET hostname_to_ipam_sync = 'on_lease' "
            "WHERE hostname_to_ipam_sync = 'on_static_only'"
        )
    )
    op.alter_column("dhcp_scope", "hostname_to_ipam_sync", server_default="on_lease")


def downgrade() -> None:
    op.alter_column("dhcp_scope", "hostname_to_ipam_sync", server_default="on_static_only")
