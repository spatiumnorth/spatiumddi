"""dns_server.zone_resync_pending_since: a re-enable's owed re-render (#2654)

Re-enabling an agent DNS server forces its agent to re-render every zone from
the database (#2281). For a BIND9 / PowerDNS agent in a group with dynamic
zones, that re-render now waits until the server has reported each dynamic
zone through the DDNS ingest-back loop, or 7 minutes have passed. Otherwise
it would replace each zone with the database's copy and drop records an
RFC 2136 writer added on the server while it was disabled, before the report
could mirror them. This column records that a re-render is owed. NULL means
nothing is owed, which is every existing row, so there is no backfill.

Revision ID: c34ff60a954f
Revises: c3f8a2d61e94
Create Date: 2026-10-26 18:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c34ff60a954f"
down_revision = "c3f8a2d61e94"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column("zone_resync_pending_since", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_server", "zone_resync_pending_since")
