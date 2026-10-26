"""dns_ingest_snapshot: each agent's last external-record report per zone (#2654)

The DDNS ingest-back reconcile (#641) treated a dynamic zone as one record
set for the whole group, so in a group with two agent servers the server the
writer did not talk to reported the record missing and the mirror row was
deleted, then re-added by the next report from the other server, forever.
The reconcile now acts on what changed on a server since its previous report,
and this table holds that previous report: one row per (server, zone) with
the external (name, type, value) keys the server held. Rows are replaced on
every report and cascade with their server and zone. No backfill: a server
with no row is compared against nothing, which only ever adds.

It also adds ``dns_server.zone_resync_pending_since``: a re-enabled server's
#2281 forced re-render now waits until that server has reported its dynamic
zones, so records a writer added on it while it was disabled are mirrored
before the re-render would replace them with the database's copy.

Revision ID: c3f8a2d61e94
Revises: c4a8e2f7b913
Create Date: 2026-10-24 09:00:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c3f8a2d61e94"
down_revision = "c4a8e2f7b913"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_ingest_snapshot",
        sa.Column(
            "server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dns_server.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "zone_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dns_zone.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "record_keys",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "reported_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_dns_ingest_snapshot_zone_id", "dns_ingest_snapshot", ["zone_id"], unique=False
    )
    # A re-enabled server's forced re-render waits for its ingest report.
    op.add_column(
        "dns_server",
        sa.Column("zone_resync_pending_since", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_server", "zone_resync_pending_since")
    op.drop_index("ix_dns_ingest_snapshot_zone_id", table_name="dns_ingest_snapshot")
    op.drop_table("dns_ingest_snapshot")
