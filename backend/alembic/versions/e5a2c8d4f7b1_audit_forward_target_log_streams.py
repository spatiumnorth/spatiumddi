"""audit_forward_target log streams (#4545)

Adds the per-target opt-in for forwarding the DNS query log and the DHCP
activity log, the filters and sampling that go with it, and the drop counter
the ``log_forward_dropping`` alert reads. Both stream flags default to false,
so no existing target starts forwarding client queries on upgrade.

Revision ID: e5a2c8d4f7b1
Revises: d8b3f6a1c274
Create Date: 2026-11-19 09:00:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e5a2c8d4f7b1"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "stream_dns_query_log", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "stream_dhcp_activity_log",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column("log_stream_filters", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "dns_query_sample_percent",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("100"),
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column(
            "log_stream_dropped_total",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "audit_forward_target",
        sa.Column("log_stream_last_drop_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_forward_target", "log_stream_last_drop_at")
    op.drop_column("audit_forward_target", "log_stream_dropped_total")
    op.drop_column("audit_forward_target", "dns_query_sample_percent")
    op.drop_column("audit_forward_target", "log_stream_filters")
    op.drop_column("audit_forward_target", "stream_dhcp_activity_log")
    op.drop_column("audit_forward_target", "stream_dns_query_log")
