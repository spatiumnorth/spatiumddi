"""DNS views: per-view default forwarders (#3523)

Adds ``dns_view.forwarders`` / ``forward_policy`` / ``forward_transport`` /
``forward_tls_hostname``. A view with no forwarders inherits the group's, which
is what every existing row does, so every rendered config is unchanged.

Revision ID: c4d8a1f6b329
Revises: ede3bcd2aff4
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "c4d8a1f6b329"
down_revision = "ede3bcd2aff4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_view",
        sa.Column("forwarders", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("dns_view", sa.Column("forward_policy", sa.String(length=20), nullable=True))
    op.add_column(
        "dns_view",
        sa.Column(
            "forward_transport",
            sa.String(length=10),
            nullable=False,
            server_default="do53",
        ),
    )
    op.add_column(
        "dns_view",
        sa.Column("forward_tls_hostname", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_view", "forward_tls_hostname")
    op.drop_column("dns_view", "forward_transport")
    op.drop_column("dns_view", "forward_policy")
    op.drop_column("dns_view", "forwarders")
