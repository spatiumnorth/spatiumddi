"""dns zone master_options + group allow_transfer_tls_only (#3568)

Revision ID: d3568a7f1c42
Revises: b6d2e9f41a07
Create Date: 2026-11-18 00:00:00.000000

Adds ``dns_zone.master_options`` — per-primary TSIG key name and TLS
certificate hostname for a secondary / stub zone, keyed by the ``masters``
entry — and ``dns_server_options.allow_transfer_tls_only``, which renders the
group's ``allow-transfer`` with ``transport tls`` (XFR-over-TLS). Both default
to a no-op, so an existing install renders the same named.conf.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d3568a7f1c42"
down_revision: str | None = "b6d2e9f41a07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "dns_zone",
        sa.Column(
            "master_options",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "dns_server_options",
        sa.Column(
            "allow_transfer_tls_only",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("dns_server_options", "allow_transfer_tls_only")
    op.drop_column("dns_zone", "master_options")
