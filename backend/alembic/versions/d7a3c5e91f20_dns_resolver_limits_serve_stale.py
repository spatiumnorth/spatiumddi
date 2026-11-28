"""DNS BIND9 recursive-clients + serve-stale options (#3567)

Adds four columns to ``dns_server_options``: ``recursive_clients``,
``serve_stale_enabled``, ``stale_answer_ttl`` and ``max_stale_ttl``. All are
no-ops by default (NULL / false), so existing groups render byte-identical
named.conf until an operator opts in.

Revision ID: d7a3c5e91f20
Revises: c4d8e1a7b9f2
Create Date: 2026-11-27 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d7a3c5e91f20"
down_revision: str | None = "c4d8e1a7b9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("dns_server_options", sa.Column("recursive_clients", sa.Integer(), nullable=True))
    op.add_column(
        "dns_server_options",
        sa.Column(
            "serve_stale_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column("dns_server_options", sa.Column("stale_answer_ttl", sa.Integer(), nullable=True))
    op.add_column("dns_server_options", sa.Column("max_stale_ttl", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_server_options", "max_stale_ttl")
    op.drop_column("dns_server_options", "stale_answer_ttl")
    op.drop_column("dns_server_options", "serve_stale_enabled")
    op.drop_column("dns_server_options", "recursive_clients")
