"""dns_query_log_entry: ``answer_source`` / ``answer_upstream`` (#4251)

How the server produced an answer (``authoritative`` / ``cache`` /
``forwarded`` / ``recursion``) and, where the flavor names it, the upstream
resolver. Both are nullable with no backfill: NULL means the server's log did
not say, and existing rows never reported anything.

Revision ID: c7e3a91d5b24
Revises: d8b3f6a1c274
Create Date: 2026-11-18 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c7e3a91d5b24"
down_revision = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_query_log_entry", sa.Column("answer_source", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "dns_query_log_entry", sa.Column("answer_upstream", sa.String(length=64), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("dns_query_log_entry", "answer_upstream")
    op.drop_column("dns_query_log_entry", "answer_source")
