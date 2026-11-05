"""Add ``dns_server.memory_limit_bytes`` (#3551).

The DNS agent reports its container's cgroup memory limit on the heartbeat,
so the control plane can compare a group's estimated named memory (zones
loaded once per distinct copy, each RPZ once per view that loads it) against
the limit it actually runs under. Nullable, no backfill: NULL means the
limit is unknown, never "unlimited".

Revision ID: d8f3a61c2e47
Revises: c4e8a2d6b917
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "d8f3a61c2e47"
down_revision: str | None = "c4e8a2d6b917"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("dns_server", sa.Column("memory_limit_bytes", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_server", "memory_limit_bytes")
