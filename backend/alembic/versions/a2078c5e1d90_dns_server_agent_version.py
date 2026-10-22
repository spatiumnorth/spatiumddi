"""Record the DNS agent's own version on dns_server (#2078)

``dns_server`` had a ``daemon_version`` (the BIND / PowerDNS binary, #638) but
nothing for the python agent: the heartbeat accepted ``agent_version`` and
dropped it, and the only trace of the version was a note seeded once at
registration, never refreshed. ``dhcp_server.agent_version`` has existed all
along; this is its DNS counterpart.

Nullable, no backfill: a row registered before this revision never reported a
version into a column, and guessing one would assert something the row never
said. NULL means UNKNOWN until the agent's next register or heartbeat.

Revision ID: a2078c5e1d90
Revises: c7d2e9a41f63
Create Date: 2026-10-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "a2078c5e1d90"
down_revision: str | None = "c7d2e9a41f63"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column("agent_version", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_server", "agent_version")
