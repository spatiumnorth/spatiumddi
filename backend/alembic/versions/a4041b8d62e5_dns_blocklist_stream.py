"""Record which DNS agents read the blocklist stream, and store it (#4041).

A blocklist entry edit moved the whole config bundle's ETag, so every agent
re-fetched a bundle whose entries are most of its size. An agent that says it
reads the blocklist stream (``blocklist-stream`` in ``X-Spatium-Agent-Features``)
is sent a bundle without the entries and fetches them from their own versioned
document. ``agent_reads_blocklist_stream`` is what that agent's last register
or heartbeat said; ``dns_agent_bundle`` keeps the rendered stream beside the
bundle it belongs to. False / NULL for an agent of an older release, which keeps
the entries embedded.

Revision ID: a4041b8d62e5
Revises: d8b3f6a1c274
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "a4041b8d62e5"
down_revision: str | None = "d8b3f6a1c274"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column(
            "agent_reads_blocklist_stream",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "dns_agent_bundle",
        sa.Column("blocklist_stream", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("dns_agent_bundle", sa.Column("blocklist_etag", sa.String(128), nullable=True))
    op.add_column("dns_agent_bundle", sa.Column("blocklist_body", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("dns_agent_bundle", "blocklist_body")
    op.drop_column("dns_agent_bundle", "blocklist_etag")
    op.drop_column("dns_agent_bundle", "blocklist_stream")
    op.drop_column("dns_server", "agent_reads_blocklist_stream")
