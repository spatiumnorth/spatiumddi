"""Record which DNS agents read packed blocklist entries (#4040).

A bundle carried every blocklist entry as its own JSON object, ~108 bytes
each: 69 MB for three common lists, which the agent then parsed whole. A
server whose agent says it reads the packed shape (``packed-blocklists`` in
``X-Spatium-Agent-Features``) is sent the entries as gzip + base64 runs of
domains instead. ``agent_renders_packed_blocklists`` is what that last
register or heartbeat said, so the worker that renders the stored bundle
knows which shape this server's agent can read. False for an agent of an
older release, which keeps the per-entry objects.

Revision ID: a4040c7e91d3
Revises: ede3bcd2aff4
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "a4040c7e91d3"
down_revision: str | None = "ede3bcd2aff4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server",
        sa.Column(
            "agent_renders_packed_blocklists",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


    op.add_column(
        "dns_agent_bundle",
        sa.Column(
            "packed_blocklists",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("dns_agent_bundle", "packed_blocklists")
    op.drop_column("dns_server", "agent_renders_packed_blocklists")
