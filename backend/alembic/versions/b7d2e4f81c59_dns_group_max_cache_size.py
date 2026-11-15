"""dns_server_group: add ``max_cache_size`` (#4185)

Optional per-group ``max-cache-size`` for the BIND9 resolver cache (a BIND
size such as ``128m``). NULL keeps the agent's own default (the
``NAMED_MAX_CACHE_SIZE`` env override, else a quarter of the container's
memory limit split across recursive views), so existing groups render exactly
as before.

Revision ID: b7d2e4f81c59
Revises: e5b1c7a94d20
Create Date: 2026-11-14 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "b7d2e4f81c59"
down_revision = "e5b1c7a94d20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dns_server_group",
        sa.Column("max_cache_size", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("dns_server_group", "max_cache_size")
