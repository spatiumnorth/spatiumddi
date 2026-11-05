"""Drop the four unrendered ``gss_tsig_*`` columns from dns_server_options (#3561).

``gss_tsig_enabled`` / ``_keytab_path`` / ``_realm`` / ``_principal`` were
accepted, stored and returned by the API, and nothing ever rendered them:
neither the agent's named.conf renderer nor the control-plane template knew
the names, so enabling GSS-TSIG changed no behaviour. Real GSS-TSIG is
tracked in #1128 (and #444). The downgrade re-adds the columns with their
original shape (the boolean keeps its ``false`` default so existing rows
satisfy NOT NULL); the dropped values are not recoverable.

Revision ID: d5a1f3c7e208
Revises: c4e8a2d6b917
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "d5a1f3c7e208"
down_revision: str | None = "c4e8a2d6b917"
branch_labels = None
depends_on = None

_COLUMNS = ("gss_tsig_enabled", "gss_tsig_keytab_path", "gss_tsig_realm", "gss_tsig_principal")


def upgrade() -> None:
    for col in _COLUMNS:
        op.drop_column("dns_server_options", col)


def downgrade() -> None:
    op.add_column(
        "dns_server_options",
        sa.Column("gss_tsig_enabled", sa.Boolean, nullable=False, server_default="false"),
    )
    op.add_column("dns_server_options", sa.Column("gss_tsig_keytab_path", sa.String(500)))
    op.add_column("dns_server_options", sa.Column("gss_tsig_realm", sa.String(255)))
    op.add_column("dns_server_options", sa.Column("gss_tsig_principal", sa.String(500)))
