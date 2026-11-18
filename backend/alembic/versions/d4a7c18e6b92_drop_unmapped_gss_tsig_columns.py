"""dns_server_options: drop the unmapped ``gss_tsig_*`` columns (#3592)

The contract step of #3561. That release stopped mapping the four GSS-TSIG
columns (``gss_tsig_enabled``, ``gss_tsig_keytab_path``, ``gss_tsig_realm``,
``gss_tsig_principal``) because nothing ever rendered them, and left them in
the database for one release so a rolling upgrade's old api pods, which still
mapped them, kept passing ``/health/ready``. This migration drops them.

A selective restore of an archive taken before this drop re-adds them for its
``COPY`` and drops them again afterwards
(``app.services.backup.legacy_columns``).

``downgrade`` re-adds the columns in the shape ``4c9e1f82a3b7`` created them
(empty; the dropped values are not recoverable).

Revision ID: d4a7c18e6b92
Revises: b6d2e9f41a07
Create Date: 2026-11-18 10:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "d4a7c18e6b92"
down_revision = "b6d2e9f41a07"
branch_labels = None
depends_on = None

_TABLE = "dns_server_options"
_COLUMNS = (
    "gss_tsig_enabled",
    "gss_tsig_keytab_path",
    "gss_tsig_realm",
    "gss_tsig_principal",
)


def _existing(conn: sa.engine.Connection) -> set[str]:
    return {c["name"] for c in sa.inspect(conn).get_columns(_TABLE)}


def upgrade() -> None:
    present = _existing(op.get_bind())
    for column in _COLUMNS:
        if column in present:
            op.drop_column(_TABLE, column)


def downgrade() -> None:
    present = _existing(op.get_bind())
    adds = (
        sa.Column("gss_tsig_enabled", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("gss_tsig_keytab_path", sa.String(500), nullable=True),
        sa.Column("gss_tsig_realm", sa.String(255), nullable=True),
        sa.Column("gss_tsig_principal", sa.String(500), nullable=True),
    )
    for col in adds:
        if col.name not in present:
            op.add_column(_TABLE, col)
