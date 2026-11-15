"""A server delete keeps client history, and runs in a worker (#4173)

Deleting a DNS server cascaded its query log, RPZ hits and metrics inside the
HTTP request: a minute-plus on a 1.2M-row log, and it erased what clients had
asked. This migration prepares the other behaviour; the code does the rest.

* ``dns_query_log_entry`` and ``dns_rpz_hit``: ``server_id`` becomes nullable
  and its foreign key ``ON DELETE SET NULL``; new nullable ``server_name`` so
  a row stays attributable once the id is gone. Same for ``dhcp_log_entry``.
  The new constraints are added ``NOT VALID`` and validated afterwards, which
  takes a lighter lock than a validating ``ADD CONSTRAINT`` over a big table.
  Existing rows get no ``server_name``: the server's own delete stamps it, and
  a reader shows "deleted server" for a row that has neither.
* ``ix_dns_rpz_hit_server_id``: ``dns_rpz_hit.server_id`` was the only
  server foreign key without an index, so each server delete scanned the table.
* ``dns_server.removing_at``: set when a delete was requested; the worker task
  removes the operational rows in batches and the row last.

``dns_metric_sample`` keeps ``ON DELETE CASCADE``: ``server_id`` is part of its
primary key, and it holds counters, not client history.

Revision ID: c4e7a1d93b52
Revises: b6d2e9f41a07
Create Date: 2026-11-14 12:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "c4e7a1d93b52"
down_revision = "b6d2e9f41a07"
branch_labels = None
depends_on = None

# (table, referenced table, constraint name Postgres gave the original FK)
_HISTORY = (
    ("dns_query_log_entry", "dns_server"),
    ("dns_rpz_hit", "dns_server"),
    ("dhcp_log_entry", "dhcp_server"),
)


def _fk(table: str, parent: str, ondelete: str) -> None:
    name = f"{table}_server_id_fkey"
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
    op.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT {name} FOREIGN KEY (server_id) "
        f"REFERENCES {parent} (id) ON DELETE {ondelete} NOT VALID"
    )
    op.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {name}")


def upgrade() -> None:
    op.add_column("dns_server", sa.Column("removing_at", sa.DateTime(timezone=True), nullable=True))
    for table, parent in _HISTORY:
        op.add_column(table, sa.Column("server_name", sa.String(length=255), nullable=True))
        op.alter_column(table, "server_id", nullable=True)
        _fk(table, parent, "SET NULL")
    op.create_index("ix_dns_rpz_hit_server_id", "dns_rpz_hit", ["server_id"])


def downgrade() -> None:
    op.drop_index("ix_dns_rpz_hit_server_id", table_name="dns_rpz_hit")
    for table, parent in _HISTORY:
        # Rows detached by a server delete have no server to point at again.
        op.execute(f"DELETE FROM {table} WHERE server_id IS NULL")
        _fk(table, parent, "CASCADE")
        op.alter_column(table, "server_id", nullable=False)
        op.drop_column(table, "server_name")
    op.drop_column("dns_server", "removing_at")
