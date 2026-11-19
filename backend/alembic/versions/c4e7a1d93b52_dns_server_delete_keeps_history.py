"""A server delete keeps client history, and runs in a worker (#4173)

Deleting a DNS server cascaded its query log, RPZ hits and metrics inside the
HTTP request: a minute-plus on a 1.2M-row log, and it erased what clients had
asked. This migration prepares the other behaviour; the code does the rest.

* ``dns_query_log_entry`` and ``dns_rpz_hit``: ``server_id`` becomes nullable
  and its foreign key ``ON DELETE SET NULL``; new nullable ``server_name`` so
  a row stays attributable once the id is gone. Same for ``dhcp_log_entry``.
  The new constraints are added ``NOT VALID`` and validated afterwards, in an
  autocommit block of their own (#4449): ``ADD CONSTRAINT`` holds SHARE ROW
  EXCLUSIVE on the table and its server table until the transaction ends, so
  validating in the same transaction would keep log ingest waiting for the whole
  scan. ``VALIDATE CONSTRAINT`` takes only SHARE UPDATE EXCLUSIVE, which writes
  do not wait on. The block commits what precedes it, so the revision may stop
  half-applied: every step is idempotent and a re-run completes it.
  Existing rows get no ``server_name``: the server's own delete stamps it, and
  a reader shows "deleted server" for a row that has neither.
* ``ix_dns_rpz_hit_server_id``: ``dns_rpz_hit.server_id`` was the only
  server foreign key without an index, so each server delete scanned the table.
* ``dns_server.removing_at``: set when a delete was requested; the worker task
  removes the operational rows in batches and the row last.

``dns_metric_sample`` keeps ``ON DELETE CASCADE``: ``server_id`` is part of its
primary key, and it holds counters, not client history.

Revision ID: c4e7a1d93b52
Revises: b7d2e4f81c59
Create Date: 2026-11-14 12:00:00.000000
"""

from alembic import op

revision = "c4e7a1d93b52"
down_revision = "b7d2e4f81c59"
branch_labels = None
depends_on = None

# (table, referenced table, constraint name Postgres gave the original FK)
_HISTORY = (
    ("dns_query_log_entry", "dns_server"),
    ("dns_rpz_hit", "dns_server"),
    ("dhcp_log_entry", "dhcp_server"),
)


def _add_fk(table: str, parent: str, ondelete: str) -> None:
    name = f"{table}_server_id_fkey"
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
    op.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT {name} FOREIGN KEY (server_id) "
        f"REFERENCES {parent} (id) ON DELETE {ondelete} NOT VALID"
    )


def _validate_fks() -> None:
    """Validate outside the transaction that added the constraints (#4449)."""
    for table, _parent in _HISTORY:
        with op.get_context().autocommit_block():
            op.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {table}_server_id_fkey")


def upgrade() -> None:
    op.execute("ALTER TABLE dns_server ADD COLUMN IF NOT EXISTS removing_at timestamptz")
    for table, parent in _HISTORY:
        op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS server_name varchar(255)")
        op.alter_column(table, "server_id", nullable=True)
        _add_fk(table, parent, "SET NULL")
    op.execute("CREATE INDEX IF NOT EXISTS ix_dns_rpz_hit_server_id ON dns_rpz_hit (server_id)")
    _validate_fks()


def downgrade() -> None:
    op.drop_index("ix_dns_rpz_hit_server_id", table_name="dns_rpz_hit")
    for table, parent in _HISTORY:
        # Rows detached by a server delete have no server to point at again.
        op.execute(f"DELETE FROM {table} WHERE server_id IS NULL")
        _add_fk(table, parent, "CASCADE")
        op.alter_column(table, "server_id", nullable=False)
        op.drop_column(table, "server_name")
    op.drop_column("dns_server", "removing_at")
    _validate_fks()
