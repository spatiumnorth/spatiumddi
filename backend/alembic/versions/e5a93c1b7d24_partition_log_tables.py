"""#2185 — time-partition the agent-shipped log tables (expand step).

``dns_query_log_entry``, ``dhcp_log_entry`` and ``dns_rpz_hit`` become
``PARTITION BY RANGE (ts)`` so retention is a partition drop instead of a
mass ``DELETE``.

Each table is swapped in one transaction:

* the existing table is renamed to ``<table>_legacy``, with its constraints
  and indexes, and keeps its rows;
* a partitioned table takes the original name, with the same columns, the
  same foreign key and indexes, and primary key ``(id, ts)`` (PostgreSQL
  needs the partition key in every unique constraint);
* the ``id`` sequence moves to the new table, so ids keep counting up and a
  default-less ``INSERT`` from the previous release's pods lands in the new
  table;
* a daily partition for each day of the retention window (the settings cap
  it at 7 days, RPZ hits are kept 30), plus today and tomorrow.
  ``maintain_log_partitions`` takes over from the end of the last one.

Expand/contract: during the rolling upgrade the previous release's pods
read, insert into and delete from the same table name with the same columns,
so nothing they do breaks. The rows in ``<table>_legacy`` are not copied
across: these are short-lived triage logs, and the tables start empty after
the upgrade (release notes say so). The ``_legacy`` tables are dropped in
the next release.

Downgrade keeps everything: the partitioned table and its partitions are
parked as ``<table>_partitioned`` / ``<table>_partitioned_pYYYYMMDD…``, the
legacy table gets its name back, and the sequence goes back to it. A
previously parked set is replaced.

Revision ID: e5a93c1b7d24
Revises: c4f81e2a9d37
"""

from __future__ import annotations

from alembic import op

revision: str = "e5a93c1b7d24"
down_revision: str | None = "c4f81e2a9d37"
branch_labels: str | None = None
depends_on: str | None = None

# table, referenced server table, indexes, days of retention to cover
_TABLES = (
    (
        "dns_query_log_entry",
        "dns_server",
        (
            ("ix_dns_query_log_server_ts", "server_id, ts"),
            ("ix_dns_query_log_ts", "ts"),
        ),
        8,
    ),
    (
        "dhcp_log_entry",
        "dhcp_server",
        (
            ("ix_dhcp_log_server_ts", "server_id, ts"),
            ("ix_dhcp_log_ts", "ts"),
        ),
        8,
    ),
    (
        "dns_rpz_hit",
        "dns_server",
        (
            ("ix_dns_rpz_hit_client_ts", "client_ip, ts"),
            ("ix_dns_rpz_hit_ts", "ts"),
            ("ix_dns_rpz_hit_zone_ts", "rpz_zone, ts"),
        ),
        31,
    ),
)


def _rename_all(table: str, *, suffix: str, add: bool) -> str:
    """Rename every constraint and standalone index of ``table`` by ``suffix``.

    Constraints go first: renaming the primary key renames its index too, and
    the second loop skips indexes that back a constraint.
    """
    new = "r.conname || '{s}'" if add else "left(r.conname, -{n})"
    new_idx = "r.relname || '{s}'" if add else "left(r.relname, -{n})"
    fmt = {"s": suffix, "n": len(suffix)}
    return f"""
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT conname FROM pg_constraint WHERE conrelid = '{table}'::regclass LOOP
    EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I', '{table}', r.conname, {new.format(**fmt)});
  END LOOP;
  FOR r IN
    SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE i.indrelid = '{table}'::regclass
      AND i.indexrelid NOT IN (SELECT conindid FROM pg_constraint WHERE conrelid = '{table}'::regclass)
  LOOP
    EXECUTE format('ALTER INDEX %I RENAME TO %I', r.relname, {new_idx.format(**fmt)});
  END LOOP;
END $$;
"""


def upgrade() -> None:
    for table, server_table, indexes, back_days in _TABLES:
        legacy = f"{table}_legacy"
        op.execute(f"ALTER TABLE {table} RENAME TO {legacy}")
        op.execute(_rename_all(legacy, suffix="_legacy", add=True))
        op.execute(
            f"CREATE TABLE {table} (LIKE {legacy} INCLUDING DEFAULTS, PRIMARY KEY (id, ts)) "
            "PARTITION BY RANGE (ts)"
        )
        op.execute(
            f"ALTER TABLE {table} ADD CONSTRAINT {table}_server_id_fkey "
            f"FOREIGN KEY (server_id) REFERENCES {server_table} (id) ON DELETE CASCADE"
        )
        for name, columns in indexes:
            op.execute(f"CREATE INDEX {name} ON {table} ({columns})")
        # The sequence follows the column that is written now, so it survives
        # the legacy table being dropped in the next release.
        op.execute(f"""
DO $$
DECLARE seq text := pg_get_serial_sequence('{legacy}', 'id');
BEGIN
  IF seq IS NULL THEN
    RAISE EXCEPTION '{legacy}.id has no owned sequence to hand over';
  END IF;
  EXECUTE format('ALTER SEQUENCE %s OWNED BY {table}.id', seq);
END $$;
""")
        op.execute(f"""
DO $$
DECLARE
  today date := (now() AT TIME ZONE 'UTC')::date;
  d date;
BEGIN
  FOR i IN -{back_days}..1 LOOP
    d := today + i;
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF {table} FOR VALUES FROM (%L) TO (%L)',
      '{table}_p' || to_char(d, 'YYYYMMDD'),
      (d::timestamp AT TIME ZONE 'UTC'),
      ((d + 1)::timestamp AT TIME ZONE 'UTC')
    );
  END LOOP;
END $$;
""")


def downgrade() -> None:
    for table, _server_table, _indexes, _back_days in reversed(_TABLES):
        legacy = f"{table}_legacy"
        parked = f"{table}_partitioned"
        # Rows written while this release ran stay in the parked table; an
        # earlier parked set, from a previous downgrade, is replaced.
        op.execute(f"DROP TABLE IF EXISTS {parked}")
        op.execute(f"ALTER TABLE {table} RENAME TO {parked}")
        op.execute(_rename_all(parked, suffix="_partitioned", add=True))
        op.execute(f"""
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
           WHERE i.inhparent = '{parked}'::regclass LOOP
    EXECUTE format('ALTER TABLE %I RENAME TO %I', r.relname,
                   replace(r.relname, '{table}_p', '{parked}_p'));
  END LOOP;
END $$;
""")
        op.execute(_rename_all(legacy, suffix="_legacy", add=False))
        op.execute(f"ALTER TABLE {legacy} RENAME TO {table}")
        op.execute(f"""
DO $$
DECLARE seq text := pg_get_serial_sequence('{parked}', 'id');
BEGIN
  IF seq IS NOT NULL THEN
    EXECUTE format('ALTER SEQUENCE %s OWNED BY {table}.id', seq);
  END IF;
END $$;
""")
