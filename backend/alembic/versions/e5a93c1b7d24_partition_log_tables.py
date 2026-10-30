"""#2185 — time-partition the agent-shipped log tables.

``dns_query_log_entry``, ``dhcp_log_entry`` and ``dns_rpz_hit`` become
``PARTITION BY RANGE (ts)`` so retention is a partition drop instead of a
mass ``DELETE``.

Each table is swapped in one step, inside this revision's transaction:

* the existing table is renamed out of the way, with its constraints and
  indexes;
* a partitioned table takes the original name, with the same columns, the
  same foreign key and indexes, and primary key ``(id, ts)`` (PostgreSQL
  needs the partition key in every unique constraint);
* the ``id`` sequence moves to it, so ids keep counting up and a
  default-less ``INSERT`` from the previous release's pods lands in it;
* it gets a daily partition for each day of the retention window (the
  settings cap the logs at 7 days, RPZ hits are kept 30), plus today and
  tomorrow; ``maintain_log_partitions`` takes over from the end of the last
  one;
* RPZ hits inside those partitions are copied across: they are 30 days of
  threat evidence in a non-volatile backup section. The query and activity
  logs start empty, as agreed in #2185: they hold a day of triage data, and
  at the rates the issue cites copying them is the mass write it removes,
  done while the previous release's ingest waits on the swap;
* the old table is dropped. Nothing reads it: the previous release's pods use
  the original name. Keeping it would keep rows past their retention and
  its foreign key would make a selective restore of ``dns`` / ``dhcp``
  refuse to run.

During a rolling upgrade the previous release's pods read, insert into and
delete from the same table name with the same columns, so nothing they do
breaks; their prepared statements are re-planned against the new table.

The swap needs ``ACCESS EXCLUSIVE`` on the three tables and on
``dns_server`` / ``dhcp_server`` (dropping a table with a foreign key into them
takes that much). It takes all of them first, under a short ``lock_timeout``,
and does the work only once it holds them; when one is not granted in time it
lets go of everything, sleeps and tries again. A long reader on one of these
busy tables therefore makes the migration wait, a few seconds at a time,
rather than leave every insert, or every read of the server tables, queued
behind it.

Downgrade swaps back the same way to plain tables with the old shape,
copying the RPZ hits and starting the two logs empty.

Revision ID: e5a93c1b7d24
Revises: c4f81e2a9d37
"""

from __future__ import annotations

from alembic import op

revision: str = "e5a93c1b7d24"
down_revision: str | None = "c4f81e2a9d37"
branch_labels: str | None = None
depends_on: str | None = None

#: How long one attempt at a swap waits for a lock, and how many attempts.
_LOCK_TIMEOUT_MS = 3000
_ATTEMPTS = 10

#: Every table the swap locks, server tables first, as a cascading delete of a
#: server reaches them.
_LOCKED = ("dns_server", "dhcp_server", "dns_query_log_entry", "dhcp_log_entry", "dns_rpz_hit")

# table, referenced server table, indexes, days of retention to cover, copy rows
_TABLES = (
    (
        "dns_query_log_entry",
        "dns_server",
        (
            ("ix_dns_query_log_server_ts", "server_id, ts"),
            ("ix_dns_query_log_ts", "ts"),
        ),
        8,
        False,
    ),
    (
        "dhcp_log_entry",
        "dhcp_server",
        (
            ("ix_dhcp_log_server_ts", "server_id, ts"),
            ("ix_dhcp_log_ts", "ts"),
        ),
        8,
        False,
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
        True,
    ),
)


def _move_aside(table: str) -> str:
    """Rename ``table`` to ``<table>_old``, with every constraint and index, so
    the new table can take all their names. Constraints first: renaming the
    primary key renames its index too, and the second loop skips indexes that
    back a constraint."""
    old = f"{table}_old"
    return f"""
      ALTER TABLE {table} RENAME TO {old};
      FOR r IN SELECT conname FROM pg_constraint WHERE conrelid = '{old}'::regclass LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I', '{old}', r.conname, r.conname || '_old');
      END LOOP;
      FOR r IN
        SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
        WHERE i.indrelid = '{old}'::regclass
          AND i.indexrelid NOT IN (SELECT conindid FROM pg_constraint WHERE conrelid = '{old}'::regclass)
      LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I', r.relname, r.relname || '_old');
      END LOOP;"""


def _swap(body: str) -> str:
    """The whole swap as one block, retried when a lock is not granted in time.

    Every lock is taken first; a failed attempt rolls back to the start of the
    block, which releases all of them before the sleep.
    """
    return f"""
DO $swap$
DECLARE
  attempt int := 0;
  r record;
  seq text;
  cols text;
  today date := (now() AT TIME ZONE 'UTC')::date;
BEGIN
  LOOP
    attempt := attempt + 1;
    BEGIN
      LOCK TABLE {", ".join(_LOCKED)} IN ACCESS EXCLUSIVE MODE;
      {body}
      EXIT;
    EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
      IF attempt >= {_ATTEMPTS} THEN
        RAISE;
      END IF;
      RAISE NOTICE 'log tables: a lock was not granted in time, retrying (attempt %)', attempt;
      PERFORM pg_sleep(least(attempt, 5));
    END;
  END LOOP;
END $swap$;
"""


def _common(table: str, server_table: str, indexes: tuple[tuple[str, str], ...]) -> str:
    """The foreign key, the indexes and the sequence of the table just created
    under ``table``, taken over from ``<table>_old``."""
    old = f"{table}_old"
    return (
        f"""
      ALTER TABLE {table} ADD CONSTRAINT {table}_server_id_fkey
        FOREIGN KEY (server_id) REFERENCES {server_table} (id) ON DELETE CASCADE;"""
        + "".join(f"\n      CREATE INDEX {name} ON {table} ({cols});" for name, cols in indexes)
        + f"""
      seq := pg_get_serial_sequence('{old}', 'id');
      IF seq IS NULL THEN
        RAISE EXCEPTION '{old}.id has no owned sequence to hand over';
      END IF;
      EXECUTE format('ALTER SEQUENCE %s OWNED BY {table}.id', seq);
      SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO cols
        FROM pg_attribute WHERE attrelid = '{old}'::regclass AND attnum > 0 AND NOT attisdropped;"""
    )


def upgrade() -> None:
    op.execute(f"SET LOCAL lock_timeout = {_LOCK_TIMEOUT_MS}")
    body = ""
    for table, server_table, indexes, back_days, copy in _TABLES:
        old = f"{table}_old"
        lower = f"((today - {back_days})::timestamp AT TIME ZONE 'UTC')"
        upper = "((today + 2)::timestamp AT TIME ZONE 'UTC')"
        body += (
            _move_aside(table)
            + f"""
      CREATE TABLE {table} (LIKE {old} INCLUDING DEFAULTS, PRIMARY KEY (id, ts))
        PARTITION BY RANGE (ts);"""
            + _common(table, server_table, indexes)
            + f"""
      FOR i IN -{back_days}..1 LOOP
        EXECUTE format(
          'CREATE TABLE %I PARTITION OF {table} FOR VALUES FROM (%L) TO (%L)',
          '{table}_p' || to_char(today + i, 'YYYYMMDD'),
          ((today + i)::timestamp AT TIME ZONE 'UTC'),
          ((today + i + 1)::timestamp AT TIME ZONE 'UTC')
        );
      END LOOP;"""
            + (
                f"""
      EXECUTE format(
        'INSERT INTO {table} (%s) SELECT %s FROM {old} WHERE ts >= %L AND ts < %L',
        cols, cols, {lower}, {upper}
      );"""
                if copy
                else ""
            )
            + f"""
      DROP TABLE {old};"""
        )
    op.execute(_swap(body))


def downgrade() -> None:
    op.execute(f"SET LOCAL lock_timeout = {_LOCK_TIMEOUT_MS}")
    body = ""
    for table, server_table, indexes, _back_days, copy in reversed(_TABLES):
        old = f"{table}_old"
        body += (
            _move_aside(table)
            + f"""
      CREATE TABLE {table} (LIKE {old} INCLUDING DEFAULTS, PRIMARY KEY (id));"""
            + _common(table, server_table, indexes)
            + (
                f"""
      EXECUTE format('INSERT INTO {table} (%s) SELECT %s FROM {old}', cols, cols);"""
                if copy
                else ""
            )
            + f"""
      DROP TABLE {old};"""
        )
    op.execute(_swap(body))
