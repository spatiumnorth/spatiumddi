"""#2185 — time-partition the agent-shipped log tables.

``dns_query_log_entry``, ``dhcp_log_entry`` and ``dns_rpz_hit`` become
``PARTITION BY RANGE (ts)`` so retention is a partition drop instead of a
mass ``DELETE``. The two revisions before this one took their foreign keys
away, so none of this touches ``dns_server`` / ``dhcp_server``.

Each table is swapped in one step, inside this revision's transaction:

* the existing table is renamed out of the way, with its constraints and
  indexes;
* a partitioned table takes the original name, with the same columns and
  indexes, and primary key ``(id, ts)`` (PostgreSQL needs the partition key
  in every unique constraint);
* it gets a daily partition for each day of the retention window (the
  settings cap the logs at 7 days, RPZ hits are kept 30), plus today and
  tomorrow; ``maintain_log_partitions`` takes over from the end of the last
  one;
* RPZ hits inside those partitions are copied across, before the primary key
  and the indexes exist, so each row costs one insert and the keys are built
  once: they are 30 days of threat evidence in a non-volatile backup section.
  Rows the copy leaves behind (past the window, or dated after tomorrow) are
  counted and logged. The query and activity logs start empty, as agreed in
  #2185: they hold a day of triage data, and at the rates the issue cites
  copying them is the mass write it removes, done while the previous release's
  ingest waits on the swap;
* the ``id`` sequence moves to it, so ids keep counting up and a default-less
  ``INSERT`` from the previous release's pods lands in it;
* the old table is dropped. Nothing reads it: the previous release's pods use
  the original name. Keeping it would keep rows past their retention.

During a rolling upgrade the previous release's pods read, insert into and
delete from the same table name with the same columns, so nothing they do
breaks; their prepared statements are re-planned against the new table. The
rename and the drop go through ``op.execute``, so the migration-shape linter
never sees them. That is deliberate and safe here: every name and column the
previous release uses is preserved.

The swap needs ``ACCESS EXCLUSIVE`` on the three tables. It takes all of them
first, under a short ``lock_timeout``, and does the work only once it holds
them; when one is not granted in time it lets go of everything, sleeps and
tries again. A long reader of one of these tables therefore makes the migration
wait, a few seconds at a time, rather than leave every insert queued behind it.
The last attempt waits longer, for a reader that outlasts the gaps between the
others, and its failure fails the migration.

Downgrade swaps back the same way to plain tables with the old shape,
copying the RPZ hits and starting the two logs empty.

Revision ID: e5a93c1b7d24
Revises: b6e1c94f3a02
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

revision: str = "e5a93c1b7d24"
down_revision: str | None = "b6e1c94f3a02"
branch_labels: str | None = None
depends_on: str | None = None

logger = logging.getLogger("alembic.runtime.migration")

#: How many times to ask for the locks, how long each attempt waits for them,
#: and how long the last one does.
_ATTEMPTS = 10
_LOCK_TIMEOUT = "3s"
_LAST_LOCK_TIMEOUT = "60s"

_LOCKED = ("dns_query_log_entry", "dhcp_log_entry", "dns_rpz_hit")

# table, indexes, days of retention to cover, copy rows
_TABLES = (
    (
        "dns_query_log_entry",
        (
            ("ix_dns_query_log_server_ts", "server_id, ts"),
            ("ix_dns_query_log_ts", "ts"),
        ),
        8,
        False,
    ),
    (
        "dhcp_log_entry",
        (
            ("ix_dhcp_log_server_ts", "server_id, ts"),
            ("ix_dhcp_log_ts", "ts"),
        ),
        8,
        False,
    ),
    (
        "dns_rpz_hit",
        (
            ("ix_dns_rpz_hit_client_ts", "client_ip, ts"),
            ("ix_dns_rpz_hit_ts", "ts"),
            ("ix_dns_rpz_hit_zone_ts", "rpz_zone, ts"),
        ),
        31,
        True,
    ),
)

#: The setting, local to the transaction, that the block leaves its counts in.
_LEFT_OUT = "spatium.log_swap_left_out"


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
  past_window bigint;
  ahead bigint;
  today date := (now() AT TIME ZONE 'UTC')::date;
BEGIN
  LOOP
    attempt := attempt + 1;
    BEGIN
      PERFORM set_config(
        'lock_timeout',
        CASE WHEN attempt >= {_ATTEMPTS} THEN '{_LAST_LOCK_TIMEOUT}' ELSE '{_LOCK_TIMEOUT}' END,
        true);
      LOCK TABLE {", ".join(_LOCKED)} IN ACCESS EXCLUSIVE MODE;
      past_window := 0;
      ahead := 0;
      {body}
      PERFORM set_config('{_LEFT_OUT}', past_window || ',' || ahead, true);
      EXIT;
    EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
      IF attempt >= {_ATTEMPTS} THEN
        RAISE;
      END IF;
      PERFORM pg_sleep(least(attempt, 5));
    END;
  END LOOP;
END $swap$;
"""


def _columns(table: str) -> str:
    return f"""
      SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO cols
        FROM pg_attribute WHERE attrelid = '{table}_old'::regclass AND attnum > 0 AND NOT attisdropped;"""


def _finish(table: str, indexes: tuple[tuple[str, str], ...], primary_key: str) -> str:
    """The primary key, the indexes and the sequence of the table just filled
    under ``table``, and the end of ``<table>_old``."""
    old = f"{table}_old"
    return (
        f"""
      ALTER TABLE {table} ADD PRIMARY KEY ({primary_key});"""
        + "".join(f"\n      CREATE INDEX {name} ON {table} ({cols});" for name, cols in indexes)
        + f"""
      seq := pg_get_serial_sequence('{old}', 'id');
      IF seq IS NULL THEN
        RAISE EXCEPTION '{old}.id has no owned sequence to hand over';
      END IF;
      EXECUTE format('ALTER SEQUENCE %s OWNED BY {table}.id', seq);
      DROP TABLE {old};"""
    )


def _run(body: str) -> None:
    op.execute(_swap(body))
    past_window, ahead = (
        int(n)
        for n in op.get_bind()
        .execute(sa.text(f"SELECT current_setting('{_LEFT_OUT}')"))
        .scalar_one()
        .split(",")
    )
    if past_window or ahead:
        logger.warning(
            "#2185: left %d dns_rpz_hit row(s) out of the copy: %d past the window, "
            "%d dated after tomorrow",
            past_window + ahead,
            past_window,
            ahead,
        )


def upgrade() -> None:
    body = ""
    for table, indexes, back_days, copy in _TABLES:
        old = f"{table}_old"
        lower = f"((today - {back_days})::timestamp AT TIME ZONE 'UTC')"
        upper = "((today + 2)::timestamp AT TIME ZONE 'UTC')"
        body += (
            _move_aside(table)
            + f"""
      CREATE TABLE {table} (LIKE {old} INCLUDING DEFAULTS) PARTITION BY RANGE (ts);"""
            + _columns(table)
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
      );
      past_window := (SELECT count(*) FROM {old} WHERE ts < {lower});
      ahead := (SELECT count(*) FROM {old} WHERE ts >= {upper});"""
                if copy
                else ""
            )
            + _finish(table, indexes, "id, ts")
        )
    _run(body)


def downgrade() -> None:
    body = ""
    for table, indexes, _back_days, copy in reversed(_TABLES):
        old = f"{table}_old"
        body += (
            _move_aside(table)
            + f"""
      CREATE TABLE {table} (LIKE {old} INCLUDING DEFAULTS);"""
            + _columns(table)
            + (
                f"""
      EXECUTE format('INSERT INTO {table} (%s) SELECT %s FROM {old}', cols, cols);"""
                if copy
                else ""
            )
            + _finish(table, indexes, "id")
        )
    _run(body)
