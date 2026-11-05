"""#2185 — drop the foreign keys of ``dns_query_log_entry`` and ``dns_rpz_hit`` into ``dns_server``.

The first of three revisions that time-partition the agent-shipped log tables.

The key went for this reason: time partitioning (``e5a93c1b7d24``) creates and
drops a partition every hour or day, and with the key each of those statements
locks the server table (attaching takes ``SHARE ROW EXCLUSIVE``, dropping a
retired partition ``ACCESS EXCLUSIVE``). Every connected agent's config long
poll holds a read on that table in a transaction for up to 30 seconds, most of
the time, so on a live install neither lock would be granted. Without the key,
maintenance never touches the server tables. What it did for the application
was a cleanup: the rows of a deleted server now stay until the retention window
removes them, and nothing reads them by a server that is gone.

Dropping the key itself takes ``ACCESS EXCLUSIVE`` on ``dns_server``, once. There
is no way round that, and a short ``lock_timeout`` would never see a gap between
the long polls, so this waits for longer than one lasts, as any ``ALTER TABLE``
on the server tables does. The polls holding the table finish within 30 seconds;
the requests after them wait behind this statement until then, and it takes
milliseconds once it runs. It gets a revision of its own so that the lock is let
go of at its commit (``alembic/env.py``): waiting for ``dns_server`` while holding
``dhcp_server``, or holding either through the swap's copy, would stall that table's
readers for no reason and could close a lock cycle.

The previous release's pods insert into these tables as before; nothing they do
depends on the key. The constraints are found in the catalog and dropped
with plain SQL. The migration-shape linter does not see that, which is fine here:
no column or table the previous release uses changes.

Downgrade puts the keys back, after removing the rows of servers that are
gone, which the keys would refuse.

Revision ID: a8d2f6c04b71
Revises: d8f3a61c2e47
"""

from __future__ import annotations

from alembic import op

revision: str = "a8d2f6c04b71"
down_revision: str | None = "d8f3a61c2e47"
branch_labels: str | None = None
depends_on: str | None = None

#: How long one attempt waits for its locks: past a long poll
#: (``LONGPOLL_TIMEOUT_SECONDS``, 30 s). How many attempts.
_LOCK_TIMEOUT = "45s"
_ATTEMPTS = 3

_SERVER = "dns_server"
_TABLES = ("dns_query_log_entry", "dns_rpz_hit")


def _retrying(body: str) -> str:
    """``body`` as one block. The server table's lock comes first, as a request
    reads it before writing a log row; when a lock is not granted in time the
    attempt lets go of everything, so the readers queued behind it can run."""
    return f"""
DO $retry$
DECLARE
  attempt int := 0;
  r record;
BEGIN
  LOOP
    attempt := attempt + 1;
    BEGIN
      PERFORM set_config('lock_timeout', '{_LOCK_TIMEOUT}', true);
      LOCK TABLE {_SERVER}, {", ".join(_TABLES)} IN ACCESS EXCLUSIVE MODE;
      {body}
      EXIT;
    EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
      IF attempt >= {_ATTEMPTS} THEN
        RAISE;
      END IF;
      PERFORM pg_sleep(5);
    END;
  END LOOP;
END $retry$;
"""


def upgrade() -> None:
    body = "".join(f"""
      FOR r IN
        SELECT conname FROM pg_constraint
        WHERE contype = 'f' AND conrelid = '{table}'::regclass AND confrelid = '{_SERVER}'::regclass
      LOOP
        EXECUTE format('ALTER TABLE {table} DROP CONSTRAINT %I', r.conname);
      END LOOP;""" for table in _TABLES)
    op.execute(_retrying(body))


def downgrade() -> None:
    body = "".join(
        f"""
      DELETE FROM {table} t WHERE NOT EXISTS (SELECT 1 FROM {_SERVER} s WHERE s.id = t.server_id);
      ALTER TABLE {table} ADD CONSTRAINT {table}_server_id_fkey
        FOREIGN KEY (server_id) REFERENCES {_SERVER} (id) ON DELETE CASCADE;""" for table in _TABLES
    )
    op.execute(_retrying(body))
