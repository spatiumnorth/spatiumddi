import asyncio
import os
import time
from logging.config import fileConfig

from alembic import context
from alembic.util import CommandError
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import all models so Alembic can detect them for autogenerate
from app.core import migrate_guard
from app.core.schema_check import explain_unknown_revision
from app.models import Base  # noqa: F401 — registers all mapped classes

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Allow DATABASE_URL env var to override the value in alembic.ini.
# Docker Compose injects the correct URL (with the right password and hostname)
# via the environment, so this takes precedence over the placeholder in alembic.ini.
if db_url := os.environ.get("DATABASE_URL"):
    config.set_main_option("sqlalchemy.url", db_url)

target_metadata = Base.metadata

# #1204 — one transaction PER REVISION, never one for the whole chain.
#
# The previous release keeps serving while this runs: the new api / worker /
# beat wait on ``wait-for-migrate``, the old pods do not. With the whole chain
# in one transaction, every ACCESS EXCLUSIVE lock a revision takes (each
# ``ALTER TABLE``) is held until the LAST revision commits. An old-release
# request that touches an already-altered table then blocks while holding
# locks on tables a later revision still has to alter; when the migration
# reaches one of those, it closes the cycle and PostgreSQL aborts the
# migration. Upgrading 2026.09.04-1 -> 7490f61b did exactly that on every
# attempt: e.g. c93f1a72e408 altered ``dhcp_server_group`` and three revisions
# later f7c3a91e50b4's ``ALTER TABLE appliance`` deadlocked against an old
# request holding ``appliance`` and waiting on ``dhcp_server_group``, with
# three different table pairs on one appliance. Per revision, a revision's
# locks are released when it commits, so no lock outlives the revision that
# took it and that cycle cannot form across revisions.
#
# The trade-off: a failure mid-chain now leaves the schema at the last
# revision that committed, not at the start. ``alembic_version`` records it,
# the next attempt resumes from there, and the previous release meanwhile runs
# against those completed revisions — as it already does, against ALL of them,
# between a successful migration and the new pods taking over. A revision the
# previous release's code cannot run against needs that care either way.
TRANSACTION_PER_MIGRATION = True


def _run_migrations() -> None:
    """``context.run_migrations()``, with a message that names the real cause
    when the database is at a revision this release does not know (#1227).

    That is what a rollback, an auto-revert or a downgrade leaves behind, and
    it is raised from inside ``run_migrations`` for ``upgrade`` and
    ``current`` alike, so the migrate Job and the ``wait-for-migrate`` init
    container both say it. The error is re-raised either way: no command that
    fails today succeeds now, so ``alembic stamp`` recovery is untouched.
    """
    try:
        context.run_migrations()
    except CommandError as exc:
        explained = explain_unknown_revision(str(exc), _database_revisions())
        if explained is None:
            raise
        raise CommandError(explained) from exc


def _database_revisions() -> tuple[str, ...]:
    """What ``alembic_version`` holds, or nothing when it cannot be read
    (offline mode has no database to ask)."""
    if context.is_offline_mode():
        return ()
    try:
        return tuple(context.get_context().get_current_heads())
    except Exception:  # noqa: BLE001 — no explanation beats a second error
        return ()


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        transaction_per_migration=TRANSACTION_PER_MIGRATION,
    )
    with context.begin_transaction():
        _run_migrations()


def _guard_enabled() -> bool:
    """The lock guard (#3932) belongs to ``upgrade`` only.

    ``alembic current`` (the ``wait-for-migrate`` init containers) and
    ``stamp`` / ``downgrade`` must never end another session. A programmatic
    ``command.upgrade`` has no ``cmd_opts`` and gets the guard.
    """
    opts = getattr(config, "cmd_opts", None)
    cmd = getattr(opts, "cmd", None)
    if not cmd:
        return True
    return getattr(cmd[0], "__name__", "") == "upgrade"


def do_run_migrations(connection: Connection) -> None:
    guard = _guard_enabled()
    if guard:
        # #3932 — a session left idle in transaction by a dead client held
        # this migration's ALTER for 2 h+. Bound every lock wait so the
        # revision leaves the lock queue (and stops stalling every query
        # queued behind it) instead of waiting silently.
        migrate_guard.apply_lock_timeout(connection)
        # #1253 — opt-in ceiling on a statement's run time (off by default:
        # a data migration may legitimately take minutes).
        migrate_guard.apply_statement_timeout(connection)
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        transaction_per_migration=TRANSACTION_PER_MIGRATION,
    )
    retries = migrate_guard.lock_retries() if guard else 0
    attempt = 0
    watcher = None
    if guard:
        # Read pg_blocking_pids of this backend while it waits (#3932): the
        # wait is over when the timeout fires, so it cannot be read then.
        pid = connection.exec_driver_sql("SELECT pg_backend_pid()").scalar()
        connection.commit()
        watcher = migrate_guard.BlockerWatcher(
            migrate_guard.asyncpg_dsn(config.get_main_option("sqlalchemy.url") or ""),
            int(pid),
            interval=max(0.2, min(2.0, migrate_guard.lock_timeout_seconds() / 4)),
        )
        watcher.start()
    try:
        _retry_loop(connection, guard, retries, attempt, watcher)
    finally:
        if watcher is not None:
            watcher.stop()


def _retry_loop(connection: Connection, guard: bool, retries, attempt: int, watcher) -> None:
    while True:
        try:
            with context.begin_transaction():
                _run_migrations()
            return
        except Exception as exc:  # noqa: BLE001 — re-raised unless a lock timeout
            if not (guard and migrate_guard.is_lock_timeout(exc)):
                raise
            if retries is not None and attempt >= retries:
                raise
            attempt += 1
            # Each revision commits on its own, so the retry resumes at the
            # revision that was waiting (alembic re-reads alembic_version).
            if connection.in_transaction():
                connection.rollback()
            blockers = watcher.take() if watcher is not None else []
            migrate_guard.log_blockers(blockers, attempt=attempt, retries=retries)
            # Only now, with a wait that has actually timed out, end the
            # abandoned sessions the migration was seen waiting on; a
            # legitimate long holder (a backup's pg_dump is active, not idle)
            # and any session that blocks nothing are left alone, and the
            # retries (unlimited by default) wait the holder out.
            migrate_guard.terminate_stale_idle_sessions(connection, [b["pid"] for b in blockers])
            time.sleep(migrate_guard.backoff_seconds(attempt))


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
