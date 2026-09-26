import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import all models so Alembic can detect them for autogenerate
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
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        transaction_per_migration=TRANSACTION_PER_MIGRATION,
    )
    with context.begin_transaction():
        context.run_migrations()


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
