"""The unmapped ``gss_tsig_*`` columns are dropped (#3592, migration ``d4a7c18e6b92``).

#3561 stopped mapping them and left them in the database for one release; this
is the contract step. The migration must drop whichever are present, tolerate a
database that already lacks them, and re-add them on downgrade. A selective
restore of an archive taken before the drop re-adds them for its ``COPY`` and
drops them again afterwards.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import Connection, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.backup.legacy_columns import (
    DROPPED_UNMAPPED_COLUMNS,
    drop_unmapped_columns,
    selective_readd_sql,
)

_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "d4a7c18e6b92_drop_unmapped_gss_tsig_columns.py"
)
_COLUMNS = {
    "gss_tsig_enabled",
    "gss_tsig_keytab_path",
    "gss_tsig_realm",
    "gss_tsig_principal",
}
_OLD_SHAPE = (
    "ALTER TABLE dns_server_options "
    "ADD COLUMN gss_tsig_enabled boolean NOT NULL DEFAULT false, "
    "ADD COLUMN gss_tsig_keytab_path varchar(500), "
    "ADD COLUMN gss_tsig_realm varchar(255), "
    "ADD COLUMN gss_tsig_principal varchar(500)"
)


def _migration():
    spec = importlib.util.spec_from_file_location("_gss_drop", _PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _gss(conn: Connection) -> set[str]:
    return {c["name"] for c in inspect(conn).get_columns("dns_server_options")} & _COLUMNS


def _run(conn: Connection, fn_name: str) -> None:
    mod = _migration()
    with Operations.context(MigrationContext.configure(conn)):
        getattr(mod, fn_name)()


def test_the_migration_is_chained_and_covers_exactly_the_four_columns() -> None:
    mod = _migration()
    assert mod.down_revision == "b6d2e9f41a07"
    assert set(mod._COLUMNS) == _COLUMNS
    assert {c for _t, c, _ty in DROPPED_UNMAPPED_COLUMNS} == _COLUMNS


@pytest.mark.asyncio
async def test_upgrade_drops_the_columns_and_downgrade_restores_them(
    db_session: AsyncSession,
) -> None:
    await db_session.execute(text(_OLD_SHAPE))
    conn = await db_session.connection()
    try:
        assert await conn.run_sync(_gss) == _COLUMNS
        await conn.run_sync(_run, "upgrade")
        assert await conn.run_sync(_gss) == set()
        await conn.run_sync(_run, "upgrade")  # already gone: a no-op
        await conn.run_sync(_run, "downgrade")
        assert await conn.run_sync(_gss) == _COLUMNS
        await conn.run_sync(_run, "downgrade")  # already there: a no-op
    finally:
        await db_session.rollback()


@pytest.mark.asyncio
async def test_a_selective_restore_readds_then_drops_the_columns(
    db_session: AsyncSession,
) -> None:
    sql = selective_readd_sql(["dns_server_options"])
    assert all(f'"{c}"' in sql for c in _COLUMNS)
    assert selective_readd_sql(["subnet"]) == ""
    conn = await db_session.connection()
    try:
        assert await conn.run_sync(_gss) == set()
        for statement in filter(None, sql.split(";\n")):
            await db_session.execute(text(statement))
        assert await conn.run_sync(_gss) == _COLUMNS
        assert await conn.run_sync(drop_unmapped_columns) == 4
        assert await conn.run_sync(_gss) == set()
        assert await conn.run_sync(drop_unmapped_columns) == 0
    finally:
        await db_session.rollback()
