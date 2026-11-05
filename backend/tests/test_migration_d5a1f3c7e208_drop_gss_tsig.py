"""``d5a1f3c7e208`` (#3561) — drops the unrendered ``gss_tsig_*`` option columns.

The test database is built from the models, so the columns are already gone:
the downgrade must put them back (the boolean NOT NULL with a ``false``
default so existing rows load) and the upgrade must drop them again.
Runs on its own connection inside one transaction that is rolled back.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
from collections.abc import AsyncIterator
from types import ModuleType

import pytest
import pytest_asyncio
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

_PATH = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("d5a1f3c7e208_*.py")
)
_COLS = {"gss_tsig_enabled", "gss_tsig_keytab_path", "gss_tsig_realm", "gss_tsig_principal"}


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("d5a1f3c7e208", _PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest_asyncio.fixture
async def conn() -> AsyncIterator[AsyncConnection]:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as c:
            trans = await c.begin()
            try:
                yield c
            finally:
                await trans.rollback()
    finally:
        await engine.dispose()


def _run(sync_conn: object, fn: str) -> None:
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        getattr(_migration(), fn)()


async def _cols(conn: AsyncConnection) -> dict[str, str]:
    rows = await conn.execute(
        sa.text(
            "SELECT column_name, is_nullable FROM information_schema.columns "
            "WHERE table_name = 'dns_server_options' AND column_name LIKE 'gss_tsig_%'"
        )
    )
    return {r[0]: r[1] for r in rows}


@pytest.mark.asyncio
async def test_downgrade_restores_and_upgrade_drops(conn: AsyncConnection) -> None:
    assert await _cols(conn) == {}

    await conn.run_sync(_run, "downgrade")
    restored = await _cols(conn)
    assert set(restored) == _COLS
    assert restored["gss_tsig_enabled"] == "NO"

    await conn.run_sync(_run, "upgrade")
    assert await _cols(conn) == {}
