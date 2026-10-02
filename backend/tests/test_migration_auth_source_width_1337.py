"""#1337 — migration ``cd10b699d988``, upgrade and downgrade, against PostgreSQL.

The revision's own ``upgrade()`` / ``downgrade()`` run through Alembic's
operations on a throwaway schema holding the two columns as the previous
revision leaves them: ``audit_log.auth_source VARCHAR(20)`` (no server default)
and ``user_session.auth_source VARCHAR(64) DEFAULT 'local'``.

Upgrade widens both to 255 and keeps the session default. Downgrade narrows
them back when every value fits, and refuses, changing nothing, when one does
not: an audit row's content is covered by its hash chain (#73), so a value
must never be truncated.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid
from collections.abc import AsyncGenerator, Callable
from types import ModuleType

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

_REVISION = "cd10b699d988"
_FILE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / f"{_REVISION}_auth_source_holds_a_provider_name.py"
)


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"migration_{_REVISION}", _FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
async def schema() -> AsyncGenerator[tuple[AsyncEngine, str], None]:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    name = f"m1337_{uuid.uuid4().hex[:8]}"
    async with engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{name}"'))
        await conn.execute(
            text(
                f'CREATE TABLE "{name}".audit_log ('
                "id serial PRIMARY KEY, auth_source varchar(20) NOT NULL)"
            )
        )
        await conn.execute(
            text(
                f'CREATE TABLE "{name}".user_session ('
                "id serial PRIMARY KEY, auth_source varchar(64) NOT NULL DEFAULT 'local')"
            )
        )
    try:
        yield engine, name
    finally:
        async with engine.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
        await engine.dispose()


async def _apply(engine: AsyncEngine, schema: str, step: Callable[[], None]) -> None:
    """Run one revision step in one transaction, as ``env.py`` does
    (``transaction_per_migration``), with the throwaway schema first."""
    async with engine.begin() as conn:
        await conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))

        def _run(sync_conn) -> None:  # type: ignore[no-untyped-def]
            with Operations.context(MigrationContext.configure(sync_conn)):
                step()

        await conn.run_sync(_run)


async def _columns(engine: AsyncEngine, schema: str) -> dict[str, tuple[int, str | None]]:
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT table_name, character_maximum_length, column_default "
                    "FROM information_schema.columns "
                    "WHERE table_schema = :s AND column_name = 'auth_source'"
                ),
                {"s": schema},
            )
        ).all()
    return {r[0]: (r[1], r[2]) for r in rows}


async def _insert(engine: AsyncEngine, schema: str, table: str, value: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(f'INSERT INTO "{schema}".{table} (auth_source) VALUES (:v)'), {"v": value}
        )


def test_the_revision_follows_the_head_it_was_written_on() -> None:
    m = _migration()
    assert (m.revision, m.down_revision) == (_REVISION, "f4a8c2e71d09")


@pytest.mark.asyncio
async def test_upgrade_widens_both_columns_to_a_provider_name(schema) -> None:
    engine, name = schema
    await _apply(engine, name, _migration().upgrade)

    cols = await _columns(engine, name)
    assert cols["audit_log"][0] == 255
    assert cols["user_session"] == (255, "'local'::character varying")
    longest = "p" * 255
    await _insert(engine, name, "audit_log", longest)
    await _insert(engine, name, "user_session", longest)


@pytest.mark.asyncio
async def test_downgrade_narrows_them_back_when_every_value_fits(schema) -> None:
    engine, name = schema
    m = _migration()
    await _apply(engine, name, m.upgrade)
    await _insert(engine, name, "audit_log", "fx-ldap-alpha")
    await _insert(engine, name, "user_session", "fx-ldap-alpha")

    await _apply(engine, name, m.downgrade)

    cols = await _columns(engine, name)
    assert cols["audit_log"][0] == 20
    assert cols["user_session"] == (64, "'local'::character varying")


@pytest.mark.asyncio
async def test_downgrade_refuses_to_truncate_a_longer_value(schema) -> None:
    engine, name = schema
    m = _migration()
    await _apply(engine, name, m.upgrade)
    await _insert(engine, name, "audit_log", "fx-ldap-alpha-long-name")

    with pytest.raises(DBAPIError, match="value too long"):
        await _apply(engine, name, m.downgrade)

    cols = await _columns(engine, name)
    assert (cols["audit_log"][0], cols["user_session"][0]) == (255, 255)
    async with engine.connect() as conn:
        kept = (
            await conn.execute(text(f'SELECT auth_source FROM "{name}".audit_log'))
        ).scalar_one()
    assert kept == "fx-ldap-alpha-long-name"
