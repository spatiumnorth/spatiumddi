"""``c4e7a1d93b52`` (#4173) — history foreign keys become SET NULL, up and down.

The suite builds its schema from the models, so the revision is exercised the
way ``test_migration_ff32b91acad8_soa_timers`` does: on its own connection in
one transaction that is rolled back, downgrade first (the schema before the
revision), then upgrade.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
import pytest_asyncio
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DNSQueryLogEntry

_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "c4e7a1d93b52_dns_server_delete_keeps_history.py"
)
_TABLES = ("dns_query_log_entry", "dns_rpz_hit", "dhcp_log_entry")

#: The revisions after this one that reshape the same tables (#2185), newest
#: first. The suite's schema comes from the models, so it is already
#: partitioned and key-less; this revision's constraints can only be added to
#: the plain tables it ran against, so the fixture walks those back first.
_LATER = (
    "e5a93c1b7d24_partition_log_tables.py",
    "b6e1c94f3a02_drop_dhcp_log_table_fk.py",
    "a8d2f6c04b71_drop_dns_log_table_fks.py",
)


def _later(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.split("_")[0], _PATH.parent / name)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("c4e7a1d93b52", _PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(sync_conn: Any, step: Callable[[], None], log: list[str] | None = None) -> None:
    """Run a revision step on ``sync_conn``.

    The fixture's connection owns the transaction, so a real
    ``autocommit_block`` (which flips the isolation level) cannot run on it;
    it is replaced by a marker, and every statement is logged with whether it
    ran inside a block.
    """
    ctx = MigrationContext.configure(connection=sync_conn)
    in_block = False

    @contextmanager
    def _block() -> Iterator[None]:
        nonlocal in_block
        in_block = True
        try:
            yield
        finally:
            in_block = False

    def _record(_c: Any, _cur: Any, statement: str, *_a: Any) -> None:
        if log is None:
            return
        if "VALIDATE CONSTRAINT" in statement:
            log.append("VALIDATE in block" if in_block else "VALIDATE in transaction")
        elif "NOT VALID" in statement:
            log.append("ADD in block" if in_block else "ADD in transaction")

    ctx.autocommit_block = _block  # type: ignore[method-assign]
    sa.event.listen(sync_conn, "before_cursor_execute", _record)
    try:
        with Operations.context(ctx):
            step()
    finally:
        sa.event.remove(sync_conn, "before_cursor_execute", _record)


@pytest_asyncio.fixture
async def conn() -> AsyncIterator[AsyncConnection]:
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect() as c:
            trans = await c.begin()
            try:
                for name in _LATER:
                    await c.run_sync(_run, _later(name).downgrade)
                yield c
            finally:
                await trans.rollback()
    finally:
        await engine.dispose()


async def _seed(conn: AsyncConnection) -> uuid.UUID:
    """A server with one log row, as the schema before the revision holds it."""
    session = AsyncSession(
        bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    session.add(grp)
    await session.flush()
    srv = DNSServer(group_id=grp.id, name="ns1", host="192.0.2.53")
    session.add(srv)
    await session.flush()
    session.add(
        DNSQueryLogEntry(server_id=srv.id, ts=datetime.now(UTC), qname="a.example.", raw="x")
    )
    await session.commit()
    sid = srv.id
    await session.close()
    return sid


async def _shape(conn: AsyncConnection, table: str) -> dict[str, Any]:
    fk = await conn.scalar(
        sa.text(
            "SELECT confdeltype::text FROM pg_constraint "
            "WHERE conrelid = CAST(:t AS regclass) AND contype = 'f' "
            "AND conname = :n"
        ),
        {"t": table, "n": f"{table}_server_id_fkey"},
    )
    cols = dict(
        (
            await conn.execute(
                sa.text(
                    "SELECT column_name, is_nullable FROM information_schema.columns "
                    "WHERE table_name = :t AND column_name IN ('server_id', 'server_name')"
                ),
                {"t": table},
            )
        ).all()
    )
    return {"fk": fk, "cols": cols}


@pytest.mark.asyncio
async def test_downgrade_then_upgrade_round_trips(conn: AsyncConnection) -> None:
    mig = _migration()
    sid = await _seed(conn)
    await conn.run_sync(_run, mig.downgrade)
    for table in _TABLES:
        assert await _shape(conn, table) == {"fk": "c", "cols": {"server_id": "NO"}}
    assert (
        await conn.scalar(sa.text("SELECT to_regclass('ix_dns_rpz_hit_server_id') IS NULL")) is True
    )
    assert (
        await conn.scalar(
            sa.text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name = 'dns_server' AND column_name = 'removing_at'"
            )
        )
        == 0
    )

    await conn.run_sync(_run, mig.upgrade)
    for table in _TABLES:
        assert await _shape(conn, table) == {
            "fk": "n",
            "cols": {"server_id": "YES", "server_name": "YES"},
        }
    assert (
        await conn.scalar(sa.text("SELECT to_regclass('ix_dns_rpz_hit_server_id') IS NOT NULL"))
        is True
    )
    assert (
        await conn.scalar(
            sa.text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name = 'dns_server' AND column_name = 'removing_at'"
            )
        )
        == 1
    )

    # The row survives and is detached, not cascaded, when its server goes.
    await conn.execute(sa.text("DELETE FROM dns_server WHERE id = :i"), {"i": sid})
    assert (
        await conn.scalar(
            sa.text("SELECT count(*) FROM dns_query_log_entry WHERE server_id IS NULL")
        )
        == 1
    )


@pytest.mark.asyncio
async def test_validate_runs_outside_the_transaction_that_adds_the_constraint(
    conn: AsyncConnection,
) -> None:
    """#4449: VALIDATE in the ADD's transaction kept the ADD's lock for the whole scan."""
    mig = _migration()
    await conn.run_sync(_run, mig.downgrade)
    log: list[str] = []
    await conn.run_sync(_run, mig.upgrade, log)
    assert log == ["ADD in transaction"] * 3 + ["VALIDATE in block"] * 3
