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
from collections.abc import AsyncIterator, Callable
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


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("c4e7a1d93b52", _PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(sync_conn: Any, step: Callable[[], None]) -> None:
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        step()


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
