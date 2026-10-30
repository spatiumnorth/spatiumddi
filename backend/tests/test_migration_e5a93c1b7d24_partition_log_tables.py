"""``e5a93c1b7d24`` (#2185) — the log tables become time-partitioned.

Most of these run the migration on its own connection inside one transaction
that is rolled back, against the three tables as the previous release had
them. The ones that need a second session (a long reader the swap must not
queue behind, the previous release's prepared statements) use a scratch
database instead.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import time
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from types import ModuleType
from typing import Any

import asyncpg
import pytest_asyncio
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.base import Base
from app.services.logs import partitions as lp
from app.services.logs.partitions import DHCP_LOG, LOG_TABLES, list_partitions
from tests.conftest import _test_engine
from tests.test_agent_spool_ingest import _dhcp_server, _dns_server
from tests.test_selective_restore_app_role_1693 import _admin, _dsn, _url_for

_NAMES = [t.name for t in LOG_TABLES]
_PATH = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("e5a93c1b7d24_*.py")
)

#: The three tables as the previous release had them.
LEGACY_DDL = (
    """CREATE TABLE dns_query_log_entry (
        id bigserial PRIMARY KEY,
        server_id uuid NOT NULL REFERENCES dns_server (id) ON DELETE CASCADE,
        ts timestamptz NOT NULL, client_ip inet, client_port integer, qname varchar(512),
        qclass varchar(8), qtype varchar(16), flags varchar(64), view varchar(255),
        raw text NOT NULL DEFAULT '', rcode varchar(16), answer_count integer)""",
    "CREATE INDEX ix_dns_query_log_server_ts ON dns_query_log_entry (server_id, ts)",
    "CREATE INDEX ix_dns_query_log_ts ON dns_query_log_entry (ts)",
    """CREATE TABLE dhcp_log_entry (
        id bigserial PRIMARY KEY,
        server_id uuid NOT NULL REFERENCES dhcp_server (id) ON DELETE CASCADE,
        ts timestamptz NOT NULL, severity varchar(16), code varchar(64), mac_address macaddr,
        ip_address inet, transaction_id varchar(32), raw text NOT NULL DEFAULT '')""",
    "CREATE INDEX ix_dhcp_log_server_ts ON dhcp_log_entry (server_id, ts)",
    "CREATE INDEX ix_dhcp_log_ts ON dhcp_log_entry (ts)",
    """CREATE TABLE dns_rpz_hit (
        id bigserial PRIMARY KEY,
        server_id uuid NOT NULL REFERENCES dns_server (id) ON DELETE CASCADE,
        ts timestamptz NOT NULL, client_ip inet, qname varchar(512), trigger varchar(16) NOT NULL,
        policy varchar(16) NOT NULL, rpz_zone varchar(255), raw text NOT NULL DEFAULT '')""",
    "CREATE INDEX ix_dns_rpz_hit_client_ts ON dns_rpz_hit (client_ip, ts)",
    "CREATE INDEX ix_dns_rpz_hit_ts ON dns_rpz_hit (ts)",
    "CREATE INDEX ix_dns_rpz_hit_zone_ts ON dns_rpz_hit (rpz_zone, ts)",
)

#: RPZ hits the fixture holds, by age: two inside the 30 days, one long past
#: them, one dated ahead of every partition the migration makes.
_RPZ_AGES = {
    "recent.example": timedelta(hours=2),
    "last-month.example": timedelta(days=20),
    "ancient.example": timedelta(days=60),
    "future.example": timedelta(days=-10),
}


def migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("e5a93c1b7d24", _PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(sync_conn: object, direction: str, **settings: Any) -> None:
    module = migration()
    for name, value in settings.items():
        setattr(module, name, value)
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        getattr(module, direction)()


async def make_legacy_tables(conn: AsyncConnection) -> None:
    for table in _NAMES:
        await conn.exec_driver_sql(f"DROP TABLE {table} CASCADE")
    for stmt in LEGACY_DDL:
        await conn.exec_driver_sql(stmt)


async def _scalar(conn: AsyncConnection, sql: str) -> Any:
    return (await conn.execute(text(sql))).scalar()


async def _column(conn: AsyncConnection, sql: str) -> list[Any]:
    return list((await conn.execute(text(sql))).scalars())


@pytest_asyncio.fixture
async def legacy() -> AsyncGenerator[tuple[AsyncConnection, uuid.UUID], None]:
    """The previous release's tables with rows in them, in a transaction that is rolled back."""
    async with _test_engine.connect() as conn:
        trans = await conn.begin()
        try:
            async with AsyncSession(bind=conn, expire_on_commit=False) as session:
                dns = (await _dns_server(session)).id
                dhcp = (await _dhcp_server(session)).id
            await make_legacy_tables(conn)
            await conn.execute(
                text(
                    "INSERT INTO dns_query_log_entry (server_id, ts, qname) "
                    "VALUES (:s, now(), 'old.example')"
                ),
                {"s": dns},
            )
            await conn.execute(
                text("INSERT INTO dhcp_log_entry (server_id, ts) VALUES (:s, now())"), {"s": dhcp}
            )
            now = datetime.now(UTC)
            for qname, age in _RPZ_AGES.items():
                await conn.execute(
                    text(
                        "INSERT INTO dns_rpz_hit (server_id, ts, qname, trigger, policy) "
                        "VALUES (:s, :t, :q, 'QNAME', 'NXDOMAIN')"
                    ),
                    {"s": dns, "t": now - age, "q": qname},
                )
            yield conn, dns
        finally:
            await trans.rollback()


async def test_the_swap_keeps_the_rpz_hits_inside_the_window_and_starts_the_logs_empty(
    legacy: tuple[AsyncConnection, uuid.UUID],
) -> None:
    conn, dns = legacy
    before = await _scalar(conn, "SELECT max(id) FROM dns_rpz_hit")

    await conn.run_sync(run, "upgrade")

    for table in _NAMES:
        assert (
            await _scalar(conn, f"SELECT relkind::text FROM pg_class WHERE relname = '{table}'")
            == "p"
        )
    # Nothing of the old tables is left behind: no rows past their window,
    # and no foreign key into dns_server / dhcp_server the models don't know.
    assert await _column(conn, "SELECT relname FROM pg_class WHERE relname LIKE '%\\_old%'") == []
    assert sorted(await _column(conn, "SELECT qname FROM dns_rpz_hit")) == [
        "last-month.example",
        "recent.example",
    ]
    assert await _scalar(conn, "SELECT count(*) FROM dns_query_log_entry") == 0
    assert await _scalar(conn, "SELECT count(*) FROM dhcp_log_entry") == 0
    for table in _NAMES:
        pk = await _scalar(
            conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            f"WHERE conrelid = '{table}'::regclass AND contype = 'p'",
        )
        assert pk == "PRIMARY KEY (id, ts)"
        names = await _column(
            conn,
            "SELECT indexrelid::regclass::text FROM pg_index "
            f"WHERE indrelid = '{table}'::regclass ORDER BY 1",
        )
        assert f"{table}_pkey" in names
    fk = await _scalar(
        conn,
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'dns_rpz_hit'::regclass AND contype = 'f'",
    )
    assert fk == "FOREIGN KEY (server_id) REFERENCES dns_server(id) ON DELETE CASCADE"
    # The previous release's pods insert without an id; the ids carry on.
    await conn.execute(
        text(
            "INSERT INTO dns_rpz_hit (server_id, ts, trigger, policy) "
            "VALUES (:s, now(), 'QNAME', 'NXDOMAIN')"
        ),
        {"s": dns},
    )
    assert await _scalar(conn, "SELECT max(id) FROM dns_rpz_hit") == before + 1
    owner = await _scalar(
        conn,
        "SELECT d.refobjid::regclass::text FROM pg_depend d "
        "WHERE d.objid = pg_get_serial_sequence('dns_rpz_hit', 'id')::regclass AND d.deptype = 'a'",
    )
    assert owner == "dns_rpz_hit"


async def test_the_partitions_cover_the_retention_windows_and_maintenance_carries_on(
    legacy: tuple[AsyncConnection, uuid.UUID],
) -> None:
    conn, _dns = legacy

    await conn.run_sync(run, "upgrade")

    now = datetime.now(UTC)
    for table, days in (("dns_query_log_entry", 7), ("dhcp_log_entry", 7), ("dns_rpz_hit", 30)):
        bounds = sorted((p.lower, p.upper) for p in await list_partitions(conn, table))
        assert bounds[0][0] <= now - timedelta(days=days), table
        assert bounds[-1][1] > now + timedelta(hours=24), table
        for (_, upper), (lower, _) in zip(bounds, bounds[1:], strict=False):
            assert upper == lower, table
    await conn.exec_driver_sql("SET lock_timeout = 3000")
    daily = lp.MaintenanceResult(DHCP_LOG.name)
    await lp._create_ahead(conn, DHCP_LOG, DHCP_LOG.window(24), now, daily)  # noqa: SLF001
    assert daily.created >= 1


async def test_downgrade_brings_back_the_old_tables_with_the_rpz_hits(
    legacy: tuple[AsyncConnection, uuid.UUID],
) -> None:
    conn, dns = legacy
    await conn.run_sync(run, "upgrade")
    await conn.execute(
        text(
            "INSERT INTO dns_query_log_entry (server_id, ts, qname) VALUES (:s, now(), 'mid.example')"
        ),
        {"s": dns},
    )

    await conn.run_sync(run, "downgrade")

    for table in _NAMES:
        assert (
            await _scalar(conn, f"SELECT relkind::text FROM pg_class WHERE relname = '{table}'")
            == "r"
        )
        pk = await _scalar(
            conn,
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            f"WHERE conrelid = '{table}'::regclass AND contype = 'p'",
        )
        assert pk == "PRIMARY KEY (id)"
    assert await _column(conn, "SELECT relname FROM pg_class WHERE relname LIKE '%\\_old%'") == []
    assert (
        await _column(conn, "SELECT relname FROM pg_class WHERE relname ~ '^dns_rpz_hit_p[0-9]'")
        == []
    )
    assert sorted(await _column(conn, "SELECT qname FROM dns_rpz_hit")) == [
        "last-month.example",
        "recent.example",
    ]
    assert await _scalar(conn, "SELECT count(*) FROM dns_query_log_entry") == 0
    await conn.execute(
        text(
            "INSERT INTO dns_query_log_entry (server_id, ts, qname) VALUES (:s, now(), 'back.example')"
        ),
        {"s": dns},
    )

    # And up again, as after a rollback that was undone.
    await conn.run_sync(run, "upgrade")

    assert (
        await _scalar(conn, "SELECT relkind::text FROM pg_class WHERE relname = 'dns_rpz_hit'")
        == "p"
    )
    assert await _scalar(conn, "SELECT count(*) FROM dns_rpz_hit") == 2


# ── with a second session ─────────────────────────────────────────────────


@pytest_asyncio.fixture
async def scratch() -> AsyncGenerator[tuple[str, uuid.UUID], None]:
    """A committed database with the previous release's log tables, and its DNS server."""
    dbname = f"spatiumddi_test_e5a93_{uuid.uuid4().hex[:10]}"
    admin = await _admin()
    try:
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()
    url = _url_for(dbname)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await make_legacy_tables(conn)
        async with AsyncSession(engine, expire_on_commit=False) as session:
            dns = (await _dns_server(session)).id
        yield url, dns
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        finally:
            await admin.close()


async def test_a_long_reader_makes_the_swap_retry_instead_of_queueing_the_inserts(
    scratch: tuple[str, uuid.UUID],
) -> None:
    """The previous release keeps inserting through the upgrade, with statements
    it prepared before it. A report reading the table holds the rename back; the
    swap gives up its place in the lock queue every 200 ms instead of making
    every insert wait behind it."""
    url, dns = scratch
    reader = await asyncpg.connect(_dsn(url))
    writer = await asyncpg.connect(_dsn(url))
    insert = await writer.prepare(
        "INSERT INTO dns_rpz_hit (server_id, ts, trigger, policy, raw) "
        "VALUES ($1, now(), 'QNAME', 'NXDOMAIN', '') RETURNING id"
    )
    slowest = 0.0
    stop = asyncio.Event()

    async def write() -> int:
        nonlocal slowest
        written = 0
        while not stop.is_set():
            started = time.perf_counter()
            await insert.fetchval(dns)
            slowest = max(slowest, time.perf_counter() - started)
            written += 1
            await asyncio.sleep(0.01)
        return written

    engine = create_async_engine(url, poolclass=NullPool)
    try:
        writing = asyncio.create_task(write())
        reading = reader.transaction()
        await reading.start()
        await reader.fetchval("SELECT count(*) FROM dns_rpz_hit")

        async def migrate() -> None:
            async with engine.begin() as conn:
                await conn.run_sync(run, "upgrade", _LOCK_TIMEOUT_MS=200, _ATTEMPTS=50)

        migrating = asyncio.create_task(migrate())
        await asyncio.sleep(1.5)
        assert not migrating.done()
        await reading.rollback()
        await asyncio.wait_for(migrating, timeout=30)
        await asyncio.sleep(0.2)
        stop.set()
        written = await writing
    finally:
        await engine.dispose()
        await reader.close()

    assert slowest < 1.0, f"an insert waited {slowest:.2f} s behind the swap"
    assert written > 50
    # The statement prepared against the old table now writes into the new one.
    assert await insert.fetchval(dns) > 0
    assert (
        await writer.fetchval("SELECT relkind::text FROM pg_class WHERE relname = 'dns_rpz_hit'")
        == "p"
    )
    assert await writer.fetchval("SELECT count(*) FROM dns_rpz_hit") == written + 1
    await writer.close()
