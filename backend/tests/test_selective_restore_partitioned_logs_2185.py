"""#2185 — a selective restore reloads the time-partitioned log tables.

``dns_rpz_hit`` is in the ``dns_threat`` section (kept 30 days, not volatile),
and the two query / activity log tables are in ``logs``. They are partitioned
by time, and a custom-format archive holds their rows under the partitions:
``pg_restore --table dns_rpz_hit`` selects the parent, which owns no data, so
a selective restore would have emptied the table and loaded nothing.

These run the real restore (``pg_dump``, ``pg_restore``, ``psql``) on a scratch
database owned by a role that is not a superuser, as the appliance has.
"""

from __future__ import annotations

import shutil
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.base import Base
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from app.models.dns_rpz_hit import DNSRPZHit
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.services.backup import restore
from app.services.logs.partitions import list_partitions
from tests.conftest import _LOG_PARTITION_DAYS_BACK, create_test_log_partitions
from tests.test_selective_restore_app_role_1693 import (
    _admin,
    _archive,
    _dsn,
    _pg_dump,
    _restore,
    _url_for,
)

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")),
    reason="needs the PostgreSQL client tools",
)

_HEAD = "r2185_archive_head"
NOW = datetime.now(UTC).replace(microsecond=0)
#: Where the suite's oldest log partition starts, and what it is named after.
_OLDEST = NOW.date() - timedelta(days=_LOG_PARTITION_DAYS_BACK)


@pytest.fixture
async def appliance_db() -> AsyncIterator[tuple[str, bytes, uuid.UUID]]:
    """(the app role's URL, an archive of its database, the server's id).

    The database holds two RPZ hits and a DNS query line, in the partitions the
    suite creates, and one RPZ hit 20 days old whose partition is dropped again
    after the archive is taken.
    """
    suffix = uuid.uuid4().hex[:10]
    role, password, dbname = (
        f"r2185_app_{suffix}",
        f"pw-{suffix}",
        f"spatiumddi_test_r2185_{suffix}",
    )
    admin = await _admin()
    try:
        await admin.execute(
            f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        )
        await admin.execute(f'CREATE DATABASE "{dbname}" OWNER "{role}"')
    finally:
        await admin.close()
    url = _url_for(dbname, role, password)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await create_test_log_partitions(conn)
        raw = await asyncpg.connect(_dsn(url))
        try:
            await raw.execute(
                "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
            await raw.execute("INSERT INTO alembic_version VALUES ($1)", _HEAD)
        finally:
            await raw.close()
        async with AsyncSession(engine, expire_on_commit=False) as db:
            group = DNSServerGroup(name=f"g2185-{suffix}")
            db.add(group)
            await db.flush()
            server = DNSServer(group_id=group.id, name="ns", host="10.0.0.53", driver="bind9")
            db.add(server)
            await db.flush()
            for hours, qname in ((2, "recent.example"), (30, "yesterday.example")):
                db.add(
                    DNSRPZHit(
                        server_id=server.id,
                        ts=NOW - timedelta(hours=hours),
                        qname=qname,
                        trigger="QNAME",
                        policy="NXDOMAIN",
                    )
                )
            db.add(
                DNSQueryLogEntry(
                    server_id=server.id, ts=NOW - timedelta(hours=1), qname="q.example"
                )
            )
            await db.commit()
            server_id = server.id
        # A partition for 20 days ago exists for as long as it takes to put a
        # row in it, and is gone by the time of the restore.
        async with engine.begin() as conn:
            await conn.exec_driver_sql(f"DROP TABLE dns_rpz_hit_p{_OLDEST:%Y%m%d}")
            await conn.exec_driver_sql(
                "CREATE TABLE dns_rpz_hit_old PARTITION OF dns_rpz_hit FOR VALUES FROM "
                f"('{(NOW - timedelta(days=20)).strftime('%Y-%m-%d')} 00:00+00') TO "
                f"('{(NOW - timedelta(days=19)).strftime('%Y-%m-%d')} 00:00+00')"
            )
        async with AsyncSession(engine, expire_on_commit=False) as db:
            db.add(
                DNSRPZHit(
                    server_id=server_id,
                    ts=NOW - timedelta(days=20),
                    qname="old.example",
                    trigger="QNAME",
                    policy="NXDOMAIN",
                )
            )
            await db.commit()
        archive = _archive(await _pg_dump(url))
        async with engine.begin() as conn:
            await conn.exec_driver_sql("DROP TABLE dns_rpz_hit_old")
        yield url, archive, server_id
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
            await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await admin.close()


async def _qnames(url: str, table: str) -> list[str]:
    conn = await asyncpg.connect(_dsn(url))
    try:
        return [r[0] for r in await conn.fetch(f"SELECT qname FROM {table} ORDER BY qname")]
    finally:
        await conn.close()


async def test_dns_threat_restore_brings_the_rpz_hits_back(
    appliance_db: tuple[str, bytes, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, archive, server_id = appliance_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        # What the install holds now: none of the archived rows, and one other.
        await conn.execute("TRUNCATE dns_rpz_hit")
        await conn.execute(
            "INSERT INTO dns_rpz_hit (server_id, ts, qname, trigger, policy, raw) "
            "VALUES ($1, now(), 'since.example', 'QNAME', 'NXDOMAIN', '')",
            server_id,
        )
    finally:
        await conn.close()

    outcome: Any = await _restore(url, archive, monkeypatch, sections=("dns_threat",))

    assert "dns_threat" in outcome.restored_sections
    # The two the archive holds inside the partitions that still exist. The one
    # from a partition that is gone has nowhere to live, and would be past its
    # window soon enough: it is dropped, and the restore does not fail on it.
    assert await _qnames(url, "dns_rpz_hit") == ["recent.example", "yesterday.example"]
    conn = await asyncpg.connect(_dsn(url))
    try:
        leftovers = await conn.fetch(
            "SELECT relname FROM pg_class WHERE relname LIKE '%restore_default'"
        )
        assert leftovers == []
        # The sequence counts on from the rows that came back.
        await conn.execute(
            "INSERT INTO dns_rpz_hit (server_id, ts, qname, trigger, policy, raw) "
            "VALUES ($1, now(), 'after.example', 'QNAME', 'NXDOMAIN', '')",
            server_id,
        )
    finally:
        await conn.close()


async def test_logs_restore_brings_the_query_log_back(
    appliance_db: tuple[str, bytes, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, archive, server_id = appliance_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        await conn.execute("TRUNCATE dns_query_log_entry, dhcp_log_entry")
    finally:
        await conn.close()

    await _restore(url, archive, monkeypatch, sections=("logs",))

    assert await _qnames(url, "dns_query_log_entry") == ["q.example"]


async def test_an_archive_from_before_the_tables_were_partitioned_still_restores(
    appliance_db: tuple[str, bytes, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An older backup holds ``dns_rpz_hit`` as one plain table. Its rows load
    through the partitioned parent, and the ones too old for any partition are
    dropped rather than failing the restore."""
    url, _archive_now, server_id = appliance_db
    suffix = uuid.uuid4().hex[:10]
    dbname = f"spatiumddi_test_r2185_old_{suffix}"
    admin = await _admin()
    try:
        await admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        await admin.close()
    old_url = _url_for(dbname)
    engine = create_async_engine(old_url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.exec_driver_sql("DROP TABLE dns_rpz_hit")
            await conn.exec_driver_sql(
                "CREATE TABLE dns_rpz_hit (id bigserial PRIMARY KEY, "
                "server_id uuid NOT NULL REFERENCES dns_server (id) ON DELETE CASCADE, "
                "ts timestamptz NOT NULL, client_ip inet, qname varchar(512), "
                "trigger varchar(16) NOT NULL, policy varchar(16) NOT NULL, "
                "rpz_zone varchar(255), raw text NOT NULL DEFAULT '')"
            )
            await conn.exec_driver_sql(
                "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
            await conn.exec_driver_sql(f"INSERT INTO alembic_version VALUES ('{_HEAD}')")
        async with AsyncSession(engine, expire_on_commit=False) as db:
            group = DNSServerGroup(name=f"old-{suffix}")
            db.add(group)
            await db.flush()
            db.add(
                DNSServer(
                    id=server_id, group_id=group.id, name="ns", host="10.0.0.53", driver="bind9"
                )
            )
            await db.flush()
            for qname, age in (
                ("recent.example", timedelta(hours=2)),
                ("ancient.example", timedelta(days=200)),
            ):
                db.add(
                    DNSRPZHit(
                        server_id=server_id,
                        ts=NOW - age,
                        qname=qname,
                        trigger="QNAME",
                        policy="NXDOMAIN",
                    )
                )
            await db.commit()
        old_archive = _archive(await _pg_dump(old_url))
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
        finally:
            await admin.close()

    await _restore(url, old_archive, monkeypatch, sections=("dns_threat",))

    assert await _qnames(url, "dns_rpz_hit") == ["recent.example"]


async def _upper(url: str, table: str) -> datetime:
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return max(p.upper for p in await list_partitions(conn, table) if p.upper)
    finally:
        await engine.dispose()


async def test_a_full_restore_makes_the_partitions_the_archive_is_missing(
    appliance_db: tuple[str, bytes, uuid.UUID], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An archive brings back the partitions that existed when it was taken.
    Ingest would drop every current line until a partition covers it, so the
    restore makes the missing ones itself instead of leaving them to the next
    15-minute tick."""
    url, _archive_now, _server_id = appliance_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        # Taken yesterday, as far as its partitions are concerned.
        for table in ("dns_query_log_entry", "dhcp_log_entry", "dns_rpz_hit"):
            for day in range(0, 3):
                await conn.execute(
                    f"DROP TABLE IF EXISTS {table}_p{NOW.date() + timedelta(days=day):%Y%m%d}"
                )
    finally:
        await conn.close()
    stale = _archive(await _pg_dump(url))
    assert await _upper(url, "dns_query_log_entry") <= NOW

    await _restore(url, stale, monkeypatch, sections=())

    assert await _upper(url, "dns_query_log_entry") > NOW + timedelta(hours=20)
    assert await _upper(url, "dhcp_log_entry") > NOW + timedelta(days=2)
    assert await _upper(url, "dns_rpz_hit") > NOW + timedelta(days=2)


@pytest.fixture
async def migrated_db() -> AsyncIterator[tuple[str, bytes]]:
    """(the app role's URL, an archive) for a database whose log tables were
    made by the previous release and converted by the migration, the shape an
    upgraded install has, with a DNS query line and a DHCP activity line."""
    from tests.test_migration_e5a93c1b7d24_partition_log_tables import make_legacy_tables, run

    suffix = uuid.uuid4().hex[:10]
    role, password, dbname = (
        f"r2185m_{suffix}",
        f"pw-{suffix}",
        f"spatiumddi_test_r2185m_{suffix}",
    )
    admin = await _admin()
    try:
        await admin.execute(
            f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        )
        await admin.execute(f'CREATE DATABASE "{dbname}" OWNER "{role}"')
    finally:
        await admin.close()
    url = _url_for(dbname, role, password)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await make_legacy_tables(conn)
            await conn.exec_driver_sql(
                "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
            await conn.exec_driver_sql(f"INSERT INTO alembic_version VALUES ('{_HEAD}')")
        async with engine.begin() as conn:
            await conn.run_sync(run, "upgrade")
        async with AsyncSession(engine, expire_on_commit=False) as db:
            group = DNSServerGroup(name=f"g2185m-{suffix}")
            db.add(group)
            await db.flush()
            dns = DNSServer(group_id=group.id, name="ns", host="10.0.0.53", driver="bind9")
            dhcp = DHCPServer(name="kea", host="127.0.0.1", driver="kea")
            db.add_all([dns, dhcp])
            await db.flush()
            db.add(DNSQueryLogEntry(server_id=dns.id, ts=NOW, qname="q.example"))
            db.add(DHCPLogEntry(server_id=dhcp.id, ts=NOW, raw="lease"))
            await db.commit()
        yield url, _archive(await _pg_dump(url))
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
            await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await admin.close()


async def test_dns_and_dhcp_restore_on_an_upgraded_install(
    migrated_db: tuple[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The DNS and DHCP sections reach the log tables through the server tables'
    foreign keys. After the upgrade nothing else may hold one: a leftover table
    with such a key makes the restore refuse to run."""
    url, archive = migrated_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        await conn.execute("TRUNCATE dns_query_log_entry, dhcp_log_entry")
    finally:
        await conn.close()

    for section in ("dns", "dhcp"):
        outcome: Any = await _restore(url, archive, monkeypatch, sections=(section,))
        assert section in outcome.restored_sections

    assert await _qnames(url, "dns_query_log_entry") == ["q.example"]
    conn = await asyncpg.connect(_dsn(url))
    try:
        assert await conn.fetchval("SELECT count(*) FROM dhcp_log_entry") == 1
    finally:
        await conn.close()


async def _chunks(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


async def _rewritten(*parts: bytes, parents: dict[str, str]) -> bytes:
    return b"".join([c async for c in restore._route_partition_copies(_chunks(*parts), parents)])


_PARENTS = {"dns_rpz_hit_p20261027": "dns_rpz_hit", "dns_rpz_hit_p2026102713": "dns_rpz_hit"}


async def test_a_copy_into_an_archived_partition_loads_through_its_parent() -> None:
    script = (
        b"SET row_security = off;\n"
        b"COPY public.dns_rpz_hit_p20261027 (id, ts, qname) FROM stdin;\n"
        b"1\t2026-10-27 10:00:00+00\ta.example\n"
        b"\\.\n\n"
        b'COPY "public"."dns_rpz_hit_p2026102713" ("id", "ts") FROM stdin;\n'
        b"2\t2026-10-27 13:00:00+00\n"
        b"\\.\n"
    )

    out = await _rewritten(script, parents=_PARENTS)

    assert out == (
        script.replace(b"public.dns_rpz_hit_p20261027", b"public.dns_rpz_hit").replace(
            b'"dns_rpz_hit_p2026102713"', b'"dns_rpz_hit"'
        )
    )


async def test_the_rewriter_does_not_depend_on_where_the_chunks_break() -> None:
    script = (
        b"COPY public.dns_rpz_hit_p20261027 (id) FROM stdin;\n1\n2\n\\.\n"
        b"COPY public.other (id) FROM stdin;\n3\n\\.\n"
    )
    whole = await _rewritten(script, parents=_PARENTS)

    for size in (1, 2, 7, 23):
        parts = [script[i : i + size] for i in range(0, len(script), size)]
        assert await _rewritten(*parts, parents=_PARENTS) == whole
    assert b"COPY public.dns_rpz_hit (id) FROM stdin;" in whole
    assert b"COPY public.other (id) FROM stdin;" in whole


async def test_a_row_that_looks_like_a_copy_head_is_data() -> None:
    row = b"COPY public.dns_rpz_hit_p20261027 (id) FROM stdin;\n"
    script = b"COPY public.dns_rpz_hit_p20261027 (qname) FROM stdin;\n" + row + b"\\.\n"

    out = await _rewritten(script, parents=_PARENTS)

    assert out == b"COPY public.dns_rpz_hit (qname) FROM stdin;\n" + row + b"\\.\n"


async def test_a_script_with_no_partitions_in_it_passes_through_untouched() -> None:
    script = b"COPY public.subnet (id) FROM stdin;\n1\n\\.\nSELECT 1;"

    assert await _rewritten(script, parents=_PARENTS) == script
