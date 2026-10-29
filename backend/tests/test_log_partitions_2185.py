"""#2185 — the agent-shipped log tables are time-partitioned.

Covers the lifecycle in ``app.services.logs.partitions`` (create ahead, retire,
the hourly / daily grain, the detach-pending recovery, orphans, the advisory
lock), what ingest does with a line no partition can hold, and the migration.

The suite's schema carries daily partitions around "now" (``conftest``). The
lifecycle tests start from none, at a fixed clock, and put them back after.
"""

from __future__ import annotations

import importlib.util
import pathlib
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from types import ModuleType

import pytest
import pytest_asyncio
from alembic.migration import MigrationContext
from alembic.operations import Operations
from httpx import AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.models.dns_rpz_hit import DNSRPZHit
from app.models.feature_module import FeatureModule
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.services.logs import partitions as lp
from app.services.logs.partitions import (
    DHCP_LOG,
    DNS_QUERY_LOG,
    DNS_RPZ_HIT,
    LOG_TABLES,
    Coverage,
    coverage,
    list_partitions,
    maintain,
)
from tests.conftest import _test_engine, create_test_log_partitions
from tests.test_agent_spool_ingest import (
    _bind_line,
    _dhcp_server,
    _dns_server,
    _kea_line,
    _post,
)

NOW = datetime(2026, 10, 27, 13, 20, tzinfo=UTC)


def _t(day: int, hour: int = 0, month: int = 10) -> datetime:
    return datetime(2026, month, day, hour, tzinfo=UTC)


# ── fixtures ──────────────────────────────────────────────────────────────


async def _drop_all_partitions(conn: AsyncConnection) -> None:
    for table in LOG_TABLES:
        for p in await list_partitions(conn, table.name):
            await conn.exec_driver_sql(f'DROP TABLE "{p.name}"')
        rows = await conn.execute(
            text(
                "SELECT relname FROM pg_class WHERE relkind = 'r' AND NOT relispartition "
                "AND relname ~ :p"
            ),
            {"p": lp._orphan_pattern(table.name)},
        )
        for (name,) in rows.fetchall():
            await conn.exec_driver_sql(f'DROP TABLE "{name}"')


@pytest_asyncio.fixture
async def bare() -> AsyncGenerator[AsyncConnection, None]:
    """An autocommit connection, with the three log tables left without partitions."""
    async with _test_engine.connect() as conn:
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await _drop_all_partitions(conn)
        lp.invalidate_coverage_cache()
        yield conn
        await _drop_all_partitions(conn)
        await create_test_log_partitions(conn)
        lp.invalidate_coverage_cache()


async def _bounds(conn: AsyncConnection, table: str) -> list[tuple[datetime, datetime]]:
    parts = await list_partitions(conn, table)
    return sorted((p.lower, p.upper) for p in parts if p.lower and p.upper)  # type: ignore[type-var]


def _assert_contiguous(bounds: list[tuple[datetime, datetime]]) -> None:
    for (_, upper), (lower, _) in zip(bounds, bounds[1:], strict=False):
        assert upper == lower, "partitions overlap or leave a gap"


# ── creating ahead ────────────────────────────────────────────────────────


async def test_creates_hourly_partitions_for_a_short_window(bare: AsyncConnection) -> None:
    result = await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)

    bounds = await _bounds(bare, DNS_QUERY_LOG.name)
    # From the hour the window starts at to the first hour past now + 24 h.
    assert bounds[0] == (_t(26, 13), _t(26, 14))
    assert bounds[-1] == (_t(28, 13), _t(28, 14))
    assert len(bounds) == result.created == 49
    _assert_contiguous(bounds)
    names = {p.name for p in await list_partitions(bare, DNS_QUERY_LOG.name)}
    assert "dns_query_log_entry_p2026102613" in names


async def test_a_converged_table_costs_no_ddl(bare: AsyncConnection) -> None:
    await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)
    again = await maintain(bare, DNS_QUERY_LOG, 24, now=NOW + timedelta(minutes=15))

    assert (again.created, again.dropped, again.failed) == (0, 0, 0)


async def test_every_other_table_and_a_long_dns_window_are_daily(bare: AsyncConnection) -> None:
    await maintain(bare, DNS_QUERY_LOG, 72, now=NOW)
    await maintain(bare, DHCP_LOG, 24, now=NOW)
    await maintain(bare, DNS_RPZ_HIT, 24, now=NOW)

    # The DNS window is three days: whole days from the one the window starts in
    # to the one three days ahead. DHCP follows the setting, RPZ is thirty days.
    assert (await _bounds(bare, DNS_QUERY_LOG.name))[0] == (_t(24), _t(25))
    assert (await _bounds(bare, DNS_QUERY_LOG.name))[-1] == (_t(30), _t(31))
    dhcp = await _bounds(bare, DHCP_LOG.name)
    assert (dhcp[0][0], dhcp[-1][1]) == (_t(26), _t(31))
    rpz = await _bounds(bare, DNS_RPZ_HIT.name)
    assert (rpz[0][0], rpz[-1][1]) == (_t(27, month=9), _t(31))
    for table in LOG_TABLES:
        _assert_contiguous(await _bounds(bare, table.name))
    names = {p.name for p in await list_partitions(bare, DHCP_LOG.name)}
    assert "dhcp_log_entry_p20261026" in names


async def test_changing_the_window_never_overlaps_partitions(bare: AsyncConnection) -> None:
    await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)

    longer = await maintain(bare, DNS_QUERY_LOG, 72, now=NOW)

    # Hourly ends at 14:00 on the 28th. The rest of that day is one partition,
    # then the new grain takes over.
    assert longer.created == 3
    bounds = await _bounds(bare, DNS_QUERY_LOG.name)
    assert bounds[-3:] == [(_t(28, 14), _t(29)), (_t(29), _t(30)), (_t(30), _t(31))]
    _assert_contiguous(bounds)
    names = {p.name for p in await list_partitions(bare, DNS_QUERY_LOG.name)}
    assert {"dns_query_log_entry_p2026102814", "dns_query_log_entry_p20261029"} <= names

    back = await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)

    assert back.created == 0


async def test_a_long_gap_is_not_filled_in(bare: AsyncConnection) -> None:
    await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)

    later = await maintain(bare, DNS_QUERY_LOG, 24, now=NOW + timedelta(days=3))

    # Nothing can have arrived for the days in between that the window still
    # wants: it starts where the clock minus the window says.
    bounds = await _bounds(bare, DNS_QUERY_LOG.name)
    assert later.created == 49
    assert later.dropped == 49
    assert bounds[0] == (_t(29, 13), _t(29, 14))
    assert bounds[-1] == (_t(31, 13), _t(31, 14))


# ── retiring ──────────────────────────────────────────────────────────────


async def test_retires_only_partitions_wholly_past_the_window(bare: AsyncConnection) -> None:
    await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)

    result = await maintain(bare, DNS_QUERY_LOG, 24, now=NOW + timedelta(hours=2))

    # 15:20 minus 24 h is 15:20 yesterday: the partitions ending by then go, the
    # one that still holds rows inside the window stays.
    assert result.dropped == 2
    bounds = await _bounds(bare, DNS_QUERY_LOG.name)
    assert bounds[0] == (_t(26, 15), _t(26, 16))


async def test_a_shorter_window_drops_more(bare: AsyncConnection) -> None:
    await maintain(bare, DHCP_LOG, 72, now=NOW)

    result = await maintain(bare, DHCP_LOG, 24, now=NOW)

    assert result.dropped == 2  # the 24th and the 25th: wholly past now - 24 h
    assert (await _bounds(bare, DHCP_LOG.name))[0][0] == _t(26)


async def test_rows_in_a_retired_partition_go_with_it(
    bare: AsyncConnection, db_session: AsyncSession
) -> None:
    await maintain(bare, DHCP_LOG, 24, now=datetime.now(UTC))
    server = await _dhcp_server(db_session)
    old = datetime.now(UTC) - timedelta(hours=20)
    db_session.add(DHCPLogEntry(server_id=server.id, ts=old, raw="old"))
    await db_session.commit()
    assert await db_session.scalar(select(func.count()).select_from(DHCPLogEntry)) == 1
    await db_session.rollback()  # a reader's open transaction would hold the partition

    later = datetime.now(UTC) + timedelta(days=2)
    await maintain(bare, DHCP_LOG, 24, now=later)

    assert await db_session.scalar(select(func.count()).select_from(DHCPLogEntry)) == 0


async def test_a_default_partition_does_not_stop_retention(bare: AsyncConnection) -> None:
    """PostgreSQL refuses ``DETACH ... CONCURRENTLY`` when a default exists; one that an
    operator added must not wedge retention."""
    await maintain(bare, DHCP_LOG, 24, now=NOW)
    await bare.exec_driver_sql(
        "CREATE TABLE dhcp_log_entry_pdefault PARTITION OF dhcp_log_entry DEFAULT"
    )

    result = await maintain(bare, DHCP_LOG, 24, now=NOW + timedelta(days=2))

    assert result.dropped == 2
    assert result.failed == 0


# ── when DDL cannot get its lock ──────────────────────────────────────────


async def test_a_concurrent_detach_that_times_out_is_finished_by_the_next_tick(
    bare: AsyncConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lp, "LOCK_TIMEOUT_MS", 300)
    await maintain(bare, DNS_QUERY_LOG, 24, now=NOW)
    later = NOW + timedelta(hours=1)

    async with _test_engine.connect() as reader:
        # A transaction that has read the table holds the partition open.
        await reader.execute(text("SELECT count(*) FROM dns_query_log_entry"))
        stuck = await maintain(bare, DNS_QUERY_LOG, 24, now=later)
        await reader.rollback()

    assert stuck.failed == 1
    assert stuck.dropped == 0
    pending = [p for p in await list_partitions(bare, DNS_QUERY_LOG.name) if p.detach_pending]
    assert len(pending) == 1
    # A pending partition no longer counts as something ingest can store into.
    lp.invalidate_coverage_cache()

    done = await maintain(bare, DNS_QUERY_LOG, 24, now=later)

    assert done.finalized == 1
    assert done.dropped == 1
    assert not [p for p in await list_partitions(bare, DNS_QUERY_LOG.name) if p.detach_pending]
    assert pending[0].name not in {p.name for p in await list_partitions(bare, DNS_QUERY_LOG.name)}


async def test_an_attach_that_times_out_leaves_no_orphan_and_is_retried(
    bare: AsyncConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lp, "LOCK_TIMEOUT_MS", 300)

    async with _test_engine.connect() as holder:
        # SHARE conflicts with the SHARE UPDATE EXCLUSIVE an attach takes.
        await holder.execute(text("LOCK TABLE dhcp_log_entry IN SHARE MODE"))
        blocked = await maintain(bare, DHCP_LOG, 24, now=NOW)
        await holder.rollback()

    assert blocked.created == 0
    assert blocked.failed == 1
    leftovers = await bare.execute(
        text(
            "SELECT relname FROM pg_class WHERE relname LIKE 'dhcp_log_entry_p%' AND relkind = 'r'"
        )
    )
    assert leftovers.fetchall() == []

    retried = await maintain(bare, DHCP_LOG, 24, now=NOW)

    assert retried.created == 5
    assert retried.failed == 0


async def test_a_table_left_by_a_crash_is_dropped(bare: AsyncConnection) -> None:
    # What a crash between the CREATE and the ATTACH, or between the DETACH and
    # the DROP, leaves behind. A name that is not one of ours is left alone.
    await bare.exec_driver_sql("CREATE TABLE dhcp_log_entry_p20200101 (LIKE dhcp_log_entry)")
    await bare.exec_driver_sql("CREATE TABLE dhcp_log_entry_notes (id int)")

    result = await maintain(bare, DHCP_LOG, 24, now=NOW)

    assert result.orphans_dropped == 1
    names = await bare.execute(
        text("SELECT relname FROM pg_class WHERE relname LIKE 'dhcp_log_entry_%'")
    )
    found = {n for (n,) in names}
    assert "dhcp_log_entry_p20200101" not in found
    assert "dhcp_log_entry_notes" in found
    await bare.exec_driver_sql("DROP TABLE dhcp_log_entry_notes")


async def test_a_second_worker_skips_a_table_that_is_being_maintained(
    bare: AsyncConnection,
) -> None:
    key = {"ns": lp.LOCK_NAMESPACE, "t": DHCP_LOG.name}
    async with _test_engine.connect() as other:
        other = await other.execution_options(isolation_level="AUTOCOMMIT")
        await other.execute(text("SELECT pg_advisory_lock(:ns, hashtext(:t))"), key)
        try:
            skipped = await maintain(bare, DHCP_LOG, 24, now=NOW)
        finally:
            await other.execute(text("SELECT pg_advisory_unlock(:ns, hashtext(:t))"), key)

    assert skipped.skipped_locked
    assert skipped.created == 0
    assert (await maintain(bare, DHCP_LOG, 24, now=NOW)).created == 5


# ── what ingest may store ─────────────────────────────────────────────────


async def test_coverage_is_the_range_the_attached_partitions_span(
    bare: AsyncConnection, db_session: AsyncSession
) -> None:
    assert await coverage(db_session, DHCP_LOG) == Coverage(None, None)
    assert not (await coverage(db_session, DHCP_LOG)).contains(NOW)

    await maintain(bare, DHCP_LOG, 24, now=NOW)
    lp.invalidate_coverage_cache()
    cov = await coverage(db_session, DHCP_LOG)

    assert (cov.lower, cov.upper) == (_t(26), _t(31))
    assert cov.contains(_t(26))
    assert cov.contains(_t(30, 23))
    assert not cov.contains(_t(31))
    assert not cov.contains(_t(25, 23))
    assert cov.contains(datetime(2026, 10, 27, 12, 0))  # naive means UTC


async def test_ingest_counts_a_line_dated_beyond_the_partitions_as_expired(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    dns = await _dns_server(db_session)
    dhcp = await _dhcp_server(db_session)
    now = datetime.now(UTC)
    far = now + timedelta(days=30)

    r = await _post(
        client,
        "dns",
        dns,
        "query-log-entries",
        {"lines": [_bind_line(far, "future.example"), _bind_line(now, "now.example")]},
    )
    assert r.status_code == 200, r.text
    assert (r.json()["inserted"], r.json()["expired"]) == (1, 1)

    r = await _post(
        client,
        "dhcp",
        dhcp,
        "log-entries",
        {"lines": [_kea_line(far, "aa:bb:cc:dd:ee:01"), _kea_line(now, "aa:bb:cc:dd:ee:02")]},
    )
    assert r.status_code == 200, r.text
    assert (r.json()["inserted"], r.json()["expired"]) == (1, 1)
    names = (await db_session.execute(select(DNSQueryLogEntry.qname))).scalars().all()
    assert names == ["now.example"]


async def test_ingest_into_a_table_with_no_partitions_drops_instead_of_failing(
    client: AsyncClient, db_session: AsyncSession, bare: AsyncConnection
) -> None:
    dns = await _dns_server(db_session)
    dhcp = await _dhcp_server(db_session)
    now = datetime.now(UTC)

    r = await _post(
        client, "dns", dns, "query-log-entries", {"lines": [_bind_line(now, "a.example")]}
    )
    assert r.status_code == 200, r.text
    assert (r.json()["inserted"], r.json()["expired"]) == (0, 1)

    r = await _post(
        client, "dhcp", dhcp, "log-entries", {"lines": [_kea_line(now, "aa:bb:cc:dd:ee:01")]}
    )
    assert r.status_code == 200, r.text
    assert (r.json()["inserted"], r.json()["expired"]) == (0, 1)


_RPZ = (
    "{ts} rpz: info: client @0x7f8 192.0.2.5#54321 (ads.tracker.example): view default: "
    "rpz QNAME NXDOMAIN rewrite ads.tracker.example via ads.tracker.example.blocklist.rpz"
)


async def test_ingest_counts_an_rpz_hit_beyond_the_partitions_as_expired(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(FeatureModule(id="security.dns_threat", enabled=True))
    await db_session.commit()
    dns = await _dns_server(db_session)
    now = datetime.now(UTC)
    stamp = "%d-%b-%Y %H:%M:%S.000"

    r = await _post(
        client,
        "dns",
        dns,
        "query-log-entries",
        {
            "lines": [
                _RPZ.format(ts=now.strftime(stamp)),
                _RPZ.format(ts=(now + timedelta(days=30)).strftime(stamp)),
            ]
        },
    )

    assert r.status_code == 200, r.text
    assert (r.json()["rpz_inserted"], r.json()["expired"]) == (1, 1)
    assert await db_session.scalar(select(func.count()).select_from(DNSRPZHit)) == 1


# ── the table behaves as the one it replaced ──────────────────────────────


async def test_an_insert_that_names_no_id_gets_the_next_one(db_session: AsyncSession) -> None:
    """What the previous release's pods do: ``INSERT`` without an ``id``."""
    dns = await _dns_server(db_session)
    now = datetime.now(UTC)
    for q in ("a", "b"):
        await db_session.execute(
            text(
                "INSERT INTO dns_query_log_entry (server_id, ts, qname, raw) VALUES (:s, :t, :q, '')"
            ),
            {"s": dns.id, "t": now, "q": q},
        )
    await db_session.commit()

    ids = (
        (await db_session.execute(select(DNSQueryLogEntry.id).order_by(DNSQueryLogEntry.id)))
        .scalars()
        .all()
    )

    assert len(ids) == 2 and ids[0] < ids[1]


async def test_a_servers_log_rows_go_when_the_server_does(db_session: AsyncSession) -> None:
    dns = await _dns_server(db_session)
    db_session.add(DNSQueryLogEntry(server_id=dns.id, ts=datetime.now(UTC), qname="a", raw=""))
    await db_session.commit()

    await db_session.execute(text("DELETE FROM dns_server WHERE id = :i"), {"i": dns.id})
    await db_session.commit()

    assert await db_session.scalar(select(func.count()).select_from(DNSQueryLogEntry)) == 0


# ── the migration ─────────────────────────────────────────────────────────

_NAMES = [t.name for t in LOG_TABLES]
_MIGRATION = next(
    (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions").glob("e5a93c1b7d24_*.py")
)

_LEGACY_DDL = {
    "dns_query_log_entry": """
        CREATE TABLE dns_query_log_entry (
          id bigserial PRIMARY KEY,
          server_id uuid NOT NULL REFERENCES dns_server (id) ON DELETE CASCADE,
          ts timestamptz NOT NULL, client_ip inet, client_port integer, qname varchar(512),
          qclass varchar(8), qtype varchar(16), flags varchar(64), view varchar(255),
          raw text NOT NULL DEFAULT '', rcode varchar(16), answer_count integer);
        CREATE INDEX ix_dns_query_log_server_ts ON dns_query_log_entry (server_id, ts);
        CREATE INDEX ix_dns_query_log_ts ON dns_query_log_entry (ts)""",
    "dhcp_log_entry": """
        CREATE TABLE dhcp_log_entry (
          id bigserial PRIMARY KEY,
          server_id uuid NOT NULL REFERENCES dhcp_server (id) ON DELETE CASCADE,
          ts timestamptz NOT NULL, severity varchar(16), code varchar(64), mac_address macaddr,
          ip_address inet, transaction_id varchar(32), raw text NOT NULL DEFAULT '');
        CREATE INDEX ix_dhcp_log_server_ts ON dhcp_log_entry (server_id, ts);
        CREATE INDEX ix_dhcp_log_ts ON dhcp_log_entry (ts)""",
    "dns_rpz_hit": """
        CREATE TABLE dns_rpz_hit (
          id bigserial PRIMARY KEY,
          server_id uuid NOT NULL REFERENCES dns_server (id) ON DELETE CASCADE,
          ts timestamptz NOT NULL, client_ip inet, qname varchar(512), trigger varchar(16) NOT NULL,
          policy varchar(16) NOT NULL, rpz_zone varchar(255), raw text NOT NULL DEFAULT '');
        CREATE INDEX ix_dns_rpz_hit_client_ts ON dns_rpz_hit (client_ip, ts);
        CREATE INDEX ix_dns_rpz_hit_ts ON dns_rpz_hit (ts);
        CREATE INDEX ix_dns_rpz_hit_zone_ts ON dns_rpz_hit (rpz_zone, ts)""",
}


def _migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("e5a93c1b7d24", _MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(sync_conn: object, direction: str) -> None:
    with Operations.context(MigrationContext.configure(connection=sync_conn)):
        getattr(_migration(), direction)()


@pytest_asyncio.fixture
async def legacy() -> AsyncGenerator[tuple[AsyncConnection, uuid.UUID, uuid.UUID], None]:
    """The three tables as the previous release had them, with a row each, in a
    transaction that is rolled back."""
    async with _test_engine.connect() as conn:
        trans = await conn.begin()
        try:
            async with AsyncSession(bind=conn, expire_on_commit=False) as session:
                dns = (await _dns_server(session)).id
                dhcp = (await _dhcp_server(session)).id
            for table in _NAMES:
                await conn.exec_driver_sql(f"DROP TABLE {table} CASCADE")
            for ddl in _LEGACY_DDL.values():
                for stmt in ddl.split(";"):
                    await conn.exec_driver_sql(stmt)
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
            await conn.execute(
                text(
                    "INSERT INTO dns_rpz_hit (server_id, ts, trigger, policy) "
                    "VALUES (:s, now(), 'QNAME', 'NXDOMAIN')"
                ),
                {"s": dns},
            )
            yield conn, dns, dhcp
        finally:
            await trans.rollback()


async def _scalar(conn: AsyncConnection, sql: str) -> object:
    return (await conn.execute(text(sql))).scalar()


async def test_the_migration_swaps_each_table_and_keeps_the_old_rows(
    legacy: tuple[AsyncConnection, uuid.UUID, uuid.UUID],
) -> None:
    conn, dns, _dhcp = legacy
    before = await _scalar(conn, "SELECT max(id) FROM dns_query_log_entry")

    await conn.run_sync(_run, "upgrade")

    for table in _NAMES:
        kind = await _scalar(conn, f"SELECT relkind::text FROM pg_class WHERE relname = '{table}'")
        assert kind == "p"
        assert await _scalar(conn, f"SELECT count(*) FROM {table}") == 0
        assert await _scalar(conn, f"SELECT count(*) FROM {table}_legacy") == 1
        # Constraints and indexes moved with the legacy table; none clash.
        names = (
            (
                await conn.execute(
                    text(
                        "SELECT indexrelid::regclass::text FROM pg_index "
                        "WHERE indrelid = CAST(:t AS regclass) ORDER BY 1"
                    ),
                    {"t": f"{table}_legacy"},
                )
            )
            .scalars()
            .all()
        )
        assert names and all(n.endswith("_legacy") for n in names)
    pk = await _scalar(
        conn,
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'dns_query_log_entry'::regclass AND contype = 'p'",
    )
    assert pk == "PRIMARY KEY (id, ts)"
    fk = await _scalar(
        conn,
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'dns_query_log_entry'::regclass AND contype = 'f'",
    )
    assert fk == "FOREIGN KEY (server_id) REFERENCES dns_server(id) ON DELETE CASCADE"

    # The previous release's pods insert without an id, into the new table,
    # and the ids carry on from where the legacy table stopped.
    await conn.execute(
        text(
            "INSERT INTO dns_query_log_entry (server_id, ts, qname) VALUES (:s, now(), 'new.example')"
        ),
        {"s": dns},
    )
    assert await _scalar(conn, "SELECT id FROM dns_query_log_entry") == before + 1
    # And the sequence now belongs to the new table.
    owner = await _scalar(
        conn,
        "SELECT d.refobjid::regclass::text FROM pg_depend d "
        "WHERE d.objid = pg_get_serial_sequence('dns_query_log_entry', 'id')::regclass "
        "AND d.deptype = 'a'",
    )
    assert owner == "dns_query_log_entry"


async def test_the_migration_covers_the_retention_windows(
    legacy: tuple[AsyncConnection, uuid.UUID, uuid.UUID],
) -> None:
    conn, dns, dhcp = legacy
    await conn.run_sync(_run, "upgrade")

    now = datetime.now(UTC)
    for table, days in (("dns_query_log_entry", 7), ("dhcp_log_entry", 7), ("dns_rpz_hit", 30)):
        parts = await list_partitions(conn, table)
        lower, upper = min(p.lower for p in parts), max(p.upper for p in parts)  # type: ignore[type-var]
        assert lower <= now - timedelta(days=days), table
        assert upper > now + timedelta(hours=24), table
        _assert_contiguous(sorted((p.lower, p.upper) for p in parts))  # type: ignore[type-var]
    # ``maintain_log_partitions`` picks up where the migration stopped.
    await conn.exec_driver_sql("SET lock_timeout = 3000")
    daily = lp.MaintenanceResult(DHCP_LOG.name)
    await lp._create_ahead(conn, DHCP_LOG, DHCP_LOG.window(24), now, daily)  # noqa: SLF001
    assert daily.created >= 1
    _assert_contiguous(await _bounds(conn, DHCP_LOG.name))


async def test_the_migration_downgrade_parks_the_new_tables_and_restores_the_old(
    legacy: tuple[AsyncConnection, uuid.UUID, uuid.UUID],
) -> None:
    conn, dns, _dhcp = legacy
    await conn.run_sync(_run, "upgrade")
    await conn.execute(
        text(
            "INSERT INTO dns_query_log_entry (server_id, ts, qname) VALUES (:s, now(), 'mid.example')"
        ),
        {"s": dns},
    )

    await conn.run_sync(_run, "downgrade")

    for table in _NAMES:
        assert (
            await _scalar(conn, f"SELECT relkind::text FROM pg_class WHERE relname = '{table}'")
            == "r"
        )
        assert await _scalar(conn, f"SELECT to_regclass('{table}_legacy')") is None
        assert (
            await _scalar(
                conn, f"SELECT relkind::text FROM pg_class WHERE relname = '{table}_partitioned'"
            )
            == "p"
        )
    # Nothing was lost: the rows written under the new release are parked, and
    # the legacy rows are back where the previous release reads them.
    assert await _scalar(conn, "SELECT count(*) FROM dns_query_log_entry_partitioned") == 1
    assert await _scalar(conn, "SELECT qname FROM dns_query_log_entry") == "old.example"
    pk = await _scalar(
        conn,
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'dns_query_log_entry'::regclass AND contype = 'p'",
    )
    assert pk == "PRIMARY KEY (id)"
    # The sequence belongs to the table that is live again, and it still counts.
    await conn.execute(
        text(
            "INSERT INTO dns_query_log_entry (server_id, ts, qname) VALUES (:s, now(), 'back.example')"
        ),
        {"s": dns},
    )
    assert await _scalar(conn, "SELECT count(*) FROM dns_query_log_entry") == 2

    # Up again, as after a rollback that was undone: the parked set is not in the way.
    await conn.run_sync(_run, "upgrade")
    assert (
        await _scalar(
            conn, "SELECT relkind::text FROM pg_class WHERE relname = 'dns_query_log_entry'"
        )
        == "p"
    )
    assert await _scalar(conn, "SELECT count(*) FROM dns_query_log_entry_legacy") == 2
