"""#2185 — the agent-shipped log tables are time-partitioned.

Covers the lifecycle in ``app.services.logs.partitions`` (create ahead, retire,
the hourly / daily grain, the detach-pending recovery, orphans, the advisory
lock), the beat task, and what ingest does with a line no partition can hold.
The migration has its own file, ``test_migration_e5a93c1b7d24_partition_log_tables.py``.

The suite's schema carries daily partitions around "now" (``conftest``). The
lifecycle tests start from none, at a fixed clock, and put them back after.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
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


def _counts(r, *keys: str) -> tuple[int, ...]:  # type: ignore[no-untyped-def]
    assert r.status_code == 200, r.text
    return tuple(r.json()[k] for k in keys)


async def test_ingest_tells_a_line_no_partition_covers_from_an_expired_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    dns = await _dns_server(db_session)
    dhcp = await _dhcp_server(db_session)
    now = datetime.now(UTC)
    far = now + timedelta(days=30)
    old = now - timedelta(days=3)

    r = await _post(
        client,
        "dns",
        dns,
        "query-log-entries",
        {
            "lines": [
                _bind_line(far, "future.example"),
                _bind_line(old, "old.example"),
                _bind_line(now, "now.example"),
            ]
        },
    )
    assert _counts(r, "inserted", "expired", "no_partition") == (1, 1, 1)

    r = await _post(
        client,
        "dhcp",
        dhcp,
        "log-entries",
        {
            "lines": [
                _kea_line(far, "aa:bb:cc:dd:ee:01"),
                _kea_line(old, "aa:bb:cc:dd:ee:03"),
                _kea_line(now, "aa:bb:cc:dd:ee:02"),
            ]
        },
    )
    assert _counts(r, "inserted", "expired", "no_partition") == (1, 1, 1)
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
    assert _counts(r, "inserted", "expired", "no_partition") == (0, 0, 1)

    r = await _post(
        client, "dhcp", dhcp, "log-entries", {"lines": [_kea_line(now, "aa:bb:cc:dd:ee:01")]}
    )
    assert _counts(r, "inserted", "expired", "no_partition") == (0, 0, 1)


_RPZ = (
    "{ts} rpz: info: client @0x7f8 192.0.2.5#54321 (ads.tracker.example): view default: "
    "rpz QNAME NXDOMAIN rewrite ads.tracker.example via ads.tracker.example.blocklist.rpz"
)


async def test_ingest_sorts_rpz_hits_the_same_way(
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
                _RPZ.format(ts=(now - timedelta(days=40)).strftime(stamp)),
            ]
        },
    )

    assert _counts(r, "rpz_inserted", "expired", "no_partition") == (1, 1, 1)
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


# ── reading the catalog ───────────────────────────────────────────────────


async def test_bounds_read_the_same_whatever_the_session_date_style(bare: AsyncConnection) -> None:
    await maintain(bare, DHCP_LOG, 24, now=NOW)
    expected = await _bounds(bare, DHCP_LOG.name)

    await bare.exec_driver_sql("SET DateStyle = 'SQL, DMY'")
    await bare.exec_driver_sql("SET TimeZone = 'Asia/Seoul'")
    try:
        assert await _bounds(bare, DHCP_LOG.name) == expected
    finally:
        await bare.exec_driver_sql("RESET DateStyle")
        await bare.exec_driver_sql("RESET TimeZone")


# ── the beat task ─────────────────────────────────────────────────────────


async def test_the_beat_task_maintains_every_table_on_a_connection_that_can_detach(
    bare: AsyncConnection,
) -> None:
    """The task's own path: a session from the task engine, switched to
    AUTOCOMMIT, which ``DETACH ... CONCURRENTLY`` needs."""
    from app.tasks.log_partitions import _maintain_all

    today = datetime.now(UTC).date()
    stale = today - timedelta(days=10)
    await bare.exec_driver_sql(
        f"CREATE TABLE dhcp_log_entry_p{stale:%Y%m%d} PARTITION OF dhcp_log_entry "
        f"FOR VALUES FROM ('{stale} 00:00+00') TO ('{stale + timedelta(days=1)} 00:00+00')"
    )

    result = await _maintain_all()

    assert set(result) == {t.name for t in LOG_TABLES}
    assert all(r["failed"] == 0 and r["created"] > 0 for r in result.values()), result
    assert result["dhcp_log_entry"]["dropped"] == 1
    names = {p.name for p in await list_partitions(bare, DHCP_LOG.name)}
    assert f"dhcp_log_entry_p{stale:%Y%m%d}" not in names


async def test_one_table_failing_does_not_hold_up_the_others(
    bare: AsyncConnection, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks.log_partitions import _maintain_all

    real = lp.maintain

    async def flaky(conn, table, hours, **kw):  # type: ignore[no-untyped-def]
        if table is DNS_QUERY_LOG:
            raise ConnectionResetError("connection was closed in the middle of operation")
        return await real(conn, table, hours, **kw)

    monkeypatch.setattr(lp, "maintain", flaky)

    result = await _maintain_all()

    assert result["dns_query_log_entry"] == {"error": "ConnectionResetError"}
    assert result["dhcp_log_entry"]["created"] > 0
    assert result["dns_rpz_hit"]["created"] > 0


def test_beat_and_worker_start_queue_the_maintenance() -> None:
    from unittest.mock import patch

    from celery.signals import beat_init, worker_ready

    from app import celery_app as ca

    with patch.object(ca.celery_app, "send_task") as send:
        ca._queue_log_partitions_at_start()
    send.assert_called_once_with("app.tasks.log_partitions.maintain_log_partitions")
    with patch.object(ca.celery_app, "send_task", side_effect=OSError("no broker")):
        ca._queue_log_partitions_at_start()
    for signal in (beat_init, worker_ready):
        assert any(
            getattr(r(), "__name__", "") == "_queue_log_partitions_at_start"
            for _, r in signal.receivers
        )


# ── health ────────────────────────────────────────────────────────────────


async def test_health_says_when_current_lines_have_nowhere_to_go(
    bare: AsyncConnection, db_session: AsyncSession
) -> None:
    now = datetime.now(UTC)
    status, detail = await lp.partition_health(db_session, now=now)
    assert status == "error"
    assert "dns_query_log_entry" in detail

    for table in LOG_TABLES:
        await maintain(bare, table, 24, now=now)
    lp.invalidate_coverage_cache()
    assert (await lp.partition_health(db_session, now=now))[0] == "ok"

    # Twenty hours without maintenance: the hourly table has four left of its 24.
    lp.invalidate_coverage_cache()
    status, detail = await lp.partition_health(db_session, now=now + timedelta(hours=20))
    assert status == "warn"
    assert "dns_query_log_entry" in detail


async def test_platform_health_lists_the_log_partitions(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.celery_app import celery_app
    from tests._signed_in import signed_in_headers
    from tests.test_platform_health_worker_ping import _CountingControl, _FakeRedis

    monkeypatch.setattr(celery_app, "control", _CountingControl())
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis())

    r = await client.get("/health/platform", headers=await signed_in_headers(db_session))

    assert r.status_code == 200, r.text
    component = next(c for c in r.json()["components"] if c["name"] == "log-partitions")
    assert component["status"] == "ok", component
