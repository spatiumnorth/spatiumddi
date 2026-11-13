"""A feed refresh runs once per list, in bounded memory, and fails visibly (#4059).

Two refreshes of one large feed (subscribe queues one, Refresh queues
another) held two copies of the feed in the worker at once and OOM-killed it;
the killed refresh left the list empty with no error.
"""

from __future__ import annotations

import os
import tracemalloc

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.tasks import dns as dns_tasks
from tests.test_blocklist_feed_refresh_bounded import _domains, _make_list, _wire


@pytest.mark.asyncio
async def test_a_second_refresh_of_the_same_list_coalesces(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """While one worker holds the list's lock, another refresh fetches nothing."""
    bl = await _make_list(db_session)
    await db_session.commit()

    fetched: list[int] = []
    _wire(monkeypatch, db_session, "a.example\n")
    real_client = dns_tasks.httpx.AsyncClient

    class _Spy(real_client):  # type: ignore[misc, valid-type]
        async def get(self, *a: object, **kw: object):  # type: ignore[no-untyped-def]
            fetched.append(1)
            return await super().get(*a, **kw)

    monkeypatch.setattr(dns_tasks.httpx, "AsyncClient", _Spy)

    # A second, independent connection stands in for the running worker.
    other = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    async with other.connect() as holder:
        got = await holder.scalar(
            text("SELECT pg_try_advisory_lock(:c, hashtext(:i))"),
            {"c": dns_tasks._REFRESH_LOCK_CLASS, "i": str(bl.id)},
        )
        assert got is True
        out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
        assert out["status"] == "already_refreshing"
        assert fetched == []
        assert await _domains(db_session, bl) == {}
    await other.dispose()

    # Lock gone with the holder's connection: the next refresh runs.
    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out["status"] == "success"
    assert set(await _domains(db_session, bl)) == {"a.example"}


@pytest.mark.asyncio
async def test_the_lock_is_released_after_a_refresh(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    bl = await _make_list(db_session)
    await db_session.commit()
    _wire(monkeypatch, db_session, "a.example\n")
    await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    other = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    async with other.connect() as c:
        got = await c.scalar(
            text("SELECT pg_try_advisory_lock(:c, hashtext(:i))"),
            {"c": dns_tasks._REFRESH_LOCK_CLASS, "i": str(bl.id)},
        )
    await other.dispose()
    assert got is True


@pytest.mark.asyncio
async def test_a_failure_mid_apply_keeps_the_old_entries_and_records_it(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    bl = await _make_list(db_session)
    bl_id = bl.id
    for i in range(5):
        db_session.add(DNSBlockListEntry(list_id=bl.id, domain=f"old{i}.example", source="feed"))
    await db_session.commit()

    _wire(monkeypatch, db_session, "".join(f"new{i}.example\n" for i in range(50)))

    # Die after the new entries are written but before the commit.
    async def _boom(*_a: object, **_kw: object) -> None:
        raise RuntimeError("worker lost mid-apply")

    monkeypatch.setattr("app.services.dns.bundle_dirty.mark_bundles_dirty", _boom)

    with pytest.raises(RuntimeError):
        await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    rows = await db_session.execute(
        select(DNSBlockListEntry.domain).where(DNSBlockListEntry.list_id == bl_id)
    )
    assert {d for (d,) in rows.tuples()} == {f"old{i}.example" for i in range(5)}
    status, err, at = (
        await db_session.execute(
            select(
                DNSBlockList.last_sync_status,
                DNSBlockList.last_sync_error,
                DNSBlockList.last_synced_at,
            ).where(DNSBlockList.id == bl_id)
        )
    ).one()
    assert status == "error"
    assert err and "Refresh failed" in err
    assert at is not None


@pytest.mark.asyncio
async def test_refresh_peak_memory_on_a_large_feed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """500k-line feed against 200k existing feed rows: the existing rows are
    no longer read into Python and the raw body is dropped after parsing."""
    bl = await _make_list(db_session)
    await db_session.execute(
        text(
            "INSERT INTO dns_blocklist_entry (id, list_id, domain, entry_type, source, "
            "is_wildcard, reason) SELECT gen_random_uuid(), :l, 'old' || g || '.example.com', "
            "'block', 'feed', true, '' FROM generate_series(1, 200000) g"
        ),
        {"l": bl.id},
    )
    await db_session.commit()
    body = "".join(f"host{i}.example.com\n" for i in range(500_000))
    _wire(monkeypatch, db_session, body)
    del body

    tracemalloc.start()
    try:
        out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert out["added"] == 500_000 and out["removed"] == 200_000
    n = await db_session.scalar(select(DNSBlockList.entry_count).where(DNSBlockList.id == bl.id))
    assert n == 500_000
    assert peak < PEAK_LIMIT_MIB * 2**20


PEAK_LIMIT_MIB = 110  # measured: 140.7 MiB before the fix, 84.4 after
