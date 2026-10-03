"""A feed refresh runs in bounded memory and is not redelivered after a kill (#1466).

The catalog's Hagezi Gambling feed is ~580k domains. The refresh loaded every
existing entry as an ORM entity and added one tracked ``DNSBlockListEntry``
per new domain, which OOM-killed a 1.4 GiB worker on every attempt. Because
the task was acked late with ``task_reject_on_worker_lost``, the killed
message went back to the broker and took down the next worker an hour later,
indefinitely.

These tests drive the real ``_refresh_blocklist_feed_async`` against the test
session (the harness ``test_dns_blocklists.test_feed_sync_counts_and_wildcards``
uses), and count ORM instances with mapper events rather than measuring
memory, so the property is pinned deterministically.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.tasks import dns as dns_tasks


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


def _wire(monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, body: str) -> None:
    class _Resp:
        text = body

        def raise_for_status(self) -> None:
            return None

    class _Client:
        def __init__(self, *a: object, **kw: object) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: object) -> None:
            return None

        async def get(self, _url: str) -> _Resp:
            return _Resp()

    monkeypatch.setattr(dns_tasks.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)


@contextlib.contextmanager
def _count_entry_instances() -> Iterator[dict[str, int]]:
    """Count ``DNSBlockListEntry`` objects constructed or loaded from the DB."""
    counts = {"init": 0, "load": 0}

    def _on_init(*_a: object, **_kw: object) -> None:
        counts["init"] += 1

    def _on_load(*_a: object, **_kw: object) -> None:
        counts["load"] += 1

    event.listen(DNSBlockListEntry, "init", _on_init)
    event.listen(DNSBlockListEntry, "load", _on_load)
    try:
        yield counts
    finally:
        event.remove(DNSBlockListEntry, "init", _on_init)
        event.remove(DNSBlockListEntry, "load", _on_load)


async def _make_list(db_session: AsyncSession) -> DNSBlockList:
    bl = DNSBlockList(
        name="bounded",
        source_type="url",
        feed_url="http://example.com/list.txt",
        feed_format="domains",
    )
    db_session.add(bl)
    await db_session.flush()
    return bl


async def _domains(db_session: AsyncSession, bl: DNSBlockList) -> dict[str, str]:
    rows = await db_session.execute(
        select(DNSBlockListEntry.domain, DNSBlockListEntry.source).where(
            DNSBlockListEntry.list_id == bl.id
        )
    )
    return {d: s for d, s in rows.tuples()}


@pytest.mark.asyncio
async def test_refresh_never_builds_an_orm_entity_per_entry(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    bl = await _make_list(db_session)
    for i in range(50):
        db_session.add(DNSBlockListEntry(list_id=bl.id, domain=f"old{i}.example", source="feed"))
    await db_session.commit()
    db_session.expunge_all()

    body = "".join(f"new{i}.example\n" for i in range(2000))
    _wire(monkeypatch, db_session, body)

    with _count_entry_instances() as counts:
        out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out == {"status": "success", "added": 2000, "removed": 50}
    # Before #1466: 2000 constructed + 50 loaded. Memory is proportional to
    # these counts, which is what took down the worker on a 580k feed.
    assert counts == {"init": 0, "load": 0}

    now = await _domains(db_session, bl)
    assert len(now) == 2000
    assert all(d.startswith("new") for d in now)


@pytest.mark.asyncio
async def test_refresh_across_several_batches_adds_prunes_and_counts(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dns_tasks, "_FEED_WRITE_BATCH", 3)
    bl = await _make_list(db_session)
    for d in ("keep1.example", "keep2.example", "drop1.example", "drop2.example"):
        db_session.add(DNSBlockListEntry(list_id=bl.id, domain=d, source="feed"))
    db_session.add(DNSBlockListEntry(list_id=bl.id, domain="mine.example", source="manual"))
    await db_session.commit()

    added = [f"add{i}.example" for i in range(7)]
    _wire(monkeypatch, db_session, "\n".join(["keep1.example", "keep2.example", *added]) + "\n")

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out == {"status": "success", "added": 7, "removed": 2}

    now = await _domains(db_session, bl)
    assert set(now) == {"keep1.example", "keep2.example", "mine.example", *added}
    assert now["mine.example"] == "manual"

    rows = (
        (
            await db_session.execute(
                select(DNSBlockListEntry).where(
                    DNSBlockListEntry.list_id == bl.id, DNSBlockListEntry.source == "feed"
                )
            )
        )
        .scalars()
        .all()
    )
    assert all(r.is_wildcard and r.entry_type == "block" for r in rows if r.domain in added)

    await db_session.refresh(bl)
    assert bl.entry_count == 10
    assert bl.last_sync_status == "success"


@pytest.mark.asyncio
async def test_a_feed_domain_already_added_by_hand_keeps_the_manual_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The list is unique on (list_id, domain). Inserting the feed's copy of a
    domain the operator added by hand used to fail the whole refresh on that
    constraint, so the feed never synced at all."""
    bl = await _make_list(db_session)
    db_session.add(DNSBlockListEntry(list_id=bl.id, domain="both.example", source="manual"))
    await db_session.commit()

    _wire(monkeypatch, db_session, "both.example\nfeed-only.example\n")

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out == {"status": "success", "added": 1, "removed": 0}

    now = await _domains(db_session, bl)
    assert now == {"both.example": "manual", "feed-only.example": "feed"}


def test_refresh_task_is_acked_on_receipt() -> None:
    """A refresh that kills its worker must not be redelivered to the next one.

    The global config acks late and rejects on worker loss, which puts a
    killed message back on the queue after the visibility timeout. This task
    overrides that; a lost refresh is idempotent and re-queued by Refresh.
    """
    assert dns_tasks.refresh_blocklist_feed.acks_late is False
