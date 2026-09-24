"""The dirty mark's row locks (#1111, review item A).

The mark is an ``UPDATE dns_server`` — a row lock on every server it bumps.
Issued at the first marking flush, those locks are held until the
transaction ends: a long transaction stalls the heartbeats and the
long-poll's ``last_config_etag`` commit of every server it marked, and two
transactions marking overlapping server sets in different orders deadlock.
The mark is instead collected per flush and issued once, at commit, in
server-id order — the locks live for the commit alone and every marker takes
them in the same order.

These run against the real Postgres the suite already needs; each opens a
second connection of its own to play the concurrent writer.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone


def _sessions() -> tuple[object, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def _group(db: AsyncSession) -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return server, zone


def _record(zone: DNSZone, name: str) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value="10.9.9.9",
    )


async def _seq(db: AsyncSession, server_id: uuid.UUID) -> int:
    return int(
        (
            await db.execute(select(DNSServer.bundle_dirty_seq).where(DNSServer.id == server_id))
        ).scalar_one()
    )


@pytest.mark.asyncio
async def test_a_marking_flush_holds_no_server_row_lock_until_commit(
    db_session: AsyncSession,
) -> None:
    """A transaction that has flushed a record change and is still open must
    not hold its servers' rows: the long-poll's ``last_config_etag`` commit
    and the heartbeat write those rows on every poll."""
    server, zone = await _group(db_session)
    await db_session.commit()
    server_id = server.id
    before = await _seq(db_session, server_id)

    engine, factory = _sessions()
    try:
        db_session.add(_record(zone, "held"))
        await db_session.flush()  # the change is in; the transaction stays open

        async with factory() as other:
            await other.execute(text("SET LOCAL lock_timeout = '1s'"))
            try:
                await other.execute(
                    update(DNSServer)
                    .where(DNSServer.id == server_id)
                    .values(last_config_etag="sha256:" + "a" * 64)
                )
            except DBAPIError as exc:
                pytest.fail(
                    "the long-poll's last_config_etag write waited on the server "
                    "row a still-open transaction locked when its flush marked the "
                    f"bundle: {type(exc.orig).__name__}: {exc.orig}"
                )
            await other.commit()

        await db_session.commit()
        assert await _seq(db_session, server_id) == before + 1, "the mark still lands"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_marks_over_overlapping_servers_in_opposite_orders_do_not_deadlock(
    db_session: AsyncSession,
) -> None:
    """T1 marks group A then group B, T2 marks B then A, interleaved flush by
    flush. With the lock taken at each flush that is the textbook deadlock
    (Postgres aborts one after ``deadlock_timeout``); with every lock taken
    at commit in id order the second committer simply waits."""
    server_a, zone_a = await _group(db_session)
    server_b, zone_b = await _group(db_session)
    await db_session.commit()
    ids = (server_a.id, server_b.id)
    before = {sid: await _seq(db_session, sid) for sid in ids}

    engine, factory = _sessions()
    try:
        async with factory() as t1, factory() as t2:
            t1.add(_record(zone_a, "t1-a"))
            await t1.flush()
            t2.add(_record(zone_b, "t2-b"))
            await t2.flush()

            async def second(db: AsyncSession, zone: DNSZone, name: str) -> None:
                db.add(_record(zone, name))
                await db.flush()
                await db.commit()

            results = await asyncio.wait_for(
                asyncio.gather(
                    second(t1, zone_b, "t1-b"),
                    second(t2, zone_a, "t2-a"),
                    return_exceptions=True,
                ),
                timeout=30,
            )
        errors = [r for r in results if isinstance(r, BaseException)]
        assert not errors, (
            "two transactions marking overlapping servers in opposite orders "
            f"aborted: {[f'{type(e).__name__}: {e}' for e in errors]}"
        )
        for sid in ids:
            assert await _seq(db_session, sid) == before[sid] + 2, "both marks landed"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_the_commits_own_final_flush_is_marked(db_session: AsyncSession) -> None:
    """``before_commit`` fires BEFORE commit's final autoflush
    (``SessionTransaction._prepare_impl``): a change still pending when
    ``commit()`` is called must be marked all the same."""
    server, zone = await _group(db_session)
    await db_session.commit()
    before = await _seq(db_session, server.id)

    db_session.add(_record(zone, "late"))  # no explicit flush
    await db_session.commit()

    assert await _seq(db_session, server.id) == before + 1


@pytest.mark.asyncio
async def test_a_savepoint_release_takes_no_server_row_lock(db_session: AsyncSession) -> None:
    """``before_commit`` also fires when a savepoint is RELEASED; the mark must
    wait for the outermost commit, or a transaction that uses savepoints holds
    the locks from its first release to its end."""
    server, zone = await _group(db_session)
    await db_session.commit()
    server_id = server.id
    before = await _seq(db_session, server_id)

    engine, factory = _sessions()
    try:
        async with db_session.begin_nested():
            db_session.add(_record(zone, "released"))
        async with factory() as other:
            await other.execute(text("SET LOCAL lock_timeout = '1s'"))
            try:
                await other.execute(
                    update(DNSServer)
                    .where(DNSServer.id == server_id)
                    .values(last_config_etag="sha256:" + "b" * 64)
                )
            except DBAPIError as exc:
                pytest.fail(
                    "a released savepoint left the server row locked for the rest "
                    f"of the transaction: {type(exc.orig).__name__}: {exc.orig}"
                )
            await other.commit()
        await db_session.commit()
        assert await _seq(db_session, server_id) == before + 1
    finally:
        await engine.dispose()
