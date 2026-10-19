"""The row-lock order for one DNS server's rows (#1703, #1929).

Several transactions lock the same server's rows at once: the worker's bundle
render, the agent's config poll / heartbeat / zone-state report / op ack, and
an operator's group move (the server PUT, the Fleet roles PUT). Two of them
that take the same rows in different orders deadlock, and a transaction that
UPDATEs a row it read before another one deleted it fails with
``StaleDataError``. Both were 500s. So every one of them takes its locks in
ONE order:

1. ``dns_server_zone_state`` rows, ascending ``id``;
2. ``dns_record_op`` rows, ascending ``id``;
3. the ``dns_server`` row.

Each step is one statement (``SELECT … ORDER BY id FOR UPDATE`` locks the rows
in the sorted order). Two transactions that lock overlapping rows of one table
in ascending order cannot each hold a row the other wants, and a transaction
never waits for a table earlier in the list while it holds a later one.

This is the order the code mostly had already — the poll marks its ops and
writes ``last_config_etag`` at commit, the render retires its ops before it
stores the bundle, the commit-time dirty bump (``bundle_dirty``) comes last of
all — and the one a server move follows: it locks the server's zone-state rows
and queued ops before it takes the server row ``FOR UPDATE`` (the strong lock
the render's foreign key is waiting on, #1703). A SQLAlchemy flush writes the
rows of one mapper in primary-key order, so the UPDATEs that follow a lock
here keep the same ascending order.

A row deleted under a waiting lock is not returned (READ COMMITTED skips it),
so a caller that locks before it writes never updates a row that is gone.

The server row's PARENTS — its group and appliance — come before all of it: a
transaction that locks one of them and then marks the server's bundle takes the
parent first and the server row at commit. So nothing that holds the server row
may then wait on a parent (#2031). The trap is implicit: Postgres re-runs a
row's foreign-key checks on an UPDATE of a version the transaction itself wrote
(a second UPDATE of the row), taking ``FOR KEY SHARE`` on every parent. The
bundle store therefore writes the server row in one statement, and a lock on a
parent that only writes non-key columns is ``FOR NO KEY UPDATE``, which an FK
check never waits for.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerZoneState


async def lock_zone_state_rows(db: AsyncSession, *conds: Any) -> list[uuid.UUID]:
    """Step 1: lock the matching ``dns_server_zone_state`` rows, ascending id."""
    return list(
        (
            await db.execute(
                select(DNSServerZoneState.id)
                .where(*conds)
                .order_by(DNSServerZoneState.id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )


async def lock_op_ids(db: AsyncSession, *conds: Any) -> list[uuid.UUID]:
    """Step 2: lock the matching ``dns_record_op`` rows, ascending id."""
    return list(
        (
            await db.execute(
                select(DNSRecordOp.id).where(*conds).order_by(DNSRecordOp.id).with_for_update()
            )
        )
        .scalars()
        .all()
    )


async def lock_ops(db: AsyncSession, *conds: Any) -> list[DNSRecordOp]:
    """Step 2, returning the rows: instances already in the session are
    refreshed from the locked versions (``populate_existing``), so a caller
    that read them before the lock decides on what is there now."""
    return list(
        (
            await db.execute(
                select(DNSRecordOp)
                .where(*conds)
                .order_by(DNSRecordOp.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


def ids_in(ids: Iterable[uuid.UUID]) -> Any:
    return DNSRecordOp.id.in_(sorted(set(ids)))


async def lock_server_key_share(db: AsyncSession, server_id: uuid.UUID) -> uuid.UUID | None:
    """Step 3 for a transaction that only references the server (an INSERT
    whose foreign key points at it): ``FOR KEY SHARE``, which waits for a
    group move in progress and for nothing else. Returns the server's group
    as it is now — after any move that held the row — or None when the row
    is gone."""
    return (
        await db.execute(
            select(DNSServer.group_id)
            .where(DNSServer.id == server_id)
            .with_for_update(read=True, key_share=True)
        )
    ).scalar_one_or_none()


__all__ = [
    "ids_in",
    "lock_op_ids",
    "lock_ops",
    "lock_server_key_share",
    "lock_zone_state_rows",
]
