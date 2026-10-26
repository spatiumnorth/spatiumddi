"""The after-commit hooks hold a bounded number of connections (#2782).

The event publisher and the audit forwarder used to open a fresh NullPool
engine per commit, so the connections they held followed the write rate.
They now share one small pool per process, and open nothing when there is
nothing to deliver to.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest
from sqlalchemy import event, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.audit_forward import AuditForwardTarget
from app.models.event_subscription import EventOutbox, EventSubscription
from app.services import audit_forward, dispatch_db, event_publisher

# Extra connections the hooks may hold at once, per process.
CAP = 2


def _snaps(n: int) -> list[dict[str, Any]]:
    return [
        {"event_type": "subnet.created", "payload": {"event_id": str(uuid.uuid4())}}
        for _ in range(n)
    ]


@pytest.fixture
async def _dispatch_pool_closed():  # noqa: ANN202
    yield
    await dispatch_db.dispose()


class _ConnectCounter:
    """Counts every real DBAPI connect, whichever engine makes it."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self, *_a: object) -> None:
        self.n += 1

    def __enter__(self) -> _ConnectCounter:
        event.listen(Engine, "connect", self)
        return self

    def __exit__(self, *_a: object) -> None:
        event.remove(Engine, "connect", self)


async def _backends(conn: asyncpg.Connection) -> int:
    return int(
        await conn.fetchval(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid()"
        )
    )


def _raw_url() -> str:
    return settings.database_url.replace("+asyncpg", "")


async def test_concurrent_commits_never_hold_more_than_the_cap(
    db_session: AsyncSession, _dispatch_pool_closed: None
) -> None:
    db_session.add(
        EventSubscription(
            name=f"s-{uuid.uuid4().hex[:6]}",
            url="https://receiver.example.test/h",
            enabled=True,
            event_types=[],
        )
    )
    await db_session.commit()

    sampler = await asyncpg.connect(_raw_url())
    try:
        baseline = await _backends(sampler)
        peak = baseline
        stop = asyncio.Event()

        async def _sample() -> None:
            nonlocal peak
            while not stop.is_set():
                peak = max(peak, await _backends(sampler))
                await asyncio.sleep(0.002)

        watcher = asyncio.create_task(_sample())
        await asyncio.gather(*(event_publisher._publish_outbox_rows(_snaps(1)) for _ in range(80)))
        stop.set()
        await watcher
    finally:
        await sampler.close()

    assert peak - baseline <= CAP, f"held {peak - baseline} extra connections (cap {CAP})"
    # Queued, not dropped: every commit's event reached the outbox.
    n = (await db_session.execute(select(func.count()).select_from(EventOutbox))).scalar_one()
    assert n == 80


async def test_no_subscription_opens_one_connection_then_none(
    _dispatch_pool_closed: None,
) -> None:
    with _ConnectCounter() as c:
        for _ in range(50):
            await event_publisher._publish_outbox_rows(_snaps(1))
    assert c.n <= 1, f"{c.n} connections for 50 commits with nothing to publish to"


async def test_no_target_opens_one_connection_not_three_then_none(
    _dispatch_pool_closed: None,
) -> None:
    with _ConnectCounter() as c:
        await audit_forward._dispatch([{"payload": {"action": "create"}}])
    assert c.n == 1, "the legacy-fallback reads must share one connection"
    with _ConnectCounter() as c:
        for _ in range(30):
            await audit_forward._dispatch([{"payload": {"action": "create"}}])
    assert c.n == 0


async def test_publisher_and_forwarder_share_the_cap(
    db_session: AsyncSession, _dispatch_pool_closed: None
) -> None:
    db_session.add_all(
        [
            EventSubscription(
                name=f"s-{uuid.uuid4().hex[:6]}",
                url="https://receiver.example.test/h",
                enabled=True,
                event_types=[],
            ),
            AuditForwardTarget(
                name=f"t-{uuid.uuid4().hex[:6]}",
                enabled=True,
                kind="syslog",
                format="rfc5424_json",
                host="10.0.0.1",
                port=514,
                protocol="udp",
                facility=16,
            ),
        ]
    )
    await db_session.commit()
    with (
        _ConnectCounter() as c,
        patch.object(audit_forward, "_deliver_to_target", new=AsyncMock()) as deliver,
    ):
        await asyncio.gather(
            *(event_publisher._publish_outbox_rows(_snaps(1)) for _ in range(40)),
            *(audit_forward._dispatch([{"payload": {"action": "create"}}]) for _ in range(40)),
        )
    assert c.n <= CAP
    assert deliver.await_count == 40  # forwarding unchanged: one per row x target


async def test_new_subscription_is_seen_at_once_after_invalidate(
    db_session: AsyncSession, _dispatch_pool_closed: None
) -> None:
    await event_publisher._publish_outbox_rows(_snaps(1))
    assert event_publisher.subscriptions_cache.known_empty()
    db_session.add(
        EventSubscription(
            name=f"s-{uuid.uuid4().hex[:6]}",
            url="https://receiver.example.test/h",
            enabled=True,
            event_types=[],
        )
    )
    await db_session.commit()
    event_publisher.subscriptions_cache.invalidate()
    await event_publisher._publish_outbox_rows(_snaps(1))
    n = (await db_session.execute(select(func.count()).select_from(EventOutbox))).scalar_one()
    assert n == 1


async def test_dispose_closes_the_pool(db_session: AsyncSession) -> None:
    await event_publisher._publish_outbox_rows(_snaps(1))
    assert dispatch_db._state.engine is not None
    await dispatch_db.dispose()
    assert dispatch_db._state.engine is None
