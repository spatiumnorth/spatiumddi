"""#3777: the scope teardown's scope-row lock keeps the one lock order.

The teardown batch holds its scope row ``FOR SHARE`` so a Trash restore waits
for the batch in flight. Where that lock sits in the order matters:

* taken BEFORE the batch's lease rows, it inverts against every writer that
  locks the scope's lease rows and then deletes the scope row (a permanent
  purge from the Trash): the purge holds the leases and waits for the scope,
  the batch holds the scope and waits for the leases;
* a restore that locks the zones it will write (#3627) BEFORE it un-stamps the
  scope inverts against a batch that holds the scope and goes on to lock the
  same zones for its mirrors' DDNS.

So the batch takes the scope after its lease rows (step 1, then the scope, as
a lease-events batch does), and the restore takes its scope rows before its
zones. Each test forces one interleave with a hold and expects both sides to
finish; on the inverted order Postgres aborts one of them with a deadlock.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.admin import trash as trash_api
from app.models.dhcp import DHCPLease, DHCPScope
from app.services import lock_order
from app.services.dhcp import lease_cleanup
from tests.test_dhcp_scope_delete_lease_hold_3733 import _seeded
from tests.test_lease_events_trashed_scope_3733 import (
    concurrent_client,  # noqa: F401 — the fixture, shared
)


async def _trash(db: AsyncSession, scope_id: Any) -> int:
    total = (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope_id)
        )
    ).scalar_one()
    scope = await db.get(DHCPScope, scope_id)
    assert scope is not None
    # Stamped as a delete stamps it: with a batch id, or the restore's
    # defensive stamp of one writes the scope row before anything else.
    scope.deleted_at = datetime.now(UTC)
    scope.deletion_batch_id = uuid.uuid4()
    await db.commit()
    return total


async def _leases(db: AsyncSession, scope_id: Any) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope_id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_a_scope_restore_does_not_deadlock_with_a_batch_on_its_zones(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The batch is held holding its scope, before it locks its mirrors'
    zones. A restore of the scope arrives; once the batch goes on, both
    finish: the restore with 200, the batch with its one batch of leases."""
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    _server, scope_id, _subnet, admin = await _seeded(concurrent_client, db_session)
    total = await _trash(db_session, scope_id)

    real = lock_order.lock_zones_for_lease_mirrors
    held, release = asyncio.Event(), asyncio.Event()

    async def _held(db: AsyncSession, ids: Any) -> Any:
        if not held.is_set():
            held.set()
            await asyncio.wait_for(release.wait(), timeout=60)
        return await real(db, ids)

    monkeypatch.setattr(lock_order, "lock_zones_for_lease_mirrors", _held)
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _teardown() -> tuple[int, int, bool]:
        async with factory() as session:
            return await lease_cleanup.tear_down_scope_leases(session, scope_id)

    try:
        teardown = asyncio.create_task(_teardown())
        await asyncio.wait_for(held.wait(), timeout=30)
        restore = asyncio.create_task(
            concurrent_client.post(
                f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=admin
            )
        )
        await asyncio.sleep(1.5)
        waited = not restore.done()
        release.set()
        removed, _mirrors, done = await asyncio.wait_for(teardown, timeout=60)
        restored = await asyncio.wait_for(restore, timeout=60)
    finally:
        release.set()
        await engine.dispose()

    assert waited, "the restore committed while a teardown batch held the scope"
    assert restored.status_code == 200, restored.text
    assert (removed, done) == (5, True)
    assert await _leases(db_session, scope_id) == total - removed


@pytest.mark.asyncio
async def test_a_trash_purge_holding_the_leases_does_not_deadlock_with_a_batch(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A permanent purge of the scope from the Trash locks its lease rows,
    then deletes the scope row. A teardown batch starts while the purge holds
    the leases. Both finish: the purge with 204, the batch finding nothing
    left to tear down."""
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    _server, scope_id, _subnet, admin = await _seeded(concurrent_client, db_session)
    await _trash(db_session, scope_id)

    real = trash_api.delete_leases_for_scope
    held, release = asyncio.Event(), asyncio.Event()

    async def _held(db: AsyncSession, sid: Any, **kwargs: Any) -> Any:
        out = await real(db, sid, **kwargs)
        held.set()
        await asyncio.wait_for(release.wait(), timeout=60)
        return out

    monkeypatch.setattr(trash_api, "delete_leases_for_scope", _held)
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _teardown() -> tuple[int, int, bool]:
        async with factory() as session:
            return await lease_cleanup.tear_down_scope_leases(session, scope_id)

    try:
        purge = asyncio.create_task(
            concurrent_client.delete(f"/api/v1/admin/trash/dhcp_scope/{scope_id}", headers=admin)
        )
        await asyncio.wait_for(held.wait(), timeout=30)
        teardown = asyncio.create_task(_teardown())
        await asyncio.sleep(1.5)
        release.set()
        purged = await asyncio.wait_for(purge, timeout=60)
        removed, _mirrors, done = await asyncio.wait_for(teardown, timeout=60)
    finally:
        release.set()
        await engine.dispose()

    assert purged.status_code == 204, purged.text
    assert (removed, done) == (0, True)
    gone = (
        await db_session.execute(
            select(DHCPScope.id)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert gone is None
    assert await _leases(db_session, scope_id) == 0
