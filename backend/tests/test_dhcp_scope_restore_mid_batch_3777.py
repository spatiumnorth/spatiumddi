"""#3777: a Trash restore waits for the scope teardown batch in flight.

``tear_down_scope_leases`` checked the scope's ``deleted_at`` with a plain
read, then purged up to ``SCOPE_DELETE_BATCH`` leases. A restore that
committed between the check and the batch's commit still lost that batch. The
batch now holds the scope row ``FOR SHARE``, so the restore (an UPDATE of the
row) waits for it, and the next batch finds the scope live and stops.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dhcp import DHCPLease, DHCPScope
from app.services.dhcp import lease_cleanup
from tests.test_dhcp_scope_delete_lease_hold_3733 import _seeded
from tests.test_lease_events_trashed_scope_3733 import (
    concurrent_client,  # noqa: F401 — the fixture, shared
)


@pytest.mark.asyncio
async def test_a_restore_waits_for_the_teardown_batch_in_flight(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 5, raising=False)
    _server, scope_id, _subnet, admin = await _seeded(concurrent_client, db_session)
    total = (
        await db_session.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope_id)
        )
    ).scalar_one()
    scope = await db_session.get(DHCPScope, scope_id)
    assert scope is not None
    scope.deleted_at = datetime.now(UTC)
    await db_session.commit()

    real = lease_cleanup.purge_lease
    held, release = asyncio.Event(), asyncio.Event()

    async def _held(db: AsyncSession, lease: Any, **kwargs: Any) -> bool:
        if not held.is_set():
            held.set()
            await asyncio.wait_for(release.wait(), timeout=60)
        return await real(db, lease, **kwargs)

    monkeypatch.setattr(lease_cleanup, "purge_lease", _held)
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
    assert done is True
    # Only the in-flight batch went; the next one found the scope live.
    assert removed == 5
    left = (
        await db_session.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope_id)
        )
    ).scalar_one()
    assert left == total - removed
