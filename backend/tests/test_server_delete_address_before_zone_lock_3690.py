"""#3690: a DHCP server delete locks the address rows it writes before its zone rows.

``delete_leases_for_server`` locked the zone rows of its leases' mirrors and
only afterwards wrote the ``ip_address`` rows (a purged DNS record NULLs
``ip_address.dns_record_id``). The permanent zone delete takes those address
rows first and the zone row second (#3691), so each held what the other
wanted: a 40P01 on one side. The order is global: dhcp_lease, ip_address,
dns_zone (ascending id).

The test needs no timing luck: the teardown is parked right after it took its
zone locks, then the zone delete is started. Unfixed the teardown holds the
zone and no address, the delete takes the addresses and waits for the zone,
and the teardown's next write waits for the addresses (the cycle). Fixed the
teardown already holds the addresses, so the delete waits on the first of
them and both finish.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.dhcp import DHCPLease
from app.models.ipam import IPAddress
from tests.test_lease_events_insert_order_3480 import (  # noqa: F401 — the fixture
    _ddns_subnet,
    concurrent_client,
)
from tests.test_lock_order_3617 import _server
from tests.test_trashed_record_zone_lock_3687 import (
    _blocked_by,
    _forward_zone,
    _live_published,
)

_WAIT_S = 20.0


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    eng = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_server_delete_holds_its_addresses_before_its_zone(
    db_session: AsyncSession, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services import lock_order
    from app.services.dhcp.lease_cleanup import delete_leases_for_server

    subnet, _ = await _ddns_subnet(db_session)
    zid = await _forward_zone(db_session, subnet)
    srv, scope = await _server(db_session, "kea", subnet)
    row = IPAddress(subnet_id=subnet.id, address="10.31.1.30", status="dhcp", auto_from_lease=True)
    db_session.add(row)
    await db_session.flush()
    await _live_published(db_session, subnet, row, "a-host")
    db_session.add(
        DHCPLease(
            server_id=srv.id,
            scope_id=scope.id,
            ip_address="10.31.1.30",
            mac_address="aa:bb:cc:31:01:30",
            state="active",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await db_session.commit()
    srv_id = srv.id

    parked = asyncio.Event()
    release = asyncio.Event()
    real = lock_order.lock_zone_rows
    first = True

    async def parking_lock_zone_rows(db: AsyncSession, zone_ids: Any) -> None:
        nonlocal first
        await real(db, zone_ids)
        if first:
            first = False
            parked.set()
            await release.wait()

    monkeypatch.setattr(lock_order, "lock_zone_rows", parking_lock_zone_rows)

    async def teardown() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            removed, _m = await delete_leases_for_server(db, srv_id)
            assert removed == 1
            await db.commit()

    async def zone_delete() -> None:
        """What the permanent zone delete does: addresses, then the zone."""
        async with AsyncSession(engine, expire_on_commit=False) as db:
            await lock_order.lock_addresses_of_zones(db, [zid])
            await db.execute(text("SELECT id FROM dns_zone WHERE id = :z FOR UPDATE"), {"z": zid})
            await db.execute(text("DELETE FROM dns_record WHERE zone_id = :z"), {"z": zid})
            await db.commit()

    probe = AsyncSession(engine)
    a = asyncio.create_task(teardown())
    b: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(parked.wait(), _WAIT_S)
        b = asyncio.create_task(zone_delete())
        # B is waiting on A's locks (the zone unfixed, the address fixed).
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _WAIT_S
        while loop.time() < deadline and not b.done():
            pids = (
                (
                    await probe.execute(
                        text(
                            "SELECT pid FROM pg_stat_activity WHERE datname = current_database()"
                            " AND pid <> pg_backend_pid()"
                        )
                    )
                )
                .scalars()
                .all()
            )
            if any([await _blocked_by(probe, p) for p in pids]):
                break
            await asyncio.sleep(0.05)
        release.set()
        results = await asyncio.gather(a, b, return_exceptions=True)
    finally:
        release.set()
        for t in (a, b):
            if t is not None and not t.done():
                t.cancel()
        await probe.close()
    assert results == [None, None], f"the teardown and the zone delete deadlocked: {results!r}"
