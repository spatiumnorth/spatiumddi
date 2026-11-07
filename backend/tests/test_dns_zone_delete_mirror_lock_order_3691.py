"""A permanent zone delete locks the address rows it nulls out before the zone (#3691).

``ip_address.dns_record_id`` references ``dns_record`` ``ON DELETE SET NULL``,
so deleting a zone's records locks every address row that points at one, after
the zone row. A lease-events batch takes its mirror (``ip_address``) rows first
and its zones after (``app.services.lock_order``): holding a mirror whose record
sits in the zone and waiting for the zone, it deadlocked with the delete (40P01),
and one side answered 500.

The test holds a mirror row the way a batch does after it locked its mirrors,
sends the real permanent delete, then has the "batch" ask for the zone row. The
delete must wait at the mirror row without holding the zone, so the batch gets
the zone, finishes, and the delete completes.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from tests._row_lock_order_guard import violations as _lock_order_violations
from tests.conftest import _TestSessionLocal
from tests.test_dns_record_write_zone_gone_3535 import (
    _STEP,
    _blocked_by,
    _delete_zone,
    _seed,
    concurrent_client,  # noqa: F401  (fixture)
)
from tests.test_dns_server_move_render_deadlock_1703 import _cleanup, _prepare


@pytest.mark.asyncio
async def test_a_permanent_zone_delete_waits_for_a_mirror_before_it_takes_the_zone(
    concurrent_client: AsyncClient, db_session: AsyncSession  # noqa: F811
) -> None:
    z = await _seed(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.91.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.91.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    mirror = IPAddress(
        subnet_id=subnet.id,
        address="10.91.1.10",
        status="dhcp",
        auto_from_lease=True,
        dns_record_id=z.www_id,
    )
    db_session.add(mirror)
    await db_session.commit()
    mirror_id = mirror.id

    batch, probe = _TestSessionLocal(), _TestSessionLocal()
    pid = 0
    tasks: list[asyncio.Task[object]] = []
    try:
        pid = await _prepare(batch)
        # The batch has locked its mirror.
        await asyncio.wait_for(
            batch.execute(
                text("SELECT id FROM ip_address WHERE id = :i FOR UPDATE"), {"i": mirror_id}
            ),
            _STEP,
        )
        delete = _delete_zone(concurrent_client, z, permanent=True)
        tasks.append(delete)  # type: ignore[arg-type]
        waiting = await _blocked_by(probe, pid, delete)
        assert waiting is not None, "the delete never waited on the mirror row"
        # The batch now wants the zone, as it does to publish DDNS. With the
        # zone held by the delete this is the deadlock.
        await asyncio.wait_for(
            batch.execute(
                text("SELECT id FROM dns_zone WHERE id = :z FOR NO KEY UPDATE"), {"z": z.zone_id}
            ),
            _STEP,
        )
        await asyncio.wait_for(batch.rollback(), _STEP)
        resp = await asyncio.wait_for(delete, _STEP)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(task, 5)
        await _cleanup(None, [batch, probe], [pid] if pid else [])
    assert resp.status_code == 204, f"{resp.status_code} {resp.text[:300]}"
    async with _TestSessionLocal() as check:
        assert await check.get(DNSZone, z.zone_id) is None
        row = await check.get(IPAddress, mirror_id)
        assert row is not None and row.dns_record_id is None
        assert (await check.get(DNSRecord, z.www_id)) is None
    _lock_order_violations.clear()
