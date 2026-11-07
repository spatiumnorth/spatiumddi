"""A permanent DNS delete locks the address rows it nulls out before the zone (#3691).

``ip_address.dns_record_id`` references ``dns_record`` ``ON DELETE SET NULL``,
so deleting records locks every address row that points at one, after the
zone row the delete holds. A lease-events batch takes its mirror
(``ip_address``) rows first and its zones after (``app.services.lock_order``):
holding a mirror whose record sits in the zone and waiting for the zone, it
deadlocked with the delete (40P01), and one side answered 500. The same shape
held for a permanent zone delete, a permanent single-record delete and a
permanent bulk record delete.

Each case holds a mirror row the way a batch does after it locked its mirrors,
sends the real permanent delete, then has the "batch" ask for the zone row. The
delete must wait at the mirror row without holding the zone, so the batch gets
the zone, finishes, and the delete completes.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.lock_order import lock_addresses_before
from tests.conftest import _TestSessionLocal
from tests.test_dns_record_write_zone_gone_3535 import (
    _PERMANENT,
    _STEP,
    _blocked_by,
    _seed,
    _Zone,
    concurrent_client,  # noqa: F401  (fixture)
)
from tests.test_dns_server_move_render_deadlock_1703 import _cleanup, _prepare


async def _mirror_of(db: AsyncSession, z: _Zone) -> uuid.UUID:
    """A lease mirror whose record is ``www`` in the zone."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.91.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.91.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    mirror = IPAddress(
        subnet_id=subnet.id,
        address="10.91.1.10",
        status="dhcp",
        auto_from_lease=True,
        dns_record_id=z.www_id,
    )
    db.add(mirror)
    await db.commit()
    return mirror.id


def _send(client: AsyncClient, z: _Zone, case: str) -> asyncio.Task[Response]:
    if case == "zone":
        req = client.delete(z.url, headers=z.headers, params=_PERMANENT)
    elif case == "record":
        req = client.delete(f"{z.url}/records/{z.www_id}", headers=z.headers, params=_PERMANENT)
    else:
        req = client.post(
            f"{z.url}/records/bulk-delete",
            headers=z.headers,
            params=_PERMANENT,
            json={"record_ids": [str(z.www_id)]},
        )
    return asyncio.create_task(req)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["zone", "record", "bulk"])
async def test_a_permanent_delete_waits_for_a_mirror_before_it_takes_the_zone(
    case: str,
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    z = await _seed(db_session)
    mirror_id = await _mirror_of(db_session, z)

    batch, probe = _TestSessionLocal(), _TestSessionLocal()
    pid = 0
    tasks: list[asyncio.Task[Response]] = []
    try:
        pid = await _prepare(batch)
        # The batch has locked its mirror.
        await asyncio.wait_for(
            batch.execute(
                text("SELECT id FROM ip_address WHERE id = :i FOR UPDATE"), {"i": mirror_id}
            ),
            _STEP,
        )
        delete = _send(concurrent_client, z, case)
        tasks.append(delete)
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
    assert resp.status_code in (200, 204), f"{resp.status_code} {resp.text[:300]}"
    if case == "bulk":
        assert resp.json()["deleted"] == 1, resp.text[:300]
    async with _TestSessionLocal() as check:
        assert (await check.get(DNSZone, z.zone_id) is None) == (case == "zone")
        row = await check.get(IPAddress, mirror_id)
        assert row is not None and row.dns_record_id is None
        assert (await check.get(DNSRecord, z.www_id)) is None


@pytest.mark.asyncio
async def test_a_row_linked_after_the_first_pass_does_not_deadlock_under_the_zone(
    db_session: AsyncSession,
) -> None:
    """A row linked to the zone between the first lock pass and the zone lock,
    and then taken by a lease batch that waits for the zone: the delete must
    not wait on it while it holds the zone. It gives the zone back and tries
    again with the row in its first pass."""
    z = await _seed(db_session)
    mirror_id = await _mirror_of(db_session, z)

    calls = 0

    async def find_ids() -> set[Any]:
        # The first pass runs before the link is visible; every later one sees it.
        nonlocal calls
        calls += 1
        return set() if calls == 1 else {mirror_id}

    deleter, batch, probe = _TestSessionLocal(), _TestSessionLocal(), _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[Any] | None = None
    try:
        pids.append(await _prepare(deleter))
        pids.append(await _prepare(batch))
        await asyncio.wait_for(
            batch.execute(
                text("SELECT id FROM ip_address WHERE id = :i FOR UPDATE"), {"i": mirror_id}
            ),
            _STEP,
        )

        async def take() -> None:
            await deleter.execute(
                select(DNSZone.id).where(DNSZone.id == z.zone_id).with_for_update()
            )

        task = asyncio.create_task(lock_addresses_before(deleter, find_ids, take))
        waiting = await _blocked_by(probe, pids[1], task)  # type: ignore[arg-type]
        assert waiting is not None, "the delete never waited on the mirror row"
        await asyncio.wait_for(
            batch.execute(
                text("SELECT id FROM dns_zone WHERE id = :z FOR NO KEY UPDATE"), {"z": z.zone_id}
            ),
            _STEP,
        )
        await asyncio.wait_for(batch.rollback(), _STEP)
        await asyncio.wait_for(task, _STEP)
        await asyncio.wait_for(deleter.rollback(), _STEP)
    finally:
        await _cleanup(task, [deleter, batch, probe], pids)
    # A first try that gave the zone back, and a second that took the row first.
    assert calls == 4
