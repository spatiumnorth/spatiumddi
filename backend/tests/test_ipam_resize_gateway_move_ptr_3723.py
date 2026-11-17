"""Resize's gateway move retracts the old gateway row's PTR (#3723).

The commit deleted the old default ``gateway`` placeholder with a bare
``db.delete``, so its auto PTR stayed in the reverse zone and was still served,
while Edit Subnet's gateway move retracts it through ``_sync_dns_record``.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSZone
from app.models.ipam import IPAddress
from tests.conftest import _TestSessionLocal
from tests.test_dns_record_write_zone_gone_3535 import (
    _STEP,
    _blocked_by,
    concurrent_client,  # noqa: F401  (fixture)
)
from tests.test_dns_server_move_render_deadlock_1703 import _cleanup, _prepare
from tests.test_subnet_gateway_ptr_1150 import (
    _admin_headers,
    _create_subnet,
    _dns,
    _gateway_records,
    _space_block,
)


async def test_resize_gateway_move_retracts_the_old_gateway_ptr(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.89.0.0/16")
    await db_session.commit()
    group_id, server_id = grp.id, server.id
    sid = await _create_subnet(
        client,
        h,
        space,
        block,
        "10.89.23.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
    )
    assert await _gateway_records(db_session, sid) == [
        ("23.89.10.in-addr.arpa.", "PTR", "1", f"gateway.{zone.name}")
    ]

    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize",
        headers=h,
        json={"new_cidr": "10.89.22.0/23", "move_gateway_to_first_usable": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["subnet"]["gateway"] == "10.89.22.1"

    db_session.expire_all()
    # The old PTR is not left in the reverse zone...
    old_ptrs = (
        await db_session.execute(
            select(DNSRecord.id)
            .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
            .where(
                DNSZone.group_id == group_id,
                DNSZone.name == "23.89.10.in-addr.arpa.",
                DNSRecord.record_type == "PTR",
                DNSRecord.name == "1",
            )
        )
    ).all()
    assert old_ptrs == []
    # ...and the agent is told to drop it.
    ops = (
        (
            await db_session.execute(
                select(DNSRecordOp.op).where(
                    DNSRecordOp.server_id == server_id,
                    DNSRecordOp.zone_name == "23.89.10.in-addr.arpa.",
                    DNSRecordOp.record["name"].astext == "1",
                )
            )
        )
        .scalars()
        .all()
    )
    assert "delete" in ops


@pytest.mark.parametrize("case", ["resize", "edit"])
async def test_a_gateway_move_takes_the_old_gateway_row_before_the_reverse_zone(
    case: str,
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    """The retraction locks the reverse zone, and the delete then locked the
    old gateway row. A permanent zone delete takes the address rows linked to
    the zone first and the zone after (#3691, ``app.services.lock_order``), so
    a gateway move holding the zone and waiting for the row deadlocked with it
    (a 500). Resize and Edit Subnet must wait at the row without the zone."""
    h = await _admin_headers(db_session)
    grp, _server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.88.0.0/16")
    await db_session.commit()
    sid = await _create_subnet(
        concurrent_client,
        h,
        space,
        block,
        "10.88.23.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
    )
    async with _TestSessionLocal() as s:
        old_row_id = await s.scalar(
            select(IPAddress.id).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.hostname == "gateway"
            )
        )
        reverse_zone_id = await s.scalar(
            select(DNSZone.id).where(
                DNSZone.group_id == grp.id, DNSZone.name == "23.88.10.in-addr.arpa."
            )
        )
    assert old_row_id is not None and reverse_zone_id is not None

    purge, probe = _TestSessionLocal(), _TestSessionLocal()
    pid = 0
    tasks: list[asyncio.Task[Response]] = []
    try:
        pid = await _prepare(purge)
        # The purge has locked the address rows of the zone it deletes.
        await asyncio.wait_for(
            purge.execute(
                text("SELECT id FROM ip_address WHERE id = :i FOR UPDATE"), {"i": old_row_id}
            ),
            _STEP,
        )
        if case == "resize":
            req = concurrent_client.post(
                f"/api/v1/ipam/subnets/{sid}/resize",
                headers=h,
                json={"new_cidr": "10.88.22.0/23", "move_gateway_to_first_usable": True},
            )
        else:
            req = concurrent_client.put(
                f"/api/v1/ipam/subnets/{sid}", headers=h, json={"gateway": "10.88.23.254"}
            )
        resize = asyncio.create_task(req)
        tasks.append(resize)
        waiting = await _blocked_by(probe, pid, resize)
        assert waiting is not None, "the move never waited on the old gateway row"
        # The purge now takes the zone row. Held by the resize, this deadlocks.
        await asyncio.wait_for(
            purge.execute(
                text("SELECT id FROM dns_zone WHERE id = :z FOR NO KEY UPDATE"),
                {"z": reverse_zone_id},
            ),
            _STEP,
        )
        await asyncio.wait_for(purge.rollback(), _STEP)
        resp = await asyncio.wait_for(resize, _STEP)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(task, 5)
        await _cleanup(None, [purge, probe], [pid] if pid else [])
    assert resp.status_code == 200, f"{resp.status_code} {resp.text[:300]}"
    async with _TestSessionLocal() as check:
        assert await check.get(IPAddress, old_row_id) is None
