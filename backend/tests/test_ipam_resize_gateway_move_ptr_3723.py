"""Resize's gateway move retracts the old gateway row's PTR (#3723).

The commit deleted the old default ``gateway`` placeholder with a bare
``db.delete``, so its auto PTR stayed in the reverse zone and was still served,
while Edit Subnet's gateway move retracts it through ``_sync_dns_record``.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSZone
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
