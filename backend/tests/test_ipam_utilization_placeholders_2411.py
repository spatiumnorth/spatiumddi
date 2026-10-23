"""A full subnet reads at most 100 % utilised (#2411).

``total_ips`` is the usable size (network + broadcast left out for IPv4),
so the auto-created ``network`` / ``broadcast`` placeholder rows must not
count as allocated — a full /29 used to read 8 / 6 (133 %).
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, IPSpace
from app.tasks.ipam_utilization_recount import recount_utilization
from tests.test_ipam_alias_cname_exclusive_2080 import _headers


async def _full_slash29(client: AsyncClient, db: AsyncSession, net: str, cidr: str):
    headers = await _headers(db)
    space = IPSpace(name=f"sp2411-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=net, name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": cidr,
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return headers, str(resp.json()["id"]), str(block.id)


async def test_full_slash29_reads_100_percent(client: AsyncClient, db_session: AsyncSession):
    headers, sid, bid = await _full_slash29(client, db_session, "10.231.0.0/16", "10.231.3.0/29")

    # Fresh subnet: only the gateway (.1) is allocated, not network/broadcast.
    got = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()
    assert (got["allocated_ips"], got["total_ips"]) == (1, 6)

    for last in range(2, 7):
        r = await client.post(
            f"/api/v1/ipam/subnets/{sid}/addresses",
            headers=headers,
            json={"address": f"10.231.3.{last}", "hostname": f"h{last}"},
        )
        assert r.status_code == 201, r.text

    got = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()
    assert got["allocated_ips"] == 6
    assert got["total_ips"] == 6
    assert got["utilization_percent"] == 100.0

    # The block rollup and the hourly recount agree with the inline count.
    blk = (await client.get(f"/api/v1/ipam/blocks/{bid}", headers=headers)).json()
    assert blk["allocated_ips"] == 6
    await recount_utilization(db_session)
    got = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()
    assert (got["allocated_ips"], got["utilization_percent"]) == (6, 100.0)
